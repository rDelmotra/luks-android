package dev.luksandroid.session

import android.content.Context
import dev.luksandroid.Entry
import dev.luksandroid.LuksDevice
import dev.luksandroid.LuksException
import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.Trace
import dev.luksandroid.UnlockService
import dev.luksandroid.security.SecurePassphraseBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * State machine for the process-scoped LUKS session.
 */
sealed interface SessionState {
    data object Locked : SessionState
    data class Unlocking(val partition: PartitionInfo) : SessionState
    data class Unlocked(
        val volume: LuksVolume,
        val partition: PartitionInfo,
        val entries: List<Entry> = emptyList(),
    ) : SessionState
    data class Detached(val message: String = "USB drive was disconnected") : SessionState
    data class Failed(val message: String, val partition: PartitionInfo? = null) : SessionState
}

/**
 * Process-scoped, thread-safe, reference-counted owner of the unlocked LUKS volume.
 */
open class SessionController(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
    private val timeProvider: () -> Long = { System.currentTimeMillis() },
) {
    private val _state = MutableStateFlow<SessionState>(SessionState.Locked)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val mutex = Mutex()
    private val _activeLeases = MutableStateFlow(0)
    val activeLeases: Int get() = _activeLeases.value
    val activeLeaseCount: Int get() = _activeLeases.value
    val activeLeasesFlow: StateFlow<Int> = _activeLeases.asStateFlow()

    private val isLocking = AtomicBoolean(false)

    var device: AutoCloseable? = null
        private set
    var volume: LuksVolume? = null
        private set

    internal var volumeCloseable: AutoCloseable? = null
    internal var deviceCloseable: AutoCloseable? = null

    private var idleTimeoutMs: Long = DEFAULT_IDLE_TIMEOUT_MS
    private var idleJob: Job? = null
    private var lastActivityMs: Long = 0L

    private val _remainingIdleMs = MutableStateFlow(DEFAULT_IDLE_TIMEOUT_MS)
    val remainingIdleMs: StateFlow<Long> = _remainingIdleMs.asStateFlow()

    companion object {
        // Idle-lock value is a trade-off against re-unlock cost, not a fixed security
        // number: hardware run 2026-08-18 measured a single unlock (Argon2 KDF) at
        // 78s. At the old 5-minute value, any pause near that length (reading a file
        // list, switching to a file manager and back) forces the user through another
        // 78s KDF just to keep working — that is what "locking in 5 mins what is this"
        // was about. 15 minutes keeps a real idle-security backstop while making
        // relock rare during actual use; it is not configurable (out of scope here),
        // so it has to be a number that is defensible on its own.
        const val DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000L // 15 minutes
    }

    fun setIdleTimeout(timeoutMs: Long) {
        idleTimeoutMs = timeoutMs
        _remainingIdleMs.value = timeoutMs
        if (_state.value is SessionState.Unlocked) {
            restartIdleTimer()
        }
    }

    private fun recordActivity() {
        lastActivityMs = timeProvider()
        _remainingIdleMs.value = idleTimeoutMs
    }

    private fun restartIdleTimer() {
        idleJob?.cancel()
        if (idleTimeoutMs <= 0) return
        recordActivity()
        idleJob = scope.launch {
            while (isActive) {
                if (_activeLeases.value > 0) {
                    recordActivity()
                    delay(100)
                    continue
                }
                val elapsed = timeProvider() - lastActivityMs
                val remaining = idleTimeoutMs - elapsed
                _remainingIdleMs.value = remaining.coerceAtLeast(0L)
                if (remaining <= 0) {
                    if (_activeLeases.value == 0) {
                        Trace.i("LuksSession: idle timeout expired, locking session")
                        lock()
                        break
                    } else {
                        delay(100)
                    }
                } else {
                    delay(minOf(250L, remaining.coerceAtLeast(1L)))
                }
            }
        }
    }

    private fun cancelIdleTimer() {
        idleJob?.cancel()
        idleJob = null
        _remainingIdleMs.value = idleTimeoutMs
    }

    /**
     * Executes [block] with reference-counted access to the active [LuksVolume].
     *
     * Multiple readers can execute concurrently. [lock] and teardown operations
     * wait for all active leases to drain.
     */
    suspend fun <T> withLease(block: suspend (LuksVolume) -> T): T {
        if (isLocking.get()) {
            throw IllegalStateException("Session is currently locking")
        }
        val currentVol = mutex.withLock {
            if (isLocking.get()) {
                throw IllegalStateException("Session is currently locking")
            }
            val s = _state.value
            if (s !is SessionState.Unlocked) {
                throw IllegalStateException("Session is not unlocked (current state: $s)")
            }
            val v = volume ?: s.volume
            _activeLeases.update { it + 1 }
            recordActivity()
            v
        }

        try {
            return block(currentVol)
        } catch (t: Throwable) {
            if (isFatalWritePoison(t)) {
                onWritePoison(t.message ?: t.toString())
            }
            throw t
        } finally {
            _activeLeases.update { it - 1 }
            recordActivity()
        }
    }

    /**
     * Unlocks [partition] on [device] using [password] within [UnlockService.holding].
     */
    suspend fun unlock(
        context: Context,
        device: LuksDevice,
        partition: PartitionInfo,
        password: SecurePassphraseBuffer,
    ): SessionState = mutex.withLock {
        Trace.i("LuksSession: unlocking partition at offset ${partition.offsetBytes}")
        _state.value = SessionState.Unlocking(partition)
        val started = timeProvider()
        try {
            val vol = UnlockService.holding(context) {
                withContext(Dispatchers.IO) {
                    device.unlock(partition.offsetBytes, password)
                }
            }
            val kdfMs = timeProvider() - started
            val info = vol.info
            Trace.i(
                "LuksSession: unlocked in $kdfMs ms · fs=${info.fsType} " +
                    "block=${info.blockSize} size=${info.sizeBytes} " +
                    "subvolumes=${info.subvolumes.size}"
            )
            val entries = withContext(Dispatchers.IO) { vol.listDir("/") }
            Trace.i("LuksSession: root listed, ${entries.size} entries")

            this.device = device
            this.volume = vol
            this.volumeCloseable = vol
            this.deviceCloseable = device

            val unlocked = SessionState.Unlocked(vol, partition, entries)
            _state.value = unlocked
            restartIdleTimer()
            unlocked
        } catch (e: LuksException) {
            Trace.err(e.code, "unlock")
            Trace.e("LuksSession: unlock failed [${e.code}]")
            val msg = if (e.isWrongPassword) "wrong passphrase" else "[${e.code}] ${e.message}"
            val failed = SessionState.Failed(msg, partition)
            _state.value = failed
            failed
        } catch (e: Exception) {
            Trace.err(-1, "unlock")
            Trace.e("LuksSession: unlock failed: ${Trace.throwableSummary(e)}")
            val failed = SessionState.Failed(e.message ?: e.toString(), partition)
            _state.value = failed
            failed
        }
    }

    /**
     * Unlocks the first LUKS partition found on [device] using [password].
     */
    suspend fun unlock(
        context: Context,
        device: LuksDevice,
        password: SecurePassphraseBuffer,
    ): SessionState {
        val partition = device.luksPartitions.firstOrNull()
            ?: throw IllegalStateException("No LUKS partition found on device")
        return unlock(context, device, partition, password)
    }

    /**
     * Waits for all active leases to drain, then tears down the volume and device handles.
     */
    suspend fun lock(): Unit {
        if (_state.value is SessionState.Locked && !isLocking.get()) {
            return
        }
        val shouldProceed = mutex.withLock {
            if (_state.value is SessionState.Locked || isLocking.get()) {
                false
            } else {
                isLocking.set(true)
                true
            }
        }
        if (!shouldProceed) return

        try {
            Trace.i("LuksSession: locking session, waiting for leases to drain")
            if (_activeLeases.value > 0) {
                _activeLeases.first { it == 0 }
            }
            mutex.withLock {
                teardownHandles()
                _state.value = SessionState.Locked
            }
        } finally {
            isLocking.set(false)
        }
    }

    /**
     * Handles USB device detachment. Immediately marks session as [SessionState.Detached]
     * and tears down handles.
     */
    suspend fun onDeviceDetached(message: String = "USB drive was disconnected") = mutex.withLock {
        Trace.i("LuksSession: device detached ($message)")
        isLocking.set(false)
        teardownHandles()
        _state.value = SessionState.Detached(message)
    }

    fun notifyDeviceDetached(message: String = "USB drive was disconnected") {
        scope.launch {
            onDeviceDetached(message)
        }
    }

    /**
     * Moves session into [SessionState.Failed] upon write poison / fatal write failure.
     */
    suspend fun onWritePoison(reason: String) = mutex.withLock {
        Trace.err(-1, "write_poison")
        Trace.e("LuksSession: write poison detected: $reason")
        isLocking.set(false)
        teardownHandles()
        _state.value = SessionState.Failed("Write poison: $reason")
    }

    /**
     * Resets any detached or failed session state back to [SessionState.Locked].
     */
    suspend fun reset() = mutex.withLock {
        Trace.i("LuksSession: reset")
        isLocking.set(false)
        teardownHandles()
        _state.value = SessionState.Locked
    }

    /**
     * Called directly by [dev.luksandroid.MainActivity]'s own `onTrimMemory` override, in
     * addition to [LuksSessionLifecycle] (registered at the Application level via
     * `registerComponentCallbacks`) receiving the same system events — both paths land here
     * or in [LuksSessionLifecycle], so the policy has to agree in both places.
     *
     * Previously this locked on any `level >= TRIM_MEMORY_RUNNING_CRITICAL (15)`, which
     * silently swept in `TRIM_MEMORY_UI_HIDDEN (20)`, `BACKGROUND (40)`, `MODERATE (60)` and
     * `COMPLETE (80)` — i.e. plain backgrounding, not memory pressure. The logcat evidence
     * for the "backgrounding destroys the session" bug (`LuksSession: onTrimMemory level=20`
     * immediately followed by `LuksSession: locking session...`) is this method's own
     * `Trace.i` format, not [LuksSessionLifecycle]'s — this was the actual live trigger, not
     * just [LuksSessionLifecycle]. Only [android.content.ComponentCallbacks2.TRIM_MEMORY_COMPLETE]
     * and [android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL] mean the process is
     * genuinely about to be killed; those are the only levels allowed to lock here.
     */
    @Suppress("DEPRECATION")
    fun onTrimMemory(level: Int) {
        Trace.i("LuksSession: onTrimMemory level=$level")
        val criticalLevel = level == android.content.ComponentCallbacks2.TRIM_MEMORY_COMPLETE ||
            level == android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL
        if (criticalLevel && _activeLeases.value == 0) {
            scope.launch { lock() }
        }
    }

    /**
     * Helper for tests to initialize the session in Unlocked state.
     */
    suspend fun startUnlockedForTest(
        volume: LuksVolume? = null,
        device: AutoCloseable? = null,
        volumeCloseable: AutoCloseable? = volume,
        deviceCloseable: AutoCloseable? = device,
        partition: PartitionInfo = PartitionInfo(0, "test", 0L, 1024L * 1024L, true, 2),
        entries: List<Entry> = emptyList(),
    ): SessionState.Unlocked = mutex.withLock {
        this.volume = volume
        this.device = device
        this.volumeCloseable = volumeCloseable
        this.deviceCloseable = deviceCloseable
        val dummyVol = volume ?: LuksVolume(0L)
        val s = SessionState.Unlocked(dummyVol, partition, entries)
        _state.value = s
        restartIdleTimer()
        s
    }

    private fun teardownHandles() {
        cancelIdleTimer()
        val volC = volumeCloseable ?: volume
        val devC = deviceCloseable ?: device
        volume = null
        device = null
        volumeCloseable = null
        deviceCloseable = null

        // 1. Volume must close FIRST
        try {
            volC?.close()
        } catch (t: Throwable) {
            Trace.e("LuksSession: error closing volume during teardown: ${Trace.throwableSummary(t)}")
        }

        // 2. Device must close SECOND
        try {
            devC?.close()
        } catch (t: Throwable) {
            Trace.e("LuksSession: error closing device during teardown: ${Trace.throwableSummary(t)}")
        }
    }

    private fun isFatalWritePoison(t: Throwable): Boolean {
        val msg = t.message?.lowercase() ?: ""
        return msg.contains("poison") || msg.contains("panic") || msg.contains("corrupt")
    }
}

/** Default singleton instance used across the application. */
object LuksSession : SessionController()
