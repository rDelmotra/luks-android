package dev.luksandroid.session

import dev.luksandroid.Entry
import dev.luksandroid.LuksException
import dev.luksandroid.PartitionInfo
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

class LuksSessionTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var session: SessionController

    @Before
    fun setUp() {
        testScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        session = SessionController(scope = testScope)
    }

    @After
    fun tearDown() {
        testScope.cancel()
    }

    /**
     * Test K.0: `withLease` allows concurrent readers and prevents `lock()` until leases drain.
     */
    @Test
    fun testK0_concurrentReadersAndLockWaitsForDrain() = runBlocking {
        val closeOrder = Collections.synchronizedList(mutableListOf<String>())
        val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
        val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }

        session.startUnlockedForTest(
            volume = null,
            device = deviceStub,
            volumeCloseable = volumeStub,
        )

        // Part 1: Verify concurrent readers can execute in parallel
        val concurrentReaders = AtomicInteger(0)
        val maxConcurrent = AtomicInteger(0)
        val readyLatch = CompletableDeferred<Unit>()

        val readerJobs = (1..5).map {
            async(Dispatchers.Default) {
                session.withLease {
                    val count = concurrentReaders.incrementAndGet()
                    maxConcurrent.updateAndGet { current -> maxOf(current, count) }
                    readyLatch.await()
                    concurrentReaders.decrementAndGet()
                }
            }
        }

        // Wait until all 5 readers have acquired their leases
        while (concurrentReaders.get() < 5) {
            delay(10)
        }

        assertTrue("Expected concurrent readers >= 2, got ${maxConcurrent.get()}", maxConcurrent.get() >= 2)
        assertEquals(5, session.activeLeaseCount)

        // Release reader latch
        readyLatch.complete(Unit)
        readerJobs.awaitAll()
        assertEquals(0, session.activeLeaseCount)

        // Part 2: Verify lock() waits for in-flight lease to drain and rejects new leases
        val leaseInFlight = CompletableDeferred<Unit>()
        val leaseCanFinish = CompletableDeferred<Unit>()
        val leaseFinished = CompletableDeferred<Unit>()

        val longLeaseJob = launch(Dispatchers.Default) {
            session.withLease {
                leaseInFlight.complete(Unit)
                leaseCanFinish.await()
            }
            leaseFinished.complete(Unit)
        }

        leaseInFlight.await()
        assertEquals(1, session.activeLeaseCount)

        val lockFinished = CompletableDeferred<Unit>()
        val lockJob = launch(Dispatchers.Default) {
            session.lock()
            lockFinished.complete(Unit)
        }

        // Give lock() a moment to initiate and wait
        delay(50)

        // Lock must still be waiting because lease is active
        assertTrue("lock() must not finish while lease is active", !lockFinished.isCompleted)
        assertTrue("State must not be Locked while lease is active", session.state.value !is SessionState.Locked)
        assertTrue("Volume must not be closed while lease is active", closeOrder.isEmpty())

        // Any new withLease call during locking must be rejected immediately
        try {
            session.withLease { }
            fail("Expected IllegalStateException for withLease while locking")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("locking") == true || e.message?.contains("not unlocked") == true)
        }

        // Finish the in-flight lease
        leaseCanFinish.complete(Unit)
        leaseFinished.await()
        lockFinished.await()
        lockJob.join()
        longLeaseJob.join()

        // Now lock() has completed
        assertEquals(SessionState.Locked, session.state.value)
        assertEquals(0, session.activeLeaseCount)
        assertNull(session.volume)
        assertNull(session.device)
        assertTrue("Handles must be closed after lock", closeOrder.contains("VOLUME_CLOSED"))
    }

    /**
     * Test K.1: Handle teardown ordering (volume closed before device).
     */
    @Test
    fun testK1_handleTeardownOrdering_volumeClosedBeforeDevice() = runBlocking {
        val closeOrder = Collections.synchronizedList(mutableListOf<String>())
        val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
        val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }

        session.startUnlockedForTest(
            volume = null,
            device = deviceStub,
            volumeCloseable = volumeStub,
        )

        session.lock()

        assertEquals(listOf("VOLUME_CLOSED", "DEVICE_CLOSED"), closeOrder)
        assertEquals(SessionState.Locked, session.state.value)
    }

    /**
     * Test K.2: Detach event transitions state immediately to `Detached`.
     */
    @Test
    fun testK2_detachEventTransitionsStateImmediatelyToDetached() = runBlocking {
        val closeOrder = Collections.synchronizedList(mutableListOf<String>())
        val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
        val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }

        session.startUnlockedForTest(
            volume = null,
            device = deviceStub,
            volumeCloseable = volumeStub,
            partition = PartitionInfo(1, "Data", 2048L, 1000000L, true, 2),
        )

        // Simulate USB unplug
        session.onDeviceDetached("Hardware disconnect on USB port")

        val state = session.state.value
        assertTrue("State must be Detached", state is SessionState.Detached)
        assertEquals("Hardware disconnect on USB port", (state as SessionState.Detached).message)

        // Volume and device must be torn down
        assertEquals(listOf("VOLUME_CLOSED", "DEVICE_CLOSED"), closeOrder)
        assertNull(session.volume)
        assertNull(session.device)

        // Subsequent lease calls must be rejected
        try {
            session.withLease { }
            fail("Expected IllegalStateException when in Detached state")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("not unlocked") == true)
        }

        // Reset transitions back to Locked
        session.reset()
        assertEquals(SessionState.Locked, session.state.value)
    }

    /**
     * A `CorruptFs` surfacing from a *read* must fail that one read and leave the
     * session unlocked.
     *
     * Regression test. `isFatalWriteFailure` (formerly `isFatalWritePoison`) used to substring-match "corrupt",
     * "poison" and "panic" against the exception message, so a read returning
     * `CorruptFs("btrfs node has no items")` -- raised by `Cursor::retreat_leaf`
     * while merely listing a btrfs volume through SAF -- tore the whole session
     * down and reported it to the user as "Write poison". Browsing the drive in a
     * file manager therefore locked them out of it, and the message named a cause
     * ("write") that had not happened.
     */
    @Test
    fun testReadSideCorruptFsDoesNotPoisonTheSession() = runBlocking {
        session.startUnlockedForTest()

        try {
            session.withLease {
                throw LuksException(
                    "corrupt filesystem structure: btrfs node has no items",
                    LuksException.CORRUPT,
                )
            }
            fail("Expected the CorruptFs to propagate to the caller")
        } catch (e: LuksException) {
            assertEquals(LuksException.CORRUPT, e.code)
        }

        assertTrue(
            "A read-side CorruptFs must not move the session out of Unlocked, " +
                "state was ${session.state.value}",
            session.state.value is SessionState.Unlocked,
        )
        // ...and the volume must still be usable.
        assertEquals(7, session.withLease { 7 })
    }

    /** The one code that genuinely does invalidate the volume still tears it down. */
    @Test
    fun testMutexPoisonedFromNativeStillPoisonsTheSession() = runBlocking {
        session.startUnlockedForTest()

        try {
            session.withLease {
                throw LuksException("write mutex poisoned", LuksException.MUTEX_POISONED)
            }
            fail("Expected the poison to propagate")
        } catch (e: LuksException) {
            assertEquals(LuksException.MUTEX_POISONED, e.code)
        }

        assertTrue(
            "MUTEX_POISONED must move the session to Failed, state was ${session.state.value}",
            session.state.value is SessionState.Failed,
        )
    }

    /**
     * Fence twin of [testMutexPoisonedFromNativeStillPoisonsTheSession]. A
     * [LuksException.WRITE_SESSION_FENCED] means a previous write left the
     * drive's on-disk state unknown (a transport failure, not a panic), and
     * `isFatalWriteFailure` must still refuse further writes on this volume.
     * The Failed message must name the fence, not claim something panicked.
     */
    @Test
    fun testWriteSessionFencedFromNativeMovesSessionToFailed() = runBlocking {
        session.startUnlockedForTest()

        try {
            session.withLease {
                throw LuksException("usb transfer timed out mid-commit", LuksException.WRITE_SESSION_FENCED)
            }
            fail("Expected the fence to propagate")
        } catch (e: LuksException) {
            assertEquals(LuksException.WRITE_SESSION_FENCED, e.code)
        }

        val state = session.state.value
        assertTrue(
            "WRITE_SESSION_FENCED must move the session to Failed, state was $state",
            state is SessionState.Failed,
        )
        val message = (state as SessionState.Failed).message
        assertFalse("Fence message must not claim a panic occurred: $message", message.contains("panic"))
        assertTrue(
            "Fence message must name the remedy (unlock again): $message",
            message.contains("Unlock the volume again"),
        )
    }

    /**
     * Negative control, the exact regression `isFatalWriteFailure` already
     * suffered once (see [testReadSideCorruptFsDoesNotPoisonTheSession]):
     * [LuksException.CORRUPT] raised by a *read* must not be treated as a
     * fatal write failure. Only [LuksException.MUTEX_POISONED],
     * [LuksException.PANIC] and [LuksException.WRITE_SESSION_FENCED] tear the
     * session down; every other code -- including CORRUPT -- must leave the
     * session in [SessionState.Unlocked] so the caller can keep working with
     * the rest of the volume.
     */
    @Test
    fun testCorruptFromReadDoesNotMoveSessionToFailed() = runBlocking {
        session.startUnlockedForTest()

        try {
            session.withLease {
                throw LuksException("btrfs node has no items", LuksException.CORRUPT)
            }
            fail("Expected the CorruptFs to propagate to the caller")
        } catch (e: LuksException) {
            assertEquals(LuksException.CORRUPT, e.code)
        }

        assertTrue(
            "CORRUPT from a read must not move the session to Failed, state was ${session.state.value}",
            session.state.value is SessionState.Unlocked,
        )
    }

    /**
     * A refusal handed to a third-party app must not name anything inside the volume.
     *
     * `withLease` used to interpolate the whole `SessionState` into its refusal
     * ("current state: $s"). `Failed`/`Detached` carry a free-text message that
     * routinely quotes a native error naming a path on the encrypted volume, so a
     * SAF caller that was just *denied* access got a plaintext filename from it.
     */
    @Test
    fun testWithLeaseRefusalDoesNotLeakVolumeContentsFromTheFailureMessage() = runBlocking {
        session.startUnlockedForTest()
        session.onWritePoison("Internal native error at /private/passwords_database.kdbx")

        val message = try {
            session.withLease { }
            fail("Expected IllegalStateException once the session is Failed")
            return@runBlocking
        } catch (e: IllegalStateException) {
            e.message.orEmpty()
        }

        assertFalse(
            "Refusal leaked a volume path: $message",
            message.contains("passwords_database") || message.contains("/private"),
        )
        assertTrue("Refusal should still say it was refused", message.contains("not unlocked"))
    }

    /**
     * Test K.4: Write poison moves session to `Failed`.
     */
    @Test
    fun testK4_writePoisonMovesSessionToFailed() = runBlocking {
        val closeOrder = Collections.synchronizedList(mutableListOf<String>())
        val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
        val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }

        session.startUnlockedForTest(
            volume = null,
            device = deviceStub,
            volumeCloseable = volumeStub,
        )

        // Simulate write poison
        session.onWritePoison("btrfs allocator panic: poisoned mutex")

        val state = session.state.value
        assertTrue("State must be Failed", state is SessionState.Failed)
        assertTrue(
            "Message should describe write poison",
            (state as SessionState.Failed).message.contains("Write poison: btrfs allocator panic: poisoned mutex")
        )

        // Teardown should have executed
        assertEquals(listOf("VOLUME_CLOSED", "DEVICE_CLOSED"), closeOrder)
        assertNull(session.volume)
        assertNull(session.device)

        // Subsequent withLease operations must be rejected
        try {
            session.withLease { }
            fail("Expected IllegalStateException when in Failed state")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("not unlocked") == true)
        }

        // Re-unlock recovery via reset
        session.reset()
        assertEquals(SessionState.Locked, session.state.value)
    }

    /**
     * Test K.5: Idle timeout fires after period of inactivity and locks session.
     */
    @Test
    fun testK5_idleTimeoutFiresAfterPeriodOfInactivityAndLocksSession() = runBlocking {
        val closeOrder = Collections.synchronizedList(mutableListOf<String>())
        val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
        val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }

        session.setIdleTimeout(100L) // 100ms idle timeout for test

        session.startUnlockedForTest(
            volume = null,
            device = deviceStub,
            volumeCloseable = volumeStub,
        )

        assertTrue(session.state.value is SessionState.Unlocked)

        // Touch the session at 40ms to record activity
        delay(40)
        session.withLease { }

        // At 80ms total (40ms since last activity), session must still be Unlocked
        delay(40)
        assertTrue("Session must remain unlocked before timeout", session.state.value is SessionState.Unlocked)

        // Wait 150ms without activity (total idle time 150ms > 100ms timeout)
        delay(150)

        assertEquals("Session must lock after idle timeout", SessionState.Locked, session.state.value)
        assertEquals(listOf("VOLUME_CLOSED", "DEVICE_CLOSED"), closeOrder)
        assertNull(session.volume)
        assertNull(session.device)

        // Subsequent lease calls must be rejected
        try {
            session.withLease { }
            fail("Expected IllegalStateException when locked")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("not unlocked") == true)
        }
    }

    /**
     * Test K.6: [SessionController.onTrimMemory] must not lock on
     * `TRIM_MEMORY_UI_HIDDEN`.
     *
     * This is the method [dev.luksandroid.MainActivity]'s own `onTrimMemory`
     * override forwards into directly (`LuksSession.onTrimMemory(level)`), separately
     * from [LuksSessionLifecycle]'s `ComponentCallbacks2` registration at the
     * Application level — both receive the same system trim events. The captured
     * hardware logcat for the "backgrounding destroys the session" bug
     * (`LuksSession: onTrimMemory level=20` immediately followed by
     * `LuksSession: locking session, waiting for leases to drain`) matches this
     * method's own `Trace.i` message format, not [LuksSessionLifecycle]'s — so this
     * was the code path that actually fired on the device, and the policy fix has to
     * apply here too, not only in [LuksSessionLifecycle].
     */
    @Test
    fun testK6_onTrimMemory_uiHidden_doesNotLock() = runBlocking {
        session.startUnlockedForTest()

        @Suppress("DEPRECATION")
        session.onTrimMemory(android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN)

        delay(300)
        assertTrue(
            "Backgrounding (UI_HIDDEN=20) must never lock the session",
            session.state.value is SessionState.Unlocked,
        )
    }

    /**
     * Test K.7: [SessionController.onTrimMemory] still locks on the levels that
     * mean the process is genuinely about to be killed.
     */
    @Test
    fun testK7_onTrimMemory_completeAndRunningCritical_locks() = runBlocking {
        @Suppress("DEPRECATION")
        suspend fun expectLocks(level: Int) {
            val closeOrder = Collections.synchronizedList(mutableListOf<String>())
            val volumeStub = AutoCloseable { closeOrder.add("VOLUME_CLOSED") }
            val deviceStub = AutoCloseable { closeOrder.add("DEVICE_CLOSED") }
            session.startUnlockedForTest(volume = null, device = deviceStub, volumeCloseable = volumeStub)

            session.onTrimMemory(level)

            withTimeout(2000) {
                while (session.state.value !is SessionState.Locked) delay(10)
            }
            assertEquals(SessionState.Locked, session.state.value)
            assertTrue(closeOrder.contains("VOLUME_CLOSED"))

            session.reset()
        }

        expectLocks(android.content.ComponentCallbacks2.TRIM_MEMORY_COMPLETE)
        expectLocks(android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL)
    }

    /**
     * Test K.8: intermediate trim levels (BACKGROUND, MODERATE, RUNNING_LOW) must not
     * lock — only exact COMPLETE/RUNNING_CRITICAL do. The old policy used
     * `level >= TRIM_MEMORY_RUNNING_CRITICAL`, which swept these in too.
     */
    @Test
    fun testK8_onTrimMemory_intermediateLevels_doNotLock() = runBlocking {
        @Suppress("DEPRECATION")
        suspend fun expectNoLock(level: Int) {
            session.startUnlockedForTest()
            session.onTrimMemory(level)
            delay(200)
            assertTrue(
                "level=$level must not lock",
                session.state.value is SessionState.Unlocked,
            )
            session.reset()
        }

        expectNoLock(android.content.ComponentCallbacks2.TRIM_MEMORY_BACKGROUND)
        expectNoLock(android.content.ComponentCallbacks2.TRIM_MEMORY_MODERATE)
        expectNoLock(android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW)
        expectNoLock(android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE)
    }
}
