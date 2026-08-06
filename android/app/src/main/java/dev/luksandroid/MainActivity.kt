package dev.luksandroid

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Diagnostic logging — **debug builds only**.
 *
 * It exists because the phone has one USB-C port. Attaching a drive means
 * unplugging the cable that carries `adb`, so nothing can be watched live; the
 * logcat ring buffer survives the disconnect and is the only record of what
 * happened while the drive was attached. (Wireless debugging would fix that,
 * but `adb tcpip` opens an *unauthenticated* port, which is not something to
 * do on a shared or public network.)
 *
 * ### What is deliberately not logged
 *
 * Never the passphrase, obviously — but also **never a file or directory name
 * from the encrypted drive**. The whole premise of the tool is that those
 * contents are private, and the system log is the wrong place for them: it
 * outlives the session, it is not encrypted, and on a debug build a bug report
 * would carry it off the device. So this logs *shapes* — counts, sizes, types,
 * timings, error codes — which is everything needed to diagnose a transport
 * failure and nothing that says what is on the drive.
 *
 * `BuildConfig.DEBUG` gates the lot, so a release build logs nothing at all
 * rather than relying on this file staying disciplined.
 */
private object Trace {
    const val TAG = "luks"

    fun i(msg: String) {
        if (BuildConfig.DEBUG) Log.i(TAG, msg)
    }

    fun e(msg: String, t: Throwable? = null) {
        if (BuildConfig.DEBUG) Log.e(TAG, msg, t)
    }
}

/**
 * A plumbing proof for the write path, reached only from outside the app —
 * not a feature, and not a button anyone ships.
 *
 * ```
 * adb shell am start -n dev.luksandroid/.MainActivity --ez debug_write_test true
 * ```
 *
 * run while the app is already open with a volume unlocked. [MainActivity] is
 * `singleTask`, so that second `am start` does not relaunch it — it arrives
 * through `onNewIntent`, which is what lets the trigger reach a screen that is
 * already composed and already holding the unlocked volume this needs.
 *
 * A [StateFlow] rather than a direct call because `onNewIntent` runs on the
 * Activity, not inside Compose, and this is the plain way to hand a signal
 * from one to the other without threading a callback through everything in
 * between. The counter (not a `Boolean`) is so a second `am start` while the
 * first write is still running is not silently indistinguishable from the
 * first — every firing gets a distinct value.
 */
private object DebugWriteTrigger {
    private val counter = MutableStateFlow(0L)
    val signal: StateFlow<Long> = counter

    fun fire() {
        counter.value += 1
    }
}

private const val EXTRA_DEBUG_WRITE_TEST = "dev.luksandroid.extra.DEBUG_WRITE_TEST"

/**
 * Pass 3: unlock and browse.
 *
 * Adds password entry, the [UnlockService]-wrapped unlock, and a root
 * directory listing with a streaming SHA-256 check per file — the last being
 * the actual acceptance test for the whole stack, since it can verify a
 * multi-gigabyte file against `STICK-MANIFEST.txt` without ever holding it in
 * memory.
 */
class MainActivity : ComponentActivity() {

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* advisory */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A startup line, so a logcat dump taken after the drive was detached
        // begins with proof of which build was running rather than with
        // whatever the first failure happened to be.
        Trace.i("start: luks_core ${LuksNative.nativeVersion()}")

        // Keeps the app out of the recents thumbnail and blocks screenshots.
        // Set here rather than on the unlock screen alone: the file listing of
        // an encrypted drive is itself something the user chose to encrypt.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        // Advisory only. Without this the foreground service still runs and
        // still protects the process — the notification is simply not shown.
        // So it is requested, not required, and nothing branches on the answer.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        handleDebugWriteIntent(intent)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DiagnosticsScreen()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTask means every later `am start` lands here, not in a fresh
        // onCreate — this is the path the debug write trigger actually uses.
        handleDebugWriteIntent(intent)
    }

    private fun handleDebugWriteIntent(intent: Intent?) {
        if (!BuildConfig.DEBUG) return
        if (intent?.getBooleanExtra(EXTRA_DEBUG_WRITE_TEST, false) != true) return
        Trace.i("debug write trigger received")
        DebugWriteTrigger.fire()
    }
}

/** What's shown for one detected [UsbMassStorage.Target]. */
private sealed interface DeviceState {
    data object Idle : DeviceState
    data object Opening : DeviceState
    data class Open(val device: LuksDevice) : DeviceState
    data class Failed(val message: String) : DeviceState
}

/**
 * Unlock state for the screen as a whole, not per device.
 *
 * One partition is unlocked at a time by construction — each unlock costs a
 * full KDF run, so a UI that invited several at once would be inviting the user
 * to wait several times over.
 */
private sealed interface VolumeState {
    data object None : VolumeState
    data class Prompting(val partition: PartitionInfo) : VolumeState
    data class Unlocking(val partition: PartitionInfo) : VolumeState
    data class Unlocked(val volume: LuksVolume, val entries: List<Entry>) : VolumeState
    data class Failed(val partition: PartitionInfo, val message: String) : VolumeState
}

@Composable
private fun DiagnosticsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // Deliberately not in a try/catch: if the library fails to load there is no
    // app, and an UnsatisfiedLinkError in logcat names the missing .so.
    val version = remember { LuksNative.nativeVersion() }

    var targets by remember { mutableStateOf(UsbMassStorage.findTargets(context)) }
    // Keyed by vendorId:productId:interfaceId rather than the object itself —
    // `findTargets()` returns fresh UsbDevice instances on every rescan, so
    // object identity would forget every open device on the next scan.
    var states by remember { mutableStateOf(mapOf<String, DeviceState>()) }
    var volume by remember { mutableStateOf<VolumeState>(VolumeState.None) }
    var selfTest by remember { mutableStateOf<String?>(null) }

    fun keyOf(t: UsbMassStorage.Target) =
        "${t.device.vendorId}:${t.device.productId}:${t.usbInterface.id}"

    // See DebugWriteTrigger's doc: this is the far end of an `adb shell am
    // start ... --ez debug_write_test true`, not a UI a released app ships
    // with. Keyed on the signal value, not on Unit, so a second trigger while
    // the volume is unchanged still re-runs the effect.
    val debugWriteSignal by DebugWriteTrigger.signal.collectAsState()
    LaunchedEffect(debugWriteSignal) {
        if (debugWriteSignal == 0L) return@LaunchedEffect
        val unlocked = volume as? VolumeState.Unlocked
        if (unlocked == null) {
            Trace.e("debug write: no unlocked volume to write to")
            return@LaunchedEffect
        }
        if (!unlocked.volume.canWrite) {
            Trace.e("debug write: this .so was not built with --write")
            return@LaunchedEffect
        }
        val name = "debug-write-$debugWriteSignal.txt"
        val content =
            "written by the debug trigger, signal $debugWriteSignal\n".toByteArray()
        try {
            val ino = withContext(Dispatchers.IO) { unlocked.volume.writeFile(name, content) }
            Trace.i("debug write: ok, inode=$ino, ${content.size} bytes")
            // Refreshed so the write is visible without also navigating away
            // and back — the whole point of the trigger is to prove the write
            // reached the volume, and re-listing is the cheapest proof there
            // is that it did.
            val entries = withContext(Dispatchers.IO) { unlocked.volume.listDir("/") }
            volume = VolumeState.Unlocked(unlocked.volume, entries)
        } catch (e: LuksException) {
            Trace.e("debug write: failed [${e.code}] ${e.message}")
        } catch (e: Exception) {
            Trace.e("debug write: failed", e)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("LUKS", style = MaterialTheme.typography.headlineMedium)
        Text("luks_core $version loaded", style = MaterialTheme.typography.bodyMedium)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { targets = UsbMassStorage.findTargets(context) }) {
                Text("Rescan USB")
            }
            // Needs no drive attached: pure CPU, and it bounds everything the
            // read pipeline can achieve regardless of how fast the link is.
            TextButton(onClick = {
                selfTest = "measuring…"
                scope.launch {
                    selfTest = try {
                        withContext(Dispatchers.IO) {
                            val j = org.json.JSONObject(LuksNative.nativeSelfTest(64))
                            "AES-XTS %d MiB/s · SHA-256 %d MiB/s (armv8 compiled: %b)".format(
                                j.getLong("xtsMiBs"),
                                j.getLong("sha256MiBs"),
                                j.getBoolean("aesArmv8Compiled"),
                            )
                        }
                    } catch (e: Exception) {
                        "self-test failed: ${e.message}"
                    }
                }
            }) {
                Text("CPU self-test")
            }
        }
        selfTest?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

        if (targets.isEmpty()) {
            Text(
                "No USB mass-storage device found.\n\n" +
                    "Connect the drive through an OTG adapter. If it is plugged " +
                    "in and still not listed, it may speak UAS rather than " +
                    "Bulk-Only Transport.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        targets.forEach { target ->
            val key = keyOf(target)
            val state = states[key] ?: DeviceState.Idle

            Card {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(target.label, style = MaterialTheme.typography.titleMedium)
                    Text(
                        "%04x:%04x · interface %d · in 0x%02x · out 0x%02x".format(
                            target.device.vendorId,
                            target.device.productId,
                            target.usbInterface.id,
                            target.endpointIn.address,
                            target.endpointOut.address,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )

                    when (state) {
                        is DeviceState.Idle -> {
                            Text(
                                if (UsbMassStorage.hasPermission(context, target.device)) {
                                    "Permission granted"
                                } else {
                                    "Permission not granted yet — tap Open to request it"
                                },
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Button(onClick = {
                                states = states + (key to DeviceState.Opening)
                                scope.launch {
                                    states = states + (key to openDevice(context, target))
                                }
                            }) {
                                Text("Open")
                            }
                        }

                        is DeviceState.Opening -> {
                            CircularProgressIndicator(modifier = Modifier.padding(4.dp))
                            Text(
                                "Claiming interface and reading capacity over USB…",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }

                        is DeviceState.Open -> {
                            OpenDeviceBody(
                                device = state.device,
                                volume = volume,
                                onVolumeChange = { volume = it },
                                onClose = {
                                    (volume as? VolumeState.Unlocked)?.volume?.close()
                                    volume = VolumeState.None
                                    state.device.close()
                                    states = states + (key to DeviceState.Idle)
                                },
                                scope = scope,
                                context = context,
                            )
                        }

                        is DeviceState.Failed -> {
                            Text(
                                "Failed: ${state.message}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Button(onClick = { states = states + (key to DeviceState.Idle) }) {
                                Text("Dismiss")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun OpenDeviceBody(
    device: LuksDevice,
    volume: VolumeState,
    onVolumeChange: (VolumeState) -> Unit,
    onClose: () -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
    context: Context,
) {
    val info = device.info

    Text(
        "${info.vendor} ${info.product} · ${formatSize(info.sizeBytes)} " +
            "· ${info.blockSize}B blocks · ${info.tableKind}",
        style = MaterialTheme.typography.bodySmall,
    )
    if (info.partitions.isEmpty()) {
        Text("No partition table found.", style = MaterialTheme.typography.bodySmall)
    }
    info.partitions.forEach { p ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("  ${p.label}", style = MaterialTheme.typography.bodySmall)
            if (p.isLuks && volume is VolumeState.None) {
                TextButton(onClick = { onVolumeChange(VolumeState.Prompting(p)) }) {
                    Text("Unlock")
                }
            }
        }
    }
    if (device.luksPartitions.isEmpty()) {
        Text("No LUKS partition on this drive.", style = MaterialTheme.typography.bodySmall)
    }

    // Raw transport throughput, with LUKS and ext4 out of the picture. Compare
    // it against the full-stack SHA-256 rate: if they match, the link is the
    // ceiling and the crypto/filesystem layers are free.
    var benchmark by remember { mutableStateOf<String?>(null) }
    var benchmarking by remember { mutableStateOf(false) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(
            onClick = {
                benchmarking = true
                benchmark = "reading 128 MiB of raw blocks…"
                scope.launch {
                    benchmark = try {
                        withContext(Dispatchers.IO) { device.benchmark().summary }
                    } catch (e: Exception) {
                        "benchmark failed: ${e.message}"
                    }
                    benchmarking = false
                }
            },
            enabled = !benchmarking,
        ) {
            Text("Benchmark raw read")
        }
    }
    benchmark?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

    when (volume) {
        is VolumeState.None -> Unit

        is VolumeState.Prompting -> PasswordPrompt(
            partition = volume.partition,
            onCancel = { onVolumeChange(VolumeState.None) },
            onSubmit = { password ->
                onVolumeChange(VolumeState.Unlocking(volume.partition))
                scope.launch {
                    onVolumeChange(unlock(context, device, volume.partition, password))
                }
            },
        )

        is VolumeState.Unlocking -> {
            CircularProgressIndicator(modifier = Modifier.padding(4.dp))
            Text(
                "Deriving the key. On a 1 GiB Argon2 keyslot this takes several " +
                    "seconds and allocates a gigabyte — the foreground service is " +
                    "holding the process while it runs.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        is VolumeState.Unlocked -> UnlockedBody(
            state = volume,
            onVolumeChange = onVolumeChange,
            scope = scope,
        )

        is VolumeState.Failed -> {
            Text("Unlock failed: ${volume.message}", style = MaterialTheme.typography.bodySmall)
            Button(onClick = { onVolumeChange(VolumeState.Prompting(volume.partition)) }) {
                Text("Try again")
            }
        }
    }

    Button(onClick = onClose) { Text("Close device") }
}

@Composable
private fun PasswordPrompt(
    partition: PartitionInfo,
    onCancel: () -> Unit,
    onSubmit: (ByteArray) -> Unit,
) {
    var text by remember { mutableStateOf("") }

    fun submit() {
        // ⚠️ Known gap: `text` is a Kotlin String, which is immutable and
        // cannot be scrubbed — it lives on the GC heap until collected. The
        // password crosses JNI correctly as a ByteArray into a zeroing Secret,
        // and LuksDevice.unlock zeroes that array in a finally, so the
        // invariant holds everywhere it can. Closing this last gap needs a
        // BasicTextField over a mutable CharArray. Tracked in STATE.md.
        val bytes = text.toByteArray(Charsets.UTF_8)
        text = ""
        onSubmit(bytes)
    }

    Text("Unlock ${partition.label}", style = MaterialTheme.typography.bodyMedium)
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text("Passphrase") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Go,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = ::submit, enabled = text.isNotEmpty()) { Text("Unlock") }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
private fun UnlockedBody(
    state: VolumeState.Unlocked,
    onVolumeChange: (VolumeState) -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    val context = LocalContext.current
    val info = state.volume.info

    var path by remember { mutableStateOf("/") }
    var entries by remember { mutableStateOf(state.entries) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    // Which file the pending "create document" dialog is for. The launcher
    // callback carries only the destination Uri, not what we were exporting.
    var pendingExport by remember { mutableStateOf<String?>(null) }

    /**
     * Writes a file out through the Storage Access Framework.
     *
     * SAF rather than a WRITE_EXTERNAL_STORAGE permission: the user picks the
     * destination themselves, the app gets access to exactly that one file, and
     * nothing has to be granted broad storage access to copy a document off an
     * encrypted drive.
     */
    val exporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val source = pendingExport
        pendingExport = null
        if (uri == null || source == null) return@rememberLauncherForActivityResult
        busy = true
        scope.launch {
            status = exportFile(context, state.volume, source, uri) { done, total ->
                // Compose snapshot state is safe to write from any thread, so
                // progress can be reported straight from the IO dispatcher.
                val pct = if (total > 0) done * 100 / total else 0
                status = "copying ${source.substringAfterLast('/')} — $pct% " +
                    "(${formatSize(done)} of ${formatSize(total)})"
            }
            busy = false
        }
    }

    fun navigate(to: String) {
        busy = true
        status = null
        scope.launch {
            try {
                val listed = withContext(Dispatchers.IO) { state.volume.listDir(to) }
                entries = listed
                path = to
            } catch (e: Exception) {
                status = "cannot open $to: ${e.message}"
            }
            busy = false
        }
    }

    Text(
        "Unlocked: ${info.label.ifBlank { "(no label)" }} · ${info.fsType} " +
            "· ${formatSize(info.sizeBytes)} · ${info.blockSize}B blocks",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(info.uuid, style = MaterialTheme.typography.bodySmall)
    if (info.subvolumes.isNotEmpty()) {
        // Worth showing rather than hiding: on a Linux install these are where
        // the actual content lives, and their paths are directly navigable.
        Text(
            "subvolumes: " + info.subvolumes.joinToString(", ") {
                it.path + if (it.readOnly) " (ro)" else ""
            },
            style = MaterialTheme.typography.bodySmall,
        )
    }

    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

    Text(path, style = MaterialTheme.typography.bodyMedium)
    if (path != "/") {
        TextButton(onClick = { navigate(parentOf(path)) }, enabled = !busy) {
            Text("⬆ up")
        }
    }

    if (busy) {
        CircularProgressIndicator(modifier = Modifier.padding(4.dp))
    }

    entries.forEach { entry ->
        val full = joinPath(path, entry.name)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            if (entry.isDir) {
                TextButton(onClick = { navigate(full) }, enabled = !busy) {
                    Text("📁 ${entry.name}")
                }
            } else {
                Text("   ${entry.name}", style = MaterialTheme.typography.bodySmall)
                Row {
                    TextButton(
                        onClick = {
                            pendingExport = full
                            exporter.launch(entry.name)
                        },
                        enabled = !busy,
                    ) {
                        Text("Save")
                    }
                    TextButton(
                        onClick = {
                            status = "hashing ${entry.name}…"
                            busy = true
                            scope.launch {
                                status = hashFile(state.volume, full)
                                busy = false
                            }
                        },
                        enabled = !busy,
                    ) {
                        Text("SHA-256")
                    }
                }
            }
        }
    }

    status?.let {
        Text(it, style = MaterialTheme.typography.bodySmall)
    }

    Button(
        onClick = {
            state.volume.close()
            onVolumeChange(VolumeState.None)
        },
        enabled = !busy,
    ) {
        Text("Lock")
    }
}

private fun joinPath(dir: String, name: String): String =
    if (dir == "/") "/$name" else "$dir/$name"

private fun parentOf(path: String): String =
    path.trimEnd('/').substringBeforeLast('/').ifEmpty { "/" }

/**
 * Requests permission if needed, then opens the device and reads its
 * partition table. All of it runs off the main thread: `requestPermission`
 * suspends on user input, and `UsbMassStorage.open` blocks on real USB
 * transfers (INQUIRY, READ CAPACITY, the LUKS-magic probe of every partition).
 */
private suspend fun openDevice(
    context: Context,
    target: UsbMassStorage.Target,
): DeviceState {
    Trace.i("open: vid=0x%04x pid=0x%04x".format(target.device.vendorId, target.device.productId))
    val granted = UsbMassStorage.requestPermission(context, target.device)
    if (!granted) {
        Trace.e("open: USB permission denied")
        return DeviceState.Failed("permission denied")
    }
    return try {
        val started = System.currentTimeMillis()
        val device = withContext(Dispatchers.IO) { UsbMassStorage.open(context, target) }
        Trace.i(
            "open: ok in ${System.currentTimeMillis() - started} ms, " +
                "${device.info.partitions.size} partitions, " +
                "${device.luksPartitions.size} LUKS"
        )
        DeviceState.Open(device)
    } catch (e: LuksException) {
        Trace.e("open: failed [${e.code}] ${e.message}")
        DeviceState.Failed("[${e.code}] ${e.message}")
    } catch (e: Exception) {
        Trace.e("open: failed", e)
        DeviceState.Failed(e.message ?: e.toString())
    }
}

/**
 * The slow path: Argon2, then the AF-merge, digest check and ext4 mount.
 *
 * Wrapped in [UnlockService.holding] so the process is in the foreground class
 * for the whole derivation, and run on [Dispatchers.IO] so the UI thread stays
 * free to draw the spinner.
 */
private suspend fun unlock(
    context: Context,
    device: LuksDevice,
    partition: PartitionInfo,
    password: ByteArray,
): VolumeState = try {
    Trace.i("unlock: partition at ${partition.offsetBytes} bytes")
    val started = System.currentTimeMillis()
    UnlockService.holding(context) {
        withContext(Dispatchers.IO) {
            val v = device.unlock(partition.offsetBytes, password)
            val kdf = System.currentTimeMillis() - started
            val info = v.info
            // The line that matters for btrfs-over-USB: which filesystem the
            // signature picked, and whether subvolume enumeration survived the
            // transport. Paths are shapes here — a count, not the names.
            Trace.i(
                "unlock: ok in $kdf ms · fs=${info.fsType} " +
                    "block=${info.blockSize} size=${info.sizeBytes} " +
                    "subvolumes=${info.subvolumes.size}"
            )
            val entries = v.listDir("/")
            Trace.i("unlock: root listed, ${entries.size} entries")
            VolumeState.Unlocked(v, entries)
        }
    }
} catch (e: LuksException) {
    Trace.e("unlock: failed [${e.code}] ${e.message}")
    VolumeState.Failed(
        partition,
        if (e.isWrongPassword) "wrong passphrase" else "[${e.code}] ${e.message}",
    )
} catch (e: Exception) {
    Trace.e("unlock: failed", e)
    VolumeState.Failed(partition, e.message ?: e.toString())
} finally {
    // Belt and braces: LuksDevice.unlock already zeroes this, but that only
    // runs if the call was reached at all.
    password.fill(0)
}

/**
 * Copies a file off the encrypted drive to a user-chosen destination,
 * streaming it a megabyte at a time.
 *
 * Never holds the whole file: the drive being read is expected to contain
 * things far larger than the app heap, and the entire point of `readChunk` is
 * that a 1 GiB file is copied with a 1 MiB buffer.
 */
private suspend fun exportFile(
    context: Context,
    volume: LuksVolume,
    path: String,
    uri: android.net.Uri,
    onProgress: (done: Long, total: Long) -> Unit,
): String = try {
    withContext(Dispatchers.IO) {
        val total = volume.fileSize(path)
        var done = 0L
        val started = System.currentTimeMillis()

        val stream = context.contentResolver.openOutputStream(uri)
            ?: throw IllegalStateException("could not open the destination for writing")

        stream.use { out ->
            while (done < total) {
                val chunk = volume.readChunk(path, done, EXPORT_CHUNK)
                if (chunk.isEmpty()) break // short read: end of file
                out.write(chunk)
                done += chunk.size
                onProgress(done, total)
            }
            out.flush()
        }

        val secs = (System.currentTimeMillis() - started).coerceAtLeast(1) / 1000.0
        Trace.i("export: %d bytes in %.1f s · %.1f MiB/s".format(done, secs, done / secs / (1L shl 20)))
        "saved ${formatSize(done)} in %.1f s · %.1f MiB/s"
            .format(secs, done / secs / (1L shl 20))
    }
} catch (e: Exception) {
    Trace.e("export: failed", e)
    "save failed: ${e.message}"
}

private const val EXPORT_CHUNK = 1 shl 20

/** Streams the file through SHA-256 and reports the throughput it managed. */
private suspend fun hashFile(volume: LuksVolume, path: String): String = try {
    val d = withContext(Dispatchers.IO) { volume.sha256(path) }
    val mbPerSec = d.bytesPerSec.toDouble() / (1L shl 20)
    // Size and rate, not the path: this is the throughput measurement, and the
    // name of the file being read off an encrypted drive is not part of it.
    Trace.i("hash: %d bytes in %d ms · %.1f MiB/s".format(d.bytes, d.elapsedMs, mbPerSec))
    "${d.sha256}\n${formatSize(d.bytes)} in ${d.elapsedMs} ms · %.1f MiB/s".format(mbPerSec)
} catch (e: Exception) {
    Trace.e("hash: failed", e)
    "hash failed: ${e.message}"
}
