package dev.luksandroid

import android.Manifest
import android.content.Context
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Diagnostic logging — **debug builds only**.
 *
 * The phone has one USB-C port, so attaching a drive means unplugging the
 * cable that carries `adb`. Wireless debugging (the Android 11+ pairing-code
 * flow — *not* `adb tcpip`, which opens an unauthenticated port) is set up on
 * the test Pixel and makes logcat watchable live with the drive attached. This
 * still earns its place without it: the ring buffer survives a disconnect, so
 * a dump taken after the drive comes off is a record of what happened while it
 * was on.
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

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DiagnosticsScreen()
                }
            }
        }
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

    // Whether a native call is in flight, for the whole screen rather than for
    // one composable.
    //
    // This is what stands between "Close device" or "Lock" and a
    // use-after-free. Both free a native handle — `nativeCloseVolume` and
    // `nativeCloseDevice` reach `Box::from_raw` — and every long operation here
    // (unlock, benchmark, listing, hashing, export, the debug write) is holding
    // a `&VolumeHandle` or a `&DeviceHandle` on an IO thread while it runs.
    // Freeing one underneath the other frees the cached superblock, the group
    // descriptors and the master key.
    //
    // It lives here, not in `UnlockedBody`, because that is the mistake this
    // replaces: `busy` was a `remember` local of `UnlockedBody`, so it could
    // gate `Lock` and could not gate `Close device`, which sits a level up in
    // `OpenDeviceBody` — and additionally closes the file descriptor Rust is
    // reading through. Reads were exposed to this too, not only the write path;
    // nothing enforced it at the level where both buttons could see it.
    var busy by remember { mutableStateOf(false) }

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
                            // Set before Open, because the transport's limit is
                            // fixed when the device is opened and cannot move
                            // afterwards. Blank or 0 leaves the built-in 128 KiB.
                            // Seeded from the object, never from "". The field
                            // is recreated whenever this screen recomposes, and
                            // `DebugTuning` is not — so a blank default made the
                            // display disagree with what Open actually used, and
                            // a run at 1 MiB looked like a run at the default.
                            var maxKib by remember {
                                mutableStateOf(
                                    DebugTuning.maxTransferBytes
                                        .takeIf { it > 0 }
                                        ?.let { (it / 1024).toString() }
                                        ?: ""
                                )
                            }
                            OutlinedTextField(
                                value = maxKib,
                                onValueChange = {
                                    maxKib = it
                                    DebugTuning.maxTransferBytes =
                                        (it.toIntOrNull() ?: 0).coerceIn(0, 8192) * 1024
                                },
                                label = { Text("Max transfer (KiB, blank = default)") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.padding(vertical = 4.dp),
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
                                busy = busy,
                                onBusyChange = { busy = it },
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
    busy: Boolean,
    onBusyChange: (Boolean) -> Unit,
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
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(
            onClick = {
                // The shared flag, not a local one: this reads through the
                // device handle for 128 MiB, and "Close device" below frees
                // that handle. A private `benchmarking` boolean could stop a
                // second benchmark and could not stop that.
                onBusyChange(true)
                benchmark = "reading 128 MiB of raw blocks…"
                scope.launch {
                    benchmark = try {
                        withContext(Dispatchers.IO) { device.benchmark().summary }
                    } catch (e: Exception) {
                        "benchmark failed: ${e.message}"
                    }
                    onBusyChange(false)
                }
            },
            enabled = !busy,
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
                // Argon2 runs for seconds against the device handle. Closing
                // the device during it frees what the derivation is reading
                // through, so this counts as busy like everything else.
                onBusyChange(true)
                scope.launch {
                    onVolumeChange(unlock(context, device, volume.partition, password))
                    onBusyChange(false)
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
            busy = busy,
            onBusyChange = onBusyChange,
            scope = scope,
        )

        is VolumeState.Failed -> {
            Text("Unlock failed: ${volume.message}", style = MaterialTheme.typography.bodySmall)
            Button(onClick = { onVolumeChange(VolumeState.Prompting(volume.partition)) }) {
                Text("Try again")
            }
        }
    }

    // Gated, which it was not before: this closes the volume *and* the device,
    // and the device close also releases the USB interface and the file
    // descriptor the Rust side reads through. Tapped during any of the above it
    // frees a handle an IO thread is still using.
    Button(onClick = onClose, enabled = !busy) { Text("Close device") }
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
    busy: Boolean,
    onBusyChange: (Boolean) -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    val context = LocalContext.current
    val info = state.volume.info

    var path by remember { mutableStateOf("/") }
    var entries by remember { mutableStateOf(state.entries) }
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
        onBusyChange(true)
        scope.launch {
            status = exportFile(context, state.volume, source, uri) { done, total ->
                // Compose snapshot state is safe to write from any thread, so
                // progress can be reported straight from the IO dispatcher.
                val pct = if (total > 0) done * 100 / total else 0
                status = "copying ${source.substringAfterLast('/')} — $pct% " +
                    "(${formatSize(done)} of ${formatSize(total)})"
            }
            onBusyChange(false)
        }
    }

    fun navigate(to: String) {
        onBusyChange(true)
        status = null
        scope.launch {
            try {
                val listed = withContext(Dispatchers.IO) { state.volume.listDir(to) }
                entries = listed
                path = to
            } catch (e: Exception) {
                status = "cannot open $to: ${e.message}"
            }
            onBusyChange(false)
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
                            onBusyChange(true)
                            scope.launch {
                                status = hashFile(state.volume, full)
                                onBusyChange(false)
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

    // A plumbing proof for the write path — debug builds only, and the only
    // way a write is reachable from the app at all today.
    //
    // It replaces an `adb shell am start --ez` intent trigger, which was the
    // wrong shape twice over. It never fired: the extra key in the code and
    // the key in every documented command did not match, and nothing noticed
    // because no hardware run had happened. And getting the signal from
    // `onNewIntent` into a composable needed a StateFlow and a LaunchedEffect,
    // which brought their own bugs — the effect cancelled on re-trigger while
    // the blocking JNI call underneath carried on regardless, and rapid
    // triggers conflated into one run. A button has none of that: it is a
    // click handler in the composable that already holds the volume, and it
    // sets the same `busy` flag every other operation here sets.
    //
    // It also closes the exported-activity question. `exported="true"` is
    // required for `USB_DEVICE_ATTACHED`, so any installed app could send the
    // trigger intent once the key was fixed; there is no longer an intent to
    // send.
    if (BuildConfig.DEBUG) {
        // Size is configurable (1-100 MB) rather than the fixed 28 bytes this
        // proved the plumbing with on 2026-08-07: three limits sit between
        // that and a real file (memory residency, the 4-extent ceiling on a
        // new inode, BLOCK_UNINIT capacity) and nothing measures which binds
        // first. This is how that gets measured, on hardware.
        var debugWriteSizeMb by remember { mutableStateOf("10") }
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(
                value = debugWriteSizeMb,
                onValueChange = { debugWriteSizeMb = it },
                label = { Text("Size (MB)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                enabled = !busy,
                modifier = Modifier.padding(end = 8.dp),
            )
            TextButton(
                onClick = {
                    if (!state.volume.canWrite) {
                        status = "this .so was not built with --write"
                        Trace.e("debug write: this .so was not built with --write")
                        return@TextButton
                    }
                    val sizeMb = debugWriteSizeMb.toIntOrNull()?.coerceIn(1, 100) ?: 10
                    val sizeBytes = sizeMb * 1_000_000
                    onBusyChange(true)
                    status = "writing ${sizeMb}MB…"
                    val name = "debug-write-${sizeMb}mb-${System.currentTimeMillis()}.txt"
                    scope.launch {
                        try {
                            val content = withContext(Dispatchers.Default) { testPayload(sizeBytes) }
                            val startMs = System.currentTimeMillis()
                            val ino = withContext(Dispatchers.IO) {
                                state.volume.writeFile(name, content)
                            }
                            val elapsedMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1)
                            val mibPerSec = (content.size / 1_048_576.0) / (elapsedMs / 1000.0)
                            // Shapes, not names — the file is on an encrypted
                            // drive and this is the system log. Same rule as
                            // everywhere else in this file.
                            Trace.i(
                                "debug write: ok, inode=$ino, ${content.size} bytes " +
                                    "in ${elapsedMs}ms (${"%.2f".format(mibPerSec)} MiB/s)"
                            )
                            // Re-listed so the write is visible without navigating
                            // away and back. Re-listing is also the cheapest proof
                            // available that it reached the volume at all.
                            entries = withContext(Dispatchers.IO) { state.volume.listDir(path) }
                            status = "wrote $name (inode $ino) — ${"%.2f".format(mibPerSec)} MiB/s"
                        } catch (e: LuksException) {
                            Trace.e("debug write: failed [${e.code}] ${e.message}")
                            status = "write failed [${e.code}] ${e.message}"
                        } catch (e: Exception) {
                            Trace.e("debug write: failed", e)
                            status = "write failed: ${e.message}"
                        }
                        onBusyChange(false)
                    }
                },
                enabled = !busy,
            ) {
                Text("Debug: write test file")
            }
        }
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

/** A repeating, non-zero pattern of [sizeBytes] — content only needs a size for this test. */
private fun testPayload(sizeBytes: Int): ByteArray {
    val pattern = ByteArray(4096) { (it % 256).toByte() }
    val data = ByteArray(sizeBytes)
    var offset = 0
    while (offset < sizeBytes) {
        val chunk = minOf(pattern.size, sizeBytes - offset)
        System.arraycopy(pattern, 0, data, offset, chunk)
        offset += chunk
    }
    return data
}

/**
 * Requests permission if needed, then opens the device and reads its
 * partition table. All of it runs off the main thread: `requestPermission`
 * suspends on user input, and `UsbMassStorage.open` blocks on real USB
 * transfers (INQUIRY, READ CAPACITY, the LUKS-magic probe of every partition).
 */
/**
 * Transport settings a debug session needs to vary between runs.
 *
 * A plain object rather than state threaded through the screen: it is read
 * once, at open, and nothing recomposes on it. Debug-only — nothing in the
 * normal path sets it, so it stays 0 and the transport keeps its default.
 */
private object DebugTuning {
    /** Bytes per bulk transfer, or 0 for the built-in 128 KiB. */
    var maxTransferBytes: Int = 0
}

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
        val requested = DebugTuning.maxTransferBytes
        // Logged unconditionally. "No line" would be ambiguous between "ran at
        // the default" and "the log was not reached", and a run whose settings
        // are inferred rather than recorded is not a measurement.
        Trace.i(
            "open: max transfer = " +
                if (requested > 0) "$requested bytes (requested)" else "built-in default"
        )
        val device = withContext(Dispatchers.IO) {
            UsbMassStorage.open(context, target, requested)
        }
        Trace.i(
            "open: ok in ${System.currentTimeMillis() - started} ms, " +
                "${device.info.partitions.size} partitions, " +
                "${device.luksPartitions.size} LUKS"
        )
        // Only present in a write-enabled build. It is the answer to "why did
        // the drive refuse WRITE(10)", and it has to be captured at open —
        // asking after a failure is too late once the volume is gone.
        device.info.writeProbe?.let { Trace.i("write probe: $it") }
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
