package dev.luksandroid

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionState
import dev.luksandroid.session.UsbDetachReceiver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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

        UsbDetachReceiver.register(this)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DiagnosticsScreen()
                }
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        LuksSession.onTrimMemory(level)
    }

    override fun onDestroy() {
        super.onDestroy()
        UsbDetachReceiver.unregister(this)
    }
}

/** What's shown for one detected [UsbMassStorage.Target]. */
private sealed interface DeviceState {
    data object Idle : DeviceState
    data object Opening : DeviceState
    data class Open(val device: LuksDevice) : DeviceState
    data class Failed(val message: String) : DeviceState
}

@Composable
private fun DiagnosticsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val sessionState by LuksSession.state.collectAsState()

    // Deliberately not in a try/catch: if the library fails to load there is no
    // app, and an UnsatisfiedLinkError in logcat names the missing .so.
    val version = remember { LuksNative.nativeVersion() }

    var targets by remember { mutableStateOf(UsbMassStorage.findTargets(context)) }
    // Keyed by vendorId:productId:interfaceId rather than the object itself —
    // `findTargets()` returns fresh UsbDevice instances on every rescan, so
    // object identity would forget every open device on the next scan.
    var states by remember { mutableStateOf(mapOf<String, DeviceState>()) }
    var selfTest by remember { mutableStateOf<String?>(null) }

    fun keyOf(t: UsbMassStorage.Target) =
        "${t.device.vendorId}:${t.device.productId}:${t.usbInterface.id}"

    // Whether a native call is in flight, for the whole screen rather than for
    // one composable.
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
                        val probe = withContext(Dispatchers.Main) { probeReflectionSurface(context) }
                        val cpu = withContext(Dispatchers.IO) {
                            val j = org.json.JSONObject(LuksNative.nativeSelfTest(64))
                            "AES-XTS %d MiB/s · SHA-256 %d MiB/s (armv8 compiled: %b)".format(
                                j.getLong("xtsMiBs"),
                                j.getLong("sha256MiBs"),
                                j.getBoolean("aesArmv8Compiled"),
                            )
                        }
                        "$cpu\n\n$probe"
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
                                sessionState = sessionState,
                                busy = busy,
                                onBusyChange = { busy = it },
                                onClose = {
                                    scope.launch {
                                        LuksSession.lock()
                                        state.device.close()
                                        states = states + (key to DeviceState.Idle)
                                    }
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
    sessionState: SessionState,
    busy: Boolean,
    onBusyChange: (Boolean) -> Unit,
    onClose: () -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
    context: Context,
) {
    val info = device.info
    var promptingPartition by remember { mutableStateOf<PartitionInfo?>(null) }

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
            if (p.isLuks && sessionState is SessionState.Locked && promptingPartition == null) {
                TextButton(onClick = { promptingPartition = p }) {
                    Text("Unlock")
                }
            }
        }
    }
    if (device.luksPartitions.isEmpty()) {
        Text("No LUKS partition on this drive.", style = MaterialTheme.typography.bodySmall)
    }

    var benchmark by remember { mutableStateOf<String?>(null) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(
            onClick = {
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

        if (LuksNative.nativeWriteSupported()) {
            TextButton(
                onClick = {
                    onBusyChange(true)
                    benchmark = "writing 64 MiB of raw blocks past the partitions…"
                    scope.launch {
                        benchmark = try {
                            withContext(Dispatchers.IO) { device.benchmarkWrite().summary }
                        } catch (e: Exception) {
                            "write benchmark failed: ${e.message}"
                        }
                        onBusyChange(false)
                    }
                },
                enabled = !busy,
            ) {
                Text("Benchmark raw write")
            }
        }
    }
    benchmark?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

    when (sessionState) {
        is SessionState.Locked -> {
            promptingPartition?.let { partition ->
                PasswordPrompt(
                    partition = partition,
                    onCancel = { promptingPartition = null },
                    onSubmit = { passwordBuffer ->
                        onBusyChange(true)
                        val part = partition
                        promptingPartition = null
                        scope.launch {
                            passwordBuffer.use { buf ->
                                LuksSession.unlock(context, device, part, buf)
                            }
                            onBusyChange(false)
                        }
                    },
                )
            }
        }

        is SessionState.Unlocking -> {
            CircularProgressIndicator(modifier = Modifier.padding(4.dp))
            Text(
                "Deriving the key. On a 1 GiB Argon2 keyslot this takes several " +
                    "seconds and allocates a gigabyte — the foreground service is " +
                    "holding the process while it runs.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        is SessionState.Unlocked -> UnlockedBody(
            state = sessionState,
            busy = busy,
            onBusyChange = onBusyChange,
            scope = scope,
        )

        is SessionState.Detached -> {
            Text(
                "Drive detached: ${sessionState.message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
            Button(onClick = { scope.launch { LuksSession.reset() } }) {
                Text("Reset")
            }
        }

        is SessionState.Failed -> {
            Text(
                "Session failed: ${sessionState.message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { scope.launch { LuksSession.reset() } }) {
                    Text("Reset")
                }
                if (sessionState.partition != null) {
                    val p = sessionState.partition
                    TextButton(onClick = {
                        scope.launch {
                            LuksSession.reset()
                            promptingPartition = p
                        }
                    }) {
                        Text("Try again")
                    }
                }
            }
        }
    }

    Button(onClick = onClose, enabled = !busy) { Text("Close device") }
}

@Composable
private fun PasswordPrompt(
    partition: PartitionInfo,
    onCancel: () -> Unit,
    onSubmit: (dev.luksandroid.security.SecurePassphraseBuffer) -> Unit,
) {
    val window = androidx.activity.compose.LocalActivity.current?.window
    DisposableEffect(Unit) {
        window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    var activeEditable by remember { mutableStateOf<android.text.Editable?>(null) }
    var hasContent by remember { mutableStateOf(false) }

    fun submit() {
        val editable = activeEditable ?: return
        val buffer = dev.luksandroid.security.PassphraseScrubber.extractAndScrub(editable)
        onSubmit(buffer)
    }

    Text("Unlock ${partition.label}", style = MaterialTheme.typography.bodyMedium)
    dev.luksandroid.ui.SecurePassphraseField(
        onEditableReady = { activeEditable = it },
        onHasContentChange = { hasContent = it },
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = ::submit, enabled = hasContent) { Text("Unlock") }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
private fun UnlockedBody(
    state: SessionState.Unlocked,
    busy: Boolean,
    onBusyChange: (Boolean) -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    val context = LocalContext.current
    val info = state.volume.info

    var path by remember { mutableStateOf("/") }
    var entries by remember { mutableStateOf(state.entries) }
    var status by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<String?>(null) }

    val exporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val source = pendingExport
        pendingExport = null
        if (uri == null || source == null) return@rememberLauncherForActivityResult
        onBusyChange(true)
        scope.launch {
            status = exportFile(context, source, uri) { done, total ->
                val pct = if (total > 0) done * 100 / total else 0
                status = "copying ${source.substringAfterLast('/')} — $pct% " +
                    "(${formatSize(done)} of ${formatSize(total)})"
            }
            onBusyChange(false)
        }
    }

    val importer = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        onBusyChange(true)
        scope.launch {
            var lastUpdateMs = System.currentTimeMillis()
            var lastUpdateBytes = 0L
            status = importFile(context, path, uri) { done, total ->
                val now = System.currentTimeMillis()
                val dt = now - lastUpdateMs
                if (dt >= 500 || done == total) {
                    val bytesDelta = done - lastUpdateBytes
                    val speedBytesPerSec = if (dt > 0) (bytesDelta * 1000L) / dt else 0L
                    lastUpdateMs = now
                    lastUpdateBytes = done
                    val pct = if (total > 0) done * 100 / total else 0
                    val speedStr = if (speedBytesPerSec > 0) " · %.1f MiB/s".format(speedBytesPerSec.toDouble() / (1L shl 20)) else ""
                    status = "uploading — $pct% (${formatSize(done)} of ${formatSize(total)})$speedStr"
                }
            }
            try {
                entries = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.listDir(path) }
                }
            } catch (_: Exception) {}
            onBusyChange(false)
        }
    }

    fun navigate(to: String) {
        onBusyChange(true)
        status = null
        scope.launch {
            try {
                val listed = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.listDir(to) }
                }
                entries = listed
                path = to
            } catch (e: LuksException) {
                Trace.err(e.code, "navigate")
                Trace.e("navigate: failed [${e.code}] ${e.message}")
                status = "cannot open $to: ${e.message}"
            } catch (e: Exception) {
                Trace.err(-1, "navigate")
                Trace.e("navigate: failed", e)
                status = "cannot open $to: ${e.message}"
            }
            onBusyChange(false)
        }
    }

    var statFsInfo by remember { mutableStateOf<StatFsInfo?>(null) }
    LaunchedEffect(state.partition, path) {
        try {
            statFsInfo = withContext(Dispatchers.IO) {
                LuksSession.withLease { v -> v.statFs() }
            }
        } catch (e: LuksException) {
            Trace.err(e.code, "statfs", "err=${e.message}")
            Trace.e("statfs: failed [${e.code}] ${e.message}")
        } catch (e: Exception) {
            Trace.err(-1, "statfs", "err=${e.message}")
            Trace.e("statfs: failed", e)
        }
    }

    fun createFolder(name: String) {
        onBusyChange(true)
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.createDirectory(path, name) }
                }
                entries = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.listDir(path) }
                }
                statFsInfo = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.statFs() }
                }
                status = "created folder $name"
            } catch (e: LuksException) {
                Trace.err(e.code, "create_directory", "err=${e.message}")
                Trace.e("create_directory: failed [${e.code}] ${e.message}")
                status = "create folder failed [${e.code}]: ${e.message}"
            } catch (e: Exception) {
                Trace.err(-1, "create_directory", "err=${e.message}")
                Trace.e("create_directory: failed", e)
                status = "create folder failed: ${e.message}"
            }
            onBusyChange(false)
        }
    }

    fun renameItem(oldName: String, newName: String) {
        onBusyChange(true)
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.rename(path, oldName, path, newName) }
                }
                entries = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.listDir(path) }
                }
                status = "renamed $oldName to $newName"
            } catch (e: LuksException) {
                Trace.err(e.code, "rename", "err=${e.message}")
                Trace.e("rename: failed [${e.code}] ${e.message}")
                status = "rename failed [${e.code}]: ${e.message}"
            } catch (e: Exception) {
                Trace.err(-1, "rename", "err=${e.message}")
                Trace.e("rename: failed", e)
                status = "rename failed: ${e.message}"
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
    statFsInfo?.let { stat ->
        Text(
            "Free: ${formatSize(stat.freeBytes)} · Available: ${formatSize(stat.availableBytes)}",
            style = MaterialTheme.typography.bodySmall,
        )
    }
    if (info.subvolumes.isNotEmpty()) {
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
                                status = hashFile(full)
                                onBusyChange(false)
                            }
                        },
                        enabled = !busy,
                    ) {
                        Text("SHA-256")
                    }
                    if (state.volume.canWrite) {
                        TextButton(
                            onClick = {
                                status = "deleting ${entry.name}…"
                                onBusyChange(true)
                                scope.launch {
                                    try {
                                        withContext(Dispatchers.IO) {
                                            LuksSession.withLease { v -> v.deleteFile(full) }
                                        }
                                        entries = withContext(Dispatchers.IO) {
                                            LuksSession.withLease { v -> v.listDir(path) }
                                        }
                                        status = "deleted ${entry.name}"
                                    } catch (e: LuksException) {
                                        Trace.err(e.code, "delete_file", "err=${e.message}")
                                        Trace.e("delete: failed [${e.code}] ${e.message}")
                                        status = "delete failed [${e.code}]: ${e.message}"
                                    } catch (e: Exception) {
                                        Trace.err(-1, "delete_file", "err=${e.message}")
                                        Trace.e("delete: failed", e)
                                        status = "delete failed: ${e.message}"
                                    }
                                    onBusyChange(false)
                                }
                            },
                            enabled = !busy,
                        ) {
                            Text("Delete", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }

    status?.let {
        Text(it, style = MaterialTheme.typography.bodySmall)
    }

    if (BuildConfig.DEBUG) {
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
                                LuksSession.withLease { v -> v.writeFile(path, name, content) }
                            }
                            val elapsedMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1)
                            val mibPerSec = (content.size / 1_048_576.0) / (elapsedMs / 1000.0)
                            Trace.i(
                                "debug write: ok, inode=$ino, ${content.size} bytes " +
                                    "in ${elapsedMs}ms (${"%.2f".format(mibPerSec)} MiB/s)"
                            )
                            entries = withContext(Dispatchers.IO) {
                                LuksSession.withLease { v -> v.listDir(path) }
                            }
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

    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        if (state.volume.canWrite) {
            Button(
                onClick = { importer.launch(arrayOf("*/*")) },
                enabled = !busy,
            ) {
                Text("Upload File")
            }
        }
        Button(
            onClick = {
                scope.launch {
                    onBusyChange(true)
                    LuksSession.lock()
                    onBusyChange(false)
                }
            },
            enabled = !busy,
        ) {
            Text("Lock")
        }
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
 * Transport settings a debug session needs to vary between runs.
 */
private object DebugTuning {
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
        device.info.writeProbe?.let { Trace.i("write probe: $it") }
        DeviceState.Open(device)
    } catch (e: LuksException) {
        Trace.err(e.code, "unlock")
        Trace.e("open: failed [${e.code}] ${e.message}")
        DeviceState.Failed("[${e.code}] ${e.message}")
    } catch (e: Exception) {
        Trace.err(-1, "unlock")
        Trace.e("open: failed", e)
        DeviceState.Failed(e.message ?: e.toString())
    }
}

/**
 * Copies a file off the encrypted drive to a user-chosen destination,
 * streaming it a megabyte at a time.
 */
private suspend fun exportFile(
    context: Context,
    path: String,
    uri: android.net.Uri,
    onProgress: (done: Long, total: Long) -> Unit,
): String = try {
    withContext(Dispatchers.IO) {
        LuksSession.withLease { volume ->
            val total = volume.fileSize(path)
            var done = 0L
            val started = System.currentTimeMillis()

            val stream = context.contentResolver.openOutputStream(uri)
                ?: throw IllegalStateException("could not open the destination for writing")

            stream.use { out ->
                while (done < total) {
                    val chunk = volume.readChunk(path, done, EXPORT_CHUNK)
                    if (chunk.isEmpty()) break
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
    }
} catch (e: LuksException) {
    Trace.err(e.code, "transfer")
    Trace.e("export: failed [${e.code}] ${e.message}")
    "save failed: ${e.message}"
} catch (e: Exception) {
    Trace.err(-1, "transfer")
    Trace.e("export: failed", e)
    "save failed: ${e.message}"
}

private const val EXPORT_CHUNK = 1 shl 20

/**
 * Copies a file from a user-chosen Uri into the encrypted drive directory,
 * streaming it via [LuksVolume.beginFile], [LuksVolume.FileWriter.write], and [LuksVolume.FileWriter.finish].
 */
private suspend fun importFile(
    context: Context,
    parentPath: String,
    uri: android.net.Uri,
    onProgress: (done: Long, total: Long) -> Unit,
): String = try {
    withContext(Dispatchers.IO) {
        LuksSession.withLease { volume ->
            val contentResolver = context.contentResolver
            var fileName: String? = null
            var fileSize: Long = -1L

            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIndex != -1) fileName = cursor.getString(nameIndex)
                    if (sizeIndex != -1 && !cursor.isNull(sizeIndex)) fileSize = cursor.getLong(sizeIndex)
                }
            }

            val name = fileName ?: uri.lastPathSegment?.substringAfterLast('/') ?: "imported_${System.currentTimeMillis()}"
            if (fileSize < 0L) {
                contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    fileSize = pfd.statSize
                }
            }

            check(fileSize >= 0L) { "could not determine file size" }

            val started = System.currentTimeMillis()
            var done = 0L
            val buffer = java.nio.ByteBuffer.allocateDirect(IMPORT_CHUNK)

            val writer = volume.beginFile(fileSize)
            try {
                contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    java.io.FileInputStream(pfd.fileDescriptor).channel.use { channel ->
                        while (done < fileSize) {
                            buffer.clear()
                            val toRead = (fileSize - done).coerceAtMost(IMPORT_CHUNK.toLong()).toInt()
                            buffer.limit(toRead)

                            var read = 0
                            while (buffer.hasRemaining()) {
                                val r = channel.read(buffer)
                                if (r <= 0) break
                                read += r
                            }
                            if (read <= 0) break

                            buffer.flip()
                            writer.write(buffer, read)
                            done += read
                            onProgress(done, fileSize)
                        }
                    }
                } ?: throw IllegalStateException("could not open input file descriptor")

                if (done < fileSize) {
                    throw IllegalStateException("short read: read $done bytes of $fileSize expected")
                }

                val ino = writer.finish(parentPath, name)
                val secs = (System.currentTimeMillis() - started).coerceAtLeast(1) / 1000.0
                Trace.i("import: %d bytes in %.1f s · %.1f MiB/s (inode %d)".format(done, secs, done / secs / (1L shl 20), ino))
                "uploaded $name (${formatSize(done)}) in %.1f s · %.1f MiB/s".format(secs, done / secs / (1L shl 20))
            } finally {
                writer.close()
            }
        }
    }
} catch (e: LuksException) {
    Trace.err(e.code, "transfer")
    Trace.e("import: failed [${e.code}] ${e.message}")
    "upload failed [${e.code}] ${e.message}"
} catch (e: Exception) {
    Trace.err(-1, "transfer")
    Trace.e("import: failed", e)
    "upload failed: ${e.message}"
}

private const val IMPORT_CHUNK = 1 shl 20

/** Streams the file through SHA-256 and reports the throughput it managed. */
private suspend fun hashFile(path: String): String = try {
    val d = withContext(Dispatchers.IO) {
        LuksSession.withLease { volume ->
            volume.sha256(path)
        }
    }
    val mbPerSec = d.bytesPerSec.toDouble() / (1L shl 20)
    Trace.i("hash: %d bytes in %d ms · %.1f MiB/s".format(d.bytes, d.elapsedMs, mbPerSec))
    "${d.sha256}\n${formatSize(d.bytes)} in ${d.elapsedMs} ms · %.1f MiB/s".format(mbPerSec)
} catch (e: LuksException) {
    Trace.err(e.code, "transfer")
    Trace.e("hash: failed [${e.code}] ${e.message}")
    "hash failed: ${e.message}"
} catch (e: Exception) {
    Trace.err(-1, "transfer")
    Trace.e("hash: failed", e)
    "hash failed: ${e.message}"
}

private fun probeReflectionSurface(context: android.content.Context): String {
    val results = mutableListOf<String>()

    try {
        val m = android.text.SpannableStringBuilder::class.java.getMethod("length")
        val ssb = android.text.SpannableStringBuilder("test")
        val res = m.invoke(ssb) as Int
        if (res == 4) {
            results.add("PROBE: CONTROL_GOOD = OK")
        } else {
            results.add("PROBE: CONTROL_GOOD = FAIL (unexpected value $res)")
        }
    } catch (t: Throwable) {
        results.add("PROBE: CONTROL_GOOD = FAIL (${t.javaClass.simpleName}: ${t.message})")
    }

    try {
        android.text.SpannableStringBuilder::class.java.getDeclaredField("mNoSuchField")
        results.add("PROBE: CONTROL_BAD = FAIL (unexpectedly found field)")
    } catch (e: NoSuchFieldException) {
        results.add("PROBE: CONTROL_BAD = OK (NoSuchFieldException)")
    } catch (t: Throwable) {
        results.add("PROBE: CONTROL_BAD = FAIL (${t.javaClass.simpleName}: ${t.message})")
    }

    try {
        val f = android.text.SpannableStringBuilder::class.java.getDeclaredField("mText").apply { isAccessible = true }
        val ssb = android.text.SpannableStringBuilder("hello")
        val arr = f.get(ssb) as CharArray
        if (arr.isNotEmpty() && arr[0] == 'h') {
            results.add("PROBE: SSB_MTEXT = OK")
        } else {
            results.add("PROBE: SSB_MTEXT = FAIL (array mismatch)")
        }
    } catch (t: Throwable) {
        results.add("PROBE: SSB_MTEXT = BLOCKED (${t.javaClass.simpleName}: ${t.message})")
    }

    try {
        val tv = android.widget.EditText(context)
        val fEditor = android.widget.TextView::class.java.getDeclaredField("mEditor").apply { isAccessible = true }
        val editor = fEditor.get(tv)
        if (editor != null) {
            results.add("PROBE: TEXTVIEW_MEDITOR = OK")
            val editorClass = editor.javaClass

            try {
                val fields = editorClass.declaredFields.map { it.name }
                val undoFields = fields.filter { it.contains("undo", ignoreCase = true) }
                results.add("PROBE: EDITOR_FIELDS_ALL = ${fields.joinToString(", ")}")
                results.add("PROBE: EDITOR_FIELDS_UNDO = ${undoFields.ifEmpty { listOf("NONE_MATCHED") }.joinToString(", ")}")

                val methods = editorClass.declaredMethods.map { it.name }
                val undoMethods = methods.filter { it.contains("undo", ignoreCase = true) }
                results.add("PROBE: EDITOR_METHODS_UNDO = ${undoMethods.ifEmpty { listOf("NONE_MATCHED") }.joinToString(", ")}")
            } catch (t: Throwable) {
                results.add("PROBE: EDITOR_FIELDS = BLOCKED (${t.javaClass.simpleName}: ${t.message})")
            }
        } else {
            results.add("PROBE: TEXTVIEW_MEDITOR = BLOCKED (mEditor null)")
        }
    } catch (t: Throwable) {
        results.add("PROBE: TEXTVIEW_MEDITOR = BLOCKED (${t.javaClass.simpleName}: ${t.message})")
    }

    results.forEach { android.util.Log.i("PassphraseProbe", it) }
    return results.joinToString("\n")
}
