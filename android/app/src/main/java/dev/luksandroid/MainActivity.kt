package dev.luksandroid

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
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

    fun keyOf(t: UsbMassStorage.Target) =
        "${t.device.vendorId}:${t.device.productId}:${t.usbInterface.id}"

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("LUKS", style = MaterialTheme.typography.headlineMedium)
        Text("luks_core $version loaded", style = MaterialTheme.typography.bodyMedium)

        Button(onClick = { targets = UsbMassStorage.findTargets(context) }) {
            Text("Rescan USB")
        }

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
    val info = state.volume.info
    var digest by remember { mutableStateOf<String?>(null) }

    Text(
        "Unlocked: ${info.label.ifBlank { "(no label)" }} · ${formatSize(info.sizeBytes)} " +
            "· ${info.blockSize}B blocks",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(info.uuid, style = MaterialTheme.typography.bodySmall)

    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

    state.entries.forEach { entry ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                if (entry.isDir) "📁 ${entry.name}" else "   ${entry.name}",
                style = MaterialTheme.typography.bodySmall,
            )
            if (!entry.isDir) {
                TextButton(onClick = {
                    digest = "hashing ${entry.name}…"
                    scope.launch {
                        digest = hashFile(state.volume, "/${entry.name}")
                    }
                }) {
                    Text("SHA-256")
                }
            }
        }
    }

    digest?.let {
        Text(it, style = MaterialTheme.typography.bodySmall)
    }

    Button(onClick = {
        state.volume.close()
        onVolumeChange(VolumeState.None)
    }) {
        Text("Lock")
    }
}

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
    val granted = UsbMassStorage.requestPermission(context, target.device)
    if (!granted) {
        return DeviceState.Failed("permission denied")
    }
    return try {
        val device = withContext(Dispatchers.IO) { UsbMassStorage.open(context, target) }
        DeviceState.Open(device)
    } catch (e: LuksException) {
        DeviceState.Failed("[${e.code}] ${e.message}")
    } catch (e: Exception) {
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
    UnlockService.holding(context) {
        withContext(Dispatchers.IO) {
            val v = device.unlock(partition.offsetBytes, password)
            VolumeState.Unlocked(v, v.listDir("/"))
        }
    }
} catch (e: LuksException) {
    VolumeState.Failed(
        partition,
        if (e.isWrongPassword) "wrong passphrase" else "[${e.code}] ${e.message}",
    )
} catch (e: Exception) {
    VolumeState.Failed(partition, e.message ?: e.toString())
} finally {
    // Belt and braces: LuksDevice.unlock already zeroes this, but that only
    // runs if the call was reached at all.
    password.fill(0)
}

/** Streams the file through SHA-256 and reports the throughput it managed. */
private suspend fun hashFile(volume: LuksVolume, path: String): String = try {
    val d = withContext(Dispatchers.IO) { volume.sha256(path) }
    val mbPerSec = d.bytesPerSec.toDouble() / (1L shl 20)
    "${d.sha256}\n${formatSize(d.bytes)} in ${d.elapsedMs} ms · %.1f MiB/s".format(mbPerSec)
} catch (e: Exception) {
    "hash failed: ${e.message}"
}
