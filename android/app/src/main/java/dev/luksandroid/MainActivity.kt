package dev.luksandroid

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Pass 2: open a detected device and read its real partition table over USB.
 *
 * Still no unlock — that needs the foreground service, which is pass 3. This
 * pass exists to isolate one question: does `UsbFsTransport` work at all
 * against real hardware? Everything below `nativeOpenDevice` (SCSI INQUIRY,
 * READ CAPACITY, GPT parsing, LUKS-magic probing) has 106 tests behind it but
 * has never once talked to a real bulk pipe before this.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Keeps the app out of the recents thumbnail and blocks screenshots.
        // Set here rather than on the unlock screen alone: the file listing of
        // an encrypted drive is itself something the user chose to encrypt.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

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
                            val info = state.device.info
                            Text(
                                "${info.vendor} ${info.product} · ${formatSize(info.sizeBytes)} " +
                                    "· ${info.blockSize}B blocks · ${info.tableKind}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            if (info.partitions.isEmpty()) {
                                Text(
                                    "No partition table found.",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            info.partitions.forEach { p ->
                                Text("  ${p.label}", style = MaterialTheme.typography.bodySmall)
                            }
                            if (state.device.luksPartitions.isEmpty()) {
                                Text(
                                    "No LUKS partition on this drive. (Unlock UI comes " +
                                        "in the next pass regardless.)",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Button(onClick = {
                                state.device.close()
                                states = states + (key to DeviceState.Idle)
                            }) {
                                Text("Close")
                            }
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

/**
 * Requests permission if needed, then opens the device and reads its
 * partition table. All of it runs off the main thread: `requestPermission`
 * suspends on user input, and `UsbMassStorage.open` blocks on real USB
 * transfers (INQUIRY, READ CAPACITY, the LUKS-magic probe of every partition).
 */
private suspend fun openDevice(
    context: android.content.Context,
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
