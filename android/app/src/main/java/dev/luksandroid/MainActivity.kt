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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/**
 * Pass 1: prove the plumbing.
 *
 * This screen does exactly two things, both of which have to work before any
 * USB or crypto code is worth writing:
 *
 *  1. calls into the Rust library, so `System.loadLibrary` and the JNI symbol
 *     names are verified on the real device rather than assumed;
 *  2. enumerates attached mass-storage devices and shows their endpoints.
 *
 * Opening a device, unlocking and browsing come in the next pass, together with
 * the foreground service that has to wrap the Argon2 allocation.
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

@Composable
private fun DiagnosticsScreen() {
    val context = LocalContext.current

    // Deliberately not in a try/catch: if the library fails to load there is no
    // app, and an UnsatisfiedLinkError in logcat names the missing .so.
    val version = remember { LuksNative.nativeVersion() }

    var targets by remember { mutableStateOf(UsbMassStorage.findTargets(context)) }

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
                    Text(
                        if (UsbMassStorage.hasPermission(context, target.device)) {
                            "Permission granted"
                        } else {
                            "Permission not granted yet"
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}
