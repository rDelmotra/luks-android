package dev.luksandroid

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import dev.luksandroid.session.LuksSession
import dev.luksandroid.ui.navigation.LuksAppNavigation
import dev.luksandroid.ui.theme.LuksTheme

/**
 * Main entry point for the LUKS Android application.
 *
 * Hosts the Material 3 Compose UI navigation with [FLAG_SECURE] enforced
 * across all screens to block screenshot capture and recents thumbnails.
 */
class MainActivity : ComponentActivity() {

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* advisory */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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

        // Broadcast receiver for remote diagnostic dumping via `adb shell am broadcast -a dev.luksandroid.DUMP_FORENSIC`
        val forensicFilter = android.content.IntentFilter("dev.luksandroid.DUMP_FORENSIC")
        val forensicReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
                val dump = Trace.dumpForensicLog()
                android.util.Log.i("LUKS_FORENSIC_DUMP", "\n=== FORENSIC LOG DUMP ===\n$dump\n=== END FORENSIC LOG DUMP ===")
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(forensicReceiver, forensicFilter, android.content.Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(forensicReceiver, forensicFilter)
        }

        setContent {
            LuksTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    LuksAppNavigation()
                }
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        LuksSession.onTrimMemory(level)
    }
}
