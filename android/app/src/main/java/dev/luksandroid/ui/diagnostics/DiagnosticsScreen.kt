package dev.luksandroid.ui.diagnostics

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.luksandroid.LuksNative
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
fun DiagnosticsScreen(
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val nativeVersion = remember {
        try {
            LuksNative.nativeVersion()
        } catch (t: Throwable) {
            "Error loading native library: ${t.message}"
        }
    }

    var selfTestResult by remember { mutableStateOf<String?>(null) }
    var isRunningSelfTest by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Title
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = Icons.Default.BugReport,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp),
            )
            Column {
                Text(
                    text = "System Diagnostics",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = "Hardware cryptology, reflection surface & JNI status",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Native Library Status
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Native JNI Engine",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "luks_core: $nativeVersion",
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = "Native Write Supported: ${LuksNative.nativeWriteSupported()}",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // CPU & Reflection Self-test Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Crypto & Memory Probes",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "Runs pure CPU benchmarks for AES-XTS and SHA-256 plus runtime introspection of TextView/SSB fields for passphrase scrubbing.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Button(
                    onClick = {
                        isRunningSelfTest = true
                        selfTestResult = "Running cryptographic benchmarks and reflection probes…"
                        scope.launch {
                            selfTestResult = try {
                                val probe = withContext(Dispatchers.Main) { probeReflectionSurface(context) }
                                val cpu = withContext(Dispatchers.IO) {
                                    val j = JSONObject(LuksNative.nativeSelfTest(64))
                                    "AES-XTS: %d MiB/s · SHA-256: %d MiB/s (ARMv8 crypto compiled: %b)".format(
                                        j.getLong("xtsMiBs"),
                                        j.getLong("sha256MiBs"),
                                        j.getBoolean("aesArmv8Compiled"),
                                    )
                                }
                                "$cpu\n\n--- Reflection Probes ---\n$probe"
                            } catch (e: Exception) {
                                "Self-test failed: ${e.message}"
                            } finally {
                                isRunningSelfTest = false
                            }
                        }
                    },
                    enabled = !isRunningSelfTest,
                    shape = RoundedCornerShape(8.dp),
                ) {
                    if (isRunningSelfTest) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(imageVector = Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Run CPU & Reflection Self-Test")
                }

                selfTestResult?.let { result ->
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                    OutlinedCard(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                    ) {
                        Text(
                            text = result,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                            ),
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }
        }

        // Forensic Event Log Card
        var forensicLogText by remember { mutableStateOf<String?>(null) }
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Forensic Event Trace",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "In-memory 256-slot ring buffer of native USB, SCSI, and Btrfs hardware events (zero filename / zero data exposure).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = {
                            val dump = dev.luksandroid.Trace.dumpForensicLog()
                            forensicLogText = if (dump.isBlank()) "(Empty log - no events recorded yet)" else dump
                            android.util.Log.i("LUKS_FORENSIC_DUMP", "\n=== FORENSIC LOG DUMP ===\n$dump\n=== END FORENSIC LOG DUMP ===")
                        },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("View / Refresh Log")
                    }
                    Button(
                        onClick = {
                            dev.luksandroid.Trace.clearForensicLog()
                            forensicLogText = "(Log cleared)"
                        },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("Clear")
                    }
                }
                forensicLogText?.let { log ->
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                    OutlinedCard(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                    ) {
                        Text(
                            text = log,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                            ),
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }
        }
    }
}

private fun probeReflectionSurface(context: Context): String {
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

    return results.joinToString("\n")
}
