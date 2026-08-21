package dev.luksandroid.ui.devices

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager
import android.os.Build
import android.text.Editable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material.icons.filled.UsbOff
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.luksandroid.LuksDevice
import dev.luksandroid.LuksException
import dev.luksandroid.PartitionInfo
import dev.luksandroid.Trace
import dev.luksandroid.UsbMassStorage
import dev.luksandroid.formatSize
import dev.luksandroid.security.PassphraseScrubber
import dev.luksandroid.security.SecurePassphraseBuffer
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionState
import dev.luksandroid.ui.SecurePassphraseField
import dev.luksandroid.ui.theme.SuccessGreen
import dev.luksandroid.ui.theme.WarningAmber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * State of a discovered USB target device before unlocking.
 */
private sealed interface DeviceItemState {
    data object Idle : DeviceItemState
    data object Opening : DeviceItemState
    data class Opened(val device: LuksDevice) : DeviceItemState
    data class Failed(val error: String) : DeviceItemState
}

@Composable
fun DevicesScreen(
    modifier: Modifier = Modifier,
    onNavigateToBrowser: (() -> Unit)? = null,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val sessionState by LuksSession.state.collectAsState()

    var targets by remember { mutableStateOf<List<UsbMassStorage.Target>>(emptyList()) }
    var deviceStates by remember { mutableStateOf<Map<String, DeviceItemState>>(emptyMap()) }
    var isScanning by remember { mutableStateOf(false) }

    fun keyOf(target: UsbMassStorage.Target) =
        "${target.device.deviceId}:${target.device.vendorId}:${target.device.productId}:${target.usbInterface.id}"

    // Re-opens a target whose USB permission is already granted, marking it Opening in
    // the meantime. Shared by the initial scan and by stale-handle recovery below, so
    // both paths reopen a device the exact same way.
    fun reopenTarget(target: UsbMassStorage.Target) {
        val key = keyOf(target)
        deviceStates = deviceStates + (key to DeviceItemState.Opening)
        scope.launch {
            val opened = openTarget(context, target)
            deviceStates = deviceStates + (key to opened)
        }
    }

    fun scanDevices() {
        isScanning = true
        scope.launch {
            val list = withContext(Dispatchers.IO) {
                UsbMassStorage.findTargets(context)
            }
            targets = list
            // Clean up stale device entries for devices no longer present or already closed
            val validKeys = list.map { keyOf(it) }.toSet()
            deviceStates = deviceStates.filter { (k, v) ->
                k in validKeys && (v !is DeviceItemState.Opened || v.device.isOpen)
            }
            // Auto-open devices that already have permissions granted
            list.forEach { target ->
                val key = keyOf(target)
                if (UsbMassStorage.hasPermission(context, target.device) &&
                    deviceStates[key] !is DeviceItemState.Opened &&
                    deviceStates[key] !is DeviceItemState.Opening
                ) {
                    reopenTarget(target)
                }
            }
            isScanning = false
        }
    }

    LaunchedEffect(Unit) {
        scanDevices()
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val action = intent.action
                if (action == UsbManager.ACTION_USB_DEVICE_ATTACHED ||
                    action == UsbManager.ACTION_USB_DEVICE_DETACHED
                ) {
                    scanDevices()
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        onDispose {
            runCatching { context.unregisterReceiver(receiver) }
        }
    }

    // A lock — automatic (idle timeout, trim) or manual (the Lock button) — tears down
    // the exact LuksDevice instance the UI is still holding in `deviceStates`: closing it
    // zeroes the native handle AND releases the USB interface underneath it. Without this,
    // the cached `Opened(device)` entry looks fine to the UI but every native call on it
    // (including a fresh unlock attempt) throws `IllegalStateException` instantly, and the
    // only way out was force-stopping the app. Once the session reports Locked or Detached, drop any
    // device entries whose handle is no longer open and transparently re-acquire them.
    LaunchedEffect(sessionState) {
        if (sessionState is SessionState.Locked || sessionState is SessionState.Detached) {
            val staleKeys = deviceStates.filterValues {
                it is DeviceItemState.Opened && !it.device.isOpen
            }.keys
            if (staleKeys.isNotEmpty()) {
                deviceStates = deviceStates - staleKeys
            }
            scanDevices()
        }
    }

    // Dialog state for passphrase entry
    var promptDialogTarget by remember { mutableStateOf<Pair<LuksDevice, PartitionInfo>?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    text = "Storage Devices",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = "Encrypted USB block storage",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            OutlinedButton(
                onClick = { scanDevices() },
                enabled = !isScanning,
                shape = RoundedCornerShape(8.dp),
            ) {
                if (isScanning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Scan",
                        modifier = Modifier.size(16.dp),
                    )
                }
                Spacer(modifier = Modifier.width(6.dp))
                Text("Rescan")
            }
        }

        // Global Session State notices (Unlocking / Detached / Failed)
        when (val s = sessionState) {
            is SessionState.Unlocking -> {
                UnlockingStateCard(partition = s.partition)
            }
            is SessionState.Detached -> {
                DetachedStateCard(
                    message = s.message,
                    onDismiss = {
                        scope.launch {
                            LuksSession.reset()
                            scanDevices()
                        }
                    }
                )
            }
            is SessionState.Failed -> {
                FailedStateCard(
                    message = s.message,
                    onReset = {
                        scope.launch {
                            LuksSession.reset()
                        }
                    },
                    onTryAgain = if (s.partition != null) {
                        {
                            val targetDev = deviceStates.values
                                .filterIsInstance<DeviceItemState.Opened>()
                                .map { it.device }
                                .firstOrNull { it.luksPartitions.any { lp -> lp.offsetBytes == s.partition.offsetBytes } }
                            if (targetDev != null) {
                                scope.launch { LuksSession.reset() }
                                promptDialogTarget = targetDev to s.partition
                            } else {
                                scope.launch { LuksSession.reset() }
                            }
                        }
                    } else null
                )
            }
            is SessionState.Unlocked -> {
                UnlockedStateCard(
                    state = s,
                    onNavigateToBrowser = onNavigateToBrowser,
                    onLock = {
                        scope.launch { LuksSession.lock() }
                    }
                )
            }
            is SessionState.Locked -> {
                // Normal locked flow
            }
        }

        // Render targets
        if (targets.isEmpty() && sessionState !is SessionState.Unlocked) {
            EmptyDevicesCard(onScan = { scanDevices() })
        } else {
            targets.forEach { target ->
                val key = keyOf(target)
                val itemState = deviceStates[key] ?: DeviceItemState.Idle
                val hasPerm = UsbMassStorage.hasPermission(context, target.device)

                TargetDeviceCard(
                    target = target,
                    hasPermission = hasPerm,
                    itemState = itemState,
                    sessionState = sessionState,
                    onRequestPermission = {
                        scope.launch {
                            val granted = UsbMassStorage.requestPermission(context, target.device)
                            if (granted) {
                                deviceStates = deviceStates + (key to DeviceItemState.Opening)
                                val opened = openTarget(context, target)
                                deviceStates = deviceStates + (key to opened)
                            }
                        }
                    },
                    onOpen = {
                        deviceStates = deviceStates + (key to DeviceItemState.Opening)
                        scope.launch {
                            val opened = openTarget(context, target)
                            deviceStates = deviceStates + (key to opened)
                        }
                    },
                    onUnlockPartition = { device, partition ->
                        promptDialogTarget = device to partition
                    },
                )
            }
        }
    }

    // Passphrase Entry Dialog
    promptDialogTarget?.let { (device, partition) ->
        PassphraseEntryDialog(
            partition = partition,
            onDismiss = { promptDialogTarget = null },
            onSubmit = { buffer ->
                promptDialogTarget = null
                scope.launch {
                    buffer.use { buf ->
                        LuksSession.unlock(context, device, partition, buf)
                    }
                }
            },
        )
    }
}

@Composable
private fun EmptyDevicesCard(
    onScan: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.Usb,
                    contentDescription = null,
                    modifier = Modifier.size(36.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }

            Text(
                text = "Plug in a USB storage drive",
                style = MaterialTheme.typography.titleLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurface,
            )

            Text(
                text = "Connect a LUKS-encrypted USB drive via an OTG adapter or USB-C cable.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(4.dp))

            Button(
                onClick = onScan,
                shape = RoundedCornerShape(8.dp),
            ) {
                Icon(imageVector = Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Scan USB")
            }
        }
    }
}

@Composable
private fun TargetDeviceCard(
    target: UsbMassStorage.Target,
    hasPermission: Boolean,
    itemState: DeviceItemState,
    sessionState: SessionState,
    onRequestPermission: () -> Unit,
    onOpen: () -> Unit,
    onUnlockPartition: (LuksDevice, PartitionInfo) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
        shape = RoundedCornerShape(14.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Header Row: USB Icon, Label, VID:PID
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surface),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Default.Usb,
                        contentDescription = "USB",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp),
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = target.label,
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "VID:PID %04x:%04x · Interface %d".format(
                            target.device.vendorId,
                            target.device.productId,
                            target.usbInterface.id,
                        ),
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

            // State specific content
            if (!hasPermission) {
                // Permission not granted
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "USB permission required to read drive",
                        style = MaterialTheme.typography.bodySmall,
                        color = WarningAmber,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = onRequestPermission,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.Key,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Grant Permission")
                    }
                }
            } else {
                // Permission granted
                when (itemState) {
                    is DeviceItemState.Idle -> {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = "Permission granted · Ready to inspect",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Button(
                                onClick = onOpen,
                                shape = RoundedCornerShape(8.dp),
                            ) {
                                Text("Inspect Drive")
                            }
                        }
                    }

                    is DeviceItemState.Opening -> {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            Text(
                                text = "Claiming interface and reading partition table…",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }

                    is DeviceItemState.Opened -> {
                        val dev = itemState.device
                        val info = dev.info

                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "${info.vendor} ${info.product} · ${formatSize(info.sizeBytes)} · ${info.tableKind}",
                                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
                                color = MaterialTheme.colorScheme.onSurface,
                            )

                            if (info.partitions.isEmpty()) {
                                Text(
                                    text = "No partition table found on drive.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }

                            // Render partitions
                            info.partitions.forEach { partition ->
                                PartitionItemCard(
                                    device = dev,
                                    partition = partition,
                                    sessionState = sessionState,
                                    onUnlock = { onUnlockPartition(dev, partition) },
                                )
                            }
                        }
                    }

                    is DeviceItemState.Failed -> {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = "Failed: ${itemState.error}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.weight(1f),
                            )
                            OutlinedButton(onClick = onOpen, shape = RoundedCornerShape(8.dp)) {
                                Text("Retry")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PartitionItemCard(
    device: LuksDevice,
    partition: PartitionInfo,
    sessionState: SessionState,
    onUnlock: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isSessionUnlocked = sessionState is SessionState.Unlocked &&
            sessionState.partition.offsetBytes == partition.offsetBytes

    OutlinedCard(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f),
            ) {
                Icon(
                    imageVector = if (partition.isLuks) {
                        if (isSessionUnlocked) Icons.Default.LockOpen else Icons.Default.Lock
                    } else {
                        Icons.Default.Storage
                    },
                    contentDescription = null,
                    tint = when {
                        isSessionUnlocked -> SuccessGreen
                        partition.isLuks -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.size(20.dp),
                )
                Spacer(modifier = Modifier.width(10.dp))

                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = partition.name.ifBlank { "Partition #${partition.index}" },
                            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        if (partition.isLuks) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(MaterialTheme.colorScheme.primaryContainer)
                                    .padding(horizontal = 6.dp, vertical = 1.dp),
                            ) {
                                Text(
                                    text = "LUKS${partition.luksVersion ?: ""}",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp,
                                    ),
                                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                                )
                            }
                        }
                    }

                    Text(
                        text = "${formatSize(partition.sizeBytes)} · Offset 0x${partition.offsetBytes.toString(16)}",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (partition.isLuks) {
                if (isSessionUnlocked) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Unlocked",
                            tint = SuccessGreen,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Unlocked",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = SuccessGreen,
                        )
                    }
                } else if (sessionState is SessionState.Locked) {
                    FilledTonalButton(
                        onClick = onUnlock,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.LockOpen,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Unlock")
                    }
                }
            }
        }
    }
}

@Composable
private fun UnlockingStateCard(
    partition: PartitionInfo,
    modifier: Modifier = Modifier,
) {
    var elapsedSec by remember { mutableIntStateOf(0) }

    LaunchedEffect(partition) {
        val start = System.currentTimeMillis()
        while (true) {
            elapsedSec = ((System.currentTimeMillis() - start) / 1000).toInt()
            delay(500)
        }
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
        ),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    strokeWidth = 2.5.dp,
                )
                Column {
                    Text(
                        text = "Unlocking ${partition.name.ifBlank { "Partition #${partition.index}" }}…",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Text(
                        text = "Deriving master key · Elapsed: ${elapsedSec}s",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
                    )
                }
            }

            Text(
                text = "Argon2 / PBKDF2 key derivation and memory allocation in progress.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
            )
        }
    }
}

@Composable
private fun DetachedStateCard(
    message: String,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f),
            ) {
                Icon(
                    imageVector = Icons.Default.UsbOff,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(28.dp),
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = "Drive Detached",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Text(
                        text = message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.9f),
                    )
                }
            }

            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Dismiss / Scan")
            }
        }
    }
}

@Composable
private fun FailedStateCard(
    message: String,
    onReset: () -> Unit,
    onTryAgain: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val isWrongPassphrase = message.contains("wrong passphrase", ignoreCase = true)

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.ErrorOutline,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(24.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (isWrongPassphrase) "Incorrect Passphrase" else "Unlock Failed",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }

            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.9f),
            )

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Button(
                    onClick = onReset,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Reset")
                }

                if (onTryAgain != null) {
                    FilledTonalButton(
                        onClick = onTryAgain,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("Try Again")
                    }
                }
            }
        }
    }
}

@Composable
private fun UnlockedStateCard(
    state: SessionState.Unlocked,
    onNavigateToBrowser: (() -> Unit)?,
    onLock: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val info = state.volume.info

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = Icons.Default.LockOpen,
                    contentDescription = null,
                    tint = SuccessGreen,
                    modifier = Modifier.size(24.dp),
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Active Session: ${info.label.ifBlank { state.partition.label }}",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "Filesystem: ${info.fsType.uppercase()} · ${formatSize(info.sizeBytes)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (onNavigateToBrowser != null) {
                    Button(
                        onClick = onNavigateToBrowser,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(imageVector = Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Open File Browser")
                    }
                }

                OutlinedButton(
                    onClick = onLock,
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(imageVector = Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Lock")
                }
            }
        }
    }
}

@Composable
private fun PassphraseEntryDialog(
    partition: PartitionInfo,
    onDismiss: () -> Unit,
    onSubmit: (SecurePassphraseBuffer) -> Unit,
) {
    var activeEditable by remember { mutableStateOf<Editable?>(null) }
    var hasContent by remember { mutableStateOf(false) }

    fun submit() {
        val editable = activeEditable ?: return
        val buffer = PassphraseScrubber.extractAndScrub(editable)
        onSubmit(buffer)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.VpnKey,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Unlock ${partition.name.ifBlank { "Partition #${partition.index}" }}",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Enter LUKS passphrase to derive decryption key:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                SecurePassphraseField(
                    onEditableReady = { activeEditable = it },
                    onHasContentChange = { hasContent = it },
                )

                Text(
                    text = "Screen capture blocked & memory scrubbed on submit.",
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = ::submit,
                enabled = hasContent,
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Unlock")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
        shape = RoundedCornerShape(16.dp),
    )
}

private suspend fun openTarget(
    context: Context,
    target: UsbMassStorage.Target,
): DeviceItemState = try {
    val device = withContext(Dispatchers.IO) {
        UsbMassStorage.open(context, target)
    }
    Trace.i("DevicesScreen: opened ${target.label} successfully")
    DeviceItemState.Opened(device)
} catch (e: LuksException) {
    Trace.err(e.code, "open_target")
    Trace.e("DevicesScreen: open failed [${e.code}]")
    DeviceItemState.Failed("[${e.code}] ${e.message}")
} catch (e: Exception) {
    Trace.err(-1, "open_target")
    Trace.e("DevicesScreen: open failed: ${Trace.throwableSummary(e)}")
    DeviceItemState.Failed(e.message ?: e.toString())
}
