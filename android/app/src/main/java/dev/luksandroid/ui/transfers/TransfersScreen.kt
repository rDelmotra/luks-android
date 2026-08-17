package dev.luksandroid.ui.transfers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.luksandroid.formatSize
import dev.luksandroid.session.TransferController
import dev.luksandroid.session.TransferItem
import dev.luksandroid.session.TransferManager
import dev.luksandroid.session.TransferState
import dev.luksandroid.session.TransferType

@Composable
fun TransfersScreen(
    modifier: Modifier = Modifier,
    manager: TransferController = TransferManager,
    onBack: (() -> Unit)? = null,
) {
    val transfers by manager.transfers.collectAsState()
    val activeTransfers = transfers.filter { it.state == TransferState.RUNNING }
    val completedTransfers = transfers.filter { it.state != TransferState.RUNNING }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Transfers",
                style = MaterialTheme.typography.headlineMedium,
            )
            if (onBack != null) {
                TextButton(onClick = onBack) {
                    Text("Close")
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Active transfers section
            item {
                Text(
                    text = "Active Transfers (${activeTransfers.size})",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }

            if (activeTransfers.isEmpty()) {
                item {
                    Text(
                        text = "No active transfers.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                }
            } else {
                items(activeTransfers, key = { it.id }) { item ->
                    ActiveTransferCard(
                        item = item,
                        onCancel = { manager.cancelTransfer(item.id) },
                    )
                }
            }

            item {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            }

            // Transfer history section
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Transfer History (${completedTransfers.size})",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (completedTransfers.isNotEmpty()) {
                        TextButton(onClick = { manager.clearHistory() }) {
                            Text("Clear History")
                        }
                    }
                }
            }

            if (completedTransfers.isEmpty()) {
                item {
                    Text(
                        text = "No transfer history.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                }
            } else {
                items(completedTransfers, key = { it.id }) { item ->
                    CompletedTransferCard(
                        item = item,
                        onRemove = { manager.removeTransfer(item.id) },
                    )
                }
            }
        }
    }
}

@Composable
private fun ActiveTransferCard(
    item: TransferItem,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = item.name,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                Spacer(modifier = Modifier.width(8.dp))
                TypeBadge(type = item.type)
            }

            val progress = if (item.totalBytes > 0) {
                (item.transferredBytes.toFloat() / item.totalBytes.toFloat()).coerceIn(0f, 1f)
            } else {
                0f
            }

            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                val pct = (progress * 100).toInt()
                Text(
                    text = "${formatSize(item.transferredBytes)} / ${formatSize(item.totalBytes)} ($pct%)",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    text = formatSpeed(item.speedBytesPerSec),
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = formatEta(item.etaSeconds),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(
                    onClick = onCancel,
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

@Composable
private fun CompletedTransferCard(
    item: TransferItem,
    onRemove: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = item.name,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    TypeBadge(type = item.type)
                    StateBadge(state = item.state)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val sizeText = when (item.state) {
                    TransferState.COMPLETED -> formatSize(item.totalBytes)
                    else -> "${formatSize(item.transferredBytes)} transferred"
                }
                Text(
                    text = sizeText,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (item.speedBytesPerSec > 0 && item.state == TransferState.COMPLETED) {
                    Text(
                        text = "avg ${formatSpeed(item.speedBytesPerSec)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (!item.error.isNullOrBlank()) {
                Text(
                    text = item.error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun TypeBadge(type: TransferType) {
    Surface(
        shape = MaterialTheme.shapes.extraSmall,
        color = when (type) {
            TransferType.IMPORT -> MaterialTheme.colorScheme.tertiaryContainer
            TransferType.EXPORT -> MaterialTheme.colorScheme.secondaryContainer
            TransferType.HASH -> MaterialTheme.colorScheme.surfaceVariant
        },
    ) {
        Text(
            text = when (type) {
                TransferType.IMPORT -> "Import"
                TransferType.EXPORT -> "Export"
                TransferType.HASH -> "Checksum"
            },
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            color = when (type) {
                TransferType.IMPORT -> MaterialTheme.colorScheme.onTertiaryContainer
                TransferType.EXPORT -> MaterialTheme.colorScheme.onSecondaryContainer
                TransferType.HASH -> MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
    }
}

@Composable
private fun StateBadge(state: TransferState) {
    Surface(
        shape = MaterialTheme.shapes.extraSmall,
        color = when (state) {
            TransferState.COMPLETED -> MaterialTheme.colorScheme.primaryContainer
            TransferState.RUNNING -> MaterialTheme.colorScheme.surfaceVariant
            TransferState.CANCELLED -> MaterialTheme.colorScheme.surfaceVariant
            TransferState.FAILED -> MaterialTheme.colorScheme.errorContainer
        },
    ) {
        Text(
            text = when (state) {
                TransferState.COMPLETED -> "Completed"
                TransferState.RUNNING -> "Running"
                TransferState.CANCELLED -> "Cancelled"
                TransferState.FAILED -> "Failed"
            },
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            color = when (state) {
                TransferState.COMPLETED -> MaterialTheme.colorScheme.onPrimaryContainer
                TransferState.RUNNING -> MaterialTheme.colorScheme.onSurfaceVariant
                TransferState.CANCELLED -> MaterialTheme.colorScheme.onSurfaceVariant
                TransferState.FAILED -> MaterialTheme.colorScheme.onErrorContainer
            },
        )
    }
}

fun formatSpeed(bytesPerSec: Long): String = when {
    bytesPerSec >= 1L shl 20 -> "%.1f MiB/s".format(bytesPerSec.toDouble() / (1L shl 20))
    bytesPerSec >= 1L shl 10 -> "%.1f KiB/s".format(bytesPerSec.toDouble() / (1L shl 10))
    bytesPerSec > 0 -> "$bytesPerSec B/s"
    else -> "0 B/s"
}

fun formatEta(etaSeconds: Long): String = when {
    etaSeconds <= 0L -> "Finishing…"
    etaSeconds < 60L -> "${etaSeconds}s remaining"
    etaSeconds < 3600L -> "${etaSeconds / 60}m ${etaSeconds % 60}s remaining"
    else -> "${etaSeconds / 3600}h ${(etaSeconds % 3600) / 60}m remaining"
}
