package dev.luksandroid.ui.browser

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.luksandroid.Entry
import dev.luksandroid.LuksException
import dev.luksandroid.LuksVolume
import dev.luksandroid.StatFsInfo
import dev.luksandroid.Trace
import dev.luksandroid.formatSize
import dev.luksandroid.formatTimestamp
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionState
import dev.luksandroid.session.TransferManager
import dev.luksandroid.session.TransferState
import dev.luksandroid.session.TransferType
import dev.luksandroid.ui.components.BreadcrumbBar
import dev.luksandroid.ui.components.CapacityBar
import dev.luksandroid.ui.components.DeleteConfirmDialog
import dev.luksandroid.ui.components.NewFolderDialog
import dev.luksandroid.ui.components.RenameDialog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Custom vector icons for Browser file types and actions.
 */
object BrowserIcons {
    val Folder: ImageVector = ImageVector.Builder(
        name = "Folder",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(10f, 4f)
            lineTo(4f, 4f)
            curveTo(2.9f, 4f, 2.01f, 4.9f, 2.01f, 6f)
            lineTo(2f, 18f)
            curveTo(2f, 19.1f, 2.9f, 20f, 4f, 20f)
            lineTo(20f, 20f)
            curveTo(21.1f, 20f, 22f, 19.1f, 22f, 18f)
            lineTo(22f, 8f)
            curveTo(22f, 6.9f, 21.1f, 6f, 20f, 6f)
            lineTo(12f, 6f)
            lineTo(10f, 4f)
            close()
        }
    }.build()

    val File: ImageVector = ImageVector.Builder(
        name = "File",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(14f, 2f)
            lineTo(6f, 2f)
            curveTo(4.9f, 2f, 4.01f, 2.9f, 4.01f, 4f)
            lineTo(4f, 20f)
            curveTo(4f, 21.1f, 4.89f, 22f, 5.99f, 22f)
            lineTo(18f, 22f)
            curveTo(19.1f, 22f, 20f, 21.1f, 20f, 20f)
            lineTo(20f, 8f)
            lineTo(14f, 2f)
            close()
            moveTo(16f, 18f)
            lineTo(8f, 18f)
            lineTo(8f, 16f)
            lineTo(16f, 16f)
            lineTo(16f, 18f)
            close()
            moveTo(16f, 14f)
            lineTo(8f, 14f)
            lineTo(8f, 12f)
            lineTo(16f, 12f)
            lineTo(16f, 14f)
            close()
            moveTo(13f, 9f)
            lineTo(13f, 3.5f)
            lineTo(18.5f, 9f)
            lineTo(13f, 9f)
            close()
        }
    }.build()

    val Subvolume: ImageVector = ImageVector.Builder(
        name = "Subvolume",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(11.99f, 18.54f)
            lineTo(4.62f, 12.81f)
            lineTo(3f, 14.07f)
            lineTo(12f, 21.07f)
            lineTo(21f, 14.07f)
            lineTo(19.37f, 12.8f)
            lineTo(11.99f, 18.54f)
            close()
            moveTo(12f, 16f)
            lineTo(19.36f, 10.27f)
            lineTo(21f, 9.07f)
            lineTo(12f, 2.07f)
            lineTo(3f, 9.07f)
            lineTo(4.63f, 10.34f)
            lineTo(12f, 16f)
            close()
        }
    }.build()

    val Symlink: ImageVector = ImageVector.Builder(
        name = "Symlink",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(3.9f, 12f)
            curveTo(3.9f, 10.29f, 5.29f, 8.9f, 7f, 8.9f)
            lineTo(11f, 8.9f)
            lineTo(11f, 7f)
            lineTo(7f, 7f)
            curveTo(4.24f, 7f, 2f, 9.24f, 2f, 12f)
            curveTo(2f, 14.76f, 4.24f, 17f, 7f, 17f)
            lineTo(11f, 17f)
            lineTo(11f, 15.1f)
            lineTo(7f, 15.1f)
            curveTo(5.29f, 15.1f, 3.9f, 13.71f, 3.9f, 12f)
            close()
            moveTo(8f, 13f)
            lineTo(16f, 13f)
            lineTo(16f, 11f)
            lineTo(8f, 11f)
            lineTo(8f, 13f)
            close()
            moveTo(17f, 7f)
            lineTo(13f, 7f)
            lineTo(13f, 8.9f)
            lineTo(17f, 8.9f)
            curveTo(18.71f, 8.9f, 20.1f, 10.29f, 20.1f, 12f)
            curveTo(20.1f, 13.71f, 18.71f, 15.1f, 17f, 15.1f)
            lineTo(13f, 15.1f)
            lineTo(13f, 17f)
            lineTo(17f, 17f)
            curveTo(19.76f, 17f, 22f, 14.76f, 22f, 12f)
            curveTo(22f, 9.24f, 19.76f, 7f, 17f, 7f)
            close()
        }
    }.build()

    val Upload: ImageVector = ImageVector.Builder(
        name = "Upload",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(9f, 16f)
            lineTo(15f, 16f)
            lineTo(15f, 10f)
            lineTo(19f, 10f)
            lineTo(12f, 3f)
            lineTo(5f, 10f)
            lineTo(9f, 10f)
            close()
            moveTo(5f, 18f)
            lineTo(19f, 18f)
            lineTo(19f, 20f)
            lineTo(5f, 20f)
            close()
        }
    }.build()

    val Download: ImageVector = ImageVector.Builder(
        name = "Download",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(19f, 9f)
            lineTo(15f, 9f)
            lineTo(15f, 3f)
            lineTo(9f, 3f)
            lineTo(9f, 9f)
            lineTo(5f, 9f)
            lineTo(12f, 16f)
            close()
            moveTo(5f, 18f)
            lineTo(19f, 18f)
            lineTo(19f, 20f)
            lineTo(5f, 20f)
            close()
        }
    }.build()

    val CreateFolder: ImageVector = ImageVector.Builder(
        name = "CreateFolder",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(20f, 6f)
            lineTo(12f, 6f)
            lineTo(10f, 4f)
            lineTo(4f, 4f)
            curveTo(2.89f, 4f, 2.01f, 4.89f, 2.01f, 6f)
            lineTo(2f, 18f)
            curveTo(2f, 19.11f, 2.89f, 20f, 4f, 20f)
            lineTo(20f, 20f)
            curveTo(21.11f, 20f, 22f, 19.11f, 22f, 18f)
            lineTo(22f, 8f)
            curveTo(22f, 6.89f, 21.11f, 6f, 20f, 6f)
            close()
            moveTo(19f, 14f)
            lineTo(16f, 14f)
            lineTo(16f, 17f)
            lineTo(14f, 17f)
            lineTo(14f, 14f)
            lineTo(11f, 14f)
            lineTo(11f, 12f)
            lineTo(14f, 12f)
            lineTo(14f, 9f)
            lineTo(16f, 9f)
            lineTo(16f, 12f)
            lineTo(19f, 12f)
            close()
        }
    }.build()

    val Sha256: ImageVector = ImageVector.Builder(
        name = "Sha256",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.White)) {
            moveTo(12f, 1f)
            lineTo(3f, 5f)
            lineTo(3f, 11f)
            curveTo(3f, 16.55f, 6.84f, 21.74f, 12f, 23f)
            curveTo(17.16f, 21.74f, 21f, 16.55f, 21f, 11f)
            lineTo(21f, 5f)
            lineTo(12f, 1f)
            close()
            moveTo(12f, 11.99f)
            lineTo(19f, 11.99f)
            curveTo(18.47f, 16.11f, 15.72f, 19.78f, 12f, 20.93f)
            lineTo(12f, 12f)
            lineTo(5f, 12f)
            lineTo(5f, 6.3f)
            lineTo(12f, 3.19f)
            lineTo(12f, 11.99f)
            close()
        }
    }.build()
}

/**
 * A directory entry paired with the full path it's reached at, along with
 * the metadata that came back with it from `listDir`.
 */
data class BrowserItem(
    val entry: Entry,
    val fullPath: String,
    val sizeBytes: Long = entry.size,
    val mtime: Long = entry.mtime,
) {
    val name: String get() = entry.name
    val type: String get() = entry.type
    val isDir: Boolean get() = entry.isDir
    val isSubvolume: Boolean get() = entry.isSubvolume
}

/**
 * What [BrowserScreen] sorts a directory listing by. Directories always
 * group before files regardless of field — this only orders within that
 * grouping, matching the convention every mainstream file manager uses.
 */
enum class SortField(val label: String) {
    NAME("Name"),
    SIZE("Size"),
    DATE("Date"),
}

data class ChecksumResult(
    val fileName: String,
    val sha256: String,
    val bytes: Long,
    val elapsedMs: Long,
    val bytesPerSec: Long,
)

/**
 * Checks if the given path is located in a read-only Btrfs subvolume or outside root tree.
 */
fun isPathInsideReadOnlySubvolume(path: String, fsType: String, subvolumes: List<dev.luksandroid.SubvolumeInfo>): Pair<Boolean, String?> {
    if (fsType != "btrfs") return Pair(false, null)
    val normPath = "/" + path.trim('/').let { if (it.isEmpty()) "" else it }

    for (subvol in subvolumes) {
        val subPath = "/" + subvol.path.trim('/').let { if (it.isEmpty()) "" else it }
        if (subPath != "/" && (normPath == subPath || normPath.startsWith("$subPath/"))) {
            return if (subvol.readOnly) {
                Pair(true, "Subvolume '${subvol.name}' is read-only")
            } else if (subvol.id != 5L) {
                Pair(true, "Subvolume '${subvol.name}' (ID ${subvol.id}) is outside root tree (read-only)")
            } else {
                Pair(false, null)
            }
        }
    }
    return Pair(false, null)
}

/**
 * Whether renaming an item named [currentName] to [newName] would collide with
 * another entry already present in the same directory, given that directory's
 * current listing [existingNames].
 *
 * This exists because the native rename implementations use POSIX rename
 * semantics: renaming onto an existing destination does not fail, it silently
 * replaces the destination and frees its data — see
 * `core/src/fs/btrfs/write/txn/rename.rs` (frees the colliding file's extents)
 * and `core/src/fs/ext4/file.rs` (unlinks and frees it). Neither native call
 * warns, confirms, or offers an undo, so a typo in the rename dialog (renaming
 * `draft.txt` to `notes.txt` when `notes.txt` already exists) would silently
 * destroy `notes.txt`. This check runs before the native call so the UI can
 * refuse instead.
 *
 * Comparison is exact and case-sensitive: ext4 and btrfs are case-sensitive
 * filesystems, so `Notes.txt` and `notes.txt` are genuinely different files
 * and both must be allowed to coexist. Renaming an item to its own current
 * name is a no-op on the native side (see `rename.rs`'s same-path check) and
 * is therefore never reported as a collision here, even though
 * [dev.luksandroid.ui.components.validateNewName] already rejects that case
 * earlier in the dialog flow for other reasons.
 *
 * IMPORTANT: this is a usability guard, not an atomicity guarantee. There is
 * an unavoidable TOCTOU window between this check (reading [existingNames], a
 * snapshot already in memory) and the native rename call that follows it: if
 * something else creates a file named [newName] in that window, the native
 * rename will still silently replace it. This function only catches the
 * common case — a typo caught against what the UI already knows — not
 * concurrent writers.
 */
fun renameTargetExists(existingNames: List<String>, currentName: String, newName: String): Boolean =
    newName != currentName && existingNames.any { it == newName }

/**
 * Main File Browser Screen for Phase L.
 */
@Composable
fun BrowserScreen(
    onNavigateToDevices: () -> Unit = {},
    onLockRequested: () -> Unit = onNavigateToDevices,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val sessionState by LuksSession.state.collectAsState()

    val unlockedState = sessionState as? SessionState.Unlocked
    if (unlockedState == null) {
        Box(
            modifier = modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Default.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(48.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "Drive is not unlocked",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = onNavigateToDevices) {
                    Text("Go to Devices")
                }
            }
        }
        return
    }

    val volume = unlockedState.volume
    val volumeInfo = volume.info
    val canWriteVolume = volume.canWrite

    var currentPath by remember { mutableStateOf("/") }
    var entries by remember { mutableStateOf<List<Entry>>(unlockedState.entries) }
    var statFsInfo by remember { mutableStateOf<StatFsInfo?>(null) }
    var isRefreshing by remember { mutableStateOf(false) }
    var isSlackLimitReached by remember { mutableStateOf(false) }
    var sortField by remember { mutableStateOf(SortField.NAME) }
    var sortAscending by remember { mutableStateOf(true) }

    // Dialog state
    var showNewFolderDialog by remember { mutableStateOf(false) }
    var isCreatingFolder by remember { mutableStateOf(false) }
    var newFolderError by remember { mutableStateOf<String?>(null) }

    var renamingItem by remember { mutableStateOf<BrowserItem?>(null) }
    var isRenaming by remember { mutableStateOf(false) }
    var renameError by remember { mutableStateOf<String?>(null) }

    var deletingItem by remember { mutableStateOf<BrowserItem?>(null) }
    var isDeleting by remember { mutableStateOf(false) }
    var deleteError by remember { mutableStateOf<String?>(null) }

    // Multi-select state. A set of full paths rather than indices, so it
    // survives a re-sort or a background refresh of the same directory
    // without pointing at the wrong row.
    var selectedPaths by remember { mutableStateOf<Set<String>>(emptySet()) }
    var confirmingDeleteSelection by remember { mutableStateOf(false) }
    var isDeletingSelection by remember { mutableStateOf(false) }
    var deleteSelectionError by remember { mutableStateOf<String?>(null) }

    var activeChecksum by remember { mutableStateOf<ChecksumResult?>(null) }
    var pendingExportItem by remember { mutableStateOf<BrowserItem?>(null) }

    // Which TransferManager transfer (if any) this screen most recently started.
    // The transfer itself lives and runs in TransferManager regardless of this
    // screen's lifecycle; this id is only used to pick which one to show inline.
    var activeTransferId by remember { mutableStateOf<Long?>(null) }
    val allTransfers by TransferManager.transfers.collectAsState()
    val activeTransferItem = activeTransferId?.let { id -> allTransfers.find { it.id == id } }

    val snackbarHostState = remember { SnackbarHostState() }

    // Check Subvolume Refusal State
    val (isSubvolumeReadOnly, subvolumeReason) = remember(currentPath, volumeInfo) {
        isPathInsideReadOnlySubvolume(currentPath, volumeInfo.fsType, volumeInfo.subvolumes)
    }

    val isWriteDisabled = !canWriteVolume || isSubvolumeReadOnly || isSlackLimitReached

    fun joinPath(dir: String, name: String): String =
        if (dir == "/" || dir.isEmpty()) "/$name" else "$dir/$name"

    // Fetch statFs
    fun refreshStatFs() {
        if (!scope.isActive) return
        scope.launch {
            try {
                statFsInfo = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.statFs() }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "statfs")
            }
        }
    }

    // Refresh directory entries & statFs
    fun loadDirectory(path: String) {
        if (!scope.isActive) return
        isRefreshing = true
        scope.launch {
            try {
                val list = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.listDir(path) }
                }
                entries = list
                currentPath = path
                isSlackLimitReached = false
                selectedPaths = emptySet()
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
                Trace.err(e.code, "list_dir")
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar("Cannot open folder: [${e.code}] ${e.message}")
                    }
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "list_dir")
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar("Cannot open folder: ${e.message}")
                    }
                }
            } finally {
                isRefreshing = false
                if (scope.isActive) {
                    refreshStatFs()
                }
            }
        }
    }

    LaunchedEffect(unlockedState.partition, currentPath) {
        refreshStatFs()
        if (entries.isEmpty() && currentPath == "/") {
            loadDirectory("/")
        }
    }

    // Watches whichever transfer this screen most recently started and reacts
    // once it reaches a terminal state. The transfer itself is NOT owned by
    // this effect: it runs on TransferManager's own scope (see
    // TransferManager.startExport/startImport/startHash) and keeps going even
    // if this Composable is disposed before this effect observes completion.
    LaunchedEffect(activeTransferId) {
        val id = activeTransferId ?: return@LaunchedEffect
        val terminal = TransferManager.transfers
            .map { list -> list.find { it.id == id } }
            .first { it == null || (it.state != TransferState.RUNNING && it.state != TransferState.QUEUED) }

        when (terminal?.state) {
            TransferState.COMPLETED -> {
                when (terminal.type) {
                    TransferType.IMPORT -> {
                        snackbarHostState.showSnackbar("Imported \"${terminal.name}\" successfully")
                        loadDirectory(currentPath)
                    }
                    TransferType.EXPORT -> {
                        snackbarHostState.showSnackbar("Exported \"${terminal.name}\" successfully")
                    }
                    TransferType.HASH -> {} // ChecksumResultDialog is driven by startHash's onResult callback.
                }
            }
            TransferState.FAILED -> {
                val code = terminal.errorCode
                if (terminal.type == TransferType.IMPORT &&
                    (code == LuksException.NO_SPACE || code == LuksException.ITEM_TOO_LARGE || code == LuksException.UNSUPPORTED)
                ) {
                    isSlackLimitReached = true
                }
                val label = when (terminal.type) {
                    TransferType.IMPORT -> "Import"
                    TransferType.EXPORT -> "Export"
                    TransferType.HASH -> "Checksum calculation"
                }
                snackbarHostState.showSnackbar("$label failed: ${terminal.error ?: "unknown error"}")
            }
            TransferState.CANCELLED -> {
                snackbarHostState.showSnackbar("Transfer cancelled")
            }
            else -> {}
        }
        if (activeTransferId == id) activeTransferId = null
    }

    // SAF Exporter
    val exporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val source = pendingExportItem
        pendingExportItem = null
        if (uri == null || source == null) return@rememberLauncherForActivityResult

        // Routed through TransferManager (N.2): the actual copy runs on
        // TransferManager's own scope, not this screen's, and is visible on
        // the Transfers screen for the whole time it runs.
        activeTransferId = TransferManager.startExport(context, source.fullPath, uri)
    }

    // SAF Importer
    val importer = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult

        for (uri in uris) {
            activeTransferId = TransferManager.startImport(context, currentPath, uri)
        }
    }

    // SHA-256 Checksum Calculation
    fun calculateChecksum(item: BrowserItem) {
        activeTransferId = TransferManager.startHash(item.fullPath) { result ->
            result.onSuccess { digest ->
                activeChecksum = ChecksumResult(
                    fileName = item.name,
                    sha256 = digest.sha256,
                    bytes = digest.bytes,
                    elapsedMs = digest.elapsedMs,
                    bytesPerSec = digest.bytesPerSec,
                )
            }
        }
    }

    // Create Directory
    fun handleCreateDirectory(name: String) {
        if (!scope.isActive) return
        isCreatingFolder = true
        newFolderError = null
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.createDirectory(currentPath, name) }
                }
                showNewFolderDialog = false
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar("Folder \"$name\" created")
                    }
                }
                loadDirectory(currentPath)
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
                Trace.err(e.code, "create_directory")
                if (e.code == LuksException.NO_SPACE || e.code == LuksException.ITEM_TOO_LARGE || e.code == LuksException.UNSUPPORTED) {
                    isSlackLimitReached = true
                }
                newFolderError = "[${e.code}] ${e.message}"
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "create_directory")
                newFolderError = e.message ?: "Failed to create folder"
            } finally {
                isCreatingFolder = false
            }
        }
    }

    // Rename Item
    fun handleRename(item: BrowserItem, newName: String) {
        if (!scope.isActive) return
        // Refuse before the native call ever runs: see renameTargetExists's
        // doc comment for why a silent collision here is a data-loss defect,
        // not a cosmetic one. This reads `entries`, the listing already held
        // in state for `currentPath` — the same directory `item` lives in —
        // so no extra fetch is needed.
        if (renameTargetExists(entries.map { it.name }, item.name, newName)) {
            renameError = "\"$newName\" already exists in this folder"
            return
        }
        isRenaming = true
        renameError = null
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    LuksSession.withLease { v ->
                        v.rename(currentPath, item.name, currentPath, newName)
                    }
                }
                renamingItem = null
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar("Renamed to \"$newName\"")
                    }
                }
                loadDirectory(currentPath)
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
                Trace.err(e.code, "rename")
                renameError = "[${e.code}] ${e.message}"
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "rename")
                renameError = e.message ?: "Failed to rename"
            } finally {
                isRenaming = false
            }
        }
    }

    // Delete Item
    fun handleDelete(item: BrowserItem) {
        if (!scope.isActive) return
        isDeleting = true
        deleteError = null
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.deleteFile(item.fullPath) }
                }
                deletingItem = null
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar("Deleted \"${item.name}\"")
                    }
                }
                loadDirectory(currentPath)
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
                Trace.err(e.code, "delete_file")
                deleteError = "[${e.code}] ${e.message}"
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "delete_file")
                deleteError = e.message ?: "Failed to delete"
            } finally {
                isDeleting = false
            }
        }
    }

    val browserItems = remember(entries, currentPath, sortField, sortAscending) {
        val items = entries.map { entry -> BrowserItem(entry = entry, fullPath = joinPath(currentPath, entry.name)) }
        val byField = when (sortField) {
            SortField.NAME -> compareBy<BrowserItem> { it.name.lowercase() }
            SortField.SIZE -> compareBy<BrowserItem> { it.sizeBytes }
            SortField.DATE -> compareBy<BrowserItem> { it.mtime }
        }
        val directed = if (sortAscending) byField else byField.reversed()
        // Directories always float to the top, independent of the chosen
        // field — sorting a mix of folders and files by size or date is not
        // a comparison any file manager actually shows the user.
        items.sortedWith(compareByDescending<BrowserItem> { it.isDir }.then(directed))
    }

    val selectedItems = remember(browserItems, selectedPaths) {
        browserItems.filter { it.fullPath in selectedPaths }
    }
    // A subvolume can be selected (for a plain "N selected" count), but not
    // batch-deleted — the same rule the per-item menu already enforces.
    val canDeleteSelection = canWriteVolume && !isSubvolumeReadOnly &&
        selectedItems.isNotEmpty() && selectedItems.none { it.isSubvolume }

    // Batch delete. Sequential rather than concurrent: deletes go through the
    // same TransferManager write mutex as everything else on this volume, so
    // parallel calls would just queue behind one another anyway, and doing it
    // one at a time lets a mid-batch failure stop with a clear "N of M"
    // rather than a pile of concurrent errors.
    fun handleDeleteSelected() {
        if (!scope.isActive) return
        val toDelete = selectedItems.filterNot { it.isSubvolume }
        if (toDelete.isEmpty()) return
        isDeletingSelection = true
        deleteSelectionError = null
        scope.launch {
            var deleted = 0
            try {
                withContext(Dispatchers.IO) {
                    for (item in toDelete) {
                        LuksSession.withLease { v -> v.deleteFile(item.fullPath) }
                        deleted++
                    }
                }
                confirmingDeleteSelection = false
                selectedPaths = emptySet()
                if (scope.isActive) {
                    scope.launch {
                        snackbarHostState.showSnackbar(
                            if (deleted == 1) "Deleted 1 item" else "Deleted $deleted items",
                        )
                    }
                }
                loadDirectory(currentPath)
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
                Trace.err(e.code, "delete_file")
                deleteSelectionError = "Deleted $deleted of ${toDelete.size}: [${e.code}] ${e.message}"
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Trace.err(-1, "delete_file")
                deleteSelectionError = "Deleted $deleted of ${toDelete.size}: ${e.message ?: "failed"}"
            } finally {
                isDeletingSelection = false
            }
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (!isWriteDisabled) {
                Column(
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    FloatingActionButton(
                        onClick = {
                            newFolderError = null
                            showNewFolderDialog = true
                        },
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    ) {
                        Icon(
                            imageVector = BrowserIcons.CreateFolder,
                            contentDescription = "New Folder",
                            modifier = Modifier.size(24.dp),
                        )
                    }

                    ExtendedFloatingActionButton(
                        onClick = { importer.launch(arrayOf("*/*")) },
                        icon = {
                            Icon(
                                imageVector = BrowserIcons.Upload,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                            )
                        },
                        text = { Text("Import File") },
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
            }
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            // Header Bar — replaced by a selection action bar while
            // selectedPaths is non-empty.
            if (selectedPaths.isNotEmpty()) {
                SelectionActionBar(
                    selectedCount = selectedPaths.size,
                    totalCount = browserItems.size,
                    canDelete = canDeleteSelection,
                    onSelectAll = { selectedPaths = browserItems.map { it.fullPath }.toSet() },
                    onClear = { selectedPaths = emptySet() },
                    onDelete = {
                        deleteSelectionError = null
                        confirmingDeleteSelection = true
                    },
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = volumeInfo.label.ifBlank { "Encrypted Volume" },
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "${volumeInfo.fsType.uppercase()} · ${formatSize(volumeInfo.sizeBytes)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        SortMenuButton(
                            field = sortField,
                            ascending = sortAscending,
                            onChange = { field, ascending ->
                                sortField = field
                                sortAscending = ascending
                            },
                        )

                        IconButton(
                            onClick = { loadDirectory(currentPath) },
                            enabled = !isRefreshing,
                        ) {
                            if (isRefreshing) {
                                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(
                                    imageVector = Icons.Default.Refresh,
                                    contentDescription = "Refresh Directory",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }

                        OutlinedButton(
                            onClick = {
                                if (scope.isActive) {
                                    scope.launch {
                                        try {
                                            onLockRequested()
                                            LuksSession.lock()
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            if (e is CancellationException) throw e
                                            Trace.err(-1, "lock")
                                        }
                                    }
                                }
                            },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Lock")
                        }
                    }
                }
            }

            // Capacity Bar
            CapacityBar(
                statFsInfo = statFsInfo,
                fsType = volumeInfo.fsType,
                isReadOnly = isSubvolumeReadOnly || !canWriteVolume,
            )

            // Refusal Warning Banners
            if (isSubvolumeReadOnly) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Read-only Location",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(20.dp),
                        )
                        Column {
                            Text(
                                text = "Subvolume: Read-only location",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            Text(
                                text = subvolumeReason ?: "Writes outside the root filesystem tree are not supported.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.9f),
                            )
                        }
                    }
                }
            } else if (isSlackLimitReached) {
                Surface(
                    color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.7f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Directory Slack Limit",
                            tint = MaterialTheme.colorScheme.tertiary,
                            modifier = Modifier.size(20.dp),
                        )
                        Column {
                            Text(
                                text = "Directory Slack Limit Reached",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                            )
                            Text(
                                text = "This folder cannot take more entries due to directory block limit.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.9f),
                            )
                        }
                    }
                }
            } else if (!canWriteVolume) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(18.dp),
                        )
                        Text(
                            text = "Volume is mounted read-only. Write operations are disabled.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            // Breadcrumbs Navigation Bar
            BreadcrumbBar(
                currentPath = currentPath,
                onNavigate = { loadDirectory(it) },
                enabled = !isRefreshing,
            )

            // Active Transfer Progress Banner. Reads live from TransferManager's
            // flow (not local composable state) so it reflects the same
            // process-wide truth as the Transfers screen.
            activeTransferItem?.takeIf { it.state == TransferState.RUNNING || it.state == TransferState.QUEUED }?.let { transfer ->
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        val statusText = if (transfer.state == TransferState.QUEUED) {
                            "(Queued)"
                        } else {
                            val pct = if (transfer.totalBytes > 0) {
                                (transfer.transferredBytes * 100 / transfer.totalBytes).toInt()
                            } else 0
                            val speedStr = if (transfer.speedBytesPerSec > 0) {
                                " · %.1f MiB/s".format(transfer.speedBytesPerSec.toDouble() / (1L shl 20))
                            } else ""
                            "$pct%$speedStr"
                        }
                        val operation = when (transfer.type) {
                            TransferType.IMPORT -> "Importing"
                            TransferType.EXPORT -> "Exporting"
                            TransferType.HASH -> "Hashing"
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = "$operation ${transfer.name}…",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f),
                            )
                            Text(
                                text = statusText,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                            )
                        }

                        LinearProgressIndicator(
                            progress = {
                                if (transfer.state != TransferState.QUEUED && transfer.totalBytes > 0) {
                                    (transfer.transferredBytes.toFloat() / transfer.totalBytes.toFloat()).coerceIn(0f, 1f)
                                } else 0f
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(4.dp)
                                .clip(RoundedCornerShape(2.dp)),
                        )
                    }
                }
            }

            // File Listing / Empty Illustration
            if (browserItems.isEmpty() && !isRefreshing) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Surface(
                            modifier = Modifier.size(72.dp),
                            shape = CircleShape,
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = BrowserIcons.Folder,
                                    contentDescription = null,
                                    modifier = Modifier.size(36.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                                )
                            }
                        }
                        Text(
                            text = "This folder is empty",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (!isWriteDisabled) {
                            Text(
                                text = "Use the buttons below to create a folder or import files.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentPadding = PaddingValues(vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    items(browserItems, key = { it.fullPath }) { item ->
                        BrowserItemRow(
                            item = item,
                            canWrite = canWriteVolume && !isSubvolumeReadOnly,
                            onOpen = {
                                if (item.isDir) {
                                    loadDirectory(item.fullPath)
                                } else {
                                    pendingExportItem = item
                                    exporter.launch(item.name)
                                }
                            },
                            onExport = {
                                pendingExportItem = item
                                exporter.launch(item.name)
                            },
                            onRename = {
                                renameError = null
                                renamingItem = item
                            },
                            onDelete = {
                                deleteError = null
                                deletingItem = item
                            },
                            onChecksum = {
                                calculateChecksum(item)
                            },
                            selectionActive = selectedPaths.isNotEmpty(),
                            isSelected = item.fullPath in selectedPaths,
                            onToggleSelect = {
                                selectedPaths = if (item.fullPath in selectedPaths) {
                                    selectedPaths - item.fullPath
                                } else {
                                    selectedPaths + item.fullPath
                                }
                            },
                        )
                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 8.dp),
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.2f),
                        )
                    }
                }
            }
        }
    }

    // Dialogs
    if (showNewFolderDialog) {
        NewFolderDialog(
            onDismissRequest = { showNewFolderDialog = false },
            onConfirm = { handleCreateDirectory(it) },
            isCreating = isCreatingFolder,
            errorMessage = newFolderError,
        )
    }

    renamingItem?.let { item ->
        RenameDialog(
            currentName = item.name,
            isDir = item.isDir,
            onDismissRequest = { renamingItem = null },
            onConfirm = { handleRename(item, it) },
            isRenaming = isRenaming,
            errorMessage = renameError,
        )
    }

    deletingItem?.let { item ->
        DeleteConfirmDialog(
            itemName = item.name,
            isDir = item.isDir,
            onDismissRequest = { deletingItem = null },
            onConfirm = { handleDelete(item) },
            isDeleting = isDeleting,
            errorMessage = deleteError,
        )
    }

    if (confirmingDeleteSelection) {
        DeleteConfirmDialog(
            itemName = "",
            isDir = selectedItems.any { it.isDir },
            count = selectedItems.size,
            onDismissRequest = { if (!isDeletingSelection) confirmingDeleteSelection = false },
            onConfirm = { handleDeleteSelected() },
            isDeleting = isDeletingSelection,
            errorMessage = deleteSelectionError,
        )
    }

    activeChecksum?.let { result ->
        ChecksumResultDialog(
            result = result,
            onDismissRequest = { activeChecksum = null },
        )
    }
}

/**
 * Replaces the normal header while one or more items are selected.
 */
/**
 * Trigger + menu for choosing [SortField] and direction. Text-only by
 * design: the extended Material icon pack (which is where a "sort" glyph
 * would come from) is not a dependency of this app, and this app owns the
 * data being sorted outright — no server round trip, no plugin surface,
 * just a comparator over a list already in memory.
 */
@Composable
fun SortMenuButton(
    field: SortField,
    ascending: Boolean,
    onChange: (SortField, Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    val arrow = if (ascending) "↑" else "↓"

    Box(modifier = modifier) {
        TextButton(onClick = { expanded = true }) {
            Text("${field.label} $arrow")
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            for (candidate in SortField.entries) {
                val isCurrent = candidate == field
                DropdownMenuItem(
                    text = {
                        Text(
                            "${candidate.label} ${if (isCurrent && !ascending) "↓" else "↑"}",
                            fontWeight = if (isCurrent) FontWeight.Bold else FontWeight.Normal,
                        )
                    },
                    leadingIcon = if (isCurrent) {
                        { Icon(imageVector = Icons.Default.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    onClick = {
                        expanded = false
                        // Tapping the already-active field flips direction —
                        // tapping a different one switches to it ascending,
                        // which is the order someone reaches for a field the
                        // first time.
                        onChange(candidate, if (isCurrent) !ascending else true)
                    },
                )
            }
        }
    }
}

@Composable
fun SelectionActionBar(
    selectedCount: Int,
    totalCount: Int,
    canDelete: Boolean,
    onSelectAll: () -> Unit,
    onClear: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            IconButton(onClick = onClear) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Clear selection",
                )
            }
            Text(
                text = "$selectedCount selected",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            TextButton(
                onClick = onSelectAll,
                enabled = selectedCount < totalCount,
            ) {
                Text("Select all")
            }
            IconButton(
                onClick = onDelete,
                enabled = canDelete,
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = "Delete selected",
                    tint = if (canDelete) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    },
                )
            }
        }
    }
}

/**
 * Row representing one directory entry in the browser.
 */
@Composable
fun BrowserItemRow(
    item: BrowserItem,
    canWrite: Boolean,
    onOpen: () -> Unit,
    onExport: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    onChecksum: () -> Unit,
    selectionActive: Boolean = false,
    isSelected: Boolean = false,
    onToggleSelect: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    var menuExpanded by remember { mutableStateOf(false) }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = { if (selectionActive) onToggleSelect() else onOpen() },
                onLongClick = onToggleSelect,
            )
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Type Icon, replaced by a checkbox once selection mode is active.
        if (selectionActive) {
            Checkbox(checked = isSelected, onCheckedChange = { onToggleSelect() })
        } else {
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = when {
                    item.isSubvolume -> MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
                    item.isDir -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)
                    item.type == "symlink" -> MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f)
                    else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                },
                modifier = Modifier.size(40.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = when {
                            item.isSubvolume -> BrowserIcons.Subvolume
                            item.isDir -> BrowserIcons.Folder
                            item.type == "symlink" -> BrowserIcons.Symlink
                            else -> BrowserIcons.File
                        },
                        contentDescription = item.type,
                        tint = when {
                            item.isSubvolume -> MaterialTheme.colorScheme.tertiary
                            item.isDir -> MaterialTheme.colorScheme.primary
                            item.type == "symlink" -> MaterialTheme.colorScheme.secondary
                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.size(22.dp),
                    )
                }
            }
        }

        // Title and Subtitle
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = item.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )

                if (item.isSubvolume) {
                    Surface(
                        color = MaterialTheme.colorScheme.tertiaryContainer,
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(
                            text = "SUBVOL",
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }

            // Subtitle: Formatted size + formatted modification timestamp
            val subtitle = buildString {
                if (item.isDir) {
                    append("Folder")
                } else {
                    append(formatSize(item.sizeBytes))
                }

                if (item.mtime > 0L) {
                    val formattedTime = formatTimestamp(item.mtime)
                    if (formattedTime.isNotEmpty()) {
                        append(" · $formattedTime")
                    }
                }
            }

            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Action Menu (3-dots) — hidden during selection; batch actions live
        // in the SelectionActionBar instead.
        if (!selectionActive) Box {
            IconButton(onClick = { menuExpanded = true }) {
                Icon(
                    imageVector = Icons.Default.MoreVert,
                    contentDescription = "Actions",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            DropdownMenu(
                expanded = menuExpanded,
                onDismissRequest = { menuExpanded = false },
            ) {
                if (!item.isDir) {
                    DropdownMenuItem(
                        text = { Text("Export to phone") },
                        leadingIcon = {
                            Icon(
                                imageVector = BrowserIcons.Download,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                            )
                        },
                        onClick = {
                            menuExpanded = false
                            onExport()
                        },
                    )

                    DropdownMenuItem(
                        text = { Text("SHA-256 Checksum") },
                        leadingIcon = {
                            Icon(
                                imageVector = BrowserIcons.Sha256,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                            )
                        },
                        onClick = {
                            menuExpanded = false
                            onChecksum()
                        },
                    )
                }

                DropdownMenuItem(
                    text = { Text("Rename") },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                    enabled = canWrite && !item.isSubvolume,
                    onClick = {
                        menuExpanded = false
                        onRename()
                    },
                )

                DropdownMenuItem(
                    text = {
                        Text(
                            text = "Delete",
                            color = if (canWrite && !item.isSubvolume) MaterialTheme.colorScheme.error else Color.Unspecified,
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = if (canWrite && !item.isSubvolume) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
                        )
                    },
                    enabled = canWrite && !item.isSubvolume,
                    onClick = {
                        menuExpanded = false
                        onDelete()
                    },
                )
            }
        }
    }
}

/**
 * Dialog displaying calculated SHA-256 Checksum and throughput details.
 */
@Suppress("DEPRECATION")
@Composable
fun ChecksumResultDialog(
    result: ChecksumResult,
    onDismissRequest: () -> Unit,
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current
    val mbPerSec = result.bytesPerSec.toDouble() / (1L shl 20)

    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = BrowserIcons.Sha256,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text("SHA-256 Checksum")
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = result.fileName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )

                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = result.sha256,
                        modifier = Modifier.padding(10.dp),
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 16.sp,
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                Text(
                    text = "Verified ${formatSize(result.bytes)} in ${result.elapsedMs} ms (%.1f MiB/s)".format(mbPerSec),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    clipboardManager.setText(AnnotatedString(result.sha256))
                    Toast.makeText(context, "Checksum copied to clipboard", Toast.LENGTH_SHORT).show()
                },
            ) {
                Text("Copy Hash")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismissRequest) {
                Text("Close")
            }
        },
    )
}
