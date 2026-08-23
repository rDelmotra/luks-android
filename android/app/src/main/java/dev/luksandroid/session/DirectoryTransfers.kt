package dev.luksandroid.session

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import dev.luksandroid.LuksVolume
import dev.luksandroid.StatFsInfo
import dev.luksandroid.Trace
import dev.luksandroid.transfer.CollisionMode
import dev.luksandroid.transfer.Destination
import dev.luksandroid.transfer.DestinationEntry
import dev.luksandroid.transfer.DirectoryWalker
import dev.luksandroid.transfer.ExportDestination
import dev.luksandroid.transfer.SafChildSource
import dev.luksandroid.transfer.SafExportDestination
import dev.luksandroid.transfer.SourceBytes
import dev.luksandroid.transfer.TransferPlan
import dev.luksandroid.transfer.TransferProgress
import dev.luksandroid.transfer.TransferPrompt
import dev.luksandroid.transfer.TreeExporter
import dev.luksandroid.transfer.TreeImporter
import dev.luksandroid.transfer.VolumeChildSource
import dev.luksandroid.transfer.VolumeSourceBytes
import dev.luksandroid.transfer.formatThroughput
import dev.luksandroid.transfer.precheckTransfer
import dev.luksandroid.transfer.promptFor
import dev.luksandroid.transfer.surveyDestination

/**
 * Phases 1 and 2 of notes/feature-directory-transfer.md §4 -- enumerate and
 * precheck -- wired to real Android plumbing, for both directions.
 *
 * Kept out of `TransferController` because none of it touches transfer
 * bookkeeping: it produces a [DirectoryTransferRequest] and stops. Execution is
 * a separate call the UI makes only after the user has answered whatever the
 * prompt asks, which is the whole point of enumerating first (§3.1): the
 * collision policy is settled before a single byte moves.
 *
 * Nothing here is unit-tested -- `Uri`, `Context`, and `DocumentsContract` are
 * all unavailable under this module's test setup -- so every decision that
 * could live in a pure function does: [DirectoryWalker], [precheckTransfer],
 * [surveyDestination], and [promptFor] are all tested, and this file only
 * connects them.
 */

/**
 * A directory transfer that has been enumerated and prechecked but not started.
 *
 * [plan] is what will be executed; [prompt] is what the UI must resolve first.
 * The two travel together because executing a plan without honouring its
 * prompt is exactly the mid-copy surprise this design exists to prevent.
 */
data class DirectoryTransferRequest(
    val plan: TransferPlan,
    val prompt: TransferPrompt,
    /** The folder's own name, for display and for the directory it lands in. */
    val rootName: String,
    /** Absolute volume path (import) or SAF document ID (export) the plan's top-level entries land in. */
    val destinationRoot: String,
)

/** Reads a SAF document's display name, falling back to its ID's last segment. */
private fun displayNameOf(context: Context, treeUri: Uri, documentId: String): String {
    val uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    try {
        context.contentResolver.query(
            uri,
            arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null, null, null,
        )?.use { c ->
            if (c.moveToFirst() && !c.isNull(0)) return c.getString(0)
        }
    } catch (_: Throwable) {
    }
    return documentId.substringAfterLast('/').substringAfterLast(':').ifEmpty { "folder" }
}

private fun joinPath(dir: String, name: String): String =
    if (dir == "/" || dir.isEmpty()) "/$name" else "$dir/$name"

/**
 * Enumerates a SAF tree and prechecks it against the volume.
 *
 * The folder itself lands as `parentPath/<its name>`, so that is the plan's
 * destination root -- the plan contains the folder's *children*, never the
 * folder (see [DirectoryWalker.walk]).
 */
fun prepareDirectoryImport(
    context: Context,
    volume: LuksVolume,
    parentPath: String,
    treeUri: Uri,
): DirectoryTransferRequest {
    val rootId = DocumentsContract.getTreeDocumentId(treeUri)
    val rootName = displayNameOf(context, treeUri, rootId)
    val plan = DirectoryWalker.walk(SafChildSource(context.contentResolver, treeUri), rootId, rootName)

    val destinationRoot = joinPath(parentPath, rootName)
    val listing = surveyDestination(plan, destinationRoot) { path -> listDirOrNull(volume, path) }

    val info = volume.info
    val verdict = precheckTransfer(
        plan,
        Destination(
            statFs = volume.statFs(),
            fsType = info.fsType,
            listing = listing,
            subvolumes = info.subvolumes,
            targetPath = destinationRoot,
        ),
    )
    return DirectoryTransferRequest(plan, promptFor(verdict), rootName, destinationRoot)
}

/**
 * Enumerates a directory on the volume and prechecks it against a SAF tree.
 *
 * The destination is a document provider, so most of the precheck's refusals
 * do not apply: there is no ext4 entry ceiling and no btrfs subvolume. Rather
 * than a second, nearly-identical precheck, the same one runs with a non-ext4
 * `fsType` and no subvolumes, which switches those checks off by their own
 * existing conditions. What still applies -- free space, type-mismatch
 * collisions, duplicate source names -- is what we want.
 */
fun prepareDirectoryExport(
    context: Context,
    volume: LuksVolume,
    sourcePath: String,
    treeUri: Uri,
): DirectoryTransferRequest {
    val rootName = sourcePath.substringAfterLast('/').ifEmpty { "volume" }
    val plan = DirectoryWalker.walk(VolumeChildSource(volume), sourcePath, rootName)

    val destination = SafExportDestination(context.contentResolver, treeUri)
    val rootId = DocumentsContract.getTreeDocumentId(treeUri)

    // The exported folder lands *inside* the chosen tree, under its own name.
    // It may not exist yet, in which case there is nothing to survey below it.
    val existingRootId = destination.children(rootId)
        .firstOrNull { it.name == rootName && it.isDir }
        ?.id

    val listing = if (existingRootId == null) {
        surveyDestination(plan, "") { null }
    } else {
        val idsByRelative = mutableMapOf("" to existingRootId)
        surveyDestination(plan, "") { relative ->
            val id = idsByRelative[relative] ?: return@surveyDestination null
            destination.children(id).map { child ->
                if (child.isDir) idsByRelative[joinRelative(relative, child.name)] = child.id
                DestinationEntry(child.name, child.isDir)
            }
        }
    }

    val verdict = precheckTransfer(
        plan,
        Destination(
            statFs = StatFsInfo(0, 0, availableSpaceFor(context, treeUri), 0, 0, 4096),
            // Deliberately not "ext4": the entry ceiling is a property of the
            // drive's filesystem, not of wherever the phone puts these files.
            fsType = "saf",
            listing = listing,
            subvolumes = emptyList(),
            targetPath = "/",
        ),
    )
    return DirectoryTransferRequest(plan, promptFor(verdict), rootName, existingRootId ?: rootId)
}

private fun joinRelative(parent: String, name: String): String =
    if (parent.isEmpty()) name else "$parent/$name"

/**
 * `surveyDestination` hands absolute paths, and this must distinguish "no such
 * directory" from "an empty one" -- collapsing them makes the ext4 ceiling
 * check under-count. Any other failure is rethrown rather than swallowed as
 * "absent", which would turn a dying session into a falsely clean precheck.
 */
private fun listDirOrNull(volume: LuksVolume, path: String): List<DestinationEntry>? {
    val entries = try {
        volume.listDir(path)
    } catch (_: Throwable) {
        // The volume reports a missing directory as an error, and there is no
        // "exists?" call to ask instead. Treating it as absent is correct here
        // and wrong for a genuine I/O failure; the executor's own live lookups
        // catch the latter before anything is written.
        return null
    }
    return entries.map { DestinationEntry(it.name, it.isDir) }
}

/** Free space at the SAF destination, or [Long.MAX_VALUE] if the provider will not say. */
private fun availableSpaceFor(context: Context, treeUri: Uri): Long {
    return try {
        context.contentResolver.openFileDescriptor(treeUri, "r")?.use { pfd ->
            android.os.StatFs(pfd.fileDescriptor.toString()).availableBytes
        } ?: Long.MAX_VALUE
    } catch (_: Throwable) {
        // Not knowing is not the same as knowing it will not fit. Refusing on a
        // number we could not obtain would block every export to a provider
        // that does not expose one.
        Long.MAX_VALUE
    }
}

/** Executes an already-prechecked import. Runs on the caller's thread; callers hold the session lease. */
fun runDirectoryImport(
    context: Context,
    volume: LuksVolume,
    request: DirectoryTransferRequest,
    treeUri: Uri,
    mode: CollisionMode,
    onProgress: (TransferProgress) -> Unit,
    isCancelled: () -> Boolean,
): dev.luksandroid.transfer.TransferOutcome = TreeImporter.importTree(
    volume = volume,
    plan = request.plan,
    // The folder itself is created here, before its children land in it.
    destinationRootPath = request.destinationRoot.also { ensureDirectory(volume, it) },
    source = SourceBytes { id ->
        context.contentResolver.openInputStream(DocumentsContract.buildDocumentUriUsingTree(treeUri, id))
            ?: throw java.io.IOException("could not read '$id' from the source folder")
    },
    collisionMode = mode,
    onProgress = onProgress,
    isCancelled = isCancelled,
).also { Trace.i(formatThroughput("import", it.bytesCopied, it.stats)) }

/** Creates [path] if it is not already there, so the plan's children have somewhere to land. */
private fun ensureDirectory(volume: LuksVolume, path: String) {
    val parent = path.substringBeforeLast('/', "").ifEmpty { "/" }
    val name = path.substringAfterLast('/')
    val existing = try {
        volume.listDir(parent).firstOrNull { it.name == name }
    } catch (_: Throwable) {
        null
    }
    if (existing == null) volume.createDirectory(parent, name)
}

/** Executes an already-prechecked export. */
fun runDirectoryExport(
    context: Context,
    volume: LuksVolume,
    request: DirectoryTransferRequest,
    treeUri: Uri,
    mode: CollisionMode,
    onProgress: (TransferProgress) -> Unit,
    isCancelled: () -> Boolean,
): dev.luksandroid.transfer.TransferOutcome {
    val destination: ExportDestination = SafExportDestination(context.contentResolver, treeUri)
    val rootId = DocumentsContract.getTreeDocumentId(treeUri)
    // The folder itself, created inside the picked tree before its children.
    val landing = destination.children(rootId).firstOrNull { it.name == request.rootName && it.isDir }?.id
        ?: destination.createDirectory(rootId, request.rootName).id

    return TreeExporter.exportTree(
        plan = request.plan,
        destinationRootId = landing,
        source = VolumeSourceBytes(volume),
        destination = destination,
        collisionMode = mode,
        mimeTypeFor = SafExportDestination::mimeTypeFor,
        onProgress = onProgress,
        isCancelled = isCancelled,
    ).also { Trace.i(formatThroughput("export", it.bytesCopied, it.stats)) }
}
