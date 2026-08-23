package dev.luksandroid.transfer

import dev.luksandroid.LuksVolume
import java.io.InputStream
import java.util.concurrent.CancellationException

/**
 * Pass 3 of notes/feature-directory-transfer.md: turns a [TransferPlan] into
 * real writes against a [LuksVolume].
 *
 * Deliberately free of coroutines, `Context`, and the mutex/`TransferItem`
 * bookkeeping `TransferManager.importFileWithProgress` wraps a single-file
 * copy in -- that plumbing belongs to the caller, not here. This file only
 * knows how to walk a plan and copy bytes, which is what makes it testable
 * against a fake in-memory [LuksVolume] with plain JUnit, no Robolectric, no
 * device.
 *
 * [TransferPlan.entries] is trusted to already be parent-before-child (that
 * is [TransferPlan.checkParentBeforeChild]'s job, enforced by the walker) and
 * to contain only children of the transfer root, never the root itself --
 * see [DirectoryWalker.walk]. [destinationRootPath] passed to [TreeImporter]
 * is therefore the *landing* directory for the plan's top-level entries: the
 * caller has already decided where the root folder itself lands (created or
 * merged) before calling in here, the same way [DestinationListing] keys its
 * "" entry to that landing directory rather than to the root's own name.
 */

/** How a file-vs-file name collision at the leaves is resolved. Directory-vs-directory is always a silent merge (§3.2) and never reaches this. */
enum class CollisionMode { SKIP, REPLACE, KEEP_BOTH }

/** Opens a source file's bytes by [PlanEntry.sourceId]. [TreeImporter] closes whatever this returns. */
fun interface SourceBytes {
    fun open(sourceId: String): InputStream
}

/**
 * One throttled progress update, fired at most every ~200 ms plus always once
 * more at the end (success, stop, or cancellation) so a UI can never stick
 * below 100%.
 *
 * [bytesTotal] mirrors [TransferPlan.totalBytes]. When [bytesTotalIsLowerBound]
 * is set (from [TransferPlan.hasUnknownSizes]) at least one source file did
 * not report its size, so [bytesDone] can legitimately end up above
 * [bytesTotal] -- that is the honest number of bytes actually moved, not a
 * bug. A caller must treat the total as approximate in that case (clamp the
 * bar, drop the ETA) rather than [TreeImporter] silently under-reporting what
 * it copied to keep a percentage under 100.
 */
data class ImportProgress(
    val filesDone: Int,
    val filesTotal: Int,
    val bytesDone: Long,
    val bytesTotal: Long,
    val bytesTotalIsLowerBound: Boolean,
    val currentPath: String,
)

/**
 * What actually happened. [stoppedAtPath] and [failure] are both null on a
 * clean run to completion, and both non-null otherwise -- never one without
 * the other. Everything counted here already landed on the volume; per
 * notes/feature-directory-transfer.md §5.2 there is deliberately no rollback,
 * so these counts are the accurate "N of M" the plan requires.
 */
data class ImportOutcome(
    val filesCopied: Int,
    val filesSkipped: Int,
    val dirsCreated: Int,
    val bytesCopied: Long,
    val stoppedAtPath: String?,
    val failure: Throwable?,
) {
    val succeeded: Boolean get() = failure == null
}

/**
 * Marks a stop as "the caller asked for this" rather than a real write
 * failure, so [ImportOutcome.failure] can tell the two apart without a
 * separate boolean that could drift from the truth.
 */
class ImportCancelledException : CancellationException("import cancelled")

object TreeImporter {

    /** Matches the chunk size `TransferManager.importFileWithProgress` uses for a single file. */
    const val CHUNK_SIZE: Int = 1 shl 20 // 1 MiB

    private const val PROGRESS_INTERVAL_MS = 200L

    /**
     * Executes [plan] against [volume], landing the plan's top-level entries
     * in [destinationRootPath]. Directories are created parent-first, in
     * [plan]'s own order; files stream through [volume]'s chunked writer.
     *
     * Stops at the first failure (§5.2: continuing past a systemic failure --
     * disk full, the ext4 ceiling, a dead session -- just fails the remaining
     * entries too) and never rolls back what already landed. [isCancelled] is
     * polled between entries and between chunks of a single file so a
     * cancellation lands cleanly at a file boundary with nothing dangling.
     */
    fun importTree(
        volume: LuksVolume,
        plan: TransferPlan,
        destinationRootPath: String,
        source: SourceBytes,
        collisionMode: CollisionMode,
        onProgress: (ImportProgress) -> Unit = {},
        isCancelled: () -> Boolean = { false },
    ): ImportOutcome {
        // Execution trusts this ordering completely (mkdir-then-descend assumes
        // the parent is already there); a broken plan must fail loudly here; not
        // half-copy a tree with directories missing their targets.
        plan.checkParentBeforeChild()

        val destination = DestinationState(volume)
        val filesTotal = plan.fileCount
        val bytesTotal = plan.totalBytes

        var filesCopied = 0
        var filesSkipped = 0
        var dirsCreated = 0
        var bytesCopied = 0L
        var lastProgressMs = Long.MIN_VALUE
        // The last entry *processed*, not the last one a throttled update
        // happened to fire on -- otherwise the forced final update reports
        // whichever file won the 200 ms race, which on a fast tree is rarely
        // the one that finished last.
        var lastPath = ""

        fun fireProgress(path: String, liveBytes: Long, force: Boolean) {
            val now = System.currentTimeMillis()
            if (!force && now - lastProgressMs < PROGRESS_INTERVAL_MS) return
            lastProgressMs = now
            onProgress(
                ImportProgress(
                    filesDone = filesCopied + filesSkipped,
                    filesTotal = filesTotal,
                    bytesDone = liveBytes,
                    bytesTotal = bytesTotal,
                    bytesTotalIsLowerBound = plan.hasUnknownSizes,
                    currentPath = path,
                )
            )
        }

        fun stop(entryPath: String, cause: Throwable): ImportOutcome {
            fireProgress(entryPath, bytesCopied, force = true)
            return ImportOutcome(filesCopied, filesSkipped, dirsCreated, bytesCopied, entryPath, cause)
        }

        for (entry in plan.entries) {
            lastPath = entry.relativePath
            if (isCancelled()) return stop(entry.relativePath, ImportCancelledException())

            val parentDir = absoluteDir(destinationRootPath, parentOf(entry.relativePath))
            val name = nameOf(entry.relativePath)
            // Reading the destination is itself a drive operation and can fail
            // exactly the way a write can -- a locked session or a yanked cable
            // mid-tree surfaces here first, since every entry looks the
            // destination up before touching it. Left uncaught this escapes
            // importTree as a bare exception and the caller loses the counts
            // entirely, which is the 2026-08-23 failure verbatim: a partial
            // tree and an IOException that says nothing about how far it got.
            val existing = try {
                destination.typeOf(parentDir, name)
            } catch (t: Throwable) {
                return stop(entry.relativePath, t)
            }

            if (entry.isDir) {
                when (existing) {
                    // Directory already there: merge, create nothing, never prompt.
                    true -> Unit
                    false -> return stop(
                        entry.relativePath,
                        IllegalStateException("'${entry.relativePath}' is a file at the destination; a directory cannot land there"),
                    )
                    null -> {
                        try {
                            volume.createDirectory(parentDir, name)
                        } catch (t: Throwable) {
                            return stop(entry.relativePath, t)
                        }
                        destination.recordCreatedDirectory(parentDir, name)
                        dirsCreated++
                    }
                }
                fireProgress(entry.relativePath, bytesCopied, force = false)
                continue
            }

            if (existing == true) {
                return stop(
                    entry.relativePath,
                    IllegalStateException("'${entry.relativePath}' is a directory at the destination; a file cannot land there"),
                )
            }

            if (existing == false) {
                when (collisionMode) {
                    CollisionMode.SKIP -> {
                        filesSkipped++
                        fireProgress(entry.relativePath, bytesCopied, force = false)
                        continue
                    }

                    CollisionMode.KEEP_BOTH -> {
                        val targetName = uniqueName(destination.namesOf(parentDir), name)
                        val written = try {
                            streamFile(volume, source, entry, parentDir, targetName) { liveBytes ->
                                fireProgress(entry.relativePath, bytesCopied + liveBytes, force = false)
                                if (isCancelled()) throw ImportCancelledException()
                            }
                        } catch (t: Throwable) {
                            return stop(entry.relativePath, t)
                        }
                        destination.recordCreatedFile(parentDir, targetName)
                        bytesCopied += written
                        filesCopied++
                        fireProgress(entry.relativePath, bytesCopied, force = false)
                    }

                    CollisionMode.REPLACE -> {
                        // The temp name is dedup'd against real siblings the same way
                        // keep-both is, so a leftover temp file from an earlier
                        // aborted run can never collide with this one either.
                        val tempName = uniqueName(destination.namesOf(parentDir), ".transfer-tmp-${name}-${System.nanoTime()}")
                        val written = try {
                            streamFile(volume, source, entry, parentDir, tempName) { liveBytes ->
                                fireProgress(entry.relativePath, bytesCopied + liveBytes, force = false)
                                if (isCancelled()) throw ImportCancelledException()
                            }
                        } catch (t: Throwable) {
                            return stop(entry.relativePath, t)
                        }
                        // POSIX overwrite: either the old file or the new one exists on
                        // the drive after this call, never a truncated hybrid -- the
                        // crash-safety property this mode exists for (§3.2).
                        try {
                            volume.rename(parentDir, tempName, parentDir, name)
                        } catch (t: Throwable) {
                            // The write succeeded but the rename didn't: clean up the
                            // temp entry so a failed replace leaves no orphan behind,
                            // and the original file is untouched because it was never
                            // in the rename's path in the first place.
                            runCatching { volume.deleteFile(childPath(parentDir, tempName)) }
                            return stop(entry.relativePath, t)
                        }
                        destination.recordCreatedFile(parentDir, name)
                        bytesCopied += written
                        filesCopied++
                        fireProgress(entry.relativePath, bytesCopied, force = false)
                    }
                }
                continue
            }

            // No collision: plain write.
            val written = try {
                streamFile(volume, source, entry, parentDir, name) { liveBytes ->
                    fireProgress(entry.relativePath, bytesCopied + liveBytes, force = false)
                    if (isCancelled()) throw ImportCancelledException()
                }
            } catch (t: Throwable) {
                return stop(entry.relativePath, t)
            }
            destination.recordCreatedFile(parentDir, name)
            bytesCopied += written
            filesCopied++
            fireProgress(entry.relativePath, bytesCopied, force = false)
        }

        fireProgress(lastPath, bytesCopied, force = true)
        return ImportOutcome(filesCopied, filesSkipped, dirsCreated, bytesCopied, null, null)
    }

    /**
     * Streams [entry]'s bytes from [source] into a fresh writer and finishes it
     * as `[parentDir]/[targetName]`. [onChunk] is called with the running byte
     * total for *this file only*, after each chunk lands, so the caller can
     * drive live progress and cancellation without this function knowing
     * anything about the rest of the tree.
     *
     * On any failure -- including [onChunk] throwing to signal cancellation --
     * the writer is abandoned, never left dangling. Nothing is finished, so no
     * entry for [targetName] is ever created; this is what makes REPLACE's
     * temp file safe to fail mid-write: an unfinished writer produces no
     * on-disk name at all.
     */
    private fun streamFile(
        volume: LuksVolume,
        source: SourceBytes,
        entry: PlanEntry,
        parentDir: String,
        targetName: String,
        onChunk: (Long) -> Unit,
    ): Long {
        val writer = volume.beginFileStreaming()
        var total = 0L
        try {
            source.open(entry.sourceId).use { input ->
                val buffer = ByteArray(CHUNK_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read == 0) continue
                    volume.writeChunk(writer, buffer, 0, read)
                    total += read
                    onChunk(total)
                }
            }
        } catch (t: Throwable) {
            volume.abandonFile(writer)
            throw t
        }
        volume.finishFile(writer, parentDir, targetName)
        return total
    }
}

/**
 * Tracks what the destination looks like as [TreeImporter] writes to it,
 * querying [LuksVolume.listDir] at most once per directory.
 *
 * A brand-new directory is seeded as empty without a query -- we just created
 * it, so nothing can be in it -- but a directory being merged into (or the
 * landing directory itself, which the caller may have handed us pre-existing)
 * is queried live on first touch. That live query, not the [Verdict][dev.luksandroid.transfer.Verdict]
 * a precheck produced earlier, is deliberately the source of truth here: the
 * precheck's [DestinationListing] can be stale by the time execution reaches
 * a given file (see §5.2's resume story -- a prior run may have already
 * landed some of these names).
 */
private class DestinationState(private val volume: LuksVolume) {
    private val children = mutableMapOf<String, MutableMap<String, Boolean>>()

    private fun listing(dirPath: String): MutableMap<String, Boolean> =
        children.getOrPut(dirPath) {
            volume.listDir(dirPath).associateTo(LinkedHashMap()) { it.name to it.isDir }
        }

    /** true if [name] exists as a directory under [dirPath], false if it exists as a file, null if absent. */
    fun typeOf(dirPath: String, name: String): Boolean? = listing(dirPath)[name]

    fun namesOf(dirPath: String): List<String> = listing(dirPath).keys.toList()

    fun recordCreatedDirectory(dirPath: String, name: String) {
        listing(dirPath)[name] = true
        children.getOrPut(childPath(dirPath, name)) { mutableMapOf() }
    }

    fun recordCreatedFile(dirPath: String, name: String) {
        listing(dirPath)[name] = false
    }
}

/**
 * Picks a name that does not collide with any of [existingNames], starting
 * from [desiredName] and appending " (1)", " (2)", ... before the extension --
 * the same scheme [LuksDocumentsProvider][dev.luksandroid.documents.LuksDocumentsProvider.uniqueDocumentName]
 * uses. Deliberately pure -- a `List<String>` in, a `String` out -- rather than
 * that version's live-volume lookups, both because a `transfer` package
 * depending on `documents` would be backwards layering and because this needs
 * to be unit-testable without a volume at all.
 *
 * A name with no extension, or one starting with a dot, is treated as pure
 * stem with no extension. The result is kept within a 255-byte UTF-8 filename
 * by truncating the stem, never the numbering or the extension -- an
 * extension-less truncated file is merely oddly named; a truncated extension
 * can make it look like the wrong file type entirely.
 */
internal fun uniqueName(existingNames: Collection<String>, desiredName: String, maxBytes: Int = 255): String {
    if (desiredName !in existingNames) return desiredName

    val dotIndex = desiredName.lastIndexOf('.')
    val (stem, ext) = if (dotIndex > 0) {
        desiredName.substring(0, dotIndex) to desiredName.substring(dotIndex)
    } else {
        desiredName to ""
    }

    var n = 1
    while (true) {
        val suffix = " ($n)"
        var candidateStem = stem
        var candidate = "$candidateStem$suffix$ext"
        while (candidate.toByteArray(Charsets.UTF_8).size > maxBytes && candidateStem.isNotEmpty()) {
            candidateStem = candidateStem.dropLast(1)
            candidate = "$candidateStem$suffix$ext"
        }
        if (candidate !in existingNames) return candidate
        n++
    }
}

private fun nameOf(relativePath: String): String = relativePath.substringAfterLast('/')

private fun childPath(dir: String, name: String): String = if (dir == "/") "/$name" else "$dir/$name"

private fun absoluteDir(destinationRoot: String, relativeDir: String): String {
    if (relativeDir.isEmpty()) return destinationRoot
    var path = destinationRoot
    for (segment in relativeDir.split('/')) {
        path = childPath(path, segment)
    }
    return path
}
