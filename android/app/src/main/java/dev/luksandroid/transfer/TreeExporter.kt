package dev.luksandroid.transfer

import java.io.OutputStream

/**
 * Pass 4 of notes/feature-directory-transfer.md: turns a [TransferPlan] built
 * over the *drive* into real writes against a SAF destination tree.
 *
 * The mirror image of [TreeImporter], but the destination is a document
 * provider rather than a filesystem we control, and that is not a symmetric
 * swap. Three differences drive this file's shape:
 *
 * 1. **`createDocument` never overwrites and never fails on collision.** It
 *    silently assigns a *different* display name and returns it. So every
 *    create here reports the name it actually got ([CreatedDocument.name]),
 *    and that -- not the name we asked for -- is what gets recorded. Assuming
 *    the requested name was honoured is how an export ends up believing it
 *    wrote `report.pdf` when the provider created `report (1).pdf`.
 * 2. **There is no atomic replace.** [TreeImporter]'s REPLACE relies on POSIX
 *    rename-over: either the old file or the new one exists, never a hybrid
 *    (§3.2). SAF has no equivalent -- renaming onto an existing name
 *    de-duplicates rather than replaces. See [exportTree]'s REPLACE branch for
 *    what is done instead and what it does and does not guarantee.
 * 3. **The provider may append an extension** it derives from the MIME type,
 *    so the type is supplied per file by [mimeTypeFor] rather than blanket
 *    `application/octet-stream`, which turns `photo.jpg` into `photo.jpg.bin`
 *    on some providers.
 *
 * Like [TreeImporter], this is free of coroutines, `Context`, and `Uri` -- all
 * identity is `String` document IDs -- which is what makes it testable with
 * plain JUnit against a fake destination. See the note in
 * notes/feature-directory-transfer.md on why `Uri` cannot appear here.
 */

/**
 * A document that now exists, and the display name it actually received.
 *
 * [name] is not decoration: SAF providers rename on collision rather than
 * failing, so the requested name and the real one routinely differ.
 */
data class CreatedDocument(val id: String, val name: String)

/**
 * The destination side of an export, as the executor needs it. Implemented for
 * real by [SafExportDestination] and by fakes in tests.
 *
 * Identity is the provider's document ID, opaque to everything here.
 */
interface ExportDestination {
    /** One listing per directory -- see §2.1 on why this is a query, never `DocumentFile.listFiles()`. */
    fun children(dirId: String): List<RawChild>

    fun createDirectory(parentId: String, name: String): CreatedDocument

    fun createFile(parentId: String, name: String, mimeType: String): CreatedDocument

    /** The executor closes this. */
    fun openOutput(docId: String): OutputStream

    fun delete(docId: String)

    /** Renames an existing document. The provider may still adjust the name, so the result is authoritative. */
    fun rename(docId: String, newName: String): CreatedDocument
}

object TreeExporter {

    /** Matches [TreeImporter.CHUNK_SIZE]; the read side chunks the same way the write side does. */
    const val CHUNK_SIZE: Int = 1 shl 20 // 1 MiB

    private const val PROGRESS_INTERVAL_MS = 200L

    private const val DEFAULT_MIME = "application/octet-stream"

    /**
     * Executes [plan] against [destination], landing the plan's top-level
     * entries under [destinationRootId].
     *
     * Same contract as [TreeImporter.importTree]: parent-before-child ordering
     * is trusted and checked, the first failure stops the run, nothing is
     * rolled back (§5.2), and [isCancelled] is polled between entries and
     * between chunks so a cancellation lands at a file boundary.
     *
     * [mimeTypeFor] maps a file name to the MIME type the document is created
     * with. It is injected rather than computed here because the real
     * implementation needs `MimeTypeMap`, which is Android-only and would make
     * this untestable.
     */
    fun exportTree(
        plan: TransferPlan,
        destinationRootId: String,
        source: SourceBytes,
        destination: ExportDestination,
        collisionMode: CollisionMode,
        mimeTypeFor: (String) -> String = { DEFAULT_MIME },
        onProgress: (TransferProgress) -> Unit = {},
        isCancelled: () -> Boolean = { false },
    ): TransferOutcome {
        // Execution trusts this ordering completely (a child's parent directory
        // must already have a document ID); a broken plan must fail loudly here,
        // not half-export a tree with directories missing their targets.
        plan.checkParentBeforeChild()

        val state = DestinationTree(destination, destinationRootId)
        val stats = StatsRecorder()
        val filesTotal = plan.fileCount
        val bytesTotal = plan.totalBytes

        var filesCopied = 0
        var filesSkipped = 0
        var dirsCreated = 0
        var bytesCopied = 0L
        var lastProgressMs = Long.MIN_VALUE
        // The last entry *processed*, not the last one a throttled update
        // happened to fire on -- same reasoning as TreeImporter's.
        var lastPath = ""

        fun fireProgress(path: String, liveBytes: Long, force: Boolean) {
            val now = System.currentTimeMillis()
            if (!force && now - lastProgressMs < PROGRESS_INTERVAL_MS) return
            lastProgressMs = now
            onProgress(
                TransferProgress(
                    filesDone = filesCopied + filesSkipped,
                    filesTotal = filesTotal,
                    bytesDone = liveBytes,
                    bytesTotal = bytesTotal,
                    bytesTotalIsLowerBound = plan.hasUnknownSizes,
                    currentPath = path,
                )
            )
        }

        fun stop(entryPath: String, cause: Throwable): TransferOutcome {
            fireProgress(entryPath, bytesCopied, force = true)
            return TransferOutcome(
                filesCopied, filesSkipped, dirsCreated, bytesCopied, entryPath, cause, stats.snapshot(),
            )
        }

        for (entry in plan.entries) {
            lastPath = entry.relativePath
            if (isCancelled()) return stop(entry.relativePath, TransferCancelledException())

            val relativeParent = parentOf(entry.relativePath)
            val name = nameOf(entry.relativePath)

            // Resolving the parent and reading its listing are both provider
            // IPC and fail the same way a write does -- a revoked permission or
            // an ejected SD card surfaces here first, since every entry looks
            // its parent up before touching it. Uncaught, this escapes as a
            // bare exception and the caller loses the counts entirely, which is
            // the 2026-08-23 failure shape.
            val parentId: String
            val existing: Boolean?
            try {
                parentId = state.directoryId(relativeParent)
                existing = state.typeOf(parentId, name)
            } catch (t: Throwable) {
                return stop(entry.relativePath, t)
            }

            if (entry.isDir) {
                when (existing) {
                    // Already there: merge into it, create nothing, never prompt.
                    true -> {
                        try {
                            state.mergeExistingDirectory(entry.relativePath, parentId, name)
                        } catch (t: Throwable) {
                            return stop(entry.relativePath, t)
                        }
                    }
                    false -> return stop(
                        entry.relativePath,
                        IllegalStateException("'${entry.relativePath}' is a file at the destination; a directory cannot land there"),
                    )
                    null -> {
                        val created = try {
                            destination.createDirectory(parentId, name)
                        } catch (t: Throwable) {
                            return stop(entry.relativePath, t)
                        }
                        state.recordCreatedDirectory(entry.relativePath, parentId, created)
                        dirsCreated++
                    }
                }
                // A whole entry finished: fire unconditionally, not throttled
                // like the intra-file chunk callback below -- see TreeImporter's
                // reasoning.
                fireProgress(entry.relativePath, bytesCopied, force = true)
                continue
            }

            if (existing == true) {
                return stop(
                    entry.relativePath,
                    IllegalStateException("'${entry.relativePath}' is a directory at the destination; a file cannot land there"),
                )
            }

            if (existing == false && collisionMode == CollisionMode.SKIP) {
                filesSkipped++
                fireProgress(entry.relativePath, bytesCopied, force = true)
                continue
            }

            val replacing = existing == false && collisionMode == CollisionMode.REPLACE
            val requestedName = when {
                // REPLACE writes to a temp document first so the target is only
                // destroyed once the new bytes are safely on the destination.
                replacing -> uniqueName(state.namesOf(parentId), ".transfer-tmp-$name-${System.nanoTime()}")
                existing == false -> uniqueName(state.namesOf(parentId), name)
                else -> name
            }

            val written: Long
            var created: CreatedDocument
            try {
                created = destination.createFile(parentId, requestedName, mimeTypeFor(name))
                written = streamFile(destination, source, stats, entry, created) { liveBytes ->
                    fireProgress(entry.relativePath, bytesCopied + liveBytes, force = false)
                    if (isCancelled()) throw TransferCancelledException()
                }
            } catch (t: Throwable) {
                return stop(entry.relativePath, t)
            }

            if (replacing) {
                // No atomic replace exists here. The best available ordering is
                // write-temp, delete-target, rename-temp: the target is only
                // removed once the new bytes are fully written, so a failure
                // never leaves a truncated file where a complete one was. It is
                // weaker than TreeImporter's POSIX rename-over -- a crash
                // between the delete and the rename leaves the data under the
                // temp name rather than the real one -- but that is recoverable,
                // and delete-then-write, the only simpler option, is not.
                try {
                    state.deleteExisting(parentId, name)
                    created = destination.rename(created.id, name)
                } catch (t: Throwable) {
                    return stop(entry.relativePath, t)
                }
            }

            // Recorded under the name the provider actually assigned, which may
            // not be the one requested -- see CreatedDocument.
            state.recordCreatedFile(parentId, created)
            bytesCopied += written
            filesCopied++
            fireProgress(entry.relativePath, bytesCopied, force = true)
        }

        fireProgress(lastPath, bytesCopied, force = true)
        return TransferOutcome(
            filesCopied, filesSkipped, dirsCreated, bytesCopied, null, null, stats.snapshot(),
        )
    }

    /**
     * Streams [entry]'s bytes from [source] into [target]'s output stream.
     * [onChunk] gets the running total for *this file only* after each chunk,
     * driving live progress and cancellation.
     *
     * Unlike the import side there is no "abandon" that leaves no trace: the
     * document already exists by the time any byte is written, so a failure
     * here leaves a short file behind. The caller deals with that -- for
     * REPLACE it is only ever the temp document, and for a plain write it is
     * the partial file §5.2 explicitly chooses to keep rather than roll back.
     */
    private fun streamFile(
        destination: ExportDestination,
        source: SourceBytes,
        stats: StatsRecorder,
        entry: PlanEntry,
        target: CreatedDocument,
        onChunk: (Long) -> Unit,
    ): Long {
        var total = 0L
        val output = destination.openOutput(target.id)
        try {
            source.open(entry.sourceId).use { input ->
                val buffer = ByteArray(CHUNK_SIZE)
                while (true) {
                    // Here "read" is the drive and "write" is the phone -- the
                    // mirror of TreeImporter's, and serialised the same way.
                    val read = stats.read { input.read(buffer) }
                    if (read < 0) break
                    if (read == 0) continue
                    stats.write { output.write(buffer, 0, read) }
                    total += read
                    onChunk(total)
                }
            }
        } finally {
            // Timed rather than left to `use`: a provider stream can hold a
            // whole file's worth of buffering until close, which would
            // otherwise land in "other" and look like per-entry overhead.
            stats.commit { output.close() }
        }
        return total
    }
}

/**
 * Maps plan-relative directory paths to destination document IDs, and tracks
 * each touched directory's children, querying the provider at most once per
 * directory.
 *
 * A directory we just created is seeded as empty without a query -- nothing
 * can be in it -- but a directory being merged into (or the destination root
 * itself) is listed live on first touch, for the same reason
 * [TreeImporter]'s state is: a precheck's listing can be stale by the time
 * execution reaches a given file (§5.2's resume story).
 */
private class DestinationTree(
    private val destination: ExportDestination,
    rootId: String,
) {
    /** Plan-relative directory path -> document ID. "" is the destination root. */
    private val dirIds = mutableMapOf("" to rootId)

    /** Document ID -> its children by name, true if the child is a directory. */
    private val children = mutableMapOf<String, MutableMap<String, Boolean>>()

    /** Document ID -> child name -> child document ID, for deletes. */
    private val childIds = mutableMapOf<String, MutableMap<String, String>>()

    private fun listing(dirId: String): MutableMap<String, Boolean> {
        children[dirId]?.let { return it }
        val byName = LinkedHashMap<String, Boolean>()
        val ids = mutableMapOf<String, String>()
        for (child in destination.children(dirId)) {
            byName[child.name] = child.isDir
            ids[child.name] = child.id
        }
        children[dirId] = byName
        childIds[dirId] = ids
        return byName
    }

    fun directoryId(relativeDir: String): String =
        dirIds[relativeDir] ?: error(
            "no destination directory for '$relativeDir' -- the plan is not parent-before-child, " +
                "which checkParentBeforeChild() should have caught before execution started",
        )

    /** true if [name] is a directory under [dirId], false if a file, null if absent. */
    fun typeOf(dirId: String, name: String): Boolean? = listing(dirId)[name]

    fun namesOf(dirId: String): List<String> = listing(dirId).keys.toList()

    fun recordCreatedDirectory(relativePath: String, parentId: String, created: CreatedDocument) {
        listing(parentId)[created.name] = true
        childIds.getOrPut(parentId) { mutableMapOf() }[created.name] = created.id
        dirIds[relativePath] = created.id
        // Just created, so it is empty -- no query needed to know that.
        children[created.id] = LinkedHashMap()
        childIds[created.id] = mutableMapOf()
    }

    /** Adopts a directory that was already at the destination, so children can descend into it. */
    fun mergeExistingDirectory(relativePath: String, parentId: String, name: String) {
        listing(parentId)
        val id = childIds[parentId]?.get(name)
            ?: error("merging '$relativePath' but the destination listing has no ID for '$name'")
        dirIds[relativePath] = id
    }

    fun recordCreatedFile(parentId: String, created: CreatedDocument) {
        listing(parentId)[created.name] = false
        childIds.getOrPut(parentId) { mutableMapOf() }[created.name] = created.id
    }

    fun deleteExisting(parentId: String, name: String) {
        listing(parentId)
        val id = childIds[parentId]?.get(name) ?: error("no destination ID for '$name' to delete")
        destination.delete(id)
        children[parentId]?.remove(name)
        childIds[parentId]?.remove(name)
    }
}
