package dev.luksandroid.transfer

/**
 * Turns a [ChildSource] into a [TransferPlan] by walking it breadth-first from
 * a root. Pure Kotlin -- no Android or JNI import may ever appear in this
 * file, because that purity is what lets every case below run as a plain JVM
 * unit test with a fake [ChildSource] instead of a device or Robolectric.
 *
 * The one performance rule this file exists to enforce: [ChildSource.children]
 * is called exactly once per directory, never once per file. See
 * notes/feature-directory-transfer.md §2.1 for what happens if that slips --
 * `DocumentFile.listFiles()` makes the same mistake at one binder IPC per
 * child, which is the whole reason [ChildSource] exists as a raw-query
 * abstraction instead of wrapping `DocumentFile` directly.
 */
object DirectoryWalker {

    /**
     * Directories beyond this many levels below the root abort the walk
     * instead of being silently dropped.
     *
     * SAF trees and volume filesystems cannot contain a cycle, so this is not
     * a cycle guard -- it is a sanity bound. `PATH_MAX` is 4096 bytes on both
     * ext4 and btrfs, and even single-character path components (`a/a/a/...`)
     * cannot exceed roughly 2048 levels before the path itself is illegal.
     * 1024 sits comfortably under that ceiling while still catching a
     * runaway walk (a buggy [ChildSource] that reports a directory as its own
     * descendant, for instance) before it turns into an unbounded plan held
     * entirely in memory.
     */
    const val DEFAULT_MAX_DEPTH: Int = 1024

    /** Thrown when a directory would be enumerated past [DEFAULT_MAX_DEPTH]. */
    class DepthExceededException(val path: String, val maxDepth: Int) :
        RuntimeException("directory '$path' exceeds the depth cap of $maxDepth levels")

    private class QueueItem(val id: String, val relativePath: String, val depth: Int)

    /**
     * Walks [source] from [rootId] and returns the resulting [TransferPlan].
     *
     * [rootName] is the label the plan is presented under; [ChildSource] only
     * ever answers "children of X", so nothing in the walk can discover the
     * root's own display name -- the caller already has it (a SAF picker
     * result carries it, a volume path's last segment is it) and must pass it
     * in.
     *
     * Enumeration has no side effects on either source, so a directory that
     * fails to enumerate (a `children()` call that throws) fails the whole
     * walk rather than producing a plan with a hole in it. A partial plan
     * would be worse than no plan: execution trusts [TransferPlan] completely,
     * and a silently incomplete one produces a silently incomplete copy --
     * exactly the failure mode this feature exists to prevent (see
     * notes/feature-directory-transfer.md §5.2). The caller sees the
     * exception and can retry or report it; there is nothing "partial" to
     * salvage from a pure enumeration pass.
     */
    fun walk(
        source: ChildSource,
        rootId: String,
        rootName: String,
        maxDepth: Int = DEFAULT_MAX_DEPTH,
    ): TransferPlan {
        val entries = mutableListOf<PlanEntry>()
        val queue = ArrayDeque<QueueItem>()
        queue.add(QueueItem(rootId, "", 0))

        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (current.depth >= maxDepth) {
                throw DepthExceededException(current.relativePath, maxDepth)
            }

            // The one and only children() call for this directory.
            for (child in source.children(current.id)) {
                val childPath = if (current.relativePath.isEmpty()) {
                    child.name
                } else {
                    "${current.relativePath}/${child.name}"
                }
                entries += PlanEntry(
                    sourceId = child.id,
                    relativePath = childPath,
                    isDir = child.isDir,
                    sizeBytes = if (child.isDir) 0L else child.sizeBytes,
                    mtime = child.mtime,
                )
                if (child.isDir) {
                    queue.add(QueueItem(child.id, childPath, current.depth + 1))
                }
            }
        }

        val plan = TransferPlan(rootName, entries)
        // Self-check: BFS order guarantees this, but a check that is only
        // ever asserted by callers and never by its own producer is a check
        // waiting to bit-rot the first time this method is refactored.
        plan.checkParentBeforeChild()
        return plan
    }
}
