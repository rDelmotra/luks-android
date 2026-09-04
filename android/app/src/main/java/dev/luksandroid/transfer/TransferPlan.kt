package dev.luksandroid.transfer

/**
 * The work list for a directory transfer, built before anything is written.
 *
 * A directory copy cannot be made atomic (see notes/feature-directory-transfer.md
 * §5.2), so the mitigation is to learn everything knowable *first*: total bytes
 * for a real progress bar, per-directory child counts for the ext4 entry ceiling,
 * and the collision list. Enumerating up front is what turns "it died at 80% and
 * said nothing" into "this will not fit, here is why".
 *
 * Everything in this file is pure Kotlin with no Android or JNI dependency, so
 * it is unit-testable without an emulator -- which matters, because the repo has
 * no Robolectric and no mocking framework.
 */

/** A file or directory as reported by a source, before it is placed in a plan. */
data class RawChild(
    /**
     * Opaque, source-defined identity. A SAF `documentId` on the Android side, an
     * absolute path on the volume side.
     *
     * Deliberately a `String` and never a `Uri`: under
     * `unitTests.isReturnDefaultValues = true` every `Uri.parse` returns null, so
     * a plan keyed by `Uri` would have every key collide to null and any test
     * asserting over those keys would pass while proving nothing.
     */
    val id: String,
    val name: String,
    val isDir: Boolean,
    /** [SIZE_UNKNOWN] when the source did not report one. Always 0 for directories. */
    val sizeBytes: Long,
    /** Epoch millis, or 0 when the source did not report one. */
    val mtime: Long,
)

/** A source of directory listings, one call per directory. */
fun interface ChildSource {
    /**
     * Direct children of [parentId] -- one call per directory, never per file.
     *
     * The SAF implementation of this is a single `ContentResolver.query` with an
     * explicit projection. `DocumentFile.listFiles()` would satisfy the same
     * signature and costs one binder round trip *per child*; it must not be used.
     */
    fun children(parentId: String): List<RawChild>
}

/** One node of a tree to be transferred. Directories are rows in their own right. */
data class PlanEntry(
    /** Source-defined identity, as [RawChild.id]. */
    val sourceId: String,
    /**
     * Path relative to the transfer root: `"/"`-separated, no leading slash. The
     * root itself is `""`.
     */
    val relativePath: String,
    val isDir: Boolean,
    /** [SIZE_UNKNOWN] when unknown. Always 0 for directories. */
    val sizeBytes: Long,
    /** Epoch millis, or 0 when unknown. */
    val mtime: Long,
)

const val SIZE_UNKNOWN: Long = -1L

/**
 * A flat, ordered work list plus the totals derived from it.
 *
 * [entries] is ordered **parent before child**. Execution relies on this: it
 * creates directories in list order and can assume the parent already exists.
 * A walker that breaks this ordering breaks the import silently, so it is
 * asserted by [checkParentBeforeChild] rather than left as a comment.
 */
data class TransferPlan(
    /** Display name of the tree's root directory, used for the transfer's label. */
    val rootName: String,
    val entries: List<PlanEntry>,
) {
    val dirCount: Int get() = entries.count { it.isDir }

    val fileCount: Int get() = entries.count { !it.isDir }

    /**
     * Sum of known file sizes. Entries with [SIZE_UNKNOWN] contribute nothing, so
     * when [hasUnknownSizes] is true this is a *lower bound* and any ETA derived
     * from it must be presented as approximate rather than as a countdown.
     */
    val totalBytes: Long
        get() = entries.sumOf { if (!it.isDir && it.sizeBytes > 0) it.sizeBytes else 0L }

    /** Whether any file's size was not reported by the source. */
    val hasUnknownSizes: Boolean
        get() = entries.any { !it.isDir && it.sizeBytes == SIZE_UNKNOWN }

    /**
     * Direct-child count per directory, keyed by that directory's
     * [PlanEntry.relativePath] (the root is `""`).
     *
     * This is what the ext4 ceiling precheck consumes: a single-block ext4
     * directory holds exactly 203 entries and we do not implement htree
     * conversion, so a folder that exceeds it strands a half-copied tree.
     */
    val childCountByDir: Map<String, Int>
        get() = entries.groupingBy { parentOf(it.relativePath) }.eachCount()

    /** Fails loudly if [entries] is not ordered parent-before-child. */
    fun checkParentBeforeChild() {
        val seenDirs = HashSet<String>().apply { add("") }
        for (entry in entries) {
            val parent = parentOf(entry.relativePath)
            require(parent in seenDirs) {
                "plan entry '${entry.relativePath}' precedes its parent '$parent'"
            }
            if (entry.isDir) seenDirs.add(entry.relativePath)
        }
    }
}

/** The containing directory of [relativePath]; `""` for a top-level entry. */
internal fun parentOf(relativePath: String): String =
    relativePath.substringBeforeLast('/', missingDelimiterValue = "")
