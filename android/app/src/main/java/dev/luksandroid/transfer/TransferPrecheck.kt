package dev.luksandroid.transfer

import dev.luksandroid.StatFsInfo
import dev.luksandroid.SubvolumeInfo
import dev.luksandroid.ui.browser.isPathInsideReadOnlySubvolume

/**
 * Phase 2 of notes/feature-directory-transfer.md §4: a pure function from a
 * [TransferPlan] and a description of the destination to a [Verdict], run
 * before a single byte moves. Nothing here touches Android, JNI, or a real
 * volume -- the caller assembles [Destination] from `StatFsInfo`,
 * `LuksVolume.listDir`, and subvolume info, all off the drive already.
 */

/** One existing entry at the destination, as reported by a prior directory listing. */
data class DestinationEntry(val name: String, val isDir: Boolean)

/**
 * The destination's current contents, scoped to only the directories the
 * plan touches.
 *
 * Keyed the same way as [TransferPlan.childCountByDir]: by the *plan-relative*
 * path of the directory ("" for the transfer root's landing directory). A
 * directory absent from this map has no existing counterpart at the
 * destination -- it will be created fresh, so it merges with nothing.
 */
data class DestinationListing(val entriesByDir: Map<String, List<DestinationEntry>> = emptyMap()) {
    fun childrenOf(dirPath: String): List<DestinationEntry> = entriesByDir[dirPath].orEmpty()
}

data class Destination(
    val statFs: StatFsInfo,
    /** "ext4" or "btrfs", as reported natively. */
    val fsType: String,
    val listing: DestinationListing,
    val subvolumes: List<SubvolumeInfo> = emptyList(),
    /** Absolute drive path the transfer root lands in, for the read-only-subvolume check. */
    val targetPath: String,
)

/** A refusal is a reason the transfer cannot proceed at all, with enough detail to act on. */
sealed class Refusal(val message: String) {
    class InsufficientSpace(neededBytes: Long, availableBytes: Long, bytesAreLowerBound: Boolean) : Refusal(
        buildString {
            append("Needs at least ${neededBytes} bytes but only ${availableBytes} are available")
            if (bytesAreLowerBound) append(" (source reported some sizes as unknown, so the real total may be higher)")
            append(".")
        }
    )

    class DirectoryEntryCeilingExceeded(
        val dirPath: String,
        val entryCount: Int,
        val ceiling: Int,
        val blockSize: Int,
    ) : Refusal(
        "Directory '${dirPath.ifEmpty { "/" }}' would hold $entryCount entries, over the " +
            "$ceiling-entry ext4 ceiling for a ${blockSize}-byte block; this app does not " +
            "implement htree conversion, so the import would strand a partial tree."
    )

    class TypeMismatchCollision(val relativePath: String) : Refusal(
        "'$relativePath' is a file at one end and a directory at the other; neither merge nor " +
            "replace is safe, so this must be resolved manually before importing."
    )

    class ReadOnlyDestination(reason: String) : Refusal(reason)
}

/** A file-vs-file name collision at the leaves: the user decides keep-both / replace / skip. */
data class FileCollision(val relativePath: String)

/** A directory-vs-directory name collision: merged silently, never a user decision. */
data class DirectoryMerge(val relativePath: String)

sealed class Verdict {
    data class Refused(val reasons: List<Refusal>) : Verdict()

    /**
     * The transfer can proceed. [fileCollisions] still need a user decision before
     * execution; [directoryMerges] are informational only. [sizeIsLowerBound] mirrors
     * [TransferPlan.hasUnknownSizes] -- space was checked against the known total,
     * but that total may understate the real transfer.
     */
    data class Proceed(
        val fileCollisions: List<FileCollision>,
        val directoryMerges: List<DirectoryMerge>,
        val sizeIsLowerBound: Boolean,
        /**
         * Plan-relative directories where "keep both" would push the directory
         * over the ext4 ceiling even though skip and replace fit. The choice is
         * per-collision, so this is a constraint on the *option*, not a reason
         * to refuse the transfer -- the UI disables keep-both for collisions in
         * these directories rather than offering a choice that cannot succeed.
         */
        val keepBothBlockedDirs: List<String> = emptyList(),
    ) : Verdict()
}

/**
 * A single-block ext4 directory holds `(blockSize - 36) / 20` entries: 36 bytes for
 * "." + ".." (12 bytes each, minimum record for a 1-2 char name) plus a 12-byte
 * metadata-checksum tail, leaving the rest for 20-byte records (the size measured
 * in core/tests/statfs.rs for its `f_NNNN.txt`-style names). This reproduces both
 * measured points exactly: 4096 -> 203, 1024 -> 49. We do not implement htree
 * conversion, so exceeding it strands a half-copied tree -- this must refuse
 * up front, never surface as a mid-copy failure.
 */
internal fun ext4DirectoryEntryCeiling(blockSize: Int): Int = (blockSize - 36) / 20

private fun nameOf(relativePath: String): String = relativePath.substringAfterLast('/')

fun precheckTransfer(plan: TransferPlan, destination: Destination): Verdict {
    val refusals = mutableListOf<Refusal>()
    val fileCollisions = mutableListOf<FileCollision>()
    val directoryMerges = mutableListOf<DirectoryMerge>()
    val keepBothBlockedDirs = mutableListOf<String>()

    // 1. Free space. `totalBytes` is a lower bound whenever `hasUnknownSizes` is
    // true, so a "fits" verdict in that case is provisional -- flagged in Proceed,
    // never claimed as certain.
    val needed = plan.totalBytes
    if (needed > destination.statFs.availableBytes) {
        refusals += Refusal.InsufficientSpace(needed, destination.statFs.availableBytes, plan.hasUnknownSizes)
    }

    // 2. Collisions, split by type. Computed once and reused for the ceiling's
    // temp-slot count below.
    val fileCollisionCountByDir = mutableMapOf<String, Int>()
    val dirMergeCountByDir = mutableMapOf<String, Int>()
    for (entry in plan.entries) {
        val parent = parentOf(entry.relativePath)
        val name = nameOf(entry.relativePath)
        val existing = destination.listing.childrenOf(parent).find { it.name == name } ?: continue
        when {
            existing.isDir && entry.isDir -> {
                directoryMerges += DirectoryMerge(entry.relativePath)
                dirMergeCountByDir.merge(parent, 1, Int::plus)
            }
            !existing.isDir && !entry.isDir -> {
                fileCollisions += FileCollision(entry.relativePath)
                fileCollisionCountByDir.merge(parent, 1, Int::plus)
            }
            else -> refusals += Refusal.TypeMismatchCollision(entry.relativePath)
        }
    }

    // 3. The ext4 directory-entry ceiling. btrfs has no such limit -- skip
    // entirely rather than run a check that can never fire.
    if (destination.fsType == "ext4") {
        val ceiling = ext4DirectoryEntryCeiling(destination.statFs.blockSize)
        for ((dirPath, newCount) in plan.childCountByDir) {
            val existingCount = destination.listing.childrenOf(dirPath).size
            val fileCollisions = fileCollisionCountByDir[dirPath] ?: 0
            val dirMerges = dirMergeCountByDir[dirPath] ?: 0

            // A colliding name reuses the entry that is already there, so it adds
            // nothing to the directory's entry count. Counting existing + new
            // wholesale double-counts every collision, which would refuse the
            // documented resume path outright (§5.2: "re-running the same import
            // acts as a resume") -- re-importing a full folder to recover the
            // files a failed run missed is exactly when this check must not fire.
            val alwaysAdded = newCount - fileCollisions - dirMerges

            // Replace is write-to-temp-then-rename (§3.2), which holds one extra
            // entry while the temp file exists. The user's choice is not known
            // yet, so reserve that slot whenever it could be taken.
            val tempSlot = if (fileCollisions > 0) 1 else 0

            // Refuse only on the floor: the count no collision policy can avoid.
            val minimum = existingCount + alwaysAdded + tempSlot
            if (minimum > ceiling) {
                refusals += Refusal.DirectoryEntryCeilingExceeded(dirPath, minimum, ceiling, destination.statFs.blockSize)
                continue
            }

            // Keep-both is the one policy that does add an entry per collision.
            // That constrains the option, not the transfer.
            if (existingCount + alwaysAdded + fileCollisions > ceiling) {
                keepBothBlockedDirs += dirPath
            }
        }
    }

    // 4. Read-only btrfs subvolume destination.
    val (readOnly, reason) = isPathInsideReadOnlySubvolume(destination.targetPath, destination.fsType, destination.subvolumes)
    if (readOnly) {
        refusals += Refusal.ReadOnlyDestination(reason ?: "Destination is inside a read-only subvolume.")
    }

    return if (refusals.isNotEmpty()) {
        Verdict.Refused(refusals)
    } else {
        Verdict.Proceed(fileCollisions, directoryMerges, plan.hasUnknownSizes, keepBothBlockedDirs)
    }
}
