package dev.luksandroid.transfer

import java.io.InputStream
import java.util.concurrent.CancellationException

/**
 * The vocabulary shared by both execution directions -- [TreeImporter]
 * (phone -> drive, Pass 3) and [TreeExporter] (drive -> phone, Pass 4).
 *
 * These started out inside [TreeImporter] named `Import*`. Export needs
 * exactly the same shapes, and Pass 5's UI has to render progress and
 * outcomes for both without caring which direction it is showing, so they are
 * one model rather than two identical ones under different names.
 */

/**
 * How a file-vs-file name collision at the leaves is resolved.
 * Directory-vs-directory is always a silent merge (§3.2) and never reaches
 * this.
 */
enum class CollisionMode { SKIP, REPLACE, KEEP_BOTH }

/** Opens a source file's bytes by [PlanEntry.sourceId]. The executor closes whatever this returns. */
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
 * bar, drop the ETA) rather than the executor silently under-reporting what it
 * copied to keep a percentage under 100.
 */
data class TransferProgress(
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
 * the other. Everything counted here already landed at the destination; per
 * notes/feature-directory-transfer.md §5.2 there is deliberately no rollback,
 * so these counts are the accurate "N of M" the plan requires.
 */
data class TransferOutcome(
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
 * Marks a stop as "the caller asked for this" rather than a real failure, so
 * [TransferOutcome.failure] can tell the two apart without a separate boolean
 * that could drift from the truth.
 */
class TransferCancelledException : CancellationException("transfer cancelled")

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

internal fun nameOf(relativePath: String): String = relativePath.substringAfterLast('/')

internal fun childPath(dir: String, name: String): String = if (dir == "/") "/$name" else "$dir/$name"

internal fun absoluteDir(destinationRoot: String, relativeDir: String): String {
    if (relativeDir.isEmpty()) return destinationRoot
    var path = destinationRoot
    for (segment in relativeDir.split('/')) {
        path = childPath(path, segment)
    }
    return path
}
