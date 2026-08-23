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
    val stats: TransferStats = TransferStats.EMPTY,
) {
    val succeeded: Boolean get() = failure == null
}

/**
 * Where a transfer's wall-clock actually went.
 *
 * This exists because of INCIDENTS.md 2026-08-08 and 2026-08-10: throughput on
 * this project has been misattributed three separate times -- to command size,
 * to buffer copies, to flash cache folding -- and each time what settled it was
 * building the cheapest instrument that could *contradict* the hypothesis
 * rather than one that could confirm it.
 *
 * The current hypothesis is that [TreeImporter.streamFile] and
 * [TreeExporter.streamFile] serialise two comparable-cost stages -- the source
 * read and the destination write -- so the destination sits idle for the whole
 * read and vice versa, capping throughput near half of either side's ceiling.
 * That hypothesis makes a falsifiable prediction: [readNanos] and [writeNanos]
 * are of the same order. If instead the read is a few percent of the total,
 * pipelining them can win at most that few percent and should not be built.
 *
 * All four buckets are measured, not derived, and they do not sum to
 * [elapsedNanos] -- the remainder is directory creation, destination listings,
 * and per-entry lookups, which is itself worth seeing on a many-small-files
 * tree.
 */
data class TransferStats(
    /** Wall-clock for the whole tree, including per-entry lookups and mkdirs. */
    val elapsedNanos: Long,
    /** Time blocked in the source's `read`. */
    val readNanos: Long,
    /** Time blocked writing a chunk to the destination. */
    val writeNanos: Long,
    /**
     * Time closing each file out: `finishFile` on import (which commits the
     * btrfs transaction) or closing the provider's stream on export. Broken out
     * rather than folded into [writeNanos] because it is per-*file* cost, not
     * per-byte, and so scales with the tree's shape instead of its size.
     */
    val commitNanos: Long,
    val readCalls: Int,
    val writeCalls: Int,
) {
    companion object {
        val EMPTY = TransferStats(0, 0, 0, 0, 0, 0)
    }
}

/**
 * A one-line, path-free summary of [stats] for [bytes] moved, safe to log in
 * any build: counts, durations and rates only, never a name from either side.
 *
 * Pure and separate from the logging call so it can be unit-tested; see
 * `Trace.err`'s `ErrDetail` for the same "make it structurally impossible to
 * log a path" reasoning.
 */
fun formatThroughput(direction: String, bytes: Long, stats: TransferStats): String {
    val seconds = stats.elapsedNanos / 1_000_000_000.0
    val mib = bytes / (1024.0 * 1024.0)
    val rate = if (seconds > 0) mib / seconds else 0.0
    fun bucket(label: String, nanos: Long): String {
        val pct = if (stats.elapsedNanos > 0) nanos * 100.0 / stats.elapsedNanos else 0.0
        return "%s=%.2fs/%.0f%%".format(label, nanos / 1_000_000_000.0, pct)
    }
    val other = stats.elapsedNanos - stats.readNanos - stats.writeNanos - stats.commitNanos
    return "throughput dir=%s bytes=%d elapsed=%.2fs rate=%.2fMiB/s %s %s %s %s reads=%d writes=%d".format(
        direction,
        bytes,
        seconds,
        rate,
        bucket("read", stats.readNanos),
        bucket("write", stats.writeNanos),
        bucket("commit", stats.commitNanos),
        bucket("other", other),
        stats.readCalls,
        stats.writeCalls,
    )
}

/**
 * Accumulates [TransferStats] while a transfer runs. Not thread-safe and does
 * not need to be: both executors are single-threaded by construction, and a
 * pipelined version would hand each stage its own counter rather than sharing
 * this one.
 */
internal class StatsRecorder {
    private val startedAt = System.nanoTime()
    var readNanos = 0L
    var writeNanos = 0L
    var commitNanos = 0L
    var readCalls = 0
    var writeCalls = 0

    inline fun <T> read(block: () -> T): T {
        val t0 = System.nanoTime()
        try {
            return block()
        } finally {
            readNanos += System.nanoTime() - t0
            readCalls++
        }
    }

    inline fun <T> write(block: () -> T): T {
        val t0 = System.nanoTime()
        try {
            return block()
        } finally {
            writeNanos += System.nanoTime() - t0
            writeCalls++
        }
    }

    inline fun <T> commit(block: () -> T): T {
        val t0 = System.nanoTime()
        try {
            return block()
        } finally {
            commitNanos += System.nanoTime() - t0
        }
    }

    // Timed on the way out too, so a failed or cancelled run still reports how
    // far it got and how fast -- a transfer that died at 90% is exactly when
    // the numbers are most interesting.
    fun snapshot() = TransferStats(
        elapsedNanos = System.nanoTime() - startedAt,
        readNanos = readNanos,
        writeNanos = writeNanos,
        commitNanos = commitNanos,
        readCalls = readCalls,
        writeCalls = writeCalls,
    )
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
