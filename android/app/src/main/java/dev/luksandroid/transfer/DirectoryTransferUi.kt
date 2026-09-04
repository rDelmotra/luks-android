package dev.luksandroid.transfer

/**
 * Pass 5 of notes/feature-directory-transfer.md, minus the Compose.
 *
 * Everything here is a pure function from a [Verdict] or a [TransferProgress]
 * to what the user should be shown. It lives outside the Composable for the
 * usual reason in this module -- there is no Robolectric, so anything inside a
 * `@Composable` is untestable -- and because these are the decisions worth
 * getting right: which collision options may legally be offered, and what a
 * progress bar is allowed to claim when the total is only a lower bound.
 *
 * The 2026-08-23 incident was a UI failure, not a write-path one: the copy was
 * working, and the user locked the session because nothing on screen said so.
 * [TreeProgressLabel] is the part of this feature that exists to prevent that.
 */

/** What must happen before a directory transfer can start. */
sealed class TransferPrompt {

    /**
     * The transfer cannot run at all. [message] is assembled for display;
     * [reasons] is kept so a caller can react to a specific refusal (the ext4
     * ceiling flips the browser's slack-limit flag, for instance).
     */
    data class Refused(val reasons: List<Refusal>, val message: String) : TransferPrompt()

    /**
     * Files collide and the user has to choose once, for all of them.
     *
     * [allowKeepBoth] is false when *any* colliding file sits in a directory
     * where keep-both would breach the ext4 entry ceiling. The choice is
     * applied to the whole transfer, so it is only offerable if it works
     * everywhere -- offering it and then failing partway is precisely the
     * mid-copy surprise the precheck exists to prevent.
     */
    data class NeedsCollisionChoice(
        val fileCollisions: List<FileCollision>,
        val directoryMerges: List<DirectoryMerge>,
        val allowKeepBoth: Boolean,
        val keepBothBlockedDirs: List<String>,
        val sizeIsLowerBound: Boolean,
    ) : TransferPrompt()

    /** Nothing to ask. Directory merges are informational only (§3.2) and never prompt. */
    data class ReadyToRun(
        val directoryMerges: List<DirectoryMerge>,
        val sizeIsLowerBound: Boolean,
    ) : TransferPrompt()
}

/**
 * Turns a precheck [Verdict] into the one thing the UI should do next.
 *
 * A refusal always wins over a collision prompt: asking someone to choose how
 * to resolve collisions in a transfer that cannot run is worse than useless.
 */
fun promptFor(verdict: Verdict): TransferPrompt = when (verdict) {
    is Verdict.Refused -> TransferPrompt.Refused(verdict.reasons, refusalMessage(verdict.reasons))

    is Verdict.Proceed -> if (verdict.fileCollisions.isEmpty()) {
        TransferPrompt.ReadyToRun(verdict.directoryMerges, verdict.sizeIsLowerBound)
    } else {
        val blocked = verdict.keepBothBlockedDirs.toSet()
        TransferPrompt.NeedsCollisionChoice(
            fileCollisions = verdict.fileCollisions,
            directoryMerges = verdict.directoryMerges,
            // Every colliding file must be able to take the option, not just most.
            allowKeepBoth = verdict.fileCollisions.none { parentOf(it.relativePath) in blocked },
            keepBothBlockedDirs = verdict.keepBothBlockedDirs,
            sizeIsLowerBound = verdict.sizeIsLowerBound,
        )
    }
}

/**
 * One human-readable block of text for a set of refusals.
 *
 * Every reason is listed rather than only the first: a transfer can be refused
 * for several independent reasons at once, and fixing the one we happened to
 * print only to be refused again is the kind of loop that makes people give up.
 */
internal fun refusalMessage(reasons: List<Refusal>): String = when (reasons.size) {
    0 -> "The transfer was refused, but no reason was given. This is a bug."
    1 -> reasons.first().message
    else -> buildString {
        append("This transfer cannot run, for ${reasons.size} reasons:")
        for (r in reasons) {
            append("\n• ")
            append(r.message)
        }
    }
}

/**
 * Everything a progress row needs, derived once from a [TransferProgress].
 *
 * [percent] is null when it cannot be stated honestly -- either nothing is
 * known about the total, or the total is a lower bound and the transfer has
 * already passed it. Showing a bar pinned at 100% while files are still
 * copying is a smaller lie than the blank screen of 2026-08-23, but it is
 * still a lie, and it is the one that teaches people the display cannot be
 * trusted.
 */
data class TreeProgressLabel(
    val files: String,
    val bytes: String,
    val currentPath: String,
    val percent: Int?,
    val etaSeconds: Long?,
) {
    /** True when the byte total is untrustworthy, so a caller can mark the bar indeterminate. */
    val isApproximate: Boolean get() = percent == null
}

/**
 * Builds the label for one progress update.
 *
 * [elapsedMs] is the time since the transfer started, used for the ETA. No ETA
 * is produced when the total is a lower bound: an estimate computed against a
 * total known to be wrong counts down to a finish line that then moves, which
 * reads as a stall.
 */
fun treeProgressLabel(
    progress: TransferProgress,
    elapsedMs: Long,
    formatBytes: (Long) -> String = ::defaultFormatBytes,
): TreeProgressLabel {
    val total = progress.bytesTotal
    val done = progress.bytesDone
    val trustworthy = total > 0 && !(progress.bytesTotalIsLowerBound && done > total)

    val percent = if (trustworthy) {
        ((done * 100) / total).toInt().coerceIn(0, 100)
    } else {
        null
    }

    val eta = if (trustworthy && elapsedMs > 0 && done > 0) {
        val bytesPerSec = (done * 1000L) / elapsedMs
        if (bytesPerSec > 0) ((total - done).coerceAtLeast(0L)) / bytesPerSec else null
    } else {
        null
    }

    val bytesText = buildString {
        append(formatBytes(done))
        append(" of ")
        if (progress.bytesTotalIsLowerBound) append("at least ")
        append(formatBytes(total))
    }

    return TreeProgressLabel(
        files = "${progress.filesDone} of ${progress.filesTotal} files",
        bytes = bytesText,
        currentPath = progress.currentPath,
        percent = percent,
        etaSeconds = eta,
    )
}

internal fun defaultFormatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    bytes < 1024L * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024))
    else -> String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024))
}

/**
 * The sentence shown when a transfer stops before finishing.
 *
 * Names how far it got and where it stopped, because "N of M, stopped at
 * <path>" is the information whose absence made the 2026-08-23 failure
 * indistinguishable from a completed copy. §5.2 keeps everything already
 * written, so this deliberately says what was kept rather than implying a
 * rollback that did not happen.
 */
fun stoppedSummary(outcome: TransferOutcome, filesTotal: Int): String {
    if (outcome.succeeded) {
        return "Copied ${outcome.filesCopied} of $filesTotal files."
    }
    val cancelled = outcome.failure is TransferCancelledException
    val lead = if (cancelled) "Cancelled after" else "Stopped after"
    return buildString {
        append("$lead ${outcome.filesCopied} of $filesTotal files")
        outcome.stoppedAtPath?.let { append(", at “$it”") }
        append(". Everything already copied has been kept.")
        if (!cancelled) {
            outcome.failure?.message?.takeIf { it.isNotBlank() }?.let { append("\n$it") }
        }
    }
}
