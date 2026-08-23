package dev.luksandroid.transfer

import dev.luksandroid.StatFsInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pass 5's decision logic, tested away from Compose.
 *
 * The questions here are the ones a screenshot cannot answer: may keep-both be
 * offered, is this percentage honest, and does a stopped transfer say how far
 * it got. The last is the 2026-08-23 incident's actual failure -- the copy
 * worked, and the UI said nothing.
 */
class DirectoryTransferUiTest {

    private fun collision(path: String) = FileCollision(path)

    private fun proceed(
        collisions: List<FileCollision> = emptyList(),
        merges: List<DirectoryMerge> = emptyList(),
        lowerBound: Boolean = false,
        blocked: List<String> = emptyList(),
    ) = Verdict.Proceed(collisions, merges, lowerBound, blocked)

    // ---- which prompt to show ----------------------------------------------

    @Test
    fun `no collisions means nothing to ask`() {
        val prompt = promptFor(proceed(merges = listOf(DirectoryMerge("Photos"))))

        val ready = prompt as TransferPrompt.ReadyToRun
        assertEquals(listOf(DirectoryMerge("Photos")), ready.directoryMerges)
    }

    @Test
    fun `file collisions require a choice`() {
        val prompt = promptFor(proceed(collisions = listOf(collision("a.txt"), collision("Docs/b.txt"))))

        val choice = prompt as TransferPrompt.NeedsCollisionChoice
        assertEquals(2, choice.fileCollisions.size)
        assertTrue(choice.allowKeepBoth)
    }

    @Test
    fun `keep both is withheld when a colliding file sits in a blocked directory`() {
        // "Docs" cannot take another entry, so keep-both cannot be honoured for
        // Docs/b.txt. The choice applies to the whole transfer, so it must not
        // be offered at all.
        val prompt = promptFor(
            proceed(
                collisions = listOf(collision("a.txt"), collision("Docs/b.txt")),
                blocked = listOf("Docs"),
            ),
        )

        val choice = prompt as TransferPrompt.NeedsCollisionChoice
        assertFalse(choice.allowKeepBoth)
        assertEquals(listOf("Docs"), choice.keepBothBlockedDirs)
    }

    @Test
    fun `a blocked directory with no collisions in it does not withhold keep both`() {
        // The control for the test above: "Elsewhere" is blocked, but nothing
        // colliding lives there, so keep-both is still perfectly achievable.
        // Without this pair, an implementation that disabled keep-both whenever
        // *any* directory was blocked would look correct.
        val prompt = promptFor(
            proceed(
                collisions = listOf(collision("a.txt")),
                blocked = listOf("Elsewhere"),
            ),
        )

        assertTrue((prompt as TransferPrompt.NeedsCollisionChoice).allowKeepBoth)
    }

    @Test
    fun `a collision at the transfer root is matched against the root's own blocked entry`() {
        // parentOf("a.txt") is "", the landing directory. A blocked "" must
        // withhold keep-both for it -- an off-by-one in how the root is keyed
        // would silently allow an option that cannot work.
        val prompt = promptFor(proceed(collisions = listOf(collision("a.txt")), blocked = listOf("")))

        assertFalse((prompt as TransferPrompt.NeedsCollisionChoice).allowKeepBoth)
    }

    @Test
    fun `a refusal is shown instead of a collision prompt, never alongside it`() {
        val verdict = Verdict.Refused(listOf(Refusal.ReadOnlyDestination("Destination is read-only.")))

        assertTrue(promptFor(verdict) is TransferPrompt.Refused)
    }

    @Test
    fun `every refusal reason is listed, not just the first`() {
        val reasons = listOf(
            Refusal.InsufficientSpace(100, 10, false),
            Refusal.TypeMismatchCollision("Docs"),
        )

        val message = (promptFor(Verdict.Refused(reasons)) as TransferPrompt.Refused).message

        assertTrue(message, message.contains("2 reasons"))
        assertTrue(message, message.contains("only 10 are available"))
        assertTrue(message, message.contains("Docs"))
    }

    @Test
    fun `a single refusal is stated plainly, without a list`() {
        val message = refusalMessage(listOf(Refusal.TypeMismatchCollision("Docs")))

        assertFalse(message, message.contains("reasons:"))
        assertFalse(message, message.contains("•"))
    }

    // ---- progress honesty --------------------------------------------------

    private fun progress(
        done: Long,
        total: Long,
        lowerBound: Boolean = false,
        filesDone: Int = 1,
        filesTotal: Int = 4,
        path: String = "Docs/a.txt",
    ) = TransferProgress(filesDone, filesTotal, done, total, lowerBound, path)

    @Test
    fun `a known total gives a percentage and an ETA`() {
        val label = treeProgressLabel(progress(done = 500, total = 1000), elapsedMs = 1000)

        assertEquals(50, label.percent)
        assertEquals("1 of 4 files", label.files)
        assertEquals("Docs/a.txt", label.currentPath)
        // 500 bytes in 1 s, 500 left -> 1 s.
        assertEquals(1L, label.etaSeconds)
        assertFalse(label.isApproximate)
    }

    @Test
    fun `a lower-bound total is labelled as such`() {
        val label = treeProgressLabel(progress(done = 100, total = 1000, lowerBound = true), elapsedMs = 1000)

        assertTrue(label.bytes, label.bytes.contains("at least"))
    }

    @Test
    fun `passing a lower-bound total drops the percentage rather than pinning it at 100`() {
        // The source under-reported: more bytes have moved than the "total"
        // claimed. Reporting 100% while files are still copying is the lie that
        // teaches people the progress display cannot be trusted.
        val label = treeProgressLabel(progress(done = 1500, total = 1000, lowerBound = true), elapsedMs = 1000)

        assertNull(label.percent)
        assertTrue(label.isApproximate)
        assertNull("an ETA against a total known to be wrong counts down to a moving finish line", label.etaSeconds)
    }

    @Test
    fun `an unknown total yields no percentage`() {
        assertNull(treeProgressLabel(progress(done = 10, total = 0), elapsedMs = 1000).percent)
    }

    @Test
    fun `a percentage is clamped rather than exceeding 100`() {
        // Not lower-bound, so the total is meant to be exact and being over it
        // is a bug elsewhere -- but the bar still must not render past full.
        val label = treeProgressLabel(progress(done = 1200, total = 1000), elapsedMs = 1000)

        assertEquals(100, label.percent)
    }

    // ---- what a stopped transfer says --------------------------------------

    @Test
    fun `a stopped transfer names how far it got and where it stopped`() {
        val outcome = TransferOutcome(
            filesCopied = 37,
            filesSkipped = 0,
            dirsCreated = 4,
            bytesCopied = 1234,
            stoppedAtPath = "Photos/IMG_0041.jpg",
            failure = java.io.IOException("the session was locked"),
        )

        val summary = stoppedSummary(outcome, filesTotal = 40)

        // This is the sentence whose absence made a partial copy on 2026-08-23
        // indistinguishable from a finished one.
        assertTrue(summary, summary.contains("37 of 40 files"))
        assertTrue(summary, summary.contains("Photos/IMG_0041.jpg"))
        assertTrue(summary, summary.contains("has been kept"))
        assertTrue(summary, summary.contains("the session was locked"))
    }

    @Test
    fun `a cancelled transfer is described as cancelled, not as a failure`() {
        val outcome = TransferOutcome(2, 0, 1, 10, "c.txt", TransferCancelledException())

        val summary = stoppedSummary(outcome, filesTotal = 5)

        assertTrue(summary, summary.startsWith("Cancelled after"))
        // The cancellation's own message is noise; the user pressed the button.
        assertFalse(summary, summary.contains("transfer cancelled"))
    }

    @Test
    fun `a successful transfer reports the count without a stopping point`() {
        val summary = stoppedSummary(TransferOutcome(5, 0, 2, 99, null, null), filesTotal = 5)

        assertEquals("Copied 5 of 5 files.", summary)
    }
}
