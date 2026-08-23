package dev.luksandroid.transfer

import dev.luksandroid.StatFsInfo
import dev.luksandroid.SubvolumeInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Table-driven tests for [precheckTransfer]. Per RULES.md:85, every check here
 * has a paired case that trips it -- a verifier that cannot fail on a known-bad
 * input is not verifying.
 */
class TransferPrecheckTest {

    private fun dir(path: String) =
        PlanEntry(sourceId = "id:$path", relativePath = path, isDir = true, sizeBytes = 0, mtime = 0)

    private fun file(path: String, size: Long = 100, mtime: Long = 0) =
        PlanEntry(sourceId = "id:$path", relativePath = path, isDir = false, sizeBytes = size, mtime = mtime)

    private fun plan(vararg entries: PlanEntry) = TransferPlan("Photos", entries.toList())

    private fun statFs(
        totalBytes: Long = 1_000_000_000,
        freeBytes: Long = 1_000_000_000,
        availableBytes: Long = 1_000_000_000,
        blockSize: Int = 4096,
    ) = StatFsInfo(
        totalBytes = totalBytes,
        freeBytes = freeBytes,
        availableBytes = availableBytes,
        totalInodes = 1_000_000,
        freeInodes = 1_000_000,
        blockSize = blockSize,
    )

    private fun destination(
        statFs: StatFsInfo = statFs(),
        fsType: String = "ext4",
        listing: DestinationListing = DestinationListing(),
        subvolumes: List<SubvolumeInfo> = emptyList(),
        targetPath: String = "/dest",
    ) = Destination(statFs = statFs, fsType = fsType, listing = listing, subvolumes = subvolumes, targetPath = targetPath)

    private fun listingOf(vararg dirs: Pair<String, List<DestinationEntry>>) =
        DestinationListing(dirs.toMap())

    private fun subvol(id: Long, name: String, path: String, readOnly: Boolean) =
        SubvolumeInfo(id = id, name = name, path = path, readOnly = readOnly)

    // ---- collisions do not consume new directory slots ----

    @Test
    fun `re-importing an identical folder is not refused, because a collision reuses its entry`() {
        // §5.2 makes re-running an import the documented way to resume after a
        // failure. Counting existing + new wholesale double-counts every
        // colliding name, which refused exactly that case: 120 files landing on
        // 120 identical names was reported as 241 entries against a 203 ceiling,
        // when the real result is still 120.
        val names = (1..120).map { "f$it.jpg" }
        val p = plan(*names.map { file(it) }.toTypedArray())
        val existing = listingOf("" to names.map { DestinationEntry(it, isDir = false) })

        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))

        assertTrue("resume must not be refused, got $v", v is Verdict.Proceed)
        assertEquals(120, (v as Verdict.Proceed).fileCollisions.size)
    }

    @Test
    fun `a directory merge does not consume a new entry either`() {
        val names = (1..120).map { "sub$it" }
        val p = plan(*names.map { dir(it) }.toTypedArray())
        val existing = listingOf("" to names.map { DestinationEntry(it, isDir = true) })

        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))

        assertTrue("merging into existing dirs must not be refused, got $v", v is Verdict.Proceed)
        assertEquals(120, (v as Verdict.Proceed).directoryMerges.size)
    }

    @Test
    fun `keep-both is blocked, not refused, when only it would breach the ceiling`() {
        // 200 existing + 200 colliding: skip and replace both land on 200
        // entries (+1 transient for replace's temp), which fits. Only keep-both
        // would need 400. That constrains the option, not the transfer.
        val names = (1..200).map { "f$it.jpg" }
        val p = plan(*names.map { file(it) }.toTypedArray())
        val existing = listingOf("" to names.map { DestinationEntry(it, isDir = false) })

        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))

        assertTrue("must proceed with keep-both restricted, got $v", v is Verdict.Proceed)
        assertEquals(listOf(""), (v as Verdict.Proceed).keepBothBlockedDirs)
    }

    @Test
    fun `keep-both is left available when there is headroom for it`() {
        val names = (1..10).map { "f$it.jpg" }
        val p = plan(*names.map { file(it) }.toTypedArray())
        val existing = listingOf("" to names.map { DestinationEntry(it, isDir = false) })

        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))

        assertEquals(emptyList<String>(), (v as Verdict.Proceed).keepBothBlockedDirs)
    }

    @Test
    fun `a directory still over the ceiling on non-colliding names alone is refused`() {
        // The floor must still refuse: 100 existing names, 150 brand-new ones,
        // no overlap at all -- no collision policy can bring that under 203.
        val existingNames = (1..100).map { "old$it.jpg" }
        val p = plan(*(1..150).map { file("new$it.jpg") }.toTypedArray())
        val existing = listingOf("" to existingNames.map { DestinationEntry(it, isDir = false) })

        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))

        assertTrue("250 unavoidable entries must still refuse, got $v", v is Verdict.Refused)
    }

    // ---- free space ----

    @Test
    fun `proceeds when the plan fits within available bytes`() {
        val p = plan(file("a.jpg", 500))
        val v = precheckTransfer(p, destination(statFs = statFs(availableBytes = 1000)))
        assertTrue(v is Verdict.Proceed)
    }

    @Test
    fun `refuses when the plan does not fit`() {
        val p = plan(file("a.jpg", 5000))
        val v = precheckTransfer(p, destination(statFs = statFs(availableBytes = 1000)))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.InsufficientSpace })
    }

    @Test
    fun `unknown sizes make a fitting total a lower bound, not a guarantee`() {
        val p = plan(file("a.jpg", 500), file("b.jpg", SIZE_UNKNOWN))
        val v = precheckTransfer(p, destination(statFs = statFs(availableBytes = 1000)))
        assertTrue(v is Verdict.Proceed)
        assertTrue((v as Verdict.Proceed).sizeIsLowerBound)
    }

    // ---- ext4 directory-entry ceiling ----

    @Test
    fun `ext4 ceiling is derived from a 4KiB block, not hardcoded`() {
        // 203 entries fits exactly; the check must key off blockSize, confirmed by
        // core-tests-statfs.rs (measure_ext4_directory_capacity_ceiling): a 4 KiB
        // single-block ext4 directory holds exactly 203 entries.
        val entries = (1..203).map { file("f_%04d.txt".format(it)) }
        val p = plan(*entries.toTypedArray())
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096)))
        assertTrue(v is Verdict.Proceed)
    }

    @Test
    fun `one entry over the 4KiB ceiling is refused`() {
        val entries = (1..204).map { file("f_%04d.txt".format(it)) }
        val p = plan(*entries.toTypedArray())
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096)))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.DirectoryEntryCeilingExceeded })
    }

    @Test
    fun `identical entry count that trips ext4 passes on btrfs`() {
        val entries = (1..204).map { file("f_%04d.txt".format(it)) }
        val p = plan(*entries.toTypedArray())
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), fsType = "btrfs"))
        assertTrue(v is Verdict.Proceed)
    }

    @Test
    fun `1KiB block ceiling is 49, not the 4KiB constant`() {
        val fits = (1..49).map { file("f_%04d.txt".format(it)) }
        val okVerdict = precheckTransfer(plan(*fits.toTypedArray()), destination(statFs = statFs(blockSize = 1024)))
        assertTrue(okVerdict is Verdict.Proceed)

        val overflow = (1..50).map { file("f_%04d.txt".format(it)) }
        val refusedVerdict = precheckTransfer(plan(*overflow.toTypedArray()), destination(statFs = statFs(blockSize = 1024)))
        assertTrue(refusedVerdict is Verdict.Refused)
    }

    @Test
    fun `temp slot for a possible replace can tip a directory over the ceiling`() {
        // 100 existing (one of them "dup.txt") + 103 genuinely new names lands on
        // exactly 203, the ceiling. The colliding "dup.txt" reuses its entry and
        // adds nothing, so the only thing left that can tip this over is the one
        // transient slot replace's write-temp-then-rename needs -- 204, refused.
        // Paired with the control below, which is the same directory one entry
        // lighter and therefore fits.
        val existingFiles = (1..99).map { DestinationEntry("e_%04d.txt".format(it), isDir = false) } +
            DestinationEntry("dup.txt", isDir = false)
        val newFiles = (1..103).map { file("n_%04d.txt".format(it)) } + file("dup.txt")
        val p = plan(*newFiles.toTypedArray())
        val existing = listingOf("" to existingFiles)
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))
        assertTrue("expected the temp slot to tip this over, got $v", v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.DirectoryEntryCeilingExceeded })
    }

    @Test
    fun `control - the same directory without a collision needs no temp slot and fits`() {
        // Identical entry count to the case above, minus the collision. No
        // collision means no replace, means no temp slot: 100 + 103 = 203, which
        // is exactly the ceiling and must pass. If this ever refuses, the temp
        // slot is being charged unconditionally rather than only when replace
        // could actually be chosen.
        val existingFiles = (1..100).map { DestinationEntry("e_%04d.txt".format(it), isDir = false) }
        val newFiles = (1..103).map { file("n_%04d.txt".format(it)) }
        val p = plan(*newFiles.toTypedArray())
        val existing = listingOf("" to existingFiles)
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))
        assertTrue("203 entries is exactly the ceiling and must fit, got $v", v is Verdict.Proceed)
    }

    @Test
    fun `existing destination entries count toward the ceiling, not just the plan's`() {
        // Plan alone is only 3 entries, comfortably under any ceiling, but the
        // destination directory already has 202 unrelated entries.
        val p = plan(file("new1.txt"), file("new2.txt"), file("new3.txt"))
        val existing = listingOf("" to (1..202).map { DestinationEntry("existing_%04d.txt".format(it), isDir = false) })
        val v = precheckTransfer(p, destination(statFs = statFs(blockSize = 4096), listing = existing))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.DirectoryEntryCeilingExceeded })
    }

    // ---- collisions ----

    @Test
    fun `directory vs directory collision merges silently`() {
        val p = plan(dir("Photos"), file("Photos/a.jpg"))
        val existing = listingOf("" to listOf(DestinationEntry("Photos", isDir = true)))
        val v = precheckTransfer(p, destination(listing = existing))
        assertTrue(v is Verdict.Proceed)
        val proceed = v as Verdict.Proceed
        assertEquals(1, proceed.directoryMerges.size)
        assertEquals("Photos", proceed.directoryMerges.single().relativePath)
        assertTrue(proceed.fileCollisions.isEmpty())
    }

    @Test
    fun `file vs file collision is reported as a question, not a refusal`() {
        val p = plan(file("notes.txt"))
        val existing = listingOf("" to listOf(DestinationEntry("notes.txt", isDir = false)))
        val v = precheckTransfer(p, destination(listing = existing))
        assertTrue(v is Verdict.Proceed)
        val proceed = v as Verdict.Proceed
        assertEquals(1, proceed.fileCollisions.size)
        assertEquals("notes.txt", proceed.fileCollisions.single().relativePath)
    }

    @Test
    fun `file colliding with an existing directory of the same name is refused`() {
        val p = plan(file("Photos"))
        val existing = listingOf("" to listOf(DestinationEntry("Photos", isDir = true)))
        val v = precheckTransfer(p, destination(listing = existing))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.TypeMismatchCollision })
    }

    @Test
    fun `directory colliding with an existing file of the same name is refused`() {
        val p = plan(dir("notes.txt"))
        val existing = listingOf("" to listOf(DestinationEntry("notes.txt", isDir = false)))
        val v = precheckTransfer(p, destination(listing = existing))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.TypeMismatchCollision })
    }

    // ---- read-only btrfs subvolume ----

    @Test
    fun `destination inside a read-only subvolume is refused up front`() {
        val p = plan(file("a.jpg"))
        val subvolumes = listOf(subvol(id = 300, name = "snap", path = "snap", readOnly = true))
        val v = precheckTransfer(p, destination(fsType = "btrfs", subvolumes = subvolumes, targetPath = "/snap/incoming"))
        assertTrue(v is Verdict.Refused)
        assertTrue((v as Verdict.Refused).reasons.any { it is Refusal.ReadOnlyDestination })
    }

    @Test
    fun `destination in a writable subvolume proceeds`() {
        val p = plan(file("a.jpg"))
        val subvolumes = listOf(subvol(id = 5, name = "root", path = "", readOnly = false))
        val v = precheckTransfer(p, destination(fsType = "btrfs", subvolumes = subvolumes, targetPath = "/incoming"))
        assertTrue(v is Verdict.Proceed)
    }
}
