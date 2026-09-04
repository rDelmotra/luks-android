package dev.luksandroid.transfer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The plan model carries three things execution depends on and cannot recompute:
 * parent-before-child ordering, per-directory child counts, and an honest total
 * byte count. Each is tested against a known-bad input as well as a good one --
 * a check that cannot fail is not a check (RULES.md:85).
 */
class TransferPlanTest {

    private fun dir(path: String) =
        PlanEntry(sourceId = "id:$path", relativePath = path, isDir = true, sizeBytes = 0, mtime = 0)

    private fun file(path: String, size: Long = 100, mtime: Long = 0) =
        PlanEntry(sourceId = "id:$path", relativePath = path, isDir = false, sizeBytes = size, mtime = mtime)

    private fun plan(vararg entries: PlanEntry) = TransferPlan("Photos", entries.toList())

    @Test
    fun `counts files and directories separately`() {
        val p = plan(dir("a"), file("a/x.jpg"), file("a/y.jpg"), dir("a/b"), file("a/b/z.jpg"))
        assertEquals(2, p.dirCount)
        assertEquals(3, p.fileCount)
    }

    @Test
    fun `totalBytes sums files only and ignores directories`() {
        val p = plan(dir("a"), file("a/x.jpg", 1000), file("a/y.jpg", 2000))
        assertEquals(3000, p.totalBytes)
        assertFalse(p.hasUnknownSizes)
    }

    @Test
    fun `unknown sizes are flagged and excluded rather than counted as zero silently`() {
        val p = plan(file("x.jpg", 1000), file("y.jpg", SIZE_UNKNOWN))
        assertEquals(1000, p.totalBytes)
        // The flag is the whole point: an ETA built from a lower bound must be
        // shown as approximate, not as a countdown that stalls at 100%.
        assertTrue(p.hasUnknownSizes)
    }

    @Test
    fun `childCountByDir counts direct children only, not descendants`() {
        val p = plan(
            dir("a"),
            file("a/x.jpg"),
            file("a/y.jpg"),
            dir("a/b"),
            file("a/b/1.jpg"),
            file("a/b/2.jpg"),
            file("a/b/3.jpg"),
        )
        // "a" holds x, y and the directory b -- three entries, not six.
        assertEquals(3, p.childCountByDir["a"])
        assertEquals(3, p.childCountByDir["a/b"])
    }

    @Test
    fun `top-level entries are children of the root key`() {
        val p = plan(dir("a"), file("top.jpg"))
        assertEquals(2, p.childCountByDir[""])
    }

    @Test
    fun `parent-before-child ordering is accepted when correct`() {
        plan(dir("a"), dir("a/b"), file("a/b/z.jpg")).checkParentBeforeChild()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a child preceding its parent is rejected`() {
        // Execution creates directories in list order and assumes the parent
        // exists. If this ordering silently broke, the import would fail
        // mid-tree on a real device instead of here.
        plan(file("a/b/z.jpg"), dir("a"), dir("a/b")).checkParentBeforeChild()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a file under a directory that is not in the plan is rejected`() {
        plan(dir("a"), file("a/missing/z.jpg")).checkParentBeforeChild()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a file cannot act as a parent`() {
        plan(file("a"), file("a/z.jpg")).checkParentBeforeChild()
    }

    @Test
    fun `mtime is carried through so import can preserve it`() {
        val p = plan(file("x.jpg", 10, mtime = 1_700_000_000_000))
        assertEquals(1_700_000_000_000, p.entries.single().mtime)
    }
}
