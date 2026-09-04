package dev.luksandroid.transfer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * [DirectoryWalker] tests all run against a fake [ChildSource] -- a plain map
 * from directory id to its children, with every call recorded. That recording
 * is what lets "one query per directory" be asserted rather than assumed: it
 * is the exact IPC-per-directory-not-per-file property §2.1 of
 * notes/feature-directory-transfer.md exists to protect, and a walker that
 * regressed to per-file queries would still produce a correct plan, so no
 * assertion about plan *contents* would ever catch it.
 */
class DirectoryWalkerTest {

    /** Records every [children] call so tests can assert call counts, not just results. */
    private class FakeChildSource(private val tree: Map<String, List<RawChild>>) : ChildSource {
        val calls = mutableListOf<String>()

        override fun children(parentId: String): List<RawChild> {
            calls += parentId
            return tree[parentId] ?: error("fake source has no entry for '$parentId' -- test bug")
        }
    }

    private fun file(id: String, name: String, size: Long = 100, mtime: Long = 0) =
        RawChild(id = id, name = name, isDir = false, sizeBytes = size, mtime = mtime)

    private fun dir(id: String, name: String, mtime: Long = 0) =
        RawChild(id = id, name = name, isDir = true, sizeBytes = 0, mtime = mtime)

    @Test
    fun `nested tree is emitted parent before child with correct relative paths`() {
        val source = FakeChildSource(
            mapOf(
                "root" to listOf(dir("d:a", "a"), file("f:top", "top.jpg")),
                "d:a" to listOf(file("f:x", "x.jpg"), dir("d:b", "b")),
                "d:b" to listOf(file("f:z", "z.jpg")),
            )
        )

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Photos")

        val paths = plan.entries.map { it.relativePath }
        assertEquals(listOf("a", "top.jpg", "a/x.jpg", "a/b", "a/b/z.jpg"), paths)
        assertEquals(2, plan.dirCount)
        assertEquals(3, plan.fileCount)

        // Belt and braces: the walker's own self-check must also agree.
        plan.checkParentBeforeChild()
    }

    @Test
    fun `empty directories are emitted as entries and survive`() {
        val source = FakeChildSource(
            mapOf(
                "root" to listOf(dir("d:empty", "Empty")),
                "d:empty" to emptyList(),
            )
        )

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        assertEquals(1, plan.entries.size)
        assertEquals("Empty", plan.entries.single().relativePath)
        assertTrue(plan.entries.single().isDir)
    }

    @Test
    fun `a directory that fails to enumerate fails the whole walk`() {
        val source = FakeChildSource(
            mapOf(
                "root" to listOf(dir("d:bad", "Bad"), file("f:ok", "ok.txt")),
                // "d:bad" deliberately absent -- FakeChildSource.children() throws for it,
                // standing in for a real children() call that throws (e.g. a permission
                // error or a dead SAF provider).
            )
        )

        try {
            DirectoryWalker.walk(source, rootId = "root", rootName = "Root")
            fail("expected the unreadable directory to fail the whole walk")
        } catch (_: IllegalStateException) {
            // Enumeration is side-effect-free, so failing outright rather than
            // returning a plan with "Bad" silently missing is the documented
            // choice -- a partial plan would produce a silently incomplete copy.
        }
    }

    @Test
    fun `a directory beyond the depth cap aborts instead of truncating`() {
        // Build a source that answers "one nested directory" no matter how deep
        // the walker asks -- if the cap did not trip, this would recurse forever.
        val source = ChildSource { parentId -> listOf(dir("$parentId/x", "x")) }

        try {
            DirectoryWalker.walk(source, rootId = "root", rootName = "Root", maxDepth = 3)
            fail("expected the depth cap to trip")
        } catch (e: DirectoryWalker.DepthExceededException) {
            assertEquals(3, e.maxDepth)
        }
    }

    @Test
    fun `children is called exactly once per directory and never twice`() {
        val source = FakeChildSource(
            mapOf(
                "root" to listOf(dir("d:a", "a"), dir("d:b", "b")),
                "d:a" to listOf(dir("d:a1", "a1")),
                "d:a1" to emptyList(),
                "d:b" to emptyList(),
            )
        )

        DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        assertEquals(listOf("d:a", "d:a1", "d:b", "root"), source.calls.sorted())
        assertEquals(4, source.calls.size)
        assertEquals(source.calls.size, source.calls.toSet().size)
    }

    @Test
    fun `children is never called per file`() {
        // A directory with many files must still cost exactly one children() call.
        val manyFiles = (1..500).map { file("f:$it", "file$it.txt") }
        val source = FakeChildSource(mapOf("root" to manyFiles))

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        assertEquals(500, plan.fileCount)
        assertEquals(1, source.calls.size)
    }

    @Test
    fun `unknown file size survives and is never coerced to zero`() {
        val source = FakeChildSource(
            mapOf("root" to listOf(file("f:x", "x.bin", size = SIZE_UNKNOWN)))
        )

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        assertEquals(SIZE_UNKNOWN, plan.entries.single().sizeBytes)
        assertFalse(plan.entries.single().sizeBytes == 0L)
    }

    @Test
    fun `mtime is carried through for files and directories`() {
        val source = FakeChildSource(
            mapOf(
                "root" to listOf(dir("d:a", "a", mtime = 1_600_000_000_000)),
                "d:a" to listOf(file("f:x", "x.jpg", mtime = 1_700_000_000_000)),
            )
        )

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        val byPath = plan.entries.associateBy { it.relativePath }
        assertEquals(1_600_000_000_000, byPath.getValue("a").mtime)
        assertEquals(1_700_000_000_000, byPath.getValue("a/x.jpg").mtime)
    }

    @Test
    fun `directories always report zero size regardless of what the source sends`() {
        // RawChild.sizeBytes is documented as always 0 for directories, but the
        // walker must enforce that rather than trust the source blindly.
        val weirdDir = RawChild(id = "d:a", name = "a", isDir = true, sizeBytes = 999, mtime = 0)
        val source = FakeChildSource(mapOf("root" to listOf(weirdDir), "d:a" to emptyList()))

        val plan = DirectoryWalker.walk(source, rootId = "root", rootName = "Root")

        assertEquals(0L, plan.entries.single().sizeBytes)
    }
}
