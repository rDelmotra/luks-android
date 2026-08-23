package dev.luksandroid.transfer

import dev.luksandroid.Entry
import dev.luksandroid.LuksVolume
import dev.luksandroid.VolumeInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Pass 3 execution, run against an in-memory fake volume rather than
 * hardware -- there is no Robolectric or mocking framework in this module
 * (`unitTests.isReturnDefaultValues = true`), so [FakeVolume] below is the
 * only way to get real coverage of [TreeImporter.importTree]. Every
 * significant behaviour here also has a deliberate-break record: see the
 * report accompanying this file for the "broken on purpose, watched fail"
 * table RULES.md:85 requires.
 */
private fun join(dir: String, name: String) = if (dir == "/") "/$name" else "$dir/$name"

class TreeImporterTest {

    private fun dir(path: String) = PlanEntry("id:$path", path, isDir = true, sizeBytes = 0, mtime = 0)

    private fun file(path: String, size: Long = -1, mtime: Long = 0) =
        PlanEntry("id:$path", path, isDir = false, sizeBytes = size, mtime = mtime)

    private fun plan(vararg entries: PlanEntry) = TransferPlan("root", entries.toList())

    // ---- fake volume -------------------------------------------------------

    /**
     * A directory tree held entirely in memory. Every method [TreeImporter]
     * touches is overridden so no test call ever reaches [dev.luksandroid.LuksNative],
     * which does not exist as a loaded `.so` under plain JUnit.
     */
    private class FakeVolume : LuksVolume(0L) {
        private sealed class Node {
            class Dir : Node()
            class File(var data: ByteArray) : Node()
        }

        private val tree = mutableMapOf<String, MutableMap<String, Node>>()

        var failWriteAfterTotalBytes: Long? = null
        var failCreateDirectoryFor: String? = null // "parentPath/name"
        var failRenameForNewName: String? = null
        /** Simulates the session dying mid-tree: every listDir past this many calls throws. */
        var failListDirAfterCalls: Int? = null
        private var listDirCalls = 0
        val deletedPaths = mutableListOf<String>()
        /** Bumped only when a writer commits (never on abandon) -- "files actually landed", for cancellation timing. */
        var finishedFileCount = 0
        private var totalBytesWritten = 0L

        override val info = VolumeInfo("fake", "uuid", 4096, 0L, "ext4", emptyList())

        /**
         * Deliberately strict: a real volume does not have a directory just
         * because someone asks for its listing. Unlike an earlier version of
         * this fake, this never auto-creates a map for an unseen path -- doing
         * that silently tolerated a mkdir-then-descend ordering bug (writing
         * into a directory nobody had created yet), which is exactly the
         * invariant [TreeImporter] must not violate.
         */
        private fun dirOf(path: String): MutableMap<String, Node> =
            tree[path] ?: error(
                "FakeVolume: no directory registered at '$path' -- seedRoot/seedDir it first, " +
                    "or this is TreeImporter touching a directory before creating it",
            )

        private fun provisionDir(path: String) = tree.getOrPut(path) { mutableMapOf() }

        /** The landing directory itself is assumed pre-existing, the same way [TreeImporter]'s caller assumes it. */
        fun seedRoot(path: String) {
            provisionDir(path)
        }

        fun seedDir(parent: String, name: String) {
            dirOf(parent)[name] = Node.Dir()
            provisionDir(join(parent, name))
        }

        fun seedFile(parent: String, name: String, data: ByteArray) {
            dirOf(parent)[name] = Node.File(data)
        }

        fun fileAt(parent: String, name: String): ByteArray? = (dirOf(parent)[name] as? Node.File)?.data

        fun namesAt(parent: String): Set<String> = dirOf(parent).keys.toSet()

        fun isDirAt(parent: String, name: String): Boolean? = dirOf(parent)[name]?.let { it is Node.Dir }

        override fun listDir(path: String): List<Entry> {
            listDirCalls++
            failListDirAfterCalls?.let {
                if (listDirCalls > it) throw IllegalStateException("session died")
            }
            return dirOf(path).map { (name, node) ->
                when (node) {
                    is Node.Dir -> Entry(name, "dir")
                    is Node.File -> Entry(name, "file", size = node.data.size.toLong())
                }
            }
        }

        override fun createDirectory(parentPath: String, name: String): Long {
            if (failCreateDirectoryFor == "$parentPath/$name") {
                throw IOException("simulated createDirectory failure at $parentPath/$name")
            }
            dirOf(parentPath)[name] = Node.Dir()
            provisionDir(join(parentPath, name))
            return 1L
        }

        override fun rename(oldParent: String, oldName: String, newParent: String, newName: String) {
            if (failRenameForNewName == newName) {
                throw IOException("simulated rename failure to $newName")
            }
            val node = dirOf(oldParent).remove(oldName) ?: error("rename: no entry $oldParent/$oldName")
            dirOf(newParent)[newName] = node
        }

        override fun deleteFile(path: String) {
            deletedPaths += path
            val parent = path.substringBeforeLast('/', "").ifEmpty { "/" }
            val name = path.substringAfterLast('/')
            dirOf(parent).remove(name)
        }

        val writersCreated = mutableListOf<FakeWriter>()

        override fun beginFileStreaming(): FileWriter = FakeWriter().also { writersCreated += it }

        inner class FakeWriter : FileWriter(0L) {
            private val buffer = ByteArrayOutputStream()
            var abandoned = false
                private set

            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                buffer.write(bytes, offset, length)
                totalBytesWritten += length
                failWriteAfterTotalBytes?.let { threshold ->
                    if (totalBytesWritten >= threshold) throw IOException("simulated write failure")
                }
            }

            override fun finish(parentPath: String, name: String): Long {
                dirOf(parentPath)[name] = Node.File(buffer.toByteArray())
                finishedFileCount++
                return 1L
            }

            override fun abandon() {
                abandoned = true
            }
        }
    }

    private class FakeSource(private val bytesById: Map<String, ByteArray>) : SourceBytes {
        override fun open(sourceId: String) = ByteArrayInputStream(bytesById.getValue(sourceId))
    }

    private lateinit var volume: FakeVolume

    @Before
    fun setUp() {
        volume = FakeVolume()
        // Every test lands in "/dst"; the landing directory itself is assumed
        // pre-existing, same as the real caller creates or merges it before
        // TreeImporter ever runs (see the class doc on destinationRootPath).
        volume.seedRoot("/dst")
    }

    // ---- nested tree, structure and content --------------------------------

    @Test
    fun `imports a nested tree with correct structure and byte content`() {
        val aBytes = "hello a".toByteArray()
        val bBytes = "hello b, deeper".toByteArray()
        val p = plan(
            dir("a"),
            file("a/x.txt", aBytes.size.toLong()),
            dir("a/b"),
            file("a/b/y.txt", bBytes.size.toLong()),
        )
        val source = FakeSource(mapOf("id:a/x.txt" to aBytes, "id:a/b/y.txt" to bBytes))

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP)

        assertTrue(outcome.succeeded)
        assertNull(outcome.stoppedAtPath)
        assertEquals(2, outcome.dirsCreated)
        assertEquals(2, outcome.filesCopied)
        assertEquals(0, outcome.filesSkipped)
        assertEquals((aBytes.size + bBytes.size).toLong(), outcome.bytesCopied)

        assertEquals(true, volume.isDirAt("/dst", "a"))
        assertEquals(true, volume.isDirAt("/dst/a", "b"))
        assertArrayEquals(aBytes, volume.fileAt("/dst/a", "x.txt"))
        assertArrayEquals(bBytes, volume.fileAt("/dst/a/b", "y.txt"))
    }

    @Test
    fun `empty directories are created`() {
        val p = plan(dir("EmptyOne"), dir("EmptyOne/EmptyTwo"))
        val outcome = TreeImporter.importTree(volume, p, "/dst", FakeSource(emptyMap()), CollisionMode.SKIP)

        assertTrue(outcome.succeeded)
        assertEquals(2, outcome.dirsCreated)
        assertEquals(true, volume.isDirAt("/dst", "EmptyOne"))
        assertEquals(true, volume.isDirAt("/dst/EmptyOne", "EmptyTwo"))
        assertTrue(volume.namesAt("/dst/EmptyOne/EmptyTwo").isEmpty())
    }

    @Test
    fun `merge - a directory that already exists is not recreated and does not error`() {
        volume.seedDir("/dst", "Photos")
        volume.seedFile("/dst/Photos", "already-here.txt", "old".toByteArray())

        val newBytes = "new file".toByteArray()
        val p = plan(dir("Photos"), file("Photos/new.txt", newBytes.size.toLong()))
        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:Photos/new.txt" to newBytes)), CollisionMode.SKIP,
        )

        assertTrue(outcome.succeeded)
        // The directory was not (re)created -- it already existed as a merge target.
        assertEquals(0, outcome.dirsCreated)
        assertEquals(1, outcome.filesCopied)
        // The pre-existing sibling survived the merge untouched.
        assertArrayEquals("old".toByteArray(), volume.fileAt("/dst/Photos", "already-here.txt"))
        assertArrayEquals(newBytes, volume.fileAt("/dst/Photos", "new.txt"))
    }

    // ---- collision modes -----------------------------------------------------

    private fun seedCollision(): ByteArray {
        val original = "original bytes".toByteArray()
        volume.seedFile("/dst", "photo.jpg", original)
        return original
    }

    @Test
    fun `collision SKIP leaves the original bytes untouched`() {
        val original = seedCollision()
        val newBytes = "new bytes".toByteArray()
        val p = plan(file("photo.jpg", newBytes.size.toLong()))

        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:photo.jpg" to newBytes)), CollisionMode.SKIP,
        )

        assertTrue(outcome.succeeded)
        assertEquals(0, outcome.filesCopied)
        assertEquals(1, outcome.filesSkipped)
        assertArrayEquals(original, volume.fileAt("/dst", "photo.jpg"))
        assertEquals(setOf("photo.jpg"), volume.namesAt("/dst"))
    }

    @Test
    fun `collision KEEP_BOTH produces both files with a suffixed name`() {
        val original = seedCollision()
        val newBytes = "new bytes".toByteArray()
        val p = plan(file("photo.jpg", newBytes.size.toLong()))

        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:photo.jpg" to newBytes)), CollisionMode.KEEP_BOTH,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesCopied)
        assertEquals(0, outcome.filesSkipped)
        assertArrayEquals(original, volume.fileAt("/dst", "photo.jpg"))
        assertArrayEquals(newBytes, volume.fileAt("/dst", "photo (1).jpg"))
        assertEquals(setOf("photo.jpg", "photo (1).jpg"), volume.namesAt("/dst"))
    }

    @Test
    fun `collision REPLACE leaves exactly one file with the new bytes`() {
        seedCollision()
        val newBytes = "replacement bytes".toByteArray()
        val p = plan(file("photo.jpg", newBytes.size.toLong()))

        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:photo.jpg" to newBytes)), CollisionMode.REPLACE,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesCopied)
        assertArrayEquals(newBytes, volume.fileAt("/dst", "photo.jpg"))
        // Exactly one entry survives -- the temp name used to get there is gone.
        assertEquals(setOf("photo.jpg"), volume.namesAt("/dst"))
    }

    @Test
    fun `REPLACE mid-write failure leaves the original intact and no temp entry behind`() {
        val original = seedCollision()
        val newBytes = ByteArray(TreeImporter.CHUNK_SIZE * 3) { it.toByte() } // multiple chunks
        volume.failWriteAfterTotalBytes = TreeImporter.CHUNK_SIZE.toLong() // fail during the temp write

        val p = plan(file("photo.jpg", newBytes.size.toLong()))
        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:photo.jpg" to newBytes)), CollisionMode.REPLACE,
        )

        assertFalse(outcome.succeeded)
        assertNotNull(outcome.failure)
        assertEquals("photo.jpg", outcome.stoppedAtPath)
        assertEquals(0, outcome.filesCopied)
        // Original untouched, and the abandoned temp write never left an entry.
        assertArrayEquals(original, volume.fileAt("/dst", "photo.jpg"))
        assertEquals(setOf("photo.jpg"), volume.namesAt("/dst"))
        // The writer that took the failure must have been abandoned, not left
        // dangling -- this is the actual claim "no temp turd" depends on.
        assertEquals(1, volume.writersCreated.size)
        assertTrue(volume.writersCreated.single().abandoned)
    }

    @Test
    fun `REPLACE rename failure cleans up the temp entry and leaves the original intact`() {
        val original = seedCollision()
        val newBytes = "replacement".toByteArray()
        // The temp name is unknown to the test (it's timestamp-derived), so
        // force every rename in this run to fail regardless of target.
        volume.failRenameForNewName = "photo.jpg"

        val p = plan(file("photo.jpg", newBytes.size.toLong()))
        val outcome = TreeImporter.importTree(
            volume, p, "/dst", FakeSource(mapOf("id:photo.jpg" to newBytes)), CollisionMode.REPLACE,
        )

        assertFalse(outcome.succeeded)
        assertNotNull(outcome.failure)
        assertEquals("photo.jpg", outcome.stoppedAtPath)
        assertArrayEquals(original, volume.fileAt("/dst", "photo.jpg"))
        // Exactly the original survives -- the temp file the write succeeded
        // into was deleted once the rename over it failed.
        assertEquals(setOf("photo.jpg"), volume.namesAt("/dst"))
        assertTrue(volume.deletedPaths.isNotEmpty())
    }

    // ---- uniqueName: pure name suffixing --------------------------------------

    @Test
    fun `uniqueName returns the desired name when nothing collides`() {
        assertEquals("photo.jpg", uniqueName(emptyList(), "photo.jpg"))
    }

    @Test
    fun `uniqueName preserves the extension and increments across multiple collisions`() {
        assertEquals("photo (1).jpg", uniqueName(listOf("photo.jpg"), "photo.jpg"))
        assertEquals("photo (2).jpg", uniqueName(listOf("photo.jpg", "photo (1).jpg"), "photo.jpg"))
        assertEquals(
            "photo (3).jpg",
            uniqueName(listOf("photo.jpg", "photo (1).jpg", "photo (2).jpg"), "photo.jpg"),
        )
    }

    @Test
    fun `uniqueName treats a dotfile as pure stem with no extension`() {
        assertEquals(".gitignore (1)", uniqueName(listOf(".gitignore"), ".gitignore"))
    }

    @Test
    fun `uniqueName truncates the stem, never the suffix or extension, to stay within 255 bytes`() {
        val longStem = "a".repeat(300)
        val desired = "$longStem.txt"
        val result = uniqueName(listOf(desired), desired)

        assertTrue(result.toByteArray(Charsets.UTF_8).size <= 255)
        assertTrue("suffix must survive truncation", result.endsWith(" (1).txt"))
        assertFalse("extension must never be truncated", result.endsWith(".tx") || result.endsWith(".t"))
    }

    // ---- stop-on-error and cancellation -----------------------------------------

    @Test
    fun `stop-on-error keeps the intact prefix and reports an accurate count and path`() {
        val fileSize = TreeImporter.CHUNK_SIZE.toLong()
        val bytesFor = { n: Int -> ByteArray(fileSize.toInt()) { n.toByte() } }
        val p = plan(
            file("one.bin", fileSize),
            file("two.bin", fileSize),
            file("three.bin", fileSize),
            file("four.bin", fileSize),
        )
        val source = FakeSource(
            mapOf(
                "id:one.bin" to bytesFor(1),
                "id:two.bin" to bytesFor(2),
                "id:three.bin" to bytesFor(3),
                "id:four.bin" to bytesFor(4),
            ),
        )
        // Two files' worth of chunks succeed; the third's write throws.
        volume.failWriteAfterTotalBytes = fileSize * 2 + 1

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP)

        assertFalse(outcome.succeeded)
        assertNotNull(outcome.failure)
        assertEquals("three.bin", outcome.stoppedAtPath)
        assertEquals(2, outcome.filesCopied)
        assertEquals(fileSize * 2, outcome.bytesCopied)
        assertArrayEquals(bytesFor(1), volume.fileAt("/dst", "one.bin"))
        assertArrayEquals(bytesFor(2), volume.fileAt("/dst", "two.bin"))
        // Neither the failed file nor anything after it landed.
        assertNull(volume.fileAt("/dst", "three.bin"))
        assertNull(volume.fileAt("/dst", "four.bin"))
    }

    @Test
    fun `cancellation mid-tree stops cleanly with the completed prefix intact`() {
        val p = plan(file("one.bin", 3), file("two.bin", 3), file("three.bin", 3))
        val bytesById = mapOf(
            "id:one.bin" to byteArrayOf(1, 1, 1),
            "id:two.bin" to byteArrayOf(2, 2, 2),
            "id:three.bin" to byteArrayOf(3, 3, 3),
        )
        // Progress is throttled to ~200ms, so it is not a reliable signal for a
        // fast unit test to key cancellation off of. isCancelled is polled both
        // between entries and mid-chunk, so gating on "files opened" would trip
        // the check while the second file's own write is still in flight.
        // "Files actually committed" only advances once a write finishes, which
        // is exactly the point after which stopping is clean.
        val source = FakeSource(bytesById)
        val outcome = TreeImporter.importTree(
            volume, p, "/dst", source, CollisionMode.SKIP,
            isCancelled = { volume.finishedFileCount >= 2 },
        )

        assertFalse(outcome.succeeded)
        assertTrue(outcome.failure is ImportCancelledException)
        assertEquals("three.bin", outcome.stoppedAtPath)
        assertEquals(2, outcome.filesCopied)
        assertArrayEquals(byteArrayOf(1, 1, 1), volume.fileAt("/dst", "one.bin"))
        assertArrayEquals(byteArrayOf(2, 2, 2), volume.fileAt("/dst", "two.bin"))
        assertNull(volume.fileAt("/dst", "three.bin"))
    }

    // ---- progress ----------------------------------------------------------------

    @Test
    fun `progress fires with correct totals and always fires a final update`() {
        val p = plan(file("a.bin", 10), file("b.bin", 20))
        val source = FakeSource(mapOf("id:a.bin" to ByteArray(10), "id:b.bin" to ByteArray(20)))
        val updates = mutableListOf<ImportProgress>()

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP, onProgress = { updates += it })

        assertTrue(outcome.succeeded)
        assertTrue("at least the final update must fire", updates.isNotEmpty())
        val last = updates.last()
        assertEquals(2, last.filesTotal)
        assertEquals(2, last.filesDone)
        assertEquals(30L, last.bytesTotal)
        assertEquals(30L, last.bytesDone)
        assertFalse(last.bytesTotalIsLowerBound)
        updates.forEach {
            assertEquals(2, it.filesTotal)
            assertEquals(30L, it.bytesTotal)
        }
    }

    @Test
    fun `hasUnknownSizes reports bytesDone honestly past bytesTotal instead of clamping`() {
        val realBytes = ByteArray(500)
        // SIZE_UNKNOWN means the plan's totalBytes undercounts this file entirely.
        val p = plan(file("mystery.bin", SIZE_UNKNOWN))
        val source = FakeSource(mapOf("id:mystery.bin" to realBytes))
        val updates = mutableListOf<ImportProgress>()

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP, onProgress = { updates += it })

        assertTrue(outcome.succeeded)
        assertEquals(0L, p.totalBytes) // the plan-level lower bound
        assertEquals(500L, outcome.bytesCopied) // what was actually moved
        val last = updates.last()
        assertTrue(last.bytesTotalIsLowerBound)
        assertTrue("bytesDone must be allowed past bytesTotal, not clamped", last.bytesDone > last.bytesTotal)
    }

    @Test
    fun `a destination read failing mid-tree returns an outcome, not a bare exception`() {
        // §5.4, and the 2026-08-23 incident verbatim: the session dies partway
        // through. Every entry reads the destination before touching it, so a
        // dead session surfaces on a listDir first. If that escapes importTree
        // uncaught, the caller loses the counts and all the user sees is an
        // IOException that says nothing about how far the copy got.
        val volume = FakeVolume().apply {
            seedRoot("/dst")
            // A directory that already exists must be listed live when merged
            // into. A freshly created one never is -- TreeImporter seeds it as
            // empty, since it just made it -- so a tree of all-new directories
            // issues exactly one listDir and cannot exercise this at all.
            seedDir("/dst", "sub")
        }
        val p = plan(file("a.txt"), dir("sub"), file("sub/b.txt"))
        val source = FakeSource(
            mapOf("id:a.txt" to "A".toByteArray(), "id:sub/b.txt" to "B".toByteArray()),
        )
        // The landing directory's listing survives, then the session dies.
        volume.failListDirAfterCalls = 1

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP)

        assertFalse("must not report success", outcome.succeeded)
        assertNotNull("the failure must be reported, not thrown", outcome.failure)
        assertNotNull("the caller needs to know where it stopped", outcome.stoppedAtPath)
        // What already landed stays landed -- there is no rollback (§5.2).
        assertArrayEquals("A".toByteArray(), volume.fileAt("/dst", "a.txt"))
        assertEquals(1, outcome.filesCopied)
    }

    @Test
    fun `the final progress update names the entry that finished last`() {
        // The forced final update must report the last entry processed, not
        // whichever one happened to win the 200 ms throttle race -- on a fast
        // tree those are almost never the same file, and the UI would be left
        // showing a stale path at 100%.
        val volume = FakeVolume().apply { seedRoot("/dst") }
        val p = plan(file("first.txt"), file("second.txt"), file("last.txt"))
        val source = FakeSource(
            mapOf(
                "id:first.txt" to "1".toByteArray(),
                "id:second.txt" to "2".toByteArray(),
                "id:last.txt" to "3".toByteArray(),
            ),
        )
        val updates = mutableListOf<ImportProgress>()

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.SKIP, onProgress = { updates += it })

        assertTrue(outcome.succeeded)
        assertEquals("last.txt", updates.last().currentPath)
    }

    private fun assertArrayEquals(expected: ByteArray, actual: ByteArray?) {
        assertNotNull("expected content but found none", actual)
        assertTrue("byte content mismatch", expected.contentEquals(actual))
    }
}
