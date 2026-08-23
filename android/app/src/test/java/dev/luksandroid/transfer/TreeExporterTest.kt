package dev.luksandroid.transfer

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Pass 4 execution, run against an in-memory fake document provider.
 *
 * [FakeDestination] models the SAF behaviours that make export different from
 * import rather than an idealised store -- above all that `createDocument`
 * de-duplicates a colliding name and returns a *different* one instead of
 * failing. A fake that let the requested name through would make the bug this
 * feature is most likely to have (believing it wrote `report.pdf` when the
 * provider created `report (1).pdf`) untestable.
 */
class TreeExporterTest {

    private fun dir(path: String) = PlanEntry("v:$path", path, isDir = true, sizeBytes = 0, mtime = 0)

    private fun file(path: String, size: Long = -1, mtime: Long = 0) =
        PlanEntry("v:$path", path, isDir = false, sizeBytes = size, mtime = mtime)

    private fun plan(vararg entries: PlanEntry) = TransferPlan("root", entries.toList())

    // ---- fake destination --------------------------------------------------

    private class FakeDestination : ExportDestination {
        class Doc(val id: String, var name: String, val isDir: Boolean, var parentId: String?) {
            var bytes: ByteArray = ByteArray(0)
        }

        val docs = mutableMapOf<String, Doc>()
        private var nextId = 0

        /**
         * Names that exist but are omitted from [children]. Models the case
         * that makes provider-assigned names load-bearing: our listing is
         * stale (another app wrote the file, or the provider's listing lags),
         * so we request a name that is actually taken and get back a different
         * one.
         */
        val hiddenFromListing = mutableSetOf<String>()

        var failCreateFor: String? = null
        var failChildrenFor: String? = null
        var failWriteAfterTotalBytes: Long? = null
        var failDeleteFor: String? = null
        var failRenameTo: String? = null
        private var totalBytesWritten = 0L

        /** Every createFile call, in order, as "parentId/requestedName mimeType". */
        val createCalls = mutableListOf<String>()
        val deletedIds = mutableListOf<String>()
        val childrenCalls = mutableListOf<String>()

        /**
         * Bumped only when an output stream closes, i.e. when a file is really
         * finished. Counting *created* documents instead would be wrong: unlike
         * the import side, where a name appears only once the writer commits, a
         * SAF document exists from the moment it is created and before a single
         * byte is written. A cancellation flag driven off the document count
         * therefore fires mid-file rather than at a boundary.
         */
        var completedFiles = 0
            private set

        fun seedRoot(): String = newDoc("ROOT", isDir = true, parentId = null).id

        fun newDoc(name: String, isDir: Boolean, parentId: String?): Doc {
            val doc = Doc("doc${nextId++}", name, isDir, parentId)
            docs[doc.id] = doc
            return doc
        }

        fun seedDir(parentId: String, name: String): String = newDoc(name, true, parentId).id

        fun seedFile(parentId: String, name: String, data: ByteArray): String {
            val d = newDoc(name, false, parentId)
            d.bytes = data
            return d.id
        }

        fun childNamed(parentId: String, name: String): Doc? =
            docs.values.find { it.parentId == parentId && it.name == name }

        fun namesUnder(parentId: String): Set<String> =
            docs.values.filter { it.parentId == parentId }.map { it.name }.toSet()

        fun bytesAt(parentId: String, name: String): ByteArray? = childNamed(parentId, name)?.bytes

        override fun children(dirId: String): List<RawChild> {
            childrenCalls += dirId
            if (failChildrenFor == dirId) throw IOException("simulated children() failure for $dirId")
            return docs.values.filter { it.parentId == dirId && it.name !in hiddenFromListing }.map {
                RawChild(it.id, it.name, it.isDir, if (it.isDir) 0 else it.bytes.size.toLong(), 0)
            }
        }

        /**
         * SAF's actual behaviour: a colliding display name is de-duplicated by
         * the provider, never rejected. Modelling this is the point of the fake.
         */
        private fun dedupe(parentId: String, desired: String): String {
            if (childNamed(parentId, desired) == null) return desired
            val dot = desired.lastIndexOf('.')
            val stem = if (dot > 0) desired.substring(0, dot) else desired
            val ext = if (dot > 0) desired.substring(dot) else ""
            var n = 1
            while (childNamed(parentId, "$stem ($n)$ext") != null) n++
            return "$stem ($n)$ext"
        }

        override fun createDirectory(parentId: String, name: String): CreatedDocument {
            val d = newDoc(dedupe(parentId, name), true, parentId)
            return CreatedDocument(d.id, d.name)
        }

        override fun createFile(parentId: String, name: String, mimeType: String): CreatedDocument {
            createCalls += "$parentId/$name $mimeType"
            if (failCreateFor == name) throw IOException("simulated createFile failure for $name")
            val d = newDoc(dedupe(parentId, name), false, parentId)
            return CreatedDocument(d.id, d.name)
        }

        override fun openOutput(docId: String): OutputStream {
            val doc = docs.getValue(docId)
            return object : ByteArrayOutputStream() {
                override fun write(b: ByteArray, off: Int, len: Int) {
                    totalBytesWritten += len
                    failWriteAfterTotalBytes?.let {
                        if (totalBytesWritten >= it) throw IOException("simulated write failure")
                    }
                    super.write(b, off, len)
                    doc.bytes = toByteArray()
                }

                override fun close() {
                    doc.bytes = toByteArray()
                    completedFiles++
                    super.close()
                }
            }
        }

        override fun delete(docId: String) {
            val doc = docs.getValue(docId)
            if (failDeleteFor == doc.name) throw IOException("simulated delete failure for ${doc.name}")
            deletedIds += docId
            docs.remove(docId)
        }

        override fun rename(docId: String, newName: String): CreatedDocument {
            if (failRenameTo == newName) throw IOException("simulated rename failure to $newName")
            val doc = docs.getValue(docId)
            doc.name = dedupe(doc.parentId!!, newName)
            return CreatedDocument(doc.id, doc.name)
        }
    }

    private class FakeSource(private val bytesById: Map<String, ByteArray>) : SourceBytes {
        override fun open(sourceId: String) = ByteArrayInputStream(bytesById.getValue(sourceId))
    }

    private lateinit var dest: FakeDestination
    private lateinit var root: String

    @Before
    fun setUp() {
        dest = FakeDestination()
        root = dest.seedRoot()
    }

    private fun export(
        p: TransferPlan,
        source: SourceBytes = FakeSource(emptyMap()),
        mode: CollisionMode = CollisionMode.SKIP,
        onProgress: (TransferProgress) -> Unit = {},
        isCancelled: () -> Boolean = { false },
        mimeTypeFor: (String) -> String = { "application/octet-stream" },
    ) = TreeExporter.exportTree(p, root, source, dest, mode, mimeTypeFor, onProgress, isCancelled)

    // ---- structure and content ---------------------------------------------

    @Test
    fun `exports a nested tree with correct structure and byte content`() {
        val a = "hello a".toByteArray()
        val b = "hello b, deeper".toByteArray()
        val p = plan(dir("a"), file("a/x.txt", a.size.toLong()), dir("a/b"), file("a/b/y.txt", b.size.toLong()))
        val source = FakeSource(mapOf("v:a/x.txt" to a, "v:a/b/y.txt" to b))

        val outcome = export(p, source)

        assertTrue(outcome.failure?.toString() ?: "expected success", outcome.succeeded)
        assertNull(outcome.stoppedAtPath)
        assertEquals(2, outcome.dirsCreated)
        assertEquals(2, outcome.filesCopied)
        assertEquals((a.size + b.size).toLong(), outcome.bytesCopied)

        val aId = dest.childNamed(root, "a")!!.id
        val bId = dest.childNamed(aId, "b")!!.id
        assertArrayEquals(a, dest.bytesAt(aId, "x.txt"))
        assertArrayEquals(b, dest.bytesAt(bId, "y.txt"))
    }

    @Test
    fun `empty directories are created`() {
        val outcome = export(plan(dir("One"), dir("One/Two")))

        assertTrue(outcome.succeeded)
        assertEquals(2, outcome.dirsCreated)
        val oneId = dest.childNamed(root, "One")!!.id
        assertNotNull(dest.childNamed(oneId, "Two"))
    }

    @Test
    fun `a file larger than one chunk is exported whole`() {
        val big = ByteArray(TreeExporter.CHUNK_SIZE + 1234) { (it % 251).toByte() }
        val outcome = export(
            plan(file("big.bin", big.size.toLong())),
            FakeSource(mapOf("v:big.bin" to big)),
        )

        assertTrue(outcome.succeeded)
        assertEquals(big.size.toLong(), outcome.bytesCopied)
        assertArrayEquals(big, dest.bytesAt(root, "big.bin"))
    }

    @Test
    fun `merge - an existing destination directory is reused, not duplicated`() {
        val photos = dest.seedDir(root, "Photos")
        dest.seedFile(photos, "already.txt", "old".toByteArray())

        val newBytes = "new".toByteArray()
        val outcome = export(
            plan(dir("Photos"), file("Photos/new.txt", newBytes.size.toLong())),
            FakeSource(mapOf("v:Photos/new.txt" to newBytes)),
        )

        assertTrue(outcome.succeeded)
        assertEquals(0, outcome.dirsCreated)
        // The new file must land *inside* the pre-existing directory, and the
        // provider must not have been asked to create a second "Photos".
        assertEquals(setOf("Photos"), dest.namesUnder(root))
        assertArrayEquals(newBytes, dest.bytesAt(photos, "new.txt"))
        assertArrayEquals("old".toByteArray(), dest.bytesAt(photos, "already.txt"))
    }

    // ---- collisions --------------------------------------------------------

    @Test
    fun `skip - a colliding file is left untouched and counted as skipped`() {
        dest.seedFile(root, "note.txt", "original".toByteArray())

        val outcome = export(
            plan(file("note.txt", 3)),
            FakeSource(mapOf("v:note.txt" to "new".toByteArray())),
            CollisionMode.SKIP,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesSkipped)
        assertEquals(0, outcome.filesCopied)
        assertArrayEquals("original".toByteArray(), dest.bytesAt(root, "note.txt"))
        assertTrue("nothing should have been created", dest.createCalls.isEmpty())
    }

    @Test
    fun `keep both - a colliding file lands beside the original under a new name`() {
        dest.seedFile(root, "note.txt", "original".toByteArray())

        val outcome = export(
            plan(file("note.txt", 3)),
            FakeSource(mapOf("v:note.txt" to "new".toByteArray())),
            CollisionMode.KEEP_BOTH,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesCopied)
        assertArrayEquals("original".toByteArray(), dest.bytesAt(root, "note.txt"))
        assertArrayEquals("new".toByteArray(), dest.bytesAt(root, "note (1).txt"))
    }

    @Test
    fun `replace - the new bytes are written before the old file is removed`() {
        val originalId = dest.seedFile(root, "note.txt", "original".toByteArray())

        val outcome = export(
            plan(file("note.txt", 3)),
            FakeSource(mapOf("v:note.txt" to "new".toByteArray())),
            CollisionMode.REPLACE,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesCopied)
        assertEquals(setOf("note.txt"), dest.namesUnder(root))
        assertArrayEquals("new".toByteArray(), dest.bytesAt(root, "note.txt"))
        // The original document was deleted, not overwritten in place, and the
        // delete happened -- so the temp document is what survived under the name.
        assertEquals(listOf(originalId), dest.deletedIds)
        // No stray temp entry left behind.
        assertTrue(dest.namesUnder(root).none { it.startsWith(".transfer-tmp-") })
    }

    @Test
    fun `replace - the temp document is written first, so a failed write never destroys the original`() {
        dest.seedFile(root, "note.txt", "original".toByteArray())
        dest.failWriteAfterTotalBytes = 1

        val outcome = export(
            plan(file("note.txt", 3)),
            FakeSource(mapOf("v:note.txt" to "new".toByteArray())),
            CollisionMode.REPLACE,
        )

        assertFalse(outcome.succeeded)
        // This is the property that ordering buys: the original is still there
        // and still correct. Under delete-then-write it would be gone.
        assertArrayEquals("original".toByteArray(), dest.bytesAt(root, "note.txt"))
        assertTrue("the original must not have been deleted", dest.deletedIds.isEmpty())
    }

    // ---- the provider renames behind our back ------------------------------

    @Test
    fun `a provider-assigned name is recorded, not the requested one`() {
        // "a.txt" is really there but our listing does not report it, so the
        // exporter asks for a name that is already taken and the provider hands
        // back "a (1).txt" instead. If the exporter recorded the name it asked
        // for rather than the one it got, its picture of the directory is now
        // wrong -- and the next entry, which really is named "a (1).txt", gets
        // treated as new instead of as the collision it is.
        dest.seedFile(root, "a.txt", "zero".toByteArray())
        dest.hiddenFromListing += "a.txt"

        val outcome = export(
            plan(file("a.txt", 3), file("a (1).txt", 3)),
            FakeSource(mapOf("v:a.txt" to "one".toByteArray(), "v:a (1).txt" to "two".toByteArray())),
            CollisionMode.SKIP,
        )

        assertTrue(outcome.succeeded)
        assertEquals(1, outcome.filesCopied)
        assertEquals(1, outcome.filesSkipped)
        assertEquals(setOf("a.txt", "a (1).txt"), dest.namesUnder(root))
        assertArrayEquals("one".toByteArray(), dest.bytesAt(root, "a (1).txt"))
    }

    // ---- type mismatches ---------------------------------------------------

    @Test
    fun `a file cannot land where the destination holds a directory`() {
        dest.seedDir(root, "thing")

        val outcome = export(plan(file("thing", 1)), FakeSource(mapOf("v:thing" to "x".toByteArray())))

        assertFalse(outcome.succeeded)
        assertEquals("thing", outcome.stoppedAtPath)
        assertTrue(outcome.failure is IllegalStateException)
    }

    @Test
    fun `a directory cannot land where the destination holds a file`() {
        dest.seedFile(root, "thing", "x".toByteArray())

        val outcome = export(plan(dir("thing")))

        assertFalse(outcome.succeeded)
        assertEquals("thing", outcome.stoppedAtPath)
        assertTrue(outcome.failure is IllegalStateException)
    }

    // ---- failures and cancellation -----------------------------------------

    @Test
    fun `a write failure stops the run and keeps what already landed`() {
        val ok = "fine".toByteArray()
        val p = plan(file("first.txt", ok.size.toLong()), file("second.txt", 4))
        val source = FakeSource(mapOf("v:first.txt" to ok, "v:second.txt" to "boom".toByteArray()))
        dest.failWriteAfterTotalBytes = (ok.size + 1).toLong()

        val outcome = export(p, source)

        assertFalse(outcome.succeeded)
        assertEquals("second.txt", outcome.stoppedAtPath)
        assertEquals(1, outcome.filesCopied)
        // §5.2: no rollback. The first file stays.
        assertArrayEquals(ok, dest.bytesAt(root, "first.txt"))
    }

    @Test
    fun `a destination read failing mid-tree returns an outcome, not a bare exception`() {
        val existing = dest.seedDir(root, "sub")
        dest.failChildrenFor = existing

        val outcome = export(plan(dir("sub"), file("sub/x.txt", 1)), FakeSource(mapOf("v:sub/x.txt" to "x".toByteArray())))

        assertFalse(outcome.succeeded)
        assertEquals("sub/x.txt", outcome.stoppedAtPath)
        assertTrue(outcome.failure is IOException)
    }

    @Test
    fun `cancelling stops at a file boundary and reports where`() {
        val p = plan(file("one.txt", 3), file("two.txt", 3), file("three.txt", 3))
        val source = FakeSource(
            mapOf(
                "v:one.txt" to "aaa".toByteArray(),
                "v:two.txt" to "bbb".toByteArray(),
                "v:three.txt" to "ccc".toByteArray(),
            ),
        )
        // Counted off the destination, not off onProgress: progress is
        // throttled to ~200 ms, so in a test this fast it fires almost never
        // and a flag driven by it would leave the export running to completion
        // -- which is exactly how the first version of this test passed
        // vacuously.
        val outcome = export(p, source, isCancelled = { dest.completedFiles >= 2 })

        assertFalse(outcome.succeeded)
        assertTrue(outcome.failure is TransferCancelledException)
        assertEquals(2, outcome.filesCopied)
        assertEquals("three.txt", outcome.stoppedAtPath)
        assertArrayEquals("aaa".toByteArray(), dest.bytesAt(root, "one.txt"))
        assertNull("the cancelled file must not exist", dest.childNamed(root, "three.txt"))
    }

    @Test
    fun `a failed replace rename stops the run without losing the new bytes`() {
        dest.seedFile(root, "note.txt", "original".toByteArray())
        dest.failRenameTo = "note.txt"

        val outcome = export(
            plan(file("note.txt", 3)),
            FakeSource(mapOf("v:note.txt" to "new".toByteArray())),
            CollisionMode.REPLACE,
        )

        assertFalse(outcome.succeeded)
        assertEquals("note.txt", outcome.stoppedAtPath)
        // The documented weakness of the SAF replace ordering, asserted rather
        // than glossed: the original is already gone and the new bytes are
        // sitting under the temp name. Recoverable, and strictly better than
        // delete-then-write, which would have lost them entirely.
        val names = dest.namesUnder(root)
        assertTrue("expected the temp document to survive, got $names", names.any { it.startsWith(".transfer-tmp-") })
        val temp = names.first { it.startsWith(".transfer-tmp-") }
        assertArrayEquals("new".toByteArray(), dest.bytesAt(root, temp))
    }

    // ---- IPC cost and progress ---------------------------------------------

    @Test
    fun `each destination directory is listed at most once`() {
        dest.seedDir(root, "Photos")
        val p = plan(
            dir("Photos"),
            file("Photos/a.txt", 1),
            file("Photos/b.txt", 1),
            file("Photos/c.txt", 1),
            dir("New"),
            file("New/d.txt", 1),
        )
        val source = FakeSource(
            listOf("Photos/a.txt", "Photos/b.txt", "Photos/c.txt", "New/d.txt")
                .associate { "v:$it" to "x".toByteArray() },
        )

        assertTrue(export(p, source).succeeded)

        // One listing per *distinct* directory touched, never one per file --
        // §2.1. "New" is created by us, so it is known empty without a query.
        assertEquals(dest.childrenCalls.distinct(), dest.childrenCalls)
    }

    @Test
    fun `the final progress update names the entry that finished last`() {
        val p = plan(file("one.txt", 3), file("two.txt", 3))
        val source = FakeSource(mapOf("v:one.txt" to "aaa".toByteArray(), "v:two.txt" to "bbb".toByteArray()))
        val seen = mutableListOf<TransferProgress>()

        assertTrue(export(p, source, onProgress = { seen += it }).succeeded)

        assertEquals("two.txt", seen.last().currentPath)
        assertEquals(2, seen.last().filesDone)
        assertEquals(6L, seen.last().bytesDone)
    }

    @Test
    fun `the mime type is derived per file, not fixed`() {
        val p = plan(file("photo.jpg", 1), file("notes.txt", 1))
        val source = FakeSource(mapOf("v:photo.jpg" to "x".toByteArray(), "v:notes.txt" to "y".toByteArray()))

        assertTrue(export(p, source, mimeTypeFor = { if (it.endsWith(".jpg")) "image/jpeg" else "text/plain" }).succeeded)

        assertTrue(dest.createCalls.any { it.endsWith("photo.jpg image/jpeg") })
        assertTrue(dest.createCalls.any { it.endsWith("notes.txt text/plain") })
    }

    @Test
    fun `a plan that is not parent-before-child is refused before anything is written`() {
        val p = plan(file("a/x.txt", 1), dir("a"))

        val thrown = runCatching { export(p, FakeSource(mapOf("v:a/x.txt" to "x".toByteArray()))) }.exceptionOrNull()

        assertNotNull("expected the ordering check to fail loudly", thrown)
        assertTrue("nothing may have been created", dest.createCalls.isEmpty())
    }
}
