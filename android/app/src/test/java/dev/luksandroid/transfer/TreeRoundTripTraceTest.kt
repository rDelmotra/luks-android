package dev.luksandroid.transfer

import dev.luksandroid.Entry
import dev.luksandroid.LuksVolume
import dev.luksandroid.VolumeInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Pass 4 exit bar: export a tree off the drive, re-import what came out,
 * and require the drive to end up holding exactly what it started with.
 *
 * A round trip is the right shape for export because the destination is a
 * document provider, which no kernel can grade. Exporting alone can only be
 * checked against our own idea of what should have been written. Feeding the
 * exported bytes back through the *import* path -- which
 * `core/tests/tree_import_oracle.rs` already replays through the real btrfs
 * writer -- turns "did the export produce the right bytes?" into a question
 * the kernel can answer, because a wrong export lands as a wrong tree on a
 * real filesystem.
 *
 * Both directions run for real here: [TreeExporter] against a fake provider,
 * then [DirectoryWalker] over that provider's contents, then [TreeImporter]
 * against a recording volume. Only the endpoints are fakes; every decision in
 * between is the shipping code's. The recorded import trace is what Rust
 * replays.
 *
 * See [TreeImportTraceTest] for why traces exist at all and how staleness is
 * prevented -- the same regeneration contract applies here.
 */
class TreeRoundTripTraceTest {

    private fun contentFor(seed: Int, length: Int): ByteArray =
        ByteArray(length) { i -> ((seed + i) and 0xFF).toByte() }

    // ---- the source tree, as it exists on the drive ------------------------

    private data class SourceFile(val path: String, val seed: Int, val length: Int)

    private val bigLength = TreeExporter.CHUNK_SIZE + (TreeExporter.CHUNK_SIZE / 2)

    private val sourceDirs = listOf("Docs", "Docs/Sub", "Empty")
    private val sourceFiles = listOf(
        SourceFile("top.txt", 5, 7),
        SourceFile("Docs/notes.txt", 11, 100),
        // Spans several chunks in both directions, with a short final one.
        SourceFile("Docs/Sub/data.bin", 23, bigLength),
    )

    /** Parent-before-child, as [DirectoryWalker] would have produced it. */
    private fun sourcePlan(): TransferPlan {
        val entries = mutableListOf<PlanEntry>()
        entries += PlanEntry("v:/src/top.txt", "top.txt", isDir = false, sizeBytes = 7, mtime = 0)
        entries += PlanEntry("v:/src/Docs", "Docs", isDir = true, sizeBytes = 0, mtime = 0)
        entries += PlanEntry("v:/src/Docs/notes.txt", "Docs/notes.txt", isDir = false, sizeBytes = 100, mtime = 0)
        entries += PlanEntry("v:/src/Docs/Sub", "Docs/Sub", isDir = true, sizeBytes = 0, mtime = 0)
        entries += PlanEntry(
            "v:/src/Docs/Sub/data.bin", "Docs/Sub/data.bin", isDir = false, sizeBytes = bigLength.toLong(), mtime = 0,
        )
        entries += PlanEntry("v:/src/Empty", "Empty", isDir = true, sizeBytes = 0, mtime = 0)
        return TransferPlan("/src", entries)
    }

    private fun sourceBytes(): SourceBytes {
        val byId = sourceFiles.associate { "v:/src/${it.path}" to contentFor(it.seed, it.length) }
        return SourceBytes { id -> ByteArrayInputStream(byId.getValue(id)) }
    }

    // ---- a fake document provider, standing in for the phone ---------------

    /**
     * Same de-duplicating semantics as the fake in [TreeExporterTest]: a
     * colliding name is renamed by the provider rather than rejected. Nothing
     * collides in this scenario, but a fake that quietly allowed duplicates
     * would let a broken export look clean.
     */
    private class FakeProvider : ExportDestination, ChildSource {
        class Doc(val id: String, var name: String, val isDir: Boolean, val parentId: String?) {
            var bytes: ByteArray = ByteArray(0)
        }

        val docs = mutableMapOf<String, Doc>()
        private var nextId = 0

        val rootId: String = newDoc("ROOT", true, null).id

        private fun newDoc(name: String, isDir: Boolean, parentId: String?): Doc {
            val d = Doc("doc${nextId++}", name, isDir, parentId)
            docs[d.id] = d
            return d
        }

        private fun childNamed(parentId: String, name: String) =
            docs.values.find { it.parentId == parentId && it.name == name }

        private fun dedupe(parentId: String, desired: String): String {
            if (childNamed(parentId, desired) == null) return desired
            var n = 1
            while (childNamed(parentId, "$desired ($n)") != null) n++
            return "$desired ($n)"
        }

        override fun children(parentId: String): List<RawChild> =
            docs.values.filter { it.parentId == parentId }
                .sortedBy { it.name }
                .map { RawChild(it.id, it.name, it.isDir, if (it.isDir) 0L else it.bytes.size.toLong(), 0L) }

        override fun createDirectory(parentId: String, name: String): CreatedDocument =
            newDoc(dedupe(parentId, name), true, parentId).let { CreatedDocument(it.id, it.name) }

        override fun createFile(parentId: String, name: String, mimeType: String): CreatedDocument =
            newDoc(dedupe(parentId, name), false, parentId).let { CreatedDocument(it.id, it.name) }

        override fun openOutput(docId: String): OutputStream {
            val doc = docs.getValue(docId)
            return object : ByteArrayOutputStream() {
                override fun close() {
                    doc.bytes = toByteArray()
                    super.close()
                }
            }
        }

        override fun delete(docId: String) {
            docs.remove(docId)
        }

        override fun rename(docId: String, newName: String): CreatedDocument {
            val doc = docs.getValue(docId)
            doc.name = dedupe(doc.parentId!!, newName)
            return CreatedDocument(doc.id, doc.name)
        }
    }

    // ---- a volume that records what the re-import asks for ------------------

    /** See [TreeImportTraceTest]'s RecordingVolume; same encoding, same reasons. */
    private class RecordingVolume : LuksVolume(0L) {
        val lines = mutableListOf<String>()
        private val dirs = mutableSetOf("/dst")
        private val filesByParent = mutableMapOf<String, MutableSet<String>>()

        override val info = VolumeInfo("fake", "uuid", 4096, 0L, "btrfs", emptyList())
        override fun commitActiveBatch() = Unit

        private fun record(vararg fields: String) {
            lines += fields.joinToString("\t")
        }

        override fun listDir(path: String): List<Entry> {
            val childDirs = dirs.filter { it != path && it.substringBeforeLast('/', "").ifEmpty { "/" } == path }
                .map { Entry(it.substringAfterLast('/'), "dir") }
            val childFiles = filesByParent[path].orEmpty().map { Entry(it, "file", size = 0) }
            return childDirs + childFiles
        }

        override fun createDirectory(parentPath: String, name: String): Long {
            record("mkdir", parentPath, name)
            dirs += if (parentPath == "/") "/$name" else "$parentPath/$name"
            return 1L
        }

        override fun beginFileStreaming(): FileWriter {
            record("begin")
            return RecordingWriter()
        }

        inner class RecordingWriter : FileWriter(0L) {
            private var offset = 0

            override fun write(bytes: ByteArray, o: Int, length: Int) {
                if (length > 0) {
                    val seed = ((bytes[o].toInt() and 0xFF) - offset) and 0xFF
                    for (i in 0 until length) {
                        check(bytes[o + i] == (((seed + offset + i) and 0xFF).toByte())) {
                            "round-tripped bytes are not the generated pattern at offset ${offset + i} -- " +
                                "the export corrupted the file, which is the finding, not a trace problem"
                        }
                    }
                    record("write", offset.toString(), length.toString(), seed.toString())
                }
                offset += length
            }

            override fun finish(parentPath: String, name: String): Long {
                record("finish", parentPath, name)
                filesByParent.getOrPut(parentPath) { mutableSetOf() }.add(name)
                return 1L
            }

            override fun abandon() {
                record("abandon")
            }
        }
    }

    // ---- fixture plumbing --------------------------------------------------

    private fun repoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            if (File(dir, "core").isDirectory && File(dir, "android").isDirectory) return dir
            dir = dir.parentFile
        }
        error("could not locate the repository root above ${System.getProperty("user.dir")}")
    }

    private fun assertTraceMatchesFixture(name: String, lines: List<String>) {
        val expected = lines.joinToString("\n", postfix = "\n")
        val target = repoRoot().resolve("fixtures").resolve("transfer").resolve(name)

        if (System.getenv("UPDATE_TRANSFER_TRACE") == "1") {
            target.parentFile?.mkdirs()
            target.writeText(expected)
            println("UPDATE_TRANSFER_TRACE=1: rewrote ${target.path}")
            return
        }

        assertTrue(
            "missing trace fixture ${target.path} -- regenerate with " +
                "UPDATE_TRANSFER_TRACE=1 ./gradlew :app:test",
            target.exists(),
        )
        assertEquals(
            "The export/re-import round trip no longer produces the same operation sequence. If this " +
                "change is intended, regenerate with UPDATE_TRANSFER_TRACE=1 ./gradlew :app:test and let " +
                "the Rust oracle re-grade it.",
            expected,
            target.readText(),
        )
    }

    // ---- the round trip ----------------------------------------------------

    @Test
    fun `a tree survives export and re-import unchanged`() {
        // 1. Export the drive's tree to the provider.
        val provider = FakeProvider()
        val exported = TreeExporter.exportTree(
            plan = sourcePlan(),
            destinationRootId = provider.rootId,
            source = sourceBytes(),
            destination = provider,
            collisionMode = CollisionMode.SKIP,
        )
        assertTrue(exported.failure?.toString() ?: "export failed", exported.succeeded)
        assertEquals(3, exported.filesCopied)
        assertEquals(3, exported.dirsCreated)

        // 2. Walk what actually landed on the provider -- not what we think we
        // wrote. Re-reading is the point: an export that dropped or misnamed a
        // file produces a different plan here, and the difference survives all
        // the way to the kernel's manifest.
        val reimportPlan = DirectoryWalker.walk(provider, provider.rootId, "ROOT")
        assertEquals(3, reimportPlan.fileCount)
        assertEquals(3, reimportPlan.dirCount)

        // 3. Import it back onto a (recording) drive.
        val volume = RecordingVolume()
        val backBytes = SourceBytes { id -> ByteArrayInputStream(provider.docs.getValue(id).bytes) }
        val reimported = TreeImporter.importTree(
            volume = volume,
            plan = reimportPlan,
            destinationRootPath = "/dst",
            source = backBytes,
            collisionMode = CollisionMode.SKIP,
        )
        assertTrue(reimported.failure?.toString() ?: "re-import failed", reimported.succeeded)
        assertEquals(3, reimported.filesCopied)
        assertEquals(3, reimported.dirsCreated)

        // 4. The bytes that came back must be the bytes that went out. Checked
        // here as well as by the kernel, so a failure says "the export
        // corrupted this file" rather than only "the manifest differs".
        for (f in sourceFiles) {
            val doc = provider.docs.values.first { d -> !d.isDir && d.name == f.path.substringAfterLast('/') }
            assertArrayEquals("content of ${f.path} changed in transit", contentFor(f.seed, f.length), doc.bytes)
        }

        assertTraceMatchesFixture("roundtrip-import.trace", volume.lines)
    }
}
