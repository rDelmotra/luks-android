package dev.luksandroid.transfer

import dev.luksandroid.Entry
import dev.luksandroid.LuksVolume
import dev.luksandroid.VolumeInfo
import java.io.ByteArrayInputStream
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Records the exact sequence of volume operations [TreeImporter] emits, so a
 * Rust test can replay that sequence through the real write path and let the
 * kernel grade the result (`core/tests/tree_import_oracle.rs`).
 *
 * # Why a trace instead of just running the importer against a real image
 *
 * [TreeImporter] is Kotlin; the oracle harness is Rust, and there is no way
 * to run `importTree` inside a `cargo test`. That leaves three options, and
 * two of them are worth less than they look:
 *
 *  - Reimplement the tree loop in Rust. The kernel would then bless code that
 *    does not ship. That is RULES.md's "grade against ourselves" trap wearing
 *    a disguise: the grading is real, the *subject* is not.
 *  - Load the real core into the JVM over JNI. This module runs with
 *    `unitTests.isReturnDefaultValues = true` and no `.so`; not available.
 *  - Capture what the shipping Kotlin actually decides to do, and replay
 *    those decisions through the real writer. That is this file.
 *
 * [RecordingVolume] sits at precisely the seam that matters: every call
 * [TreeImporter] makes that would touch a drive passes through it, so the
 * trace is the complete set of drive-facing decisions, with nothing
 * reinterpreted on the way out.
 *
 * # Staleness
 *
 * A checked-in trace can drift from the code that generated it, at which
 * point the oracle grades a sequence nobody emits any more — green, and
 * meaningless. So the trace is not merely written, it is *asserted*: these
 * tests regenerate it and compare against the fixture on disk, failing with
 * instructions if [TreeImporter]'s behaviour has changed. Set
 * `UPDATE_TRANSFER_TRACE=1` to rewrite it deliberately, after which the Rust
 * oracle re-grades the new sequence.
 */
class TreeImportTraceTest {

    /**
     * Content is generated rather than stored: byte `i` of a file with seed
     * `s` is `(s + i) & 0xFF`. Two properties earn this over embedding literal
     * bytes in the fixture. It stays small enough to check in even for a
     * multi-megabyte file, and unlike a uniform fill it varies per offset, so
     * a replay that duplicated, dropped, or reordered a chunk produces
     * different bytes and a different hash. A constant fill would hash
     * identically under all three.
     */
    private fun contentFor(seed: Int, length: Int): ByteArray =
        ByteArray(length) { i -> ((seed + i) and 0xFF).toByte() }

    /**
     * A volume that performs no I/O and remembers, in order, every operation
     * [TreeImporter] asked for.
     */
    private class RecordingVolume(
        existingDirs: Set<String> = emptySet(),
        /** Pre-existing files as "parentPath" to names, so collisions are real. */
        existingFiles: Map<String, Set<String>> = emptyMap(),
    ) : LuksVolume(0L) {
        val lines = mutableListOf<String>()

        /** Directories known to exist, so `typeOf` lookups behave like a real destination. */
        private val dirs = mutableSetOf("/dst").apply { addAll(existingDirs) }
        private val filesByParent = mutableMapOf<String, MutableSet<String>>().apply {
            existingFiles.forEach { (parent, names) -> put(parent, names.toMutableSet()) }
        }

        override val info = VolumeInfo("fake", "uuid", 4096, 0L, "btrfs", emptyList())

        /**
         * `REPLACE` builds its temp name from `System.nanoTime()`, so the raw
         * name differs on every run and a checked-in trace recorded verbatim
         * would never match twice. The nondeterminism is not the behaviour
         * under test — that the write goes to a temp entry and is then renamed
         * over the target is — so the varying suffix is normalised to a
         * counter here, and the replayer uses the normalised name literally.
         */
        private val tempNames = mutableMapOf<String, String>()

        private fun normalise(name: String): String =
            if (!name.startsWith(".transfer-tmp-")) {
                name
            } else {
                tempNames.getOrPut(name) { ".transfer-tmp-${tempNames.size}" }
            }

        private fun record(vararg fields: String) {
            // Tab-separated: a filename may legitimately contain a space, and
            // a space-split replayer would mis-parse exactly the name most
            // worth testing.
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

        override fun rename(oldParent: String, oldName: String, newParent: String, newName: String) {
            record("rename", oldParent, normalise(oldName), newParent, normalise(newName))
            filesByParent.getOrPut(oldParent) { mutableSetOf() }.remove(oldName)
            filesByParent.getOrPut(newParent) { mutableSetOf() }.add(newName)
        }

        override fun deleteFile(path: String) {
            val parent = path.substringBeforeLast('/', "").ifEmpty { "/" }
            val name = path.substringAfterLast('/')
            record("delete", parent, normalise(name))
            filesByParent[parent]?.remove(name)
        }

        override fun beginFileStreaming(): FileWriter {
            record("begin")
            return RecordingWriter()
        }

        inner class RecordingWriter : FileWriter(0L) {
            private var offset = 0

            override fun write(bytes: ByteArray, o: Int, length: Int) {
                if (length > 0) {
                    // Derive the seed from the first byte and its offset, then
                    // verify every remaining byte follows. If a test ever
                    // streams content that is not of this shape, the trace
                    // would silently describe bytes that were never written --
                    // so this fails loudly instead of recording a lie.
                    val seed = ((bytes[o].toInt() and 0xFF) - offset) and 0xFF
                    for (i in 0 until length) {
                        val expected = ((seed + offset + i) and 0xFF).toByte()
                        check(bytes[o + i] == expected) {
                            "RecordingWriter: chunk at offset ${offset + i} is not the generated " +
                                "pattern, so it cannot be encoded in the trace"
                        }
                    }
                    record("write", offset.toString(), length.toString(), seed.toString())
                }
                offset += length
            }

            override fun finish(parentPath: String, name: String): Long {
                record("finish", parentPath, normalise(name))
                filesByParent.getOrPut(parentPath) { mutableSetOf() }.add(name)
                return 1L
            }

            override fun abandon() {
                record("abandon")
            }
        }
    }

    private class GeneratedSource(private val specs: Map<String, Pair<Int, Int>>) : SourceBytes {
        override fun open(sourceId: String): ByteArrayInputStream {
            val (seed, length) = specs.getValue(sourceId)
            return ByteArrayInputStream(ByteArray(length) { i -> ((seed + i) and 0xFF).toByte() })
        }
    }

    private fun dir(path: String) = PlanEntry("id:$path", path, isDir = true, sizeBytes = 0, mtime = 0)
    private fun file(path: String, size: Long) =
        PlanEntry("id:$path", path, isDir = false, sizeBytes = size, mtime = 0)

    /**
     * `core/tests/tree_import_oracle.rs` reads these, so they belong to the
     * repo-root `fixtures/`, not anywhere under `android/`.
     *
     * Found by ascending for a marker rather than by counting `..` levels:
     * Gradle runs tests with `user.dir` at `android/app`, which is not
     * documented anywhere and is not the kind of thing that stays put. A
     * hard-coded hop that silently resolves to the wrong directory writes a
     * fixture nobody reads and leaves the oracle grading a stale one.
     */
    private fun repoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            if (File(dir, "core").isDirectory && File(dir, "android").isDirectory) return dir
            dir = dir.parentFile
        }
        error("could not locate the repository root above ${System.getProperty("user.dir")}")
    }

    private fun traceFile(name: String): File =
        repoRoot().resolve("fixtures").resolve("transfer").resolve(name)

    private fun assertTraceMatchesFixture(name: String, lines: List<String>) {
        val expected = lines.joinToString("\n", postfix = "\n")
        val target = traceFile(name)

        if (System.getenv("UPDATE_TRANSFER_TRACE") == "1") {
            target.parentFile.mkdirs()
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
            "TreeImporter's operation sequence no longer matches ${target.name}. If this change " +
                "is intended, regenerate with UPDATE_TRANSFER_TRACE=1 ./gradlew :app:test and let " +
                "the Rust oracle re-grade the new sequence. Until then the kernel oracle is " +
                "grading a sequence this code no longer emits.",
            expected,
            target.readText(),
        )
    }

    // ---- the traces --------------------------------------------------------

    /**
     * A nested tree with the shapes that have historically gone wrong: a
     * directory created before anything descends into it, an empty directory
     * that must survive, a file large enough to span several
     * [TreeImporter.CHUNK_SIZE] chunks, and a replace collision that must land
     * as write-to-temp-then-rename rather than delete-then-write.
     */
    @Test
    fun `records a nested tree import`() {
        val volume = RecordingVolume(
            existingDirs = setOf("/dst/Photos"),
            // A real pre-existing file, not just the directory holding it:
            // without this the "replace" entry below collides with nothing and
            // the write-to-temp-then-rename path -- the whole reason this
            // scenario chooses REPLACE -- never executes.
            existingFiles = mapOf("/dst/Photos" to setOf("existing.txt")),
        )
        val big = TreeImporter.CHUNK_SIZE + (TreeImporter.CHUNK_SIZE / 2)
        val p = TransferPlan(
            "root",
            listOf(
                dir("Photos"),
                file("Photos/existing.txt", 40),
                dir("Notes"),
                file("Notes/small.txt", 11),
                dir("Notes/Deep"),
                file("Notes/Deep/big.bin", big.toLong()),
                dir("Empty"),
            ),
        )
        val source = GeneratedSource(
            mapOf(
                "id:Photos/existing.txt" to (7 to 40),
                "id:Notes/small.txt" to (19 to 11),
                "id:Notes/Deep/big.bin" to (3 to big),
            ),
        )

        val outcome = TreeImporter.importTree(volume, p, "/dst", source, CollisionMode.REPLACE)

        assertTrue(outcome.failure?.toString() ?: "expected success", outcome.succeeded)
        assertEquals(3, outcome.filesCopied)
        // Photos already exists and is merged, so only three are created.
        assertEquals(3, outcome.dirsCreated)

        assertTraceMatchesFixture("nested-import.trace", volume.lines)
    }

    /**
     * The 2026-08-23 incident's shape: a transfer that stops partway. The
     * oracle's job for this one is to confirm the *completed prefix* is intact
     * and mountable -- §5.2 keeps whatever landed rather than rolling back, so
     * "half a tree" must still be a valid filesystem, not a corrupt one.
     */
    @Test
    fun `records a tree import cancelled partway`() {
        val volume = RecordingVolume()
        var filesFinished = 0
        val p = TransferPlan(
            "root",
            listOf(
                dir("A"),
                file("A/one.txt", 12),
                file("A/two.txt", 12),
                dir("B"),
                file("B/three.txt", 12),
            ),
        )
        val source = GeneratedSource(
            mapOf(
                "id:A/one.txt" to (1 to 12),
                "id:A/two.txt" to (2 to 12),
                "id:B/three.txt" to (3 to 12),
            ),
        )

        val outcome = TreeImporter.importTree(
            volume,
            p,
            "/dst",
            source,
            CollisionMode.SKIP,
            isCancelled = {
                // Cancel once two files have actually committed, so the trace
                // ends on a genuine mid-tree boundary rather than before any
                // work happened.
                filesFinished = volume.lines.count { it.startsWith("finish\t") }
                filesFinished >= 2
            },
        )

        assertFalse(outcome.succeeded)
        assertEquals(2, outcome.filesCopied)
        assertTrue("expected a stopping point", outcome.stoppedAtPath != null)
        // Nothing may be left half-written: a cancel between files, never mid-file.
        assertFalse(volume.lines.contains("abandon"))

        assertTraceMatchesFixture("cancelled-import.trace", volume.lines)
    }
}
