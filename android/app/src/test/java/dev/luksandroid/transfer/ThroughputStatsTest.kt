package dev.luksandroid.transfer

import dev.luksandroid.Entry
import dev.luksandroid.LuksVolume
import dev.luksandroid.VolumeInfo
import java.io.ByteArrayInputStream
import java.io.InputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The instrument that decides whether pipelining the source read against the
 * destination write is worth building.
 *
 * INCIDENTS.md 2026-08-08 and 2026-08-10 are the same failure twice: a
 * throughput hypothesis stated with more confidence than it had earned, one
 * measurement away from being shipped as a fix. So the measurement itself gets
 * tested -- an instrument whose display can disagree with its behaviour "is
 * worse than no instrument, because it produces numbers that look like
 * evidence" (INCIDENTS.md, "The instrument that lied").
 *
 * Two properties matter here, neither cosmetic:
 *
 * 1. The read/write split is really measured per stage, not apportioned. That
 *    is the entire falsifiable content of the serial-stages hypothesis: if the
 *    read turns out to be a few percent of the total, pipelining wins at most
 *    that few percent and must not be built.
 * 2. The rendered line carries no name from either side of the transfer -- the
 *    same rule `Trace.err`'s `ErrDetail` enforces structurally for errors.
 */
class ThroughputStatsTest {

    @Test
    fun `summary reports rate and per-stage split`() {
        val stats = TransferStats(
            elapsedNanos = 10_000_000_000L,
            readNanos = 4_000_000_000L,
            writeNanos = 5_000_000_000L,
            commitNanos = 500_000_000L,
            readCalls = 20,
            writeCalls = 20,
        )
        val line = formatThroughput("import", bytes = 10L * 1024 * 1024, stats = stats)

        assertTrue(line, line.contains("dir=import"))
        assertTrue(line, line.contains("bytes=10485760"))
        assertTrue(line, line.contains("elapsed=10.00s"))
        assertTrue(line, line.contains("rate=1.00MiB/s"))
        assertTrue(line, line.contains("read=4.00s/40%"))
        assertTrue(line, line.contains("write=5.00s/50%"))
        assertTrue(line, line.contains("commit=0.50s/5%"))
        // Whatever the named buckets do not account for is reported rather than
        // hidden: on a many-small-files tree the per-entry lookups live here,
        // and a large "other" is itself a finding.
        assertTrue(line, line.contains("other=0.50s/5%"))
        assertTrue(line, line.contains("reads=20 writes=20"))
    }

    @Test
    fun `a zero-length run renders without dividing by zero`() {
        // A transfer that failed before moving a byte still gets logged, and
        // NaN or Infinity would make the line unreadable exactly when it is
        // most wanted.
        val line = formatThroughput("export", bytes = 0, stats = TransferStats.EMPTY)
        assertTrue(line, line.contains("rate=0.00MiB/s"))
        assertTrue(line, !line.contains("NaN") && !line.contains("Infinity"))
    }

    /**
     * The point of the split: a fake whose read and write block for known,
     * *different* durations must be attributed to the right bucket. If this
     * ever apportions rather than measures, the pipelining decision would rest
     * on a number that was assumed instead of observed -- which is precisely
     * the 2026-08-08 mistake.
     */
    @Test
    fun `importer attributes blocking time to the stage that actually blocked`() {
        val payload = ByteArray(3 * TreeImporter.CHUNK_SIZE)
        val volume = SlowFakeVolume(writeDelayMs = 40)
        val plan = TransferPlan(
            "root",
            listOf(PlanEntry("big", "big.bin", isDir = false, sizeBytes = payload.size.toLong(), mtime = 0)),
        )

        val outcome = TreeImporter.importTree(
            volume = volume,
            plan = plan,
            destinationRootPath = "/dst",
            source = { _ -> SlowInputStream(payload, readDelayMs = 2) },
            collisionMode = CollisionMode.SKIP,
        )

        assertEquals(null, outcome.failure)
        assertEquals(payload.size.toLong(), outcome.bytesCopied)
        assertEquals(3, outcome.stats.writeCalls)
        assertTrue(
            "write (${outcome.stats.writeNanos} ns) should dominate read (${outcome.stats.readNanos} ns) " +
                "when the destination is the deliberately slow side",
            outcome.stats.writeNanos > outcome.stats.readNanos * 2,
        )
        assertTrue(
            "elapsed must cover both stages, not just one",
            outcome.stats.elapsedNanos >= outcome.stats.readNanos + outcome.stats.writeNanos,
        )
    }

    /** Blocks for a fixed time per `read`, so read time is attributable rather than incidental. */
    private class SlowInputStream(data: ByteArray, private val readDelayMs: Long) : InputStream() {
        private val delegate = ByteArrayInputStream(data)
        override fun read(): Int = delegate.read()
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            Thread.sleep(readDelayMs)
            return delegate.read(b, off, len)
        }
    }

    /** Minimal volume: only what [TreeImporter] touches, with a deliberately slow write. */
    private class SlowFakeVolume(private val writeDelayMs: Long) : LuksVolume(0L) {
        override val info = VolumeInfo("fake", "uuid", 4096, 0L, "btrfs", emptyList())

        private val names = mutableSetOf<String>()

        override fun commitActiveBatch() = Unit

        override fun listDir(path: String): List<Entry> = emptyList()

        override fun beginFileStreaming(): FileWriter = SlowWriter()
        override fun beginFile(sizeBytes: Long): FileWriter = SlowWriter()

        inner class SlowWriter : FileWriter(0L) {
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                Thread.sleep(writeDelayMs)
            }

            override fun finish(parentPath: String, name: String): Long {
                names += name
                return 1L
            }

            override fun abandon() = Unit
        }
    }
}
