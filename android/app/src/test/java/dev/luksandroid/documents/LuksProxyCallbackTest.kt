package dev.luksandroid.documents

import android.system.ErrnoException
import android.system.OsConstants
import dev.luksandroid.Entry
import dev.luksandroid.FileInfo
import dev.luksandroid.LuksException
import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.VolumeInfo
import dev.luksandroid.session.SessionController
import dev.luksandroid.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer

class LuksProxyCallbackTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var session: SessionController
    private lateinit var testVolume: TestLuksVolume

    class TestLuksVolume(
        override val info: VolumeInfo = VolumeInfo(
            label = "ProxyTestVol",
            uuid = "uuid-proxy-1234",
            blockSize = 4096,
            sizeBytes = 100L * 1024 * 1024,
            fsType = "ext4",
            subvolumes = emptyList()
        ),
        val fileDataMap: MutableMap<String, ByteArray> = mutableMapOf(),
        val fileInfoMap: MutableMap<String, FileInfo> = mutableMapOf(),
    ) : LuksVolume(0L) {

        val writtenFiles = mutableListOf<Triple<String, String, ByteArray>>()
        val abandonedWriters = mutableListOf<FileWriter>()
        var throwOnRead: Throwable? = null
        var throwOnWrite: Throwable? = null
        var throwOnFinish: Throwable? = null
        var throwOnFileInfo: Throwable? = null

        /**
         * Overridable seam for `nativeWriteSupported()`. Defaults to true here (unlike the
         * provider test's fake) because most of this file's write tests exercise the real
         * streaming path; the fail-closed tests opt out explicitly.
         */
        var writeSupported: Boolean = true
        override val canWrite: Boolean get() = writeSupported

        override fun fileInfo(path: String): FileInfo {
            throwOnFileInfo?.let { throw it }
            return fileInfoMap[path] ?: FileInfo(
                path = path,
                size = fileDataMap[path]?.size?.toLong() ?: 1024L,
                mode = 0,
                uid = 0,
                gid = 0,
                links = 1,
                type = if (path.endsWith("/")) "dir" else "file",
                atime = 1000L,
                mtime = 1700000000L,
                ctime = 1000L,
            )
        }

        override fun fileSize(path: String): Long {
            return fileDataMap[path]?.size?.toLong() ?: 1024L
        }

        override fun readChunk(path: String, offset: Long, len: Int): ByteArray {
            throwOnRead?.let { throw it }
            val data = fileDataMap[path] ?: ByteArray(1024) { (it % 256).toByte() }
            if (offset >= data.size) return ByteArray(0)
            val end = minOf(data.size.toLong(), offset + len).toInt()
            return data.copyOfRange(offset.toInt(), end)
        }

        override fun beginFile(sizeBytes: Long): FileWriter {
            return TestFileWriter()
        }

        override fun beginFileStreaming(): FileWriter {
            return TestFileWriter()
        }

        override fun writeChunk(writer: FileWriter, data: ByteArray, offset: Int, length: Int) {
            throwOnWrite?.let { throw it }
            writer.write(data, offset, length)
        }

        override fun finishFile(writer: FileWriter, parentPath: String, name: String): Long {
            throwOnFinish?.let { throw it }
            return writer.finish(parentPath, name)
        }

        override fun abandonFile(writer: FileWriter) {
            abandonedWriters.add(writer)
            writer.abandon()
        }

        inner class TestFileWriter : FileWriter(0L) {
            val chunks = mutableListOf<ByteArray>()
            var finished = false
            var abandoned = false

            override fun write(data: ByteBuffer, len: Int) {
                val bytes = ByteArray(len)
                data.get(bytes)
                chunks.add(bytes)
            }

            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                chunks.add(bytes.copyOfRange(offset, offset + length))
            }

            override fun finish(parentPath: String, name: String): Long {
                finished = true
                val combined = chunks.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
                writtenFiles.add(Triple(parentPath, name, combined))
                val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                fileDataMap[fullPath] = combined
                return 200L
            }

            override fun abandon() {
                abandoned = true
            }

            override fun close() {
                abandoned = true
            }
        }
    }

    @Before
    fun setUp() {
        runBlocking {
            testScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            session = SessionController(scope = testScope)
            testVolume = TestLuksVolume()

            session.startUnlockedForTest(
                volume = testVolume,
                partition = PartitionInfo(0, "TestPartition", 0L, 100L * 1024 * 1024, true, 2)
            )
        }
    }

    @After
    fun tearDown() {
        testScope.cancel()
        PendingDocuments.clear()
    }

    // ==========================================
    // Pass M.2: Seekable Read Streaming Tests
    // ==========================================

    @Test
    fun testM2_onGetSize_returnsVolumeFileSize() {
        testVolume.fileDataMap["/sample.txt"] = ByteArray(256) { 0x42 }
        testVolume.fileInfoMap["/sample.txt"] = FileInfo(
            path = "/sample.txt",
            size = 256L,
            mode = 0,
            uid = 0,
            gid = 0,
            links = 1,
            type = "file",
            atime = 1000L,
            mtime = 1000L,
            ctime = 1000L
        )

        val callback = LuksReadProxyCallback(session = session, documentId = "/sample.txt")
        val size = callback.onGetSize()
        assertEquals(256L, size)
    }

    /**
     * A write proxy's [LuksProxyCallback.onGetSize] must never consult the volume.
     *
     * Regression test for the failure that made every create-a-file and every
     * copy-into-the-volume fail on device while reads, mkdir and delete worked.
     *
     * FUSE calls onGetSize for getattr, which happens on *open* -- before any byte is
     * written. The document a write proxy serves is still pending by construction, so
     * asking the volume returned NOT_FOUND, and throwing it made the open itself fail.
     * That surfaced to the caller as ContentResolver.openFileDescriptor() returning null
     * with no exception, which reads as "this provider cannot write" rather than as a
     * stat of a not-yet-materialized file.
     *
     * The fake volume is left deliberately empty here: the pending document has no entry,
     * exactly as on device.
     */
    @Test
    fun testWrite_onGetSizeOnAPendingDocumentReportsZeroWithoutTouchingTheVolume() {
        val docId = PendingDocuments.register("/", "brand-new.txt")
        assertTrue(testVolume.fileInfoMap.isEmpty())
        // Make any volume lookup fail loudly, so "returns 0" cannot pass by accident.
        testVolume.throwOnFileInfo = RuntimeException("onGetSize must not reach the volume")

        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        assertEquals(
            "a pending document has zero bytes until something is written",
            0L,
            callback.onGetSize(),
        )
    }

    @Test
    fun testM2_onGetSize_throwsEioWhenSessionDead() = runBlocking {
        testVolume.fileDataMap["/sample.txt"] = ByteArray(256)
        val callback = LuksReadProxyCallback(session = session, documentId = "/sample.txt")

        // Lock session to simulate dead/closed session
        session.lock()

        try {
            callback.onGetSize()
            fail("Expected ErrnoException(EIO) when session is locked")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }
    }

    @Test
    fun testM2_onGetSize_throwsEioWhenVolumeErrors() {
        testVolume.throwOnFileInfo = RuntimeException("I/O error reading metadata")
        val callback = LuksReadProxyCallback(session = session, documentId = "/corrupt.txt")

        try {
            callback.onGetSize()
            fail("Expected ErrnoException(EIO) on volume error")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }
    }

    @Test
    fun testM2_onRead_readsChunksAndCopiesToBuffer() {
        val original = ByteArray(500) { (it % 100).toByte() }
        testVolume.fileDataMap["/binary.dat"] = original

        val callback = LuksReadProxyCallback(session = session, documentId = "/binary.dat")

        // 1. Read first 100 bytes from offset 0
        val buffer1 = ByteArray(100)
        val read1 = callback.onRead(0L, 100, buffer1)
        assertEquals(100, read1)
        val expected1 = original.copyOfRange(0, 100)
        assertArrayEquals(expected1, buffer1)

        // 2. Read next 200 bytes from offset 100
        val buffer2 = ByteArray(200)
        val read2 = callback.onRead(100L, 200, buffer2)
        assertEquals(200, read2)
        val expected2 = original.copyOfRange(100, 300)
        assertArrayEquals(expected2, buffer2)

        // 3. Read past EOF (offset 500) returns 0
        val bufferEof = ByteArray(100)
        val readEof = callback.onRead(500L, 100, bufferEof)
        assertEquals(0, readEof)

        // 4. Read size <= 0 returns 0
        val readZero = callback.onRead(0L, 0, buffer1)
        assertEquals(0, readZero)
    }

    @Test
    fun testM2_onRead_throwsEioWhenSessionDead() = runBlocking {
        testVolume.fileDataMap["/binary.dat"] = ByteArray(100)
        val callback = LuksReadProxyCallback(session = session, documentId = "/binary.dat")

        session.lock()

        val buf = ByteArray(50)
        try {
            callback.onRead(0L, 50, buf)
            fail("Expected ErrnoException(EIO) when session is locked")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }
    }

    @Test
    fun testM2_onRead_throwsEioWhenVolumeErrors() {
        testVolume.fileDataMap["/binary.dat"] = ByteArray(100)
        testVolume.throwOnRead = LuksException("Read failed", LuksException.IO)
        val callback = LuksReadProxyCallback(session = session, documentId = "/binary.dat")

        val buf = ByteArray(50)
        try {
            callback.onRead(0L, 50, buf)
            fail("Expected ErrnoException(EIO) on volume read exception")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }
    }

    // ===================================================================
    // Fail-closed: without write support, onWrite always refuses, and never
    // touches the volume's write path at all. (Formerly the unconditional
    // read-only trim from §6.2, now scoped to the write-support-absent case
    // now that the streaming write path itself is implemented below.)
    // ===================================================================

    @Test
    fun testReadOnlyTrim_onWrite_alwaysThrowsErofsWithoutTouchingVolume() {
        testVolume.writeSupported = false
        val callback = LuksWriteProxyCallback(session = session, documentId = "/write_test.bin")

        // Even a well-formed, in-order, initial write must be refused.
        try {
            callback.onWrite(0L, 100, ByteArray(100))
            fail("Expected ErrnoException(EROFS) on write")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EROFS, e.errno)
        }

        // The volume's write primitives must never have been invoked.
        assertTrue(testVolume.writtenFiles.isEmpty())
        assertTrue(testVolume.abandonedWriters.isEmpty())
    }

    @Test
    fun testReadOnlyTrim_onWrite_refusesRegardlessOfOffsetOrRepetition() {
        testVolume.writeSupported = false
        val callback = LuksWriteProxyCallback(session = session, documentId = "/refuse.bin")

        for (offset in listOf(0L, 10L, 100L, 0L)) {
            try {
                callback.onWrite(offset, 50, ByteArray(50))
                fail("Expected ErrnoException(EROFS) at offset $offset")
            } catch (e: ErrnoException) {
                assertEquals(OsConstants.EROFS, e.errno)
            }
        }
    }

    @Test
    fun testReadOnlyTrim_onRelease_isCleanNoOpForWriteMode() {
        testVolume.writeSupported = false
        val callback = LuksWriteProxyCallback(session = session, documentId = "/abandon.bin")

        try {
            callback.onWrite(0L, 50, ByteArray(50))
        } catch (_: ErrnoException) {
            // Expected refusal.
        }

        // No writer was ever created, so release must not attempt to finish or abandon one.
        callback.onRelease()
        assertTrue(testVolume.writtenFiles.isEmpty())
        assertTrue(testVolume.abandonedWriters.isEmpty())
    }

    // ===================================================================
    // Streaming write path: sequential offsets, mutex-for-the-lifetime,
    // abandon-on-error. See LuksProxyCallback's class doc for the invariants.
    // ===================================================================

    @Test
    fun testWrite_successfulMultiChunkStream_materializesOnRelease() {
        val docId = PendingDocuments.register("/", "upload.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        val chunk1 = ByteArray(100) { 1 }
        val chunk2 = ByteArray(200) { 2 }
        val chunk3 = ByteArray(50) { 3 }

        assertEquals(100, callback.onWrite(0L, 100, chunk1))
        assertEquals(200, callback.onWrite(100L, 200, chunk2))
        assertEquals(50, callback.onWrite(300L, 50, chunk3))

        callback.onRelease()

        assertEquals(1, testVolume.writtenFiles.size)
        val (parentPath, name, combined) = testVolume.writtenFiles.single()
        assertEquals("/", parentPath)
        assertEquals("upload.bin", name)
        assertEquals(350, combined.size)
        assertArrayEquals(chunk1, combined.copyOfRange(0, 100))
        assertArrayEquals(chunk2, combined.copyOfRange(100, 300))
        assertArrayEquals(chunk3, combined.copyOfRange(300, 350))

        // The pending registration is consumed once the file is real.
        assertFalse(PendingDocuments.isPending(docId))
    }

    @Test
    fun testWrite_nonSequentialOffset_rejectedWithEinvalAndAbandons() {
        val docId = PendingDocuments.register("/", "seek_attempt.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        assertEquals(100, callback.onWrite(0L, 100, ByteArray(100)))

        try {
            // Skips ahead instead of continuing at offset 100 -- the one thing this writer
            // can never honor safely.
            callback.onWrite(250L, 50, ByteArray(50))
            fail("Expected ErrnoException(EINVAL) for a non-sequential offset")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EINVAL, e.errno)
        }

        assertTrue("a non-sequential write must abandon, not materialize", testVolume.writtenFiles.isEmpty())
        assertEquals(1, testVolume.abandonedWriters.size)
        assertFalse("pending entry must be dropped once abandoned", PendingDocuments.isPending(docId))
    }

    @Test
    fun testWrite_midStreamVolumeFailure_abandonsAndLeavesNoPendingEntry() {
        val docId = PendingDocuments.register("/", "flaky.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        assertEquals(100, callback.onWrite(0L, 100, ByteArray(100)))

        testVolume.throwOnWrite = RuntimeException("simulated I/O failure")
        try {
            callback.onWrite(100L, 50, ByteArray(50))
            fail("Expected ErrnoException(EIO) when the volume write fails")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }

        assertTrue("a failed write must never materialize a half file", testVolume.writtenFiles.isEmpty())
        assertEquals(1, testVolume.abandonedWriters.size)
        assertFalse(PendingDocuments.isPending(docId))
    }

    @Test
    fun testWrite_onReleaseWithNoWrites_materializesNothing() {
        val docId = PendingDocuments.register("/", "untouched.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        callback.onRelease()

        assertTrue(testVolume.writtenFiles.isEmpty())
        assertTrue(testVolume.abandonedWriters.isEmpty())
        // The registration is dropped rather than left open for a second attempt: a caller
        // that created a document and closed it unwritten has abandoned it, and a surviving
        // entry would keep queryDocument reporting a 0-byte file that never materializes --
        // visible to the user as a real file they cannot open.
        assertFalse(PendingDocuments.isPending(docId))
    }

    @Test
    fun testWrite_readModeReleaseLeavesAnUnrelatedPendingDocumentAlone() {
        // A read proxy never owns a pending entry, so closing one must not evict a document
        // some other caller is still preparing to write.
        val docId = PendingDocuments.register("/", "someone_elses.bin")
        val readCallback = LuksReadProxyCallback(session = session, documentId = docId)

        readCallback.onRelease()

        assertTrue(PendingDocuments.isPending(docId))
    }

    @Test
    fun testWrite_withoutWriteSupport_refusesBeforeClaimingTheTransferLock() {
        testVolume.writeSupported = false
        val docId = PendingDocuments.register("/", "no_support.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        try {
            callback.onWrite(0L, 10, ByteArray(10))
            fail("Expected ErrnoException(EROFS) without write support")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EROFS, e.errno)
        }

        // The transfer lock must never have been claimed -- it must still be free.
        val stillFree = runBlocking { dev.luksandroid.session.TransferManager.tryAcquireForSafWrite(100L) }
        assertTrue("write-support refusal must not have claimed the transfer lock", stillFree)
        if (stillFree) {
            dev.luksandroid.session.TransferManager.releaseSafWriteLock()
        }
    }

    @Test
    fun testWrite_notAPendingDocument_refusesWithoutCreatingAWriter() {
        // No PendingDocuments.register call for this id -- simulates an existing on-disk
        // file, or a stale/foreign id. The provider is meant to gate this before ever
        // constructing the callback, but the callback enforces it independently too.
        val callback = LuksWriteProxyCallback(session = session, documentId = "/not_pending.bin")

        try {
            callback.onWrite(0L, 10, ByteArray(10))
            fail("Expected ErrnoException(EROFS) for a non-pending document")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EROFS, e.errno)
        }
        assertTrue(testVolume.writtenFiles.isEmpty())
    }

    @Test
    fun testOnFsync_isANoOpReportingSuccess() {
        val docId = PendingDocuments.register("/", "fsync_test.bin")
        val callback = LuksWriteProxyCallback(session = session, documentId = docId)

        callback.onWrite(0L, 10, ByteArray(10))
        // Must not throw -- nothing is durable yet, but that is reported as success, not EIO.
        callback.onFsync()

        assertTrue(testVolume.writtenFiles.isEmpty())
        callback.onRelease()
        assertEquals(1, testVolume.writtenFiles.size)
    }

    @Test
    fun testProxyHandlerThread() {
        val handler = LuksProxyHandlerThread.handler
        assertNotNull(handler)
    }
}
