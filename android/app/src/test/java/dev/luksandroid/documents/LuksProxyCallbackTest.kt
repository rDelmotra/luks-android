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
    // Read-only trim (§6.2, supersedes Pass M.5): onWrite always refuses.
    //
    // `begin_file_streaming` (the unknown-size write primitive) has no JNI or
    // Kotlin surface. The only write primitive available, `beginFile`, requires
    // an upfront size the proxy cannot know, and the sized writer rejects any
    // write past that size. Rather than half-work via the broken sized API,
    // onWrite refuses explicitly and immediately with EROFS, and never touches
    // the volume's write path at all.
    // ===================================================================

    @Test
    fun testReadOnlyTrim_onWrite_alwaysThrowsErofsWithoutTouchingVolume() {
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

    @Test
    fun testProxyHandlerThread() {
        val handler = LuksProxyHandlerThread.handler
        assertNotNull(handler)
    }
}
