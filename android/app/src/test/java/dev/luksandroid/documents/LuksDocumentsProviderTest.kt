package dev.luksandroid.documents

import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.system.ErrnoException
import android.system.OsConstants
import dev.luksandroid.Entry
import dev.luksandroid.FileInfo
import dev.luksandroid.LuksException
import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.StatFsInfo
import dev.luksandroid.VolumeInfo
import dev.luksandroid.session.SessionController
import dev.luksandroid.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class LuksDocumentsProviderTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var session: SessionController
    private lateinit var testVolume: TestLuksVolume
    private lateinit var testContext: TestContext
    private lateinit var provider: LuksDocumentsProvider

    class TestContext : ContextWrapper(null) {
        val revokedUris = mutableListOf<Pair<Uri?, Int>>()

        override fun revokeUriPermission(uri: Uri?, modeFlags: Int) {
            revokedUris.add(uri to modeFlags)
        }
    }

    class TestLuksVolume(
        override val info: VolumeInfo = VolumeInfo(
            label = "TestVol",
            uuid = "uuid-1234",
            blockSize = 4096,
            sizeBytes = 100L * 1024 * 1024,
            fsType = "ext4",
            subvolumes = emptyList()
        ),
        val entriesMap: MutableMap<String, List<Entry>> = mutableMapOf(),
        val fileInfoMap: MutableMap<String, FileInfo> = mutableMapOf(),
        val fileDataMap: MutableMap<String, ByteArray> = mutableMapOf(),
    ) : LuksVolume(0L) {

        val deletedFiles = mutableListOf<String>()
        val createdDirectories = mutableListOf<Pair<String, String>>()
        val writtenFiles = mutableListOf<Triple<String, String, ByteArray>>()
        val renamedFiles = mutableListOf<List<String>>()

        var throwOnDelete: LuksException? = null
        var throwOnCreate: LuksException? = null
        var throwOnRename: LuksException? = null
        var throwOnListDir: LuksException? = null
        var throwOnFileInfo: LuksException? = null

        override fun listDir(path: String): List<Entry> {
            throwOnListDir?.let { throw it }
            return entriesMap[path] ?: emptyList()
        }

        override fun fileInfo(path: String): FileInfo {
            throwOnFileInfo?.let { throw it }
            return fileInfoMap[path] ?: FileInfo(
                path = path,
                size = fileDataMap[path]?.size?.toLong() ?: 1024L,
                mode = 0,
                uid = 0,
                gid = 0,
                links = 1,
                type = if (path.endsWith("/") || entriesMap.containsKey(path)) "dir" else "file",
                atime = 1000L,
                mtime = 1700000000L,
                ctime = 1000L,
            )
        }

        override fun fileSize(path: String): Long {
            return fileDataMap[path]?.size?.toLong() ?: 1024L
        }

        override fun readChunk(path: String, offset: Long, len: Int): ByteArray {
            val data = fileDataMap[path] ?: ByteArray(1024) { (it % 256).toByte() }
            if (offset >= data.size) return ByteArray(0)
            val end = minOf(data.size.toLong(), offset + len).toInt()
            return data.copyOfRange(offset.toInt(), end)
        }

        override fun deleteFile(path: String) {
            throwOnDelete?.let { throw it }
            deletedFiles.add(path)
            fileDataMap.remove(path)
        }

        override fun createDirectory(parentPath: String, name: String): Long {
            throwOnCreate?.let { throw it }
            createdDirectories.add(parentPath to name)
            return 100L
        }

        override fun rename(oldParent: String, oldName: String, newParent: String, newName: String) {
            throwOnRename?.let { throw it }
            renamedFiles.add(listOf(oldParent, oldName, newParent, newName))
        }

        override fun writeFile(parentPath: String, name: String, data: ByteArray): Long {
            throwOnCreate?.let { throw it }
            writtenFiles.add(Triple(parentPath, name, data))
            val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
            fileDataMap[fullPath] = data
            return 101L
        }

        override fun statFs(): StatFsInfo {
            return StatFsInfo(
                totalBytes = 100L * 1024 * 1024,
                freeBytes = 50L * 1024 * 1024,
                availableBytes = 40L * 1024 * 1024,
                totalInodes = 10000L,
                freeInodes = 5000L,
                blockSize = 4096,
            )
        }

        val writtenChunks = mutableListOf<ByteArray>()

        override fun beginFile(sizeBytes: Long): FileWriter {
            throwOnCreate?.let { throw it }
            return object : FileWriter(0L) {
                override fun write(data: java.nio.ByteBuffer, len: Int) {
                    val bytes = ByteArray(len)
                    data.get(bytes)
                    writtenChunks.add(bytes)
                }

                override fun finish(parentPath: String, name: String): Long {
                    val combined = writtenChunks.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
                    writtenFiles.add(Triple(parentPath, name, combined))
                    return 200L
                }

                override fun close() {}
            }
        }
    }

    @Before
    fun setUp() = runBlocking {
        testScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        session = SessionController(scope = testScope)
        testVolume = TestLuksVolume()
        testContext = TestContext()

        session.startUnlockedForTest(
            volume = testVolume,
            partition = PartitionInfo(0, "TestPartition", 0L, 100L * 1024 * 1024, true, 2)
        )

        provider = LuksDocumentsProvider(session = session, scope = testScope)
        val providerInfo = ProviderInfo().apply { authority = LuksDocumentsProvider.AUTHORITY }
        provider.attachInfo(testContext, providerInfo)
    }

    @After
    fun tearDown() {
        testScope.cancel()
    }

    /**
     * Test Pass M.0: queryRoots returns empty cursor when locked/detached, returns root row when unlocked.
     */
    @Test
    fun testM0_queryRoots_returnsEmptyWhenLockedOrDetached_returnsRowWhenUnlocked() = runBlocking {
        // 1. Unlocked state -> 1 root row
        val cursorUnlocked: Cursor = provider.queryRoots(null)
        assertEquals(1, cursorUnlocked.count)
        assertTrue(cursorUnlocked.moveToFirst())

        val rootIdCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_ROOT_ID)
        val docIdCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_DOCUMENT_ID)
        val titleCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_TITLE)
        val flagsCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_FLAGS)
        val availableCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_AVAILABLE_BYTES)
        val capacityCol = cursorUnlocked.getColumnIndexOrThrow(Root.COLUMN_CAPACITY_BYTES)

        assertEquals("luks_root", cursorUnlocked.getString(rootIdCol))
        assertEquals("/", cursorUnlocked.getString(docIdCol))
        assertEquals("TestVol", cursorUnlocked.getString(titleCol))

        val flags = cursorUnlocked.getInt(flagsCol)
        assertTrue(flags and Root.FLAG_LOCAL_ONLY != 0)
        assertTrue(flags and Root.FLAG_SUPPORTS_IS_CHILD != 0)
        assertTrue(flags and Root.FLAG_SUPPORTS_EJECT != 0)
        assertTrue(flags and Root.FLAG_SUPPORTS_CREATE != 0)

        assertEquals(40L * 1024 * 1024, cursorUnlocked.getLong(availableCol))
        assertEquals(100L * 1024 * 1024, cursorUnlocked.getLong(capacityCol))

        // 2. Locked state -> 0 rows
        session.lock()
        assertEquals(SessionState.Locked, session.state.value)
        val cursorLocked: Cursor = provider.queryRoots(null)
        assertEquals(0, cursorLocked.count)

        // 3. Detached state -> 0 rows
        session.onDeviceDetached("Device disconnected")
        val cursorDetached: Cursor = provider.queryRoots(null)
        assertEquals(0, cursorDetached.count)
    }

    /**
     * Test Pass M.1: queryDocument and queryChildDocuments return required 6 columns and correct MIME types.
     */
    @Test
    fun testM1_queryDocumentAndQueryChildDocuments_requiredColumnsAndMimeTypes() {
        testVolume.entriesMap["/"] = listOf(
            Entry("Documents", "dir"),
            Entry("subvol_backup", "dir", isSubvolume = true),
            Entry("photo.jpg", "file"),
            Entry("song.mp3", "file"),
            Entry("video.mp4", "file"),
            Entry("archive.zip", "file"),
            Entry("code.json", "file"),
            Entry("readme.txt", "file"),
            Entry("document.pdf", "file"),
            Entry("unknown_blob", "file"),
        )

        testVolume.fileInfoMap["/Documents"] = FileInfo("/Documents", 0L, 0, 0, 0, 1, "dir", 1000L, 1700000000L, 1000L)
        testVolume.fileInfoMap["/photo.jpg"] = FileInfo("/photo.jpg", 2048L, 0, 0, 0, 1, "file", 1000L, 1700000000L, 1000L)
        testVolume.fileInfoMap["/readme.txt"] = FileInfo("/readme.txt", 512L, 0, 0, 0, 1, "file", 1000L, 1700000000L, 1000L)

        // 1. queryDocument for root "/"
        val rootCursor: Cursor = provider.queryDocument("/", null)
        assertEquals(1, rootCursor.count)
        assertEquals(6, rootCursor.columnCount)
        assertTrue(rootCursor.moveToFirst())

        assertEquals("/", rootCursor.getString(rootCursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
        assertEquals("TestVol", rootCursor.getString(rootCursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
        assertEquals(Document.MIME_TYPE_DIR, rootCursor.getString(rootCursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)))
        val rootFlags = rootCursor.getInt(rootCursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertTrue(rootFlags and Document.FLAG_DIR_SUPPORTS_CREATE != 0)

        // 2. queryDocument for directory "/Documents"
        val dirCursor: Cursor = provider.queryDocument("/Documents", null)
        assertEquals(1, dirCursor.count)
        assertTrue(dirCursor.moveToFirst())
        assertEquals("/Documents", dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
        assertEquals("Documents", dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
        assertEquals(Document.MIME_TYPE_DIR, dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)))
        val dirFlags = dirCursor.getInt(dirCursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertTrue(dirFlags and Document.FLAG_DIR_SUPPORTS_CREATE != 0)
        assertTrue(dirFlags and Document.FLAG_SUPPORTS_DELETE != 0)
        assertTrue(dirFlags and Document.FLAG_SUPPORTS_RENAME != 0)

        // 3. queryDocument for file "/photo.jpg"
        val photoCursor: Cursor = provider.queryDocument("/photo.jpg", null)
        assertEquals(1, photoCursor.count)
        assertTrue(photoCursor.moveToFirst())
        assertEquals("/photo.jpg", photoCursor.getString(photoCursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
        assertEquals("photo.jpg", photoCursor.getString(photoCursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
        assertEquals("image/jpeg", photoCursor.getString(photoCursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)))
        assertEquals(2048L, photoCursor.getLong(photoCursor.getColumnIndexOrThrow(Document.COLUMN_SIZE)))
        val fileFlags = photoCursor.getInt(photoCursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_WRITE != 0)
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_DELETE != 0)
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_RENAME != 0)

        // 4. queryChildDocuments for root "/"
        @Suppress("UNCHECKED_CAST")
        val childCursor: Cursor = provider.queryChildDocuments("/", null, null as String?)
        assertEquals(10, childCursor.count)

        val expectedMimes = mapOf(
            "/Documents" to Document.MIME_TYPE_DIR,
            "/subvol_backup" to Document.MIME_TYPE_DIR,
            "/photo.jpg" to "image/jpeg",
            "/video.mp4" to "video/mp4",
            "/archive.zip" to "application/zip",
            "/code.json" to "application/json",
            "/readme.txt" to "text/plain",
            "/document.pdf" to "application/pdf",
            "/unknown_blob" to "application/octet-stream",
        )

        while (childCursor.moveToNext()) {
            val id = childCursor.getString(childCursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID))
            val mime = childCursor.getString(childCursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE))
            val name = childCursor.getString(childCursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME))
            assertNotNull(name)
            expectedMimes[id]?.let { expectedMime ->
                assertEquals("MIME mismatch for $id", expectedMime, mime)
            }
        }
    }

    /**
     * Test Pass M.2: openDocument("r") callback read chunking and EIO on dead session.
     */
    @Test
    fun testM2_openDocumentReadCallback_chunkingAndEioOnDeadSession() = runBlocking {
        val testData = ByteArray(5000) { (it % 128).toByte() }
        testVolume.fileDataMap["/video.mp4"] = testData

        val callback = LuksProxyCallback("/video.mp4", "r", null, session)

        // 1. Check size
        assertEquals(5000L, callback.onGetSize())

        // 2. Read first chunk
        val chunk1 = ByteArray(1024)
        val read1 = callback.onRead(0L, 1024, chunk1)
        assertEquals(1024, read1)
        assertEquals(0.toByte(), chunk1[0])
        assertEquals(127.toByte(), chunk1[127])

        // 3. Read second chunk with offset
        val chunk2 = ByteArray(2000)
        val read2 = callback.onRead(1024L, 2000, chunk2)
        assertEquals(2000, read2)

        // 4. Read past EOF
        val chunkEof = ByteArray(100)
        val readEof = callback.onRead(6000L, 100, chunkEof)
        assertEquals(0, readEof)

        // 5. Lock session (dead session) -> throws ErrnoException(EIO)
        session.lock()

        try {
            callback.onRead(0L, 100, ByteArray(100))
            fail("Expected ErrnoException on read with locked session")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }

        try {
            callback.onGetSize()
            fail("Expected ErrnoException on onGetSize with locked session")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EIO, e.errno)
        }
    }

    /**
     * Test Pass M.3: isChildDocument prefix matching.
     */
    @Test
    fun testM3_isChildDocument_prefixMatching() {
        // Root parent cases
        assertTrue(provider.isChildDocument("/", "/photo.jpg"))
        assertTrue(provider.isChildDocument("/", "/nested/folder/file.txt"))
        assertFalse(provider.isChildDocument("/", "/"))

        // Subdirectory parent cases
        assertTrue(provider.isChildDocument("/DCIM", "/DCIM/photo.jpg"))
        assertTrue(provider.isChildDocument("/DCIM", "/DCIM/2026/08/photo.jpg"))
        assertFalse(provider.isChildDocument("/DCIM", "/DCIM"))
        assertFalse(provider.isChildDocument("/DCIM", "/DCIM_BACKUP/photo.jpg"))
        assertFalse(provider.isChildDocument("/DCIM", "/Documents/photo.jpg"))
        assertFalse(provider.isChildDocument("/DCIM", "/other"))

        // Multi-level parent cases
        assertTrue(provider.isChildDocument("/a/b/c", "/a/b/c/d.txt"))
        assertFalse(provider.isChildDocument("/a/b/c", "/a/b/cd.txt"))
        assertFalse(provider.isChildDocument("/a/b/c", "/a/b/c"))
    }

    /**
     * Test Pass M.4: deleteDocument revokes URI permission.
     */
    @Test
    fun testM4_deleteDocument_deletesVolumeFileAndRevokesUriPermission() {
        testVolume.fileDataMap["/obsolete.log"] = "log data".toByteArray()

        provider.deleteDocument("/obsolete.log")

        // 1. File must be deleted from volume
        assertTrue(testVolume.deletedFiles.contains("/obsolete.log"))
        assertFalse(testVolume.fileDataMap.containsKey("/obsolete.log"))

        // 2. URI permission must be proactively revoked
        assertTrue(testContext.revokedUris.isNotEmpty())
        val expectedFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        assertEquals(expectedFlags, testContext.revokedUris[0].second)

        // 3. Attempting to delete root document "/" must throw UnsupportedOperationException
        try {
            provider.deleteDocument("/")
            fail("Expected UnsupportedOperationException when deleting root")
        } catch (e: UnsupportedOperationException) {
            // Success
        }
    }

    /**
     * Test Pass M.5: Sequential write tracking and EINVAL refusal on out-of-order onWrite.
     */
    @Test
    fun testM5_sequentialWriteTracking_andEinvalRefusalOnOutOfOrder() {
        // 1. Test createDocument for Directory and File
        val dirId = provider.createDocument("/", Document.MIME_TYPE_DIR, "MyFolder")
        assertEquals("/MyFolder", dirId)
        assertTrue(testVolume.createdDirectories.contains("/" to "MyFolder"))

        val fileId = provider.createDocument("/MyFolder", "text/plain", "notes.txt")
        assertEquals("/MyFolder/notes.txt", fileId)
        assertTrue(testVolume.writtenFiles.any { it.first == "/MyFolder" && it.second == "notes.txt" })

        // 2. Test LuksProxyCallback sequential writes
        val writeCallback = LuksProxyCallback("/stream.bin", "w", null, session)
        assertEquals(0L, writeCallback.onGetSize())

        // In-order write 1: offset 0, len 100
        val chunk1 = ByteArray(100) { 1 }
        val written1 = writeCallback.onWrite(0L, 100, chunk1)
        assertEquals(100, written1)
        assertEquals(100L, writeCallback.onGetSize())

        // In-order write 2: offset 100, len 50
        val chunk2 = ByteArray(50) { 2 }
        val written2 = writeCallback.onWrite(100L, 50, chunk2)
        assertEquals(50, written2)
        assertEquals(150L, writeCallback.onGetSize())

        // Out-of-order write refusal: offset 100 (expected 150) -> EINVAL
        try {
            writeCallback.onWrite(100L, 50, chunk2)
            fail("Expected EINVAL on repeat offset write")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EINVAL, e.errno)
        }

        // Out-of-order write refusal: offset 0 (seek backward) -> EINVAL
        try {
            writeCallback.onWrite(0L, 50, chunk2)
            fail("Expected EINVAL on seek backwards write")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EINVAL, e.errno)
        }

        // Out-of-order write refusal: offset 500 (seek forward gap) -> EINVAL
        try {
            writeCallback.onWrite(500L, 50, chunk2)
            fail("Expected EINVAL on gap write")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EINVAL, e.errno)
        }

        // In-order write continuation: offset 150, len 25
        val chunk3 = ByteArray(25) { 3 }
        val written3 = writeCallback.onWrite(150L, 25, chunk3)
        assertEquals(25, written3)
        assertEquals(175L, writeCallback.onGetSize())

        // Release finishes file
        writeCallback.onRelease()
        assertTrue(testVolume.writtenFiles.any { it.first == "/" && it.second == "stream.bin" })
    }

    /**
     * Test Pass M.6: ejectRoot triggers LuksSession.lock() and exception messages have 0 filename leakage.
     */
    @Test
    fun testM6_ejectRootLocksSession_andZeroFilenameLeakageInRefusalExceptions() = runBlocking {
        // 1. ejectRoot triggers lock
        assertEquals(SessionState.Unlocked::class, session.state.value::class)
        provider.ejectRoot(LuksDocumentsProvider.ROOT_ID)
        assertEquals(SessionState.Locked, session.state.value)

        try {
            provider.ejectRoot("invalid_root_id")
            fail("Expected IllegalArgumentException on invalid root ID")
        } catch (e: IllegalArgumentException) {
            assertFalse(e.message?.contains("invalid_root_id") == true)
        }

        // Reset session to Unlocked for testing refusal exceptions
        session.startUnlockedForTest(volume = testVolume)

        // 2. Test renameDocument
        testContext.revokedUris.clear()
        val newDocId = provider.renameDocument("/old_secret.txt", "new_name.txt")
        assertEquals("/new_name.txt", newDocId)
        assertEquals(listOf("/", "old_secret.txt", "/", "new_name.txt"), testVolume.renamedFiles.last())
        assertTrue(testContext.revokedUris.isNotEmpty())
        assertEquals(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION, testContext.revokedUris[0].second)

        // 3. Test refusal mappings and strict Security Invariant #7 (0 filename leakage)
        val sensitivePath = "/private/passwords_database.kdbx"
        val sensitiveName = "passwords_database.kdbx"

        val refusalCodes = listOf(
            LuksException.ALREADY_EXISTS,
            LuksException.NOT_FOUND,
            LuksException.UNSUPPORTED,
            LuksException.WRONG_TARGET,
            LuksException.ITEM_TOO_LARGE,
            LuksException.NO_SPACE,
            LuksException.WRITER_BUSY,
            LuksException.CORRUPT,
            LuksException.IO,
            LuksException.TRANSPORT,
            LuksException.PANIC,
            LuksException.MUTEX_POISONED,
        )

        for (code in refusalCodes) {
            testVolume.throwOnCreate = LuksException("Internal native error at $sensitivePath", code)
            testVolume.throwOnDelete = LuksException("Internal native error at $sensitivePath", code)
            testVolume.throwOnRename = LuksException("Internal native error at $sensitivePath", code)
            testVolume.throwOnFileInfo = LuksException("Internal native error at $sensitivePath", code)

            // Test createDocument refusal
            try {
                provider.createDocument("/", "text/plain", sensitiveName)
                fail("Expected exception for code $code in createDocument")
            } catch (t: Throwable) {
                val msg = t.message.orEmpty()
                assertFalse("Leaked filename in createDocument for code $code: $msg", msg.contains(sensitiveName))
                assertFalse("Leaked path in createDocument for code $code: $msg", msg.contains(sensitivePath))
            }

            // Test deleteDocument refusal
            try {
                provider.deleteDocument(sensitivePath)
                fail("Expected exception for code $code in deleteDocument")
            } catch (t: Throwable) {
                val msg = t.message.orEmpty()
                assertFalse("Leaked filename in deleteDocument for code $code: $msg", msg.contains(sensitiveName))
                assertFalse("Leaked path in deleteDocument for code $code: $msg", msg.contains(sensitivePath))
            }

            // Test renameDocument refusal
            try {
                provider.renameDocument(sensitivePath, "renamed.txt")
                fail("Expected exception for code $code in renameDocument")
            } catch (t: Throwable) {
                val msg = t.message.orEmpty()
                assertFalse("Leaked filename in renameDocument for code $code: $msg", msg.contains(sensitiveName))
                assertFalse("Leaked path in renameDocument for code $code: $msg", msg.contains(sensitivePath))
            }

            // Test queryDocument refusal
            try {
                provider.queryDocument(sensitivePath, null)
                fail("Expected exception for code $code in queryDocument")
            } catch (t: Throwable) {
                val msg = t.message.orEmpty()
                assertFalse("Leaked filename in queryDocument for code $code: $msg", msg.contains(sensitiveName))
                assertFalse("Leaked path in queryDocument for code $code: $msg", msg.contains(sensitivePath))
            }
        }
    }
}
