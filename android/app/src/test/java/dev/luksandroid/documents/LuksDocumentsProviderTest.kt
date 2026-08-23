package dev.luksandroid.documents

import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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
        // CopyOnWriteArrayList, not a plain mutableListOf: revocation on lock/detach happens
        // on the session's background collector coroutine (N.8), while tests observe this
        // list from the test thread. A plain ArrayList has no happens-before edge across
        // threads here, so a mutation can go unseen indefinitely (or forever, if the JIT
        // hoists the read out of a polling loop).
        val revokedUris = java.util.concurrent.CopyOnWriteArrayList<Pair<Uri?, Int>>()

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

        /**
         * Overridable seam for `nativeWriteSupported()`. Defaults to false, matching the
         * common case (a build without dangerous-write-support) and keeping every test that
         * doesn't opt in exercising the fail-closed path -- calling the real native function
         * in a host JVM test throws UnsatisfiedLinkError, which is exactly what this seam
         * exists to avoid.
         */
        var writeSupported: Boolean = false
        override val canWrite: Boolean get() = writeSupported

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
        PendingDocuments.clear()
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
        // Read-only trim (§6.2): the provider must never advertise create support it cannot deliver.
        assertFalse(flags and Root.FLAG_SUPPORTS_CREATE != 0)

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
        assertFalse(rootFlags and Document.FLAG_DIR_SUPPORTS_CREATE != 0)

        // 2. queryDocument for directory "/Documents"
        val dirCursor: Cursor = provider.queryDocument("/Documents", null)
        assertEquals(1, dirCursor.count)
        assertTrue(dirCursor.moveToFirst())
        assertEquals("/Documents", dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
        assertEquals("Documents", dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
        assertEquals(Document.MIME_TYPE_DIR, dirCursor.getString(dirCursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)))
        val dirFlags = dirCursor.getInt(dirCursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertFalse(dirFlags and Document.FLAG_DIR_SUPPORTS_CREATE != 0)
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
        assertFalse(fileFlags and Document.FLAG_SUPPORTS_WRITE != 0)
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
     * DEFECT 1: renameDocument must refuse a rename onto a name that already exists,
     * matching the platform's own FileSystemProvider rather than the native layer's POSIX
     * semantics (which silently free the destination's extents -- see
     * core/src/fs/btrfs/write/txn/rename.rs and core/src/fs/ext4/file.rs). The native
     * `rename` call must never even be reached once a collision is detected -- that is the
     * only proof that nothing was destroyed.
     */
    @Test
    fun testRenameDocument_refusesWhenDestinationNameAlreadyExists() {
        testVolume.entriesMap["/"] = listOf(
            Entry("keep_me.txt", "file"),
            Entry("old_name.txt", "file"),
        )

        try {
            provider.renameDocument("/old_name.txt", "keep_me.txt")
            fail("Expected an exception when renaming onto an existing name")
        } catch (e: IllegalStateException) {
            // Success: ALREADY_EXISTS maps to IllegalStateException via mapLuksException,
            // the same path a native-side collision would take.
        }

        // The native rename must never have been called -- the destination survives.
        assertTrue("rename must not reach the volume once a collision is detected", testVolume.renamedFiles.isEmpty())
    }

    /**
     * DEFECT 1 (pending-document half): a rename must also be refused when the destination
     * name is claimed by a still-pending (not yet materialized) document, not only by a
     * real on-disk entry -- otherwise a rename could collide with a file mid-upload that
     * `listDir` cannot see yet.
     */
    @Test
    fun testRenameDocument_refusesWhenDestinationNameIsPending() {
        testVolume.entriesMap["/"] = listOf(Entry("old_name.txt", "file"))
        PendingDocuments.register("/", "incoming.txt")

        try {
            provider.renameDocument("/old_name.txt", "incoming.txt")
            fail("Expected an exception when renaming onto a pending document's name")
        } catch (e: IllegalStateException) {
            // Success
        }
        assertTrue(testVolume.renamedFiles.isEmpty())
    }

    /**
     * A no-op rename (new name equal to the current name) is not a collision with itself
     * and must be allowed through to the native layer unchanged.
     */
    @Test
    fun testRenameDocument_sameNameIsNotTreatedAsACollision() {
        testVolume.entriesMap["/"] = listOf(Entry("same.txt", "file"))

        val newDocId = provider.renameDocument("/same.txt", "same.txt")

        assertEquals("/same.txt", newDocId)
        assertEquals(listOf("/", "same.txt", "/", "same.txt"), testVolume.renamedFiles.last())
    }

    /**
     * Test Pass M.5: the provider must never advertise or act on a write capability the
     * loaded .so cannot deliver. With `writeSupported` false (the fake's default, matching
     * a build without dangerous-write-support), createDocument refuses both kinds and
     * openDocument refuses every write-capable mode cleanly, without touching the volume,
     * while "r" is still accepted past the guard.
     */
    @Test
    fun testM5_writeSupportAbsent_createDocumentAndWriteModeOpenDocumentRefuseCleanly() {
        assertFalse("this test covers the fail-closed path", testVolume.writeSupported)

        // 1. createDocument for a directory must refuse.
        try {
            provider.createDocument("/", Document.MIME_TYPE_DIR, "MyFolder")
            fail("Expected UnsupportedOperationException creating a directory")
        } catch (e: UnsupportedOperationException) {
            // Success
        }
        assertTrue(testVolume.createdDirectories.isEmpty())

        // 2. createDocument for a file must refuse.
        try {
            provider.createDocument("/", "text/plain", "notes.txt")
            fail("Expected UnsupportedOperationException creating a file")
        } catch (e: UnsupportedOperationException) {
            // Success
        }
        assertTrue(testVolume.writtenFiles.isEmpty())

        // 3. openDocument with any write-capable mode must refuse before touching the volume
        //    or the platform ProxyFileDescriptor machinery (TestContext has no StorageManager,
        //    so reaching that code would throw something other than UnsupportedOperationException).
        for (writeMode in listOf("w", "wt", "wa", "rw", "rwt")) {
            try {
                provider.openDocument("/photo.jpg", writeMode, null)
                fail("Expected UnsupportedOperationException for openDocument mode=$writeMode")
            } catch (e: UnsupportedOperationException) {
                // Success
            }
        }

        // 4. openDocument("r") must NOT be refused by the write-mode guard: it should fail later,
        //    for an unrelated reason (no StorageManager in the test Context), proving the read
        //    path is not blocked by the read-only trim.
        try {
            provider.openDocument("/photo.jpg", "r", null)
            fail("Expected an exception once past the write-mode guard (no StorageManager in test)")
        } catch (e: UnsupportedOperationException) {
            fail("openDocument(\"r\") must not be refused by the write-mode guard")
        } catch (e: Throwable) {
            // Success: got past the guard, failed for an unrelated (environment) reason.
        }
    }

    /**
     * With write support built in, createDocument creates a directory for real and
     * immediately: directories have a create-empty primitive (nativeCreateDirectory), unlike
     * files. Creating a file instead registers a pending document -- nothing touches the
     * volume until the write proxy opened against that id finishes (see PendingDocuments).
     */
    @Test
    fun testCreateDocument_withWriteSupport_createsDirectoryForRealAndRegistersFileAsPending() {
        testVolume.writeSupported = true

        val docId = provider.createDocument("/", Document.MIME_TYPE_DIR, "MyFolder")

        assertEquals("/MyFolder", docId)
        assertEquals(listOf("/" to "MyFolder"), testVolume.createdDirectories)

        // Nested parent: the documentId must not end up with a doubled separator.
        val nested = provider.createDocument("/MyFolder", Document.MIME_TYPE_DIR, "Inner")
        assertEquals("/MyFolder/Inner", nested)

        // A file has no create-empty primitive: it is registered pending, not written.
        val fileDocId = provider.createDocument("/", "text/plain", "notes.txt")
        assertEquals("/notes.txt", fileDocId)
        assertTrue(testVolume.writtenFiles.isEmpty())
        assertTrue(PendingDocuments.isPending(fileDocId))
    }

    /**
     * DEFECT 2 (up-front half): createDocument for a file whose name already exists on disk
     * must not register the pending document under the colliding name -- doing so defers the
     * collision to finish_file's own check deep inside a void platform callback
     * (LuksProxyCallback.onRelease), silently discarding every byte the caller had already
     * streamed in when it fires. Resolve it up front instead, the way
     * FileSystemProvider.createDocument does, and hand back the id for the name actually
     * chosen -- SAF's contract explicitly allows that.
     */
    @Test
    fun testCreateDocument_fileNameCollisionOnDisk_resolvesToAUniqueNameUpFront() {
        testVolume.writeSupported = true
        testVolume.entriesMap["/"] = listOf(Entry("notes.txt", "file"))

        val docId = provider.createDocument("/", "text/plain", "notes.txt")

        assertEquals("/notes (1).txt", docId)
        assertTrue(PendingDocuments.isPending(docId))
        assertFalse(PendingDocuments.isPending("/notes.txt"))
    }

    /**
     * Same collision, but against a still-pending document rather than an on-disk one --
     * PendingDocuments must be consulted, not just the volume listing.
     */
    @Test
    fun testCreateDocument_fileNameCollisionWithPendingDocument_resolvesToAUniqueNameUpFront() {
        testVolume.writeSupported = true
        provider.createDocument("/", "text/plain", "draft.txt")

        val secondDocId = provider.createDocument("/", "text/plain", "draft.txt")

        assertEquals("/draft (1).txt", secondDocId)
    }

    /**
     * A repeated collision must keep counting up rather than looping or throwing.
     */
    @Test
    fun testCreateDocument_repeatedFileNameCollision_countsUpPastTheFirstSuffix() {
        testVolume.writeSupported = true
        testVolume.entriesMap["/"] = listOf(
            Entry("notes.txt", "file"),
            Entry("notes (1).txt", "file"),
        )

        val docId = provider.createDocument("/", "text/plain", "notes.txt")

        assertEquals("/notes (2).txt", docId)
    }

    /**
     * queryDocument on a still-pending file synthesizes a 0-byte row without touching the
     * volume at all -- it carries FLAG_SUPPORTS_WRITE (the one flag an existing on-disk file
     * never gets) so a write-mode openDocument against it is exactly what is expected.
     */
    @Test
    fun testQueryDocument_pendingFile_synthesizesZeroByteRowWithWriteFlag() {
        testVolume.writeSupported = true
        val docId = provider.createDocument("/", "text/plain", "draft.txt")

        val cursor = provider.queryDocument(docId, null)
        assertEquals(1, cursor.count)
        assertTrue(cursor.moveToFirst())
        assertEquals(docId, cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
        assertEquals("draft.txt", cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
        assertEquals(0L, cursor.getLong(cursor.getColumnIndexOrThrow(Document.COLUMN_SIZE)))
        val flags = cursor.getInt(cursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertTrue(flags and Document.FLAG_SUPPORTS_WRITE != 0)

        // The volume itself was never asked about this id -- it does not exist there.
        assertFalse(testVolume.fileInfoMap.containsKey(docId))
    }

    /**
     * openDocument gating for write-capable modes, with write support built in: "w"/"wt"
     * succeed past the guard for a pending document (failing later only because the test
     * Context has no StorageManager); an existing on-disk file is refused distinctly from an
     * unsupported mode; "wa"/"rw"/"rwt" are refused outright regardless of pending status.
     */
    @Test
    fun testOpenDocument_writeModeGating_withWriteSupportBuiltIn() {
        testVolume.writeSupported = true
        val pendingDocId = provider.createDocument("/", "text/plain", "in_progress.txt")

        // "w"/"wt" against a pending document get past the write-mode guard entirely --
        // they fail only because this test Context has no StorageManager to hand back a
        // real proxy fd, the same trick testM5 uses to prove the read path isn't blocked.
        for (writeMode in listOf("w", "wt")) {
            try {
                provider.openDocument(pendingDocId, writeMode, null)
                fail("Expected an exception once past the write-mode guard (no StorageManager in test)")
            } catch (e: UnsupportedOperationException) {
                fail("openDocument(\"$writeMode\") on a pending document must not be refused: ${e.message}")
            } catch (e: Throwable) {
                // Success: got past every write gate, failed for an unrelated reason.
            }
        }

        // An existing on-disk file (never registered as pending) must be refused distinctly
        // from the append/read-write refusal below -- overwrite is out of scope.
        try {
            provider.openDocument("/photo.jpg", "w", null)
            fail("Expected UnsupportedOperationException opening an existing file for write")
        } catch (e: UnsupportedOperationException) {
            assertTrue(
                "expected an overwrite-specific message, got: ${e.message}",
                e.message?.contains("verwrit") == true,
            )
        }

        // "wa" (append), "rw" and "rwt" have no counterpart in a streaming, single-writer,
        // append-only primitive -- refused outright, even for the pending document itself.
        for (unsupportedMode in listOf("wa", "rw", "rwt")) {
            try {
                provider.openDocument(pendingDocId, unsupportedMode, null)
                fail("Expected UnsupportedOperationException for mode=$unsupportedMode")
            } catch (e: UnsupportedOperationException) {
                // Success
            }
        }
    }

    /**
     * Pending documents reference a volume session that stops existing once the session
     * locks -- they must be dropped on the same transition that revokes issued URI grants
     * (§4.4), not left to dangle and resurrect a stale write target on the next unlock.
     */
    @Test
    fun testPendingDocuments_clearedOnSessionLock() = runBlocking {
        testVolume.writeSupported = true
        val docId = provider.createDocument("/", "text/plain", "orphan.txt")
        assertTrue(PendingDocuments.isPending(docId))

        provider.onCreate()
        session.lock()

        withTimeout(3000) {
            while (PendingDocuments.isPending(docId)) {
                delay(10)
            }
        }
        assertFalse(PendingDocuments.isPending(docId))
    }

    /**
     * A display name that would escape its parent, or name no document at all, must be
     * rejected before any volume call -- a documentId is a path here, so "../x" or "a/b"
     * would silently write outside the intended directory.
     */
    @Test
    fun testCreateDocument_rejectsInvalidDisplayNamesBeforeTouchingTheVolume() {
        testVolume.writeSupported = true

        for (bad in listOf("", "   ", "a/b", ".", "..")) {
            try {
                provider.createDocument("/", Document.MIME_TYPE_DIR, bad)
                fail("Expected IllegalArgumentException for display name \"$bad\"")
            } catch (e: IllegalArgumentException) {
                // Success
            }
        }
        assertTrue(testVolume.createdDirectories.isEmpty())
    }

    /**
     * Create flags track the build, not wishful thinking: they appear only when the loaded
     * .so links the write path, so a read-only build never advertises create support a file
     * manager would then fail to use.
     */
    @Test
    fun testCreateFlags_areAdvertisedOnlyWhenWriteSupportIsBuiltIn() {
        testVolume.entriesMap["/"] = listOf(Entry("Documents", "dir"))
        // The fake reports a path as a directory only when it is itself a listing key.
        testVolume.entriesMap["/Documents"] = emptyList()

        // Write support absent -> no create flags anywhere.
        val rootsOff = provider.queryRoots(null)
        assertTrue(rootsOff.moveToFirst())
        val rootFlagsOff = rootsOff.getInt(rootsOff.getColumnIndexOrThrow(Root.COLUMN_FLAGS))
        assertFalse(rootFlagsOff and Root.FLAG_SUPPORTS_CREATE != 0)

        val dirOff = provider.queryDocument("/Documents", null)
        assertTrue(dirOff.moveToFirst())
        val dirFlagsOff = dirOff.getInt(dirOff.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertFalse(dirFlagsOff and Document.FLAG_DIR_SUPPORTS_CREATE != 0)

        // Write support present -> create flags appear, on the root and on directories.
        testVolume.writeSupported = true

        val rootsOn = provider.queryRoots(null)
        assertTrue(rootsOn.moveToFirst())
        val rootFlagsOn = rootsOn.getInt(rootsOn.getColumnIndexOrThrow(Root.COLUMN_FLAGS))
        assertTrue(rootFlagsOn and Root.FLAG_SUPPORTS_CREATE != 0)

        val dirOn = provider.queryDocument("/Documents", null)
        assertTrue(dirOn.moveToFirst())
        val dirFlagsOn = dirOn.getInt(dirOn.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertTrue(dirFlagsOn and Document.FLAG_DIR_SUPPORTS_CREATE != 0)

        // A regular file must never gain FLAG_SUPPORTS_WRITE: overwriting an existing file
        // is out of scope, and advertising it would invite writes that cannot be served.
        testVolume.entriesMap["/"] = listOf(Entry("photo.jpg", "file"))
        val fileOn = provider.queryDocument("/photo.jpg", null)
        assertTrue(fileOn.moveToFirst())
        val fileFlagsOn = fileOn.getInt(fileOn.getColumnIndexOrThrow(Document.COLUMN_FLAGS))
        assertFalse(fileFlagsOn and Document.FLAG_SUPPORTS_WRITE != 0)
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

    /**
     * Test Pass N.8: URI grants issued for this provider's documents must be revoked
     * proactively when the session transitions into Locked, not merely on delete/rename.
     * §4.4 requires "delete, rename, and lock/detach for everything issued."
     */
    @Test
    fun testN8_sessionLockTransition_revokesIssuedUriGrants() = runBlocking {
        provider.onCreate()

        // Simulate the provider becoming aware of documents the way Files/SAF would:
        // by querying them (and thereby making their document URIs eligible for a
        // persistable grant the provider cannot refuse).
        provider.queryDocument("/tracked.txt", null)
        provider.queryChildDocuments("/", null, null as String?)

        testContext.revokedUris.clear()
        assertTrue(testContext.revokedUris.isEmpty())

        session.lock()
        assertEquals(SessionState.Locked, session.state.value)

        withTimeout(3000) {
            while (testContext.revokedUris.isEmpty()) {
                delay(10)
            }
        }

        // Exactly one document was ever handed out ("/tracked.txt"; queryChildDocuments("/")
        // returned no entries), so exactly one revoke is expected -- proving this is driven
        // by tracked issuance, not some unrelated side effect.
        assertEquals(1, testContext.revokedUris.size)
        // Full-mask revocation (0.inv(), i.e. Java's ~0), matching the AOSP
        // ExternalStorageProvider.onDocIdDeleted pattern, not merely the read/write grant
        // flags used for explicit delete/rename.
        assertEquals(0.inv(), testContext.revokedUris[0].second)
    }

    /**
     * Test Pass N.8: same guarantee on a Detached transition (device pulled while unlocked).
     */
    @Test
    fun testN8_sessionDetachTransition_revokesIssuedUriGrants() = runBlocking {
        provider.onCreate()

        provider.queryDocument("/tracked2.txt", null)

        testContext.revokedUris.clear()
        assertTrue(testContext.revokedUris.isEmpty())

        session.onDeviceDetached("Device disconnected")

        withTimeout(3000) {
            while (testContext.revokedUris.isEmpty()) {
                delay(10)
            }
        }

        // Exactly one document was ever handed out ("/tracked2.txt"), so exactly one revoke
        // is expected on the Detached transition too.
        assertEquals(1, testContext.revokedUris.size)
        assertEquals(0.inv(), testContext.revokedUris[0].second)
    }

    /**
     * The mode handed to `openProxyFileDescriptor` must be a bare access constant.
     *
     * Regression test. `openDocument` passed `ParcelFileDescriptor.parseMode(openMode)`
     * straight through, and `parseMode("w")` is
     * `MODE_WRITE_ONLY or MODE_CREATE or MODE_TRUNCATE`. `openProxyFileDescriptor` accepts
     * only one of the three bare access constants and throws IllegalArgumentException on
     * anything else, so every write-mode open died before the proxy existed and the caller
     * saw `ContentResolver.openFileDescriptor()` return null. On device that read as
     * "no write support": folder create and delete worked (neither opens a descriptor),
     * browsing worked (`parseMode("r")` is already a bare MODE_READ_ONLY), and every
     * copy-into-the-volume failed.
     *
     * Asserting the exact constants rather than "not parseMode" is deliberate: it pins the
     * one property `openProxyFileDescriptor` actually enforces.
     */
    @Test
    fun testOpenDocumentUsesBareAccessModeForTheProxyDescriptor() {
        assertEquals(
            ParcelFileDescriptor.MODE_READ_ONLY,
            LuksDocumentsProvider.proxyAccessMode("r"),
        )
        for (writeMode in listOf("w", "wt")) {
            assertEquals(
                "mode $writeMode must map to a bare MODE_WRITE_ONLY",
                ParcelFileDescriptor.MODE_WRITE_ONLY,
                LuksDocumentsProvider.proxyAccessMode(writeMode),
            )
        }

        // The bits that must never be set: openProxyFileDescriptor rejects the whole value
        // if either is present, and neither means anything when the callback is the file.
        val forbidden = ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE
        for (mode in listOf("r", "w", "wt")) {
            assertEquals(
                "mode $mode leaked MODE_CREATE/MODE_TRUNCATE into the proxy mode",
                0,
                LuksDocumentsProvider.proxyAccessMode(mode) and forbidden,
            )
        }
    }
}
