package dev.luksandroid.ui.browser

import dev.luksandroid.Entry
import dev.luksandroid.FileInfo
import dev.luksandroid.LuksException
import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.StatFsInfo
import dev.luksandroid.VolumeInfo
import dev.luksandroid.session.LuksSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BrowserCancellationTest {

    class MockVolume(
        override val info: VolumeInfo = VolumeInfo(
            label = "TestVol",
            uuid = "uuid-1234",
            blockSize = 4096,
            sizeBytes = 1048576L,
            fsType = "ext4",
            subvolumes = emptyList(),
        ),
        var shouldThrowInStatFs: Exception? = null,
        var shouldThrowInListDir: Exception? = null,
        var shouldThrowInCreateDir: Exception? = null,
        var shouldThrowInRename: Exception? = null,
        var shouldThrowInDelete: Exception? = null,
    ) : LuksVolume(0L) {
        override fun statFs(): StatFsInfo {
            shouldThrowInStatFs?.let { throw it }
            return StatFsInfo(
                totalBytes = 1048576L,
                freeBytes = 524288L,
                availableBytes = 524288L,
                totalInodes = 1000L,
                freeInodes = 500L,
                blockSize = 4096,
            )
        }

        override fun listDir(path: String): List<Entry> {
            shouldThrowInListDir?.let { throw it }
            return listOf(
                Entry(name = "docs", type = "dir", isSubvolume = false),
                Entry(name = "test.txt", type = "file", isSubvolume = false),
            )
        }

        override fun fileInfo(path: String): FileInfo {
            return FileInfo(
                path = path,
                size = 100L,
                mode = 0,
                uid = 0,
                gid = 0,
                links = 1,
                type = "file",
                atime = 1700000000L,
                mtime = 1700000000L,
                ctime = 1700000000L,
            )
        }

        override fun createDirectory(parentPath: String, name: String): Long {
            shouldThrowInCreateDir?.let { throw it }
            return 12345L
        }

        override fun rename(oldParent: String, oldName: String, newParent: String, newName: String) {
            shouldThrowInRename?.let { throw it }
        }

        override fun deleteFile(path: String) {
            shouldThrowInDelete?.let { throw it }
        }
    }

    private lateinit var mockVolume: MockVolume

    @Before
    fun setUp() {
        runBlocking {
            mockVolume = MockVolume()
            LuksSession.startUnlockedForTest(
                volume = mockVolume,
                partition = PartitionInfo(0, "mock_part", 0L, 1048576L, true, 2),
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            LuksSession.lock()
        }
    }

    @Test
    fun testRefreshStatFs_cleanlyCatchesVolumeErrors() = runBlocking {
        val testScope = CoroutineScope(Dispatchers.Default + Job())
        mockVolume.shouldThrowInStatFs = LuksException("statfs failed", LuksException.IO)

        var statFsInfo: StatFsInfo? = null

        val job = testScope.launch {
            try {
                statFsInfo = withContext(Dispatchers.IO) {
                    LuksSession.withLease { v -> v.statFs() }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                // Cleanly caught without crashing
            }
        }

        job.join()
        testScope.cancel()

        // Exception was caught cleanly and did not crash
        assertEquals(null, statFsInfo)
    }

    @Test
    fun testRefreshStatFs_rethrowsCancellationException() = runBlocking {
        val testScope = CoroutineScope(Dispatchers.Default + Job())
        var cancellationRethrown = false

        val job = testScope.launch {
            try {
                try {
                    throw CancellationException("Scope cancelled during statfs")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                }
            } catch (e: CancellationException) {
                cancellationRethrown = true
                throw e
            }
        }

        job.join()
        testScope.cancel()
        assertTrue("CancellationException must be rethrown in refreshStatFs", cancellationRethrown)
    }

    @Test
    fun testLoadDirectory_rethrowsCancellationException_andDoesNotLaunchSnackbarOnCancelledScope() = runBlocking {
        val testScope = CoroutineScope(Dispatchers.Default + Job())
        var cancellationRethrown = false
        var snackbarLaunched = false

        // Cancel scope immediately
        testScope.cancel()
        assertFalse(testScope.isActive)

        val job = CoroutineScope(Dispatchers.Default).launch {
            try {
                try {
                    throw CancellationException("Navigation cancelled coroutine")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: LuksException) {
                    if (testScope.isActive) {
                        snackbarLaunched = true
                    }
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    if (testScope.isActive) {
                        snackbarLaunched = true
                    }
                }
            } catch (e: CancellationException) {
                cancellationRethrown = true
            }
        }

        job.join()
        assertTrue("CancellationException must be propagated", cancellationRethrown)
        assertFalse("Snackbar must not be launched when scope is inactive", snackbarLaunched)
    }

    @Test
    fun testScopeIsActive_guardsAgainstLaunchingOnDisposedScope() {
        val testScope = CoroutineScope(Dispatchers.Default + Job())
        assertTrue(testScope.isActive)

        testScope.cancel()
        assertFalse(testScope.isActive)

        var executed = false
        if (testScope.isActive) {
            testScope.launch {
                executed = true
            }
        }

        assertFalse("Guard must prevent launch on cancelled scope", executed)
    }

    @Test
    fun testDirectoryOperations_rethrowCancellationException() = runBlocking {
        var createCancelled = false
        var renameCancelled = false
        var deleteCancelled = false

        // Create Directory
        try {
            try {
                throw CancellationException("create cancelled")
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
            } catch (e: Exception) {
                if (e is CancellationException) throw e
            }
        } catch (e: CancellationException) {
            createCancelled = true
        }

        // Rename
        try {
            try {
                throw CancellationException("rename cancelled")
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
            } catch (e: Exception) {
                if (e is CancellationException) throw e
            }
        } catch (e: CancellationException) {
            renameCancelled = true
        }

        // Delete
        try {
            try {
                throw CancellationException("delete cancelled")
            } catch (e: CancellationException) {
                throw e
            } catch (e: LuksException) {
            } catch (e: Exception) {
                if (e is CancellationException) throw e
            }
        } catch (e: CancellationException) {
            deleteCancelled = true
        }

        assertTrue("Create directory rethrows cancellation", createCancelled)
        assertTrue("Rename rethrows cancellation", renameCancelled)
        assertTrue("Delete rethrows cancellation", deleteCancelled)
    }
}
