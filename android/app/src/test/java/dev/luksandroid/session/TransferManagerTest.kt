package dev.luksandroid.session

import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.VolumeInfo
import dev.luksandroid.ui.transfers.formatEta
import dev.luksandroid.ui.transfers.formatSpeed
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

class TransferManagerTest {

    private lateinit var transferController: TransferController

    @Before
    fun setUp() {
        transferController = TransferController()
    }

    @Test
    fun testInitialState_empty() {
        assertTrue(transferController.transfers.value.isEmpty())
        assertNull(transferController.getTransfer(1L))
    }

    @Test
    fun testTransferModels() {
        val item = TransferItem(
            id = 101L,
            name = "data.bin",
            type = TransferType.EXPORT,
            totalBytes = 10_000_000L,
            transferredBytes = 5_000_000L,
            speedBytesPerSec = 1_048_576L,
            etaSeconds = 5L,
            state = TransferState.RUNNING,
            cancelToken = 0L,
            error = null,
        )

        assertEquals(101L, item.id)
        assertEquals("data.bin", item.name)
        assertEquals(TransferType.EXPORT, item.type)
        assertEquals(10_000_000L, item.totalBytes)
        assertEquals(5_000_000L, item.transferredBytes)
        assertEquals(1_048_576L, item.speedBytesPerSec)
        assertEquals(5L, item.etaSeconds)
        assertEquals(TransferState.RUNNING, item.state)
        assertEquals(0L, item.cancelToken)
        assertNull(item.error)

        val queuedItem = item.copy(state = TransferState.QUEUED)
        assertEquals(TransferState.QUEUED, queuedItem.state)
    }

    @Test
    fun testCancelTransfer() {
        // Subclass to simulate active transfer in controller
        val controller = object : TransferController() {
            fun addTestItem(item: TransferItem) {
                val method = TransferController::class.java.getDeclaredField("_transfers")
                method.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val flow = method.get(this) as MutableStateFlow<List<TransferItem>>
                flow.value = listOf(item)
            }
        }

        val item = TransferItem(
            id = 1L,
            name = "test.txt",
            type = TransferType.IMPORT,
            totalBytes = 1000L,
            transferredBytes = 200L,
            speedBytesPerSec = 50L,
            etaSeconds = 16L,
            state = TransferState.RUNNING,
            cancelToken = 0L,
            error = null,
        )
        controller.addTestItem(item)

        assertFalse(controller.isTransferCancelled(1L))

        controller.cancelTransfer(1L)

        val updated = controller.getTransfer(1L)
        assertNotNull(updated)
        assertEquals(TransferState.CANCELLED, updated!!.state)
        assertEquals(0L, updated.etaSeconds)
        assertTrue(controller.isTransferCancelled(1L))

        // Also verify cancelling a QUEUED transfer
        val queued = TransferItem(
            id = 2L,
            name = "queued.txt",
            type = TransferType.IMPORT,
            totalBytes = 1000L,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.QUEUED,
            cancelToken = 0L,
            error = null,
        )
        controller.addTestItem(queued)
        assertFalse(controller.isTransferCancelled(2L))

        controller.cancelTransfer(2L)
        val updatedQueued = controller.getTransfer(2L)
        assertNotNull(updatedQueued)
        assertEquals(TransferState.CANCELLED, updatedQueued!!.state)
        assertTrue(controller.isTransferCancelled(2L))
    }

    @Test
    fun testClearHistoryAndRemove() {
        val controller = object : TransferController() {
            fun setList(items: List<TransferItem>) {
                val field = TransferController::class.java.getDeclaredField("_transfers")
                field.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val flow = field.get(this) as MutableStateFlow<List<TransferItem>>
                flow.value = items
            }
        }

        val running = TransferItem(1L, "run.bin", TransferType.EXPORT, 100L, 20L, 10L, 8L, TransferState.RUNNING, 0L, null)
        val queued = TransferItem(2L, "queue.bin", TransferType.IMPORT, 100L, 0L, 0L, 0L, TransferState.QUEUED, 0L, null)
        val completed = TransferItem(3L, "done.bin", TransferType.IMPORT, 100L, 100L, 50L, 0L, TransferState.COMPLETED, 0L, null)
        val cancelled = TransferItem(4L, "canc.bin", TransferType.EXPORT, 100L, 40L, 0L, 0L, TransferState.CANCELLED, 0L, null)
        val failed = TransferItem(5L, "fail.bin", TransferType.IMPORT, 100L, 10L, 0L, 0L, TransferState.FAILED, 0L, "Disk full")

        controller.setList(listOf(running, queued, completed, cancelled, failed))
        assertEquals(5, controller.transfers.value.size)

        // Attempting to remove QUEUED item should be rejected (remains active)
        controller.removeTransfer(2L)
        assertEquals(5, controller.transfers.value.size)
        assertNotNull(controller.getTransfer(2L))

        // Remove single completed item
        controller.removeTransfer(5L)
        assertEquals(4, controller.transfers.value.size)
        assertNull(controller.getTransfer(5L))

        // Clear history should remove completed & cancelled, keeping running and queued
        controller.clearHistory()
        val remaining = controller.transfers.value
        assertEquals(2, remaining.size)
        assertTrue(remaining.any { it.id == 1L && it.state == TransferState.RUNNING })
        assertTrue(remaining.any { it.id == 2L && it.state == TransferState.QUEUED })
    }

    @Test
    fun testFormatSpeed() {
        assertEquals("0 B/s", formatSpeed(0L))
        assertEquals("500 B/s", formatSpeed(500L))
        assertEquals("1.0 KiB/s", formatSpeed(1024L))
        assertEquals("2.5 KiB/s", formatSpeed(2560L))
        assertEquals("1.0 MiB/s", formatSpeed(1024 * 1024L))
        assertEquals("24.5 MiB/s", formatSpeed((24.5 * 1024 * 1024).toLong()))
    }

    @Test
    fun testFormatEta() {
        assertEquals("Finishing…", formatEta(0L))
        assertEquals("Finishing…", formatEta(-5L))
        assertEquals("45s remaining", formatEta(45L))
        assertEquals("1m 15s remaining", formatEta(75L))
        assertEquals("1h 10m remaining", formatEta(4200L))
    }

    @Test
    fun testSingletonTransferManagerInstance() {
        assertNotNull(TransferManager)
        assertTrue(TransferManager.transfers.value.isEmpty())
    }

    /** Fake volume to track concurrency and FIFO execution order for sequential queue test */
    private class SequentialTrackingVolume(
        override val info: VolumeInfo = VolumeInfo(
            label = "Test",
            uuid = "uuid-0000",
            blockSize = 4096,
            sizeBytes = 1024L,
            fsType = "ext4",
            subvolumes = emptyList(),
        ),
        private val delayMs: Long = 100L,
    ) : LuksVolume(0L) {
        val concurrentCount = AtomicInteger(0)
        val maxConcurrent = AtomicInteger(0)
        val executedPaths = CopyOnWriteArrayList<String>()

        override fun fileSize(path: String): Long = 100L

        override fun sha256(path: String, chunkBytes: Int): Digest {
            val current = concurrentCount.incrementAndGet()
            maxConcurrent.updateAndGet { maxOf(it, current) }
            try {
                Thread.sleep(delayMs)
                executedPaths.add(path)
                return Digest(sha256 = "hash_$path", bytes = 100L, elapsedMs = delayMs, bytesPerSec = 500L)
            } finally {
                concurrentCount.decrementAndGet()
            }
        }
    }

    @Test
    fun testSequentialTransferQueueExecution() = runBlocking {
        val volume = SequentialTrackingVolume(delayMs = 100L)
        LuksSession.startUnlockedForTest(
            volume = volume,
            partition = PartitionInfo(0, "test", 0L, 1024L, true, 2),
        )
        try {
            val id1 = TransferManager.startHash("/file1.bin")
            val id2 = TransferManager.startHash("/file2.bin")
            val id3 = TransferManager.startHash("/file3.bin")

            // Wait for all 3 transfers to finish
            withTimeout(5000) {
                while (TransferManager.getTransfer(id3)?.state != TransferState.COMPLETED) {
                    delay(20)
                }
            }

            assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id1)?.state)
            assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id2)?.state)
            assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id3)?.state)

            // Concurrency must never exceed 1 (mutex-locked sequential execution)
            assertEquals(1, volume.maxConcurrent.get())

            // Completed strictly in FIFO order
            assertEquals(listOf("/file1.bin", "/file2.bin", "/file3.bin"), volume.executedPaths)
        } finally {
            LuksSession.lock()
            val field = TransferController::class.java.getDeclaredField("_transfers")
            field.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = field.get(TransferManager) as MutableStateFlow<List<TransferItem>>
            flow.value = emptyList()
        }
    }

    @Test
    fun testCancelQueuedTransfer_skipsExecutionAndProceedsToNextInQueue() = runBlocking {
        val volume = SequentialTrackingVolume(delayMs = 150L)
        LuksSession.startUnlockedForTest(
            volume = volume,
            partition = PartitionInfo(0, "test", 0L, 1024L, true, 2),
        )
        try {
            val id1 = TransferManager.startHash("/task1.bin")
            val id2 = TransferManager.startHash("/task2.bin")
            val id3 = TransferManager.startHash("/task3.bin")

            // Transfer 2 is queued: cancel it immediately
            TransferManager.cancelTransfer(id2)
            assertEquals(TransferState.CANCELLED, TransferManager.getTransfer(id2)?.state)

            // Wait for transfer 3 to finish
            withTimeout(5000) {
                while (TransferManager.getTransfer(id3)?.state != TransferState.COMPLETED) {
                    delay(20)
                }
            }

            assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id1)?.state)
            assertEquals(TransferState.CANCELLED, TransferManager.getTransfer(id2)?.state)
            assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id3)?.state)

            // Task 2 was skipped by the volume execution
            assertEquals(listOf("/task1.bin", "/task3.bin"), volume.executedPaths)
            assertEquals(1, volume.maxConcurrent.get())
        } finally {
            LuksSession.lock()
            val field = TransferController::class.java.getDeclaredField("_transfers")
            field.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = field.get(TransferManager) as MutableStateFlow<List<TransferItem>>
            flow.value = emptyList()
        }
    }
}
