package dev.luksandroid.session

import dev.luksandroid.ui.transfers.formatEta
import dev.luksandroid.ui.transfers.formatSpeed
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

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
    }

    @Test
    fun testCancelTransfer() {
        // Subclass to simulate active transfer in controller
        val controller = object : TransferController() {
            fun addTestItem(item: TransferItem) {
                val method = TransferController::class.java.getDeclaredField("_transfers")
                method.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val flow = method.get(this) as kotlinx.coroutines.flow.MutableStateFlow<List<TransferItem>>
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
    }

    @Test
    fun testClearHistoryAndRemove() {
        val controller = object : TransferController() {
            fun setList(items: List<TransferItem>) {
                val field = TransferController::class.java.getDeclaredField("_transfers")
                field.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val flow = field.get(this) as kotlinx.coroutines.flow.MutableStateFlow<List<TransferItem>>
                flow.value = items
            }
        }

        val running = TransferItem(1L, "run.bin", TransferType.EXPORT, 100L, 20L, 10L, 8L, TransferState.RUNNING, 0L, null)
        val completed = TransferItem(2L, "done.bin", TransferType.IMPORT, 100L, 100L, 50L, 0L, TransferState.COMPLETED, 0L, null)
        val cancelled = TransferItem(3L, "canc.bin", TransferType.EXPORT, 100L, 40L, 0L, 0L, TransferState.CANCELLED, 0L, null)
        val failed = TransferItem(4L, "fail.bin", TransferType.IMPORT, 100L, 10L, 0L, 0L, TransferState.FAILED, 0L, "Disk full")

        controller.setList(listOf(running, completed, cancelled, failed))
        assertEquals(4, controller.transfers.value.size)

        // Remove single item
        controller.removeTransfer(4L)
        assertEquals(3, controller.transfers.value.size)
        assertNull(controller.getTransfer(4L))

        // Clear history should remove completed & cancelled, keeping running
        controller.clearHistory()
        val remaining = controller.transfers.value
        assertEquals(1, remaining.size)
        assertEquals(1L, remaining[0].id)
        assertEquals(TransferState.RUNNING, remaining[0].state)
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
}
