package dev.luksandroid.session

import dev.luksandroid.LuksVolume
import dev.luksandroid.PartitionInfo
import dev.luksandroid.VolumeInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * N.2: BrowserScreen must route transfers through [TransferManager] rather
 * than a Composable-scoped local implementation. The two properties that
 * matter (per notes/feature-remediation.md N.2's exit bar) are:
 *
 *  1. A transfer started from the Browser path is visible in
 *     [TransferController.transfers] (so the Transfers screen shows it).
 *  2. The transfer's coroutine runs on TransferManager's OWN scope, not on
 *     a caller-supplied scope such as `rememberCoroutineScope()` — so
 *     navigating away from (and disposing) the screen that started it does
 *     not cancel it.
 *
 * [TransferManager.startHash] is used as the concrete vehicle here because it
 * needs only a [LuksVolume], not an Android [android.content.Context] /
 * [android.net.Uri] pair. This project has no Robolectric / instrumented-test
 * setup, so `context.contentResolver.query(...)` /
 * `openFileDescriptor(...)` used by [TransferManager.startImport] /
 * [TransferManager.startExport] cannot be exercised from a plain JVM unit
 * test. Those two functions are implemented with the exact same
 * `managerScope.launch { LuksSession.withLease { ... } }` shape as
 * [TransferManager.startHash] (see session/TransferManager.kt), so the same
 * guarantee applies to them by construction, but actually driving a real SAF
 * import/export end to end is device-only, consistent with the exit bar's own
 * words: "This one needs the device."
 */
class TransferManagerBrowserWiringTest {

    /** A fake volume whose sha256() takes just long enough to still be RUNNING when we cancel the caller scope. */
    class SlowHashVolume(
        override val info: VolumeInfo = VolumeInfo(
            label = "Test",
            uuid = "uuid-0000",
            blockSize = 4096,
            sizeBytes = 1024L,
            fsType = "ext4",
            subvolumes = emptyList(),
        ),
        private val delayMs: Long = 500L,
    ) : LuksVolume(0L) {
        override fun fileSize(path: String): Long = 42L

        override fun sha256(path: String, chunkBytes: Int): Digest {
            Thread.sleep(delayMs)
            return Digest(sha256 = "deadbeefcafe", bytes = 42L, elapsedMs = delayMs, bytesPerSec = 84L)
        }
    }

    @Before
    fun setUp() = runBlocking<Unit> {
        LuksSession.startUnlockedForTest(
            volume = SlowHashVolume(),
            partition = PartitionInfo(0, "test", 0L, 1024L, true, 2),
        )
    }

    @After
    fun tearDown() = runBlocking {
        LuksSession.lock()
        // TransferManager is a process-wide singleton; don't leak this test's
        // transfer history into whatever test class runs next in this JVM.
        val field = TransferController::class.java.getDeclaredField("_transfers")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = field.get(TransferManager) as MutableStateFlow<List<TransferItem>>
        flow.value = emptyList()
    }

    @Test
    fun testStartHash_registersInTransfers_andSurvivesCallerScopeCancellation() = runBlocking {
        // Stand-in for `rememberCoroutineScope()` inside a Composable.
        val composableScope = CoroutineScope(Dispatchers.Default + Job())
        var transferId: Long? = null

        // Mirrors how BrowserScreen must call TransferManager: from a scope
        // whose lifetime is tied to the Composable, NOT to TransferManager.
        composableScope.launch {
            transferId = TransferManager.startHash(path = "/big.bin")
        }.join()

        val id = requireNotNull(transferId) { "startHash did not return a transfer id" }

        // Property 1: visible on the Transfers screen immediately, i.e.
        // registered in TransferManager.transfers, not held in local
        // Composable state that only this screen can see.
        withTimeout(2000) {
            while (TransferManager.getTransfer(id)?.state == TransferState.QUEUED) delay(10)
        }
        val registered = TransferManager.getTransfer(id)
        assertEquals(TransferType.HASH, registered?.type)
        assertEquals(
            "Expected the hash to still be running (it sleeps 500ms) when we simulate navigating away",
            TransferState.RUNNING,
            registered?.state,
        )

        // Simulate "navigate away": the Composable and its scope are torn
        // down WHILE the transfer is still in flight.
        composableScope.cancel()

        // Property 2: it keeps running on TransferManager's own scope and
        // reaches COMPLETED despite the caller scope being gone. Before N.2,
        // this transfer would have been a child of the caller's scope and
        // cancelling that scope would have cancelled it too.
        withTimeout(3000) {
            while (TransferManager.getTransfer(id)?.state != TransferState.COMPLETED) delay(20)
        }
        assertEquals(TransferState.COMPLETED, TransferManager.getTransfer(id)?.state)
    }

    @Test
    fun testStartHash_cancellingComposableScope_doesNotCancelTheDetachedJob_evenThoughEquivalentDirectCallWould() = runBlocking {
        // Contrast case: calling the underlying suspend function directly
        // inside a caller-owned scope (the anti-pattern the old BrowserScreen
        // effectively used for import/export/hash) DOES tie the job's
        // cancellation to that scope, because it becomes a structural child
        // of it. This is the mechanism N.2 fixes by routing through
        // TransferManager's own managerScope via startHash/startImport/startExport.
        val callerScope = CoroutineScope(Dispatchers.Default + Job())
        var directCallCompletedNormally = false

        val directJob = callerScope.launch {
            TransferManager.hashFileWithProgress(SlowHashVolume(delayMs = 600L), "/direct.bin")
            directCallCompletedNormally = true
        }
        delay(80)
        callerScope.cancel()
        directJob.join()

        assertTrue(
            "A hash launched as a direct child of a caller scope should not complete normally " +
                "once that scope is cancelled — this reproduces why the old BrowserScreen " +
                "implementation could lose transfers on navigation.",
            !directCallCompletedNormally,
        )
    }
}
