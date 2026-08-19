package dev.luksandroid.session

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import dev.luksandroid.LuksException
import dev.luksandroid.LuksNative
import dev.luksandroid.LuksVolume
import dev.luksandroid.Trace
import dev.luksandroid.ui.UiErrorMessage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class TransferType { IMPORT, EXPORT, HASH }

enum class TransferState { QUEUED, RUNNING, COMPLETED, CANCELLED, FAILED }

data class TransferItem(
    val id: Long,
    val name: String,
    val type: TransferType,
    val totalBytes: Long,
    val transferredBytes: Long,
    val speedBytesPerSec: Long,
    val etaSeconds: Long,
    val state: TransferState,
    val cancelToken: Long,
    val error: String?,
    /** Raw [LuksException.code] behind [error], when the failure came from one. Null otherwise. */
    val errorCode: Int? = null,
)

/**
 * Process-wide singleton tracking active and completed file transfers.
 * Survives screen navigation and backgrounding.
 */
open class TransferController {

    private val nextTransferId = AtomicLong(1)
    private val _transfers = MutableStateFlow<List<TransferItem>>(emptyList())
    val transfers: StateFlow<List<TransferItem>> = _transfers.asStateFlow()

    private val activeJobs = ConcurrentHashMap<Long, Job>()
    private val transferMutex = Mutex()

    /**
     * The manager's own coroutine scope. Transfers started via [startImport] /
     * [startExport] / [startHash] run here, NOT on a caller-supplied (e.g.
     * `rememberCoroutineScope()`) scope, so navigating away from the screen that
     * started a transfer does not cancel it: this scope is process-wide, tied to
     * [TransferManager] itself, not to any Composable's lifecycle.
     */
    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        const val CHUNK_SIZE = 1 shl 20 // 1 MiB
    }

    /**
     * Starts an export on the manager's own scope, holding a [LuksSession] lease
     * for the whole transfer (so the idle timer cannot lock the session out from
     * under it). Returns the transfer id immediately; observe [transfers] for
     * progress. Safe to call from a Composable without tying the transfer's
     * lifetime to that Composable's.
     */
    fun startExport(context: Context, path: String, targetUri: Uri): Long {
        val transferId = nextTransferId.getAndIncrement()
        val fileName = path.substringAfterLast('/').ifEmpty { "export_${System.currentTimeMillis()}" }
        val queuedItem = TransferItem(
            id = transferId,
            name = fileName,
            type = TransferType.EXPORT,
            totalBytes = -1L,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.QUEUED,
            cancelToken = 0L,
            error = null,
        )
        _transfers.update { listOf(queuedItem) + it }

        val job = managerScope.launch {
            try {
                runCatching {
                    transferMutex.withLock {
                        if (isTransferCancelled(transferId)) return@withLock
                        updateTransfer(transferId) { it.copy(state = TransferState.RUNNING) }
                        LuksSession.withLease { volume ->
                            exportFileWithProgress(context, volume, path, targetUri, transferId)
                        }
                    }
                }.onFailure { t ->
                    if (t !is CancellationException) {
                        Trace.err(LuksException.GENERIC, "export")
                    }
                }
            } finally {
                activeJobs.remove(transferId)
            }
        }
        activeJobs[transferId] = job
        return transferId
    }

    /**
     * Starts an import on the manager's own scope, holding a [LuksSession] lease
     * for the whole transfer. Returns the transfer id immediately; observe
     * [transfers] for progress. Safe to call from a Composable without tying the
     * transfer's lifetime to that Composable's.
     */
    fun startImport(context: Context, parentPath: String, sourceUri: Uri): Long {
        val transferId = nextTransferId.getAndIncrement()
        val contentResolver = context.contentResolver
        var queryName: String? = null
        var querySize: Long = -1L

        try {
            contentResolver.query(sourceUri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIdx != -1) queryName = cursor.getString(nameIdx)
                    if (sizeIdx != -1 && !cursor.isNull(sizeIdx)) querySize = cursor.getLong(sizeIdx)
                }
            }
        } catch (_: Throwable) {}

        if (querySize < 0L) {
            try {
                contentResolver.openFileDescriptor(sourceUri, "r")?.use { pfd ->
                    querySize = pfd.statSize
                }
            } catch (_: Throwable) {}
        }

        val targetName = queryName
            ?: sourceUri.lastPathSegment?.substringAfterLast('/')
            ?: "imported_${System.currentTimeMillis()}"

        val totalBytes = querySize

        val queuedItem = TransferItem(
            id = transferId,
            name = targetName,
            type = TransferType.IMPORT,
            totalBytes = totalBytes,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.QUEUED,
            cancelToken = 0L,
            error = null,
        )
        _transfers.update { listOf(queuedItem) + it }

        val job = managerScope.launch {
            try {
                runCatching {
                    transferMutex.withLock {
                        if (isTransferCancelled(transferId)) return@withLock
                        updateTransfer(transferId) { it.copy(state = TransferState.RUNNING) }
                        LuksSession.withLease { volume ->
                            importFileWithProgress(context, volume, parentPath, sourceUri, transferId)
                        }
                    }
                }.onFailure { t ->
                    if (t !is CancellationException) {
                        Trace.err(LuksException.GENERIC, "import")
                    }
                }
            } finally {
                activeJobs.remove(transferId)
            }
        }
        activeJobs[transferId] = job
        return transferId
    }

    /**
     * Starts a SHA-256 checksum on the manager's own scope, tracked as a HASH
     * transfer like imports/exports and holding a [LuksSession] lease for the
     * duration. [onResult] is invoked with the outcome once finished; it may run
     * after any originating Composable has left composition, so callers must
     * tolerate a no-op update in that case.
     */
    fun startHash(
        path: String,
        onResult: (Result<LuksVolume.Digest>) -> Unit = {},
    ): Long {
        val transferId = nextTransferId.getAndIncrement()
        val fileName = path.substringAfterLast('/').ifEmpty { "hash_${System.currentTimeMillis()}" }
        val queuedItem = TransferItem(
            id = transferId,
            name = fileName,
            type = TransferType.HASH,
            totalBytes = -1L,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.QUEUED,
            cancelToken = 0L,
            error = null,
        )
        _transfers.update { listOf(queuedItem) + it }

        val job = managerScope.launch {
            val result = try {
                runCatching {
                    transferMutex.withLock {
                        if (isTransferCancelled(transferId)) {
                            throw CancellationException("Transfer cancelled")
                        }
                        updateTransfer(transferId) { it.copy(state = TransferState.RUNNING) }
                        LuksSession.withLease { volume -> hashFileWithProgress(volume, path, transferId) }
                    }
                }
            } finally {
                activeJobs.remove(transferId)
            }
            onResult(result)
        }
        activeJobs[transferId] = job
        return transferId
    }

    fun getTransfer(id: Long): TransferItem? =
        _transfers.value.find { it.id == id }

    fun clearCompleted() {
        _transfers.update { list ->
            list.filter { it.state == TransferState.RUNNING || it.state == TransferState.QUEUED }
        }
    }

    fun clearHistory() {
        clearCompleted()
    }

    fun removeTransfer(id: Long) {
        _transfers.update { list ->
            list.filterNot { it.id == id && it.state != TransferState.RUNNING && it.state != TransferState.QUEUED }
        }
    }

    fun isTransferCancelled(id: Long): Boolean {
        return _transfers.value.find { it.id == id }?.state == TransferState.CANCELLED
    }

    private fun updateTransfer(id: Long, transform: (TransferItem) -> TransferItem) {
        _transfers.update { list ->
            list.map { if (it.id == id) transform(it) else it }
        }
    }

    /**
     * Signals cancellation for the transfer identified by [id].
     * Invokes native cancellation token and cancels the associated coroutine job.
     */
    fun cancelTransfer(id: Long) {
        val item = _transfers.value.find { it.id == id } ?: return
        if (item.state == TransferState.RUNNING || item.state == TransferState.QUEUED) {
            if (item.cancelToken > 0L) {
                try {
                    LuksNative.nativeCancelOperation(item.cancelToken)
                } catch (t: Throwable) {
                    Trace.e("TransferManager: nativeCancelOperation failed: ${Trace.throwableSummary(t)}")
                }
            }
            activeJobs[id]?.cancel()
            updateTransfer(id) {
                it.copy(state = TransferState.CANCELLED, etaSeconds = 0L, speedBytesPerSec = 0L)
            }
        }
    }

    /**
     * Exports a file from the encrypted [volume] at [path] to the destination [targetUri]
     * with real-time speed, ETA, and cancellation tracking.
     */
    suspend fun exportFileWithProgress(
        context: Context,
        volume: LuksVolume,
        path: String,
        targetUri: Uri,
        transferId: Long = nextTransferId.getAndIncrement(),
    ): Long = withContext(Dispatchers.IO) {
        val cancelToken = try {
            LuksNative.nativeCreateCancelToken()
        } catch (_: Throwable) {
            0L
        }

        val fileName = path.substringAfterLast('/').ifEmpty { "export_${System.currentTimeMillis()}" }
        val totalBytes = try {
            volume.fileSize(path)
        } catch (e: Exception) {
            -1L
        }

        val initialItem = TransferItem(
            id = transferId,
            name = fileName,
            type = TransferType.EXPORT,
            totalBytes = totalBytes,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.RUNNING,
            cancelToken = cancelToken,
            error = null,
        )
        _transfers.update { list ->
            if (list.any { it.id == transferId }) {
                list.map {
                    if (it.id == transferId) {
                        it.copy(
                            name = fileName,
                            totalBytes = totalBytes,
                            state = TransferState.RUNNING,
                            cancelToken = cancelToken,
                        )
                    } else it
                }
            } else {
                listOf(initialItem) + list
            }
        }

        activeJobs[transferId] = currentCoroutineContext().job

        var done = 0L
        val started = System.currentTimeMillis()
        var lastUpdateMs = started
        var lastUpdateBytes = 0L

        try {
            if (totalBytes < 0L) {
                throw IllegalStateException("Cannot determine file size for export")
            }

            val stream = context.contentResolver.openOutputStream(targetUri)
                ?: throw IllegalStateException("Could not open destination URI for writing")

            stream.use { out ->
                while (done < totalBytes && currentCoroutineContext().isActive) {
                    if (isTransferCancelled(transferId)) {
                        throw CancellationException("Transfer cancelled")
                    }

                    val toRead = (totalBytes - done).coerceAtMost(CHUNK_SIZE.toLong()).toInt()
                    val chunk = volume.readChunk(path, done, toRead)
                    if (chunk.isEmpty()) break

                    out.write(chunk)
                    done += chunk.size

                    val now = System.currentTimeMillis()
                    val dt = now - lastUpdateMs
                    if (dt >= 200 || done >= totalBytes) {
                        val speed = if (dt > 0) ((done - lastUpdateBytes) * 1000L) / dt else 0L
                        val totalElapsedSec = (now - started) / 1000.0
                        val avgSpeed = if (totalElapsedSec > 0) (done / totalElapsedSec).toLong() else speed
                        val currentSpeed = if (speed > 0) speed else avgSpeed
                        val remainingBytes = (totalBytes - done).coerceAtLeast(0L)
                        val eta = if (currentSpeed > 0) remainingBytes / currentSpeed else 0L

                        lastUpdateMs = now
                        lastUpdateBytes = done

                        updateTransfer(transferId) {
                            it.copy(
                                transferredBytes = done,
                                speedBytesPerSec = currentSpeed,
                                etaSeconds = eta,
                            )
                        }
                    }
                }
                out.flush()
            }

            if (isTransferCancelled(transferId)) {
                throw CancellationException("Transfer cancelled")
            }

            if (done < totalBytes) {
                throw IllegalStateException("Short read: exported $done bytes of $totalBytes expected")
            }

            val totalSec = (System.currentTimeMillis() - started).coerceAtLeast(1) / 1000.0
            val finalSpeed = (done / totalSec).toLong()
            updateTransfer(transferId) {
                it.copy(
                    transferredBytes = done,
                    speedBytesPerSec = finalSpeed,
                    etaSeconds = 0L,
                    state = TransferState.COMPLETED,
                )
            }
            Trace.i("TransferManager", "Export completed: $transferId in ${totalSec}s")
        } catch (e: CancellationException) {
            updateTransfer(transferId) {
                it.copy(
                    state = TransferState.CANCELLED,
                    etaSeconds = 0L,
                    speedBytesPerSec = 0L,
                )
            }
            Trace.err(LuksException.CANCELLED, "export")
        } catch (e: LuksException) {
            if (e.isCancelled || isTransferCancelled(transferId)) {
                updateTransfer(transferId) {
                    it.copy(
                        state = TransferState.CANCELLED,
                        etaSeconds = 0L,
                        speedBytesPerSec = 0L,
                    )
                }
                Trace.err(LuksException.CANCELLED, "export")
            } else {
                val errorMsg = UiErrorMessage.getUserMessage(e, "Export")
                updateTransfer(transferId) {
                    it.copy(
                        state = TransferState.FAILED,
                        error = errorMsg,
                        errorCode = e.code,
                        etaSeconds = 0L,
                        speedBytesPerSec = 0L,
                    )
                }
                Trace.err(e.code, "export")
            }
        } catch (t: Throwable) {
            val errorMsg = UiErrorMessage.getUserMessage(t, "Export")
            updateTransfer(transferId) {
                it.copy(
                    state = TransferState.FAILED,
                    error = errorMsg,
                    etaSeconds = 0L,
                    speedBytesPerSec = 0L,
                )
            }
            Trace.err(LuksException.GENERIC, "export")
        } finally {
            activeJobs.remove(transferId)
            if (cancelToken > 0L) {
                try {
                    LuksNative.nativeCloseCancelToken(cancelToken)
                } catch (_: Throwable) {}
            }
        }

        transferId
    }

    /**
     * Imports a file from [sourceUri] into the encrypted [volume] under [parentPath]
     * with real-time speed, ETA, and cancellation tracking.
     */
    suspend fun importFileWithProgress(
        context: Context,
        volume: LuksVolume,
        parentPath: String,
        sourceUri: Uri,
        transferId: Long = nextTransferId.getAndIncrement(),
    ): Long = withContext(Dispatchers.IO) {
        val cancelToken = try {
            LuksNative.nativeCreateCancelToken()
        } catch (_: Throwable) {
            0L
        }

        val contentResolver = context.contentResolver
        var queryName: String? = null
        var querySize: Long = -1L

        try {
            contentResolver.query(sourceUri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIdx != -1) queryName = cursor.getString(nameIdx)
                    if (sizeIdx != -1 && !cursor.isNull(sizeIdx)) querySize = cursor.getLong(sizeIdx)
                }
            }
        } catch (_: Throwable) {}

        if (querySize < 0L) {
            try {
                contentResolver.openFileDescriptor(sourceUri, "r")?.use { pfd ->
                    querySize = pfd.statSize
                }
            } catch (_: Throwable) {}
        }

        val targetName = queryName
            ?: sourceUri.lastPathSegment?.substringAfterLast('/')
            ?: "imported_${System.currentTimeMillis()}"

        val totalBytes = querySize

        val initialItem = TransferItem(
            id = transferId,
            name = targetName,
            type = TransferType.IMPORT,
            totalBytes = totalBytes,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.RUNNING,
            cancelToken = cancelToken,
            error = null,
        )
        _transfers.update { list ->
            if (list.any { it.id == transferId }) {
                list.map {
                    if (it.id == transferId) {
                        it.copy(
                            name = targetName,
                            totalBytes = totalBytes,
                            state = TransferState.RUNNING,
                            cancelToken = cancelToken,
                        )
                    } else it
                }
            } else {
                listOf(initialItem) + list
            }
        }

        activeJobs[transferId] = currentCoroutineContext().job

        var done = 0L
        val started = System.currentTimeMillis()
        var lastUpdateMs = started
        var lastUpdateBytes = 0L

        try {
            if (totalBytes < 0L) {
                throw IllegalStateException("Cannot determine file size for import")
            }

            val writer = volume.beginFile(totalBytes)
            val buffer = ByteBuffer.allocateDirect(CHUNK_SIZE)

            try {
                contentResolver.openFileDescriptor(sourceUri, "r")?.use { pfd ->
                    FileInputStream(pfd.fileDescriptor).channel.use { channel ->
                        while (done < totalBytes && currentCoroutineContext().isActive) {
                            if (isTransferCancelled(transferId)) {
                                throw CancellationException("Transfer cancelled")
                            }

                            buffer.clear()
                            val toRead = (totalBytes - done).coerceAtMost(CHUNK_SIZE.toLong()).toInt()
                            buffer.limit(toRead)

                            var read = 0
                            while (buffer.hasRemaining()) {
                                val r = channel.read(buffer)
                                if (r <= 0) break
                                read += r
                            }
                            if (read <= 0) break

                            buffer.flip()
                            writer.write(buffer, read)
                            done += read

                            val now = System.currentTimeMillis()
                            val dt = now - lastUpdateMs
                            if (dt >= 200 || done >= totalBytes) {
                                val speed = if (dt > 0) ((done - lastUpdateBytes) * 1000L) / dt else 0L
                                val totalElapsedSec = (now - started) / 1000.0
                                val avgSpeed = if (totalElapsedSec > 0) (done / totalElapsedSec).toLong() else speed
                                val currentSpeed = if (speed > 0) speed else avgSpeed
                                val remainingBytes = (totalBytes - done).coerceAtLeast(0L)
                                val eta = if (currentSpeed > 0) remainingBytes / currentSpeed else 0L

                                lastUpdateMs = now
                                lastUpdateBytes = done

                                updateTransfer(transferId) {
                                    it.copy(
                                        transferredBytes = done,
                                        speedBytesPerSec = currentSpeed,
                                        etaSeconds = eta,
                                    )
                                }
                            }
                        }
                    }
                } ?: throw IllegalStateException("Could not open input file descriptor")

                if (isTransferCancelled(transferId)) {
                    throw CancellationException("Transfer cancelled")
                }

                if (done < totalBytes) {
                    throw IllegalStateException("Short read: imported $done bytes of $totalBytes expected")
                }

                val ino = writer.finish(parentPath, targetName)
                val totalSec = (System.currentTimeMillis() - started).coerceAtLeast(1) / 1000.0
                val finalSpeed = (done / totalSec).toLong()
                updateTransfer(transferId) {
                    it.copy(
                        transferredBytes = done,
                        speedBytesPerSec = finalSpeed,
                        etaSeconds = 0L,
                        state = TransferState.COMPLETED,
                    )
                }
                Trace.i("TransferManager", "Import completed: $transferId in ${totalSec}s (inode $ino)")
            } finally {
                writer.close()
            }
        } catch (e: CancellationException) {
            updateTransfer(transferId) {
                it.copy(
                    state = TransferState.CANCELLED,
                    etaSeconds = 0L,
                    speedBytesPerSec = 0L,
                )
            }
            Trace.err(LuksException.CANCELLED, "import")
        } catch (e: LuksException) {
            if (e.isCancelled || isTransferCancelled(transferId)) {
                updateTransfer(transferId) {
                    it.copy(
                        state = TransferState.CANCELLED,
                        etaSeconds = 0L,
                        speedBytesPerSec = 0L,
                    )
                }
                Trace.err(LuksException.CANCELLED, "import")
            } else {
                val errorMsg = UiErrorMessage.getUserMessage(e, "Import")
                updateTransfer(transferId) {
                    it.copy(
                        state = TransferState.FAILED,
                        error = errorMsg,
                        errorCode = e.code,
                        etaSeconds = 0L,
                        speedBytesPerSec = 0L,
                    )
                }
                Trace.err(e.code, "import")
            }
        } catch (t: Throwable) {
            val errorMsg = UiErrorMessage.getUserMessage(t, "Import")
            updateTransfer(transferId) {
                it.copy(
                    state = TransferState.FAILED,
                    error = errorMsg,
                    etaSeconds = 0L,
                    speedBytesPerSec = 0L,
                )
            }
            Trace.err(LuksException.GENERIC, "import")
        } finally {
            activeJobs.remove(transferId)
            if (cancelToken > 0L) {
                try {
                    LuksNative.nativeCloseCancelToken(cancelToken)
                } catch (_: Throwable) {}
            }
        }

        transferId
    }

    /**
     * Computes a SHA-256 digest of the file at [path] in [volume], tracked as a
     * HASH transfer in [transfers] like an import or export.
     */
    suspend fun hashFileWithProgress(
        volume: LuksVolume,
        path: String,
        transferId: Long = nextTransferId.getAndIncrement(),
    ): LuksVolume.Digest = withContext(Dispatchers.IO) {
        val fileName = path.substringAfterLast('/').ifEmpty { "hash_${System.currentTimeMillis()}" }
        val totalBytes = try {
            volume.fileSize(path)
        } catch (e: Exception) {
            -1L
        }

        val initialItem = TransferItem(
            id = transferId,
            name = fileName,
            type = TransferType.HASH,
            totalBytes = totalBytes,
            transferredBytes = 0L,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            state = TransferState.RUNNING,
            cancelToken = 0L,
            error = null,
        )
        _transfers.update { list ->
            if (list.any { it.id == transferId }) {
                list.map {
                    if (it.id == transferId) {
                        it.copy(
                            name = fileName,
                            totalBytes = if (totalBytes >= 0L) totalBytes else it.totalBytes,
                            state = TransferState.RUNNING,
                        )
                    } else it
                }
            } else {
                listOf(initialItem) + list
            }
        }
        activeJobs[transferId] = currentCoroutineContext().job

        try {
            val digest = volume.sha256(path)
            updateTransfer(transferId) {
                it.copy(
                    transferredBytes = digest.bytes,
                    totalBytes = if (it.totalBytes >= 0L) it.totalBytes else digest.bytes,
                    speedBytesPerSec = digest.bytesPerSec,
                    etaSeconds = 0L,
                    state = TransferState.COMPLETED,
                )
            }
            Trace.i("TransferManager", "Hash completed: $transferId")
            digest
        } catch (e: CancellationException) {
            updateTransfer(transferId) {
                it.copy(state = TransferState.CANCELLED, etaSeconds = 0L, speedBytesPerSec = 0L)
            }
            Trace.err(LuksException.CANCELLED, "hash")
            throw e
        } catch (e: LuksException) {
            val errorMsg = UiErrorMessage.getUserMessage(e, "Checksum")
            updateTransfer(transferId) {
                it.copy(state = TransferState.FAILED, error = errorMsg, etaSeconds = 0L, speedBytesPerSec = 0L)
            }
            Trace.err(e.code, "hash")
            throw e
        } catch (t: Throwable) {
            val errorMsg = UiErrorMessage.getUserMessage(t, "Checksum")
            updateTransfer(transferId) {
                it.copy(state = TransferState.FAILED, error = errorMsg, etaSeconds = 0L, speedBytesPerSec = 0L)
            }
            Trace.err(LuksException.GENERIC, "hash")
            throw t
        } finally {
            activeJobs.remove(transferId)
        }
    }
}

/** Process-wide singleton instance. */
object TransferManager : TransferController()
