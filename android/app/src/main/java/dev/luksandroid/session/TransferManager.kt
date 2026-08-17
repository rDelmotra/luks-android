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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class TransferType { IMPORT, EXPORT }

enum class TransferState { RUNNING, COMPLETED, CANCELLED, FAILED }

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

    companion object {
        const val CHUNK_SIZE = 1 shl 20 // 1 MiB
    }

    fun getTransfer(id: Long): TransferItem? =
        _transfers.value.find { it.id == id }

    fun clearCompleted() {
        _transfers.update { list ->
            list.filter { it.state == TransferState.RUNNING }
        }
    }

    fun clearHistory() {
        clearCompleted()
    }

    fun removeTransfer(id: Long) {
        _transfers.update { list ->
            list.filterNot { it.id == id && it.state != TransferState.RUNNING }
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
        if (item.state == TransferState.RUNNING) {
            if (item.cancelToken > 0L) {
                try {
                    LuksNative.nativeCancelOperation(item.cancelToken)
                } catch (t: Throwable) {
                    Trace.e("TransferManager: nativeCancelOperation failed", t)
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
    ): Long = withContext(Dispatchers.IO) {
        val transferId = nextTransferId.getAndIncrement()
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
        _transfers.update { listOf(initialItem) + it }

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
            Trace.err(LuksException.GENERIC, "export", t.javaClass.simpleName)
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
    ): Long = withContext(Dispatchers.IO) {
        val transferId = nextTransferId.getAndIncrement()
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
        _transfers.update { listOf(initialItem) + it }

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
            Trace.err(LuksException.GENERIC, "import", t.javaClass.simpleName)
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
}

/** Process-wide singleton instance. */
object TransferManager : TransferController()
