package dev.luksandroid.documents

import android.content.Context
import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import dev.luksandroid.LuksVolume
import dev.luksandroid.Trace
import dev.luksandroid.Trace.throwableSummary
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionController
import dev.luksandroid.session.TransferManager
import kotlinx.coroutines.runBlocking

/**
 * [ProxyFileDescriptorCallback] bridging kernel VFS read/write operations through the active
 * [LuksSession] lease to an unlocked LUKS volume.
 *
 * The write path serves exactly one shape: a streaming, sequential, create-then-write of a
 * document [PendingDocuments] is still holding pending -- see the architecture note on
 * [LuksDocumentsProvider.createDocument] and [LuksDocumentsProvider.openDocument]. Overwriting
 * an existing on-disk file is out of scope and refused before this callback is ever
 * constructed. Three invariants matter more than anything else here:
 *
 * - **Offsets must be strictly sequential.** The Rust writer is append-only against an
 *   internal cursor with no concept of "seek then write" -- a non-sequential offset would
 *   silently land in the wrong place with no native-side error. [onWrite] tracks the expected
 *   next offset itself and refuses with EINVAL rather than trust the caller.
 * - **The transfer mutex spans the whole write, not just one call.** It is claimed on the
 *   first [onWrite] and released in [onRelease], because a `WriterBusy` arriving mid-stream
 *   (after the native writer is already claimed) is unrecoverable -- contention must be
 *   resolved before that point, never after.
 * - **Any failure abandons, it never leaks a half file.** Every error path -- a rejected
 *   offset, a native write failure, a failed finish -- calls the writer's abandon, drops the
 *   pending registration, and releases the mutex via try/finally.
 */
open class LuksProxyCallback(
    val documentId: String,
    val mode: String,
    val context: Context? = null,
    val session: SessionController = LuksSession,
) : ProxyFileDescriptorCallback() {

    constructor(documentId: String, mode: String, context: Context) : this(documentId, mode, context as Context?, LuksSession)

    /** Non-null from the first successful [onWrite] until [onRelease] consumes it. */
    private var writer: LuksVolume.FileWriter? = null

    /** The offset the next [onWrite] must arrive with -- see the class doc for why. */
    private var expectedNextOffset: Long = 0L

    /** Whether this callback currently holds [TransferManager]'s SAF write lock. */
    private var writeLockHeld: Boolean = false

    override fun onGetSize(): Long {
        return try {
            runBlocking {
                session.withLease { volume ->
                    volume.fileInfo(documentId).size
                }
            }
        } catch (e: ErrnoException) {
            throw e
        } catch (t: Throwable) {
            Trace.e("LuksProxyCallback: getSize failed: ${throwableSummary(t)}")
            throw ErrnoException("getSize", OsConstants.EIO)
        }
    }

    override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
        if (size <= 0) return 0
        return try {
            runBlocking {
                session.withLease { volume ->
                    val chunk = volume.readChunk(documentId, offset, size.toLong())
                    if (chunk.isEmpty()) {
                        0
                    } else {
                        val bytesToCopy = minOf(chunk.size, size, data.size)
                        System.arraycopy(chunk, 0, data, 0, bytesToCopy)
                        bytesToCopy
                    }
                }
            }
        } catch (e: ErrnoException) {
            throw e
        } catch (t: Throwable) {
            Trace.e("LuksProxyCallback: read failed at offset $offset size $size: ${throwableSummary(t)}")
            throw ErrnoException("read", OsConstants.EIO)
        }
    }

    override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
        if (size <= 0) return 0

        // A read-mode callback (or any mode other than "w"/"wt") must never reach the write
        // path at all, regardless of write support -- the provider only ever opens those two
        // modes for writing, but this callback is also constructed directly in tests, so it
        // enforces the same boundary itself rather than trusting the caller.
        if (mode != "w" && mode != "wt") {
            throw ErrnoException("pwrite", OsConstants.EROFS)
        }

        // Fail closed first, before touching the mutex or the volume: a build without
        // dangerous-write-support must refuse here rather than reach a native symbol that
        // does not exist in that .so (UnsatisfiedLinkError, not a catchable LuksException).
        val writeSupported = try {
            runBlocking { session.withLease { it.canWrite } }
        } catch (t: Throwable) {
            false
        }
        if (!writeSupported) {
            throw ErrnoException("pwrite", OsConstants.EROFS)
        }

        if (writer == null) {
            // First write of this stream: claim the transfer-wide mutex before touching the
            // native writer at all. See TransferManager.tryAcquireForSafWrite -- a WriterBusy
            // arriving mid-stream is unrecoverable, so contention has to be resolved here.
            val acquired = try {
                runBlocking { TransferManager.tryAcquireForSafWrite() }
            } catch (t: Throwable) {
                false
            }
            if (!acquired) {
                throw ErrnoException("pwrite", OsConstants.EBUSY)
            }
            writeLockHeld = true

            val pending = PendingDocuments.get(documentId)
            if (pending == null) {
                // Should not happen -- the provider only opens a write-mode proxy for a
                // still-pending document -- but a callback constructed directly (as tests do)
                // has no such guarantee, and there is nothing to finish against without it.
                releaseWriteLockIfHeld()
                throw ErrnoException("pwrite", OsConstants.EROFS)
            }

            writer = try {
                runBlocking { session.withLease { it.beginFileStreaming() } }
            } catch (e: ErrnoException) {
                releaseWriteLockIfHeld()
                throw e
            } catch (t: Throwable) {
                releaseWriteLockIfHeld()
                Trace.e("LuksProxyCallback: beginFileStreaming failed: ${throwableSummary(t)}")
                throw ErrnoException("pwrite", OsConstants.EIO)
            }
            expectedNextOffset = 0L
        }

        if (offset != expectedNextOffset) {
            // The single most dangerous mistake available here: a seek-then-write against an
            // append-only cursor would land at the wrong offset with no native-side error at
            // all. Refuse explicitly rather than let it corrupt silently.
            abandonWrite()
            throw ErrnoException("pwrite", OsConstants.EINVAL)
        }

        val activeWriter = writer ?: throw ErrnoException("pwrite", OsConstants.EIO)
        return try {
            runBlocking { session.withLease { volume -> volume.writeChunk(activeWriter, data, 0, size) } }
            expectedNextOffset += size
            size
        } catch (e: ErrnoException) {
            abandonWrite()
            throw e
        } catch (t: Throwable) {
            Trace.e("LuksProxyCallback: write failed at offset $offset size $size: ${throwableSummary(t)}")
            abandonWrite()
            throw ErrnoException("pwrite", OsConstants.EIO)
        }
    }

    override fun onFsync() {
        // Nothing is durable until onRelease's finish materializes the file -- there is no
        // partial commit this streaming writer can offer. Reporting success here, rather than
        // an error, is deliberate: a failed fsync is read by most callers as "your data is
        // gone", which is false -- the bytes are still buffered natively and will land
        // atomically at close. Reporting success for not-yet-durable data is the better of the
        // two available answers, since fsync's real guarantee (durability now) is unavailable
        // either way until the writer finishes.
    }

    override fun onRelease() {
        val activeWriter = writer ?: return
        writer = null
        val pending = PendingDocuments.get(documentId)
        try {
            if (pending != null) {
                runBlocking { session.withLease { it.finishFile(activeWriter, pending.parentPath, pending.name) } }
                notifyMaterialized(pending.parentPath)
            } else {
                // The pending entry vanished underneath us (session lock/detach cleared the
                // registry -- see PendingDocuments.clear) -- there is nothing left to finish
                // against, so the only safe thing left to do is discard what was written.
                runCatching { runBlocking { session.withLease { it.abandonFile(activeWriter) } } }
            }
        } catch (t: Throwable) {
            Trace.e("LuksProxyCallback: finish failed, abandoning: ${throwableSummary(t)}")
            runCatching { runBlocking { session.withLease { it.abandonFile(activeWriter) } } }
        } finally {
            PendingDocuments.remove(documentId)
            releaseWriteLockIfHeld()
        }
    }

    /** Discards the in-progress writer and every trace of this write attempt. */
    private fun abandonWrite() {
        val activeWriter = writer
        writer = null
        if (activeWriter != null) {
            runCatching { runBlocking { session.withLease { it.abandonFile(activeWriter) } } }
        }
        PendingDocuments.remove(documentId)
        releaseWriteLockIfHeld()
    }

    private fun releaseWriteLockIfHeld() {
        if (writeLockHeld) {
            writeLockHeld = false
            runCatching { TransferManager.releaseSafWriteLock() }
        }
    }

    private fun notifyMaterialized(parentPath: String) {
        val ctx = context ?: return
        runCatching {
            val childrenUri = runCatching {
                android.provider.DocumentsContract.buildChildDocumentsUri(LuksDocumentsProvider.AUTHORITY, parentPath)
            }.getOrNull()
            if (childrenUri != null) {
                ctx.contentResolver?.notifyChange(childrenUri, null)
            }
        }
    }
}

/** Specialized read proxy callback. */
open class LuksReadProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "r", context = context, session = session)

/**
 * Specialized write proxy callback. The provider constructs a [LuksProxyCallback] with
 * mode "w"/"wt" directly (see [LuksDocumentsProvider.openDocument]); this subclass exists so
 * tests can exercise the write path without going through the provider.
 */
open class LuksWriteProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "w", context = context, session = session)
