package dev.luksandroid.documents

import android.content.Context
import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import dev.luksandroid.Trace
import dev.luksandroid.Trace.throwableSummary
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionController
import kotlinx.coroutines.runBlocking

/**
 * [ProxyFileDescriptorCallback] bridging kernel VFS read operations through the active
 * [LuksSession] lease to an unlocked LUKS volume.
 *
 * Read-only trim (§6.2): writes are refused unconditionally. The only write primitive
 * exposed to Kotlin, `beginFile`, requires an upfront size the proxy cannot know ahead of
 * a streaming write, and the sized writer rejects any write past that size -- so every
 * write beyond zero bytes would fail with EIO regardless. `begin_file_streaming` (the
 * unknown-size primitive) has no JNI or Kotlin surface at all. Rather than half-work
 * against a broken API, [onWrite] refuses explicitly with EROFS and never touches the
 * volume's write path.
 */
open class LuksProxyCallback(
    val documentId: String,
    val mode: String,
    val context: Context? = null,
    val session: SessionController = LuksSession,
) : ProxyFileDescriptorCallback() {

    constructor(documentId: String, mode: String, context: Context) : this(documentId, mode, context as Context?, LuksSession)

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
        // Read-only trim (§6.2): refuse unconditionally, before any volume interaction.
        throw ErrnoException("pwrite", OsConstants.EROFS)
    }

    override fun onFsync() {
        // No write path exists to flush.
    }

    override fun onRelease() {
        // No writer is ever created, so there is nothing to finish or abandon.
    }
}

/** Specialized read proxy callback. */
open class LuksReadProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "r", context = context, session = session)

/**
 * Specialized write proxy callback. Retained for tests exercising the [LuksProxyCallback]
 * write refusal directly; the provider itself never opens a document in a write mode
 * (see [LuksDocumentsProvider.openDocument]).
 */
open class LuksWriteProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "w", context = context, session = session)
