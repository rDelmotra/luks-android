package dev.luksandroid.documents

import android.content.Context
import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import dev.luksandroid.LuksVolume
import dev.luksandroid.Trace
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionController
import kotlinx.coroutines.runBlocking

/**
 * [ProxyFileDescriptorCallback] bridging kernel VFS read and sequential write operations
 * through the active [LuksSession] lease to an unlocked LUKS volume.
 */
open class LuksProxyCallback(
    val documentId: String,
    val mode: String,
    val context: Context? = null,
    val session: SessionController = LuksSession,
) : ProxyFileDescriptorCallback() {

    constructor(documentId: String, mode: String, context: Context) : this(documentId, mode, context as Context?, LuksSession)

    private val isWriteMode: Boolean =
        mode.contains("w") || mode.contains("a") || mode.contains("+") ||
            mode == "rw" || mode == "rwt" || mode == "wt" || mode == "wa"

    private val parentPath: String
    private val fileName: String

    init {
        val clean = documentId.trimEnd('/')
        val lastSlash = clean.lastIndexOf('/')
        if (lastSlash == -1) {
            parentPath = "/"
            fileName = clean
        } else if (lastSlash == 0) {
            parentPath = "/"
            fileName = clean.substring(1)
        } else {
            parentPath = clean.substring(0, lastSlash)
            fileName = clean.substring(lastSlash + 1)
        }
    }

    private var expectedOffset: Long = 0L
    private var activeWriter: LuksVolume.FileWriter? = null
    private var errorOccurred: Boolean = false
    private var isFinished: Boolean = false

    override fun onGetSize(): Long {
        if (isWriteMode && (mode.contains("w") || expectedOffset > 0L)) {
            return expectedOffset
        }
        return try {
            runBlocking {
                session.withLease { volume ->
                    volume.fileInfo(documentId).size
                }
            }
        } catch (e: ErrnoException) {
            throw e
        } catch (t: Throwable) {
            Trace.e("LuksProxyCallback: getSize failed for $documentId", t)
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
            Trace.e("LuksProxyCallback: read failed at offset $offset size $size", t)
            throw ErrnoException("read", OsConstants.EIO)
        }
    }

    override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
        if (errorOccurred) {
            throw ErrnoException("pwrite", OsConstants.EIO)
        }
        // Refusal Gate (§3.4): strictly refuse non-sequential seeks/writes
        if (offset != expectedOffset) {
            Trace.e("LuksProxyCallback: non-sequential write rejected: offset=$offset expectedOffset=$expectedOffset")
            throw ErrnoException("pwrite", OsConstants.EINVAL)
        }
        if (size <= 0) {
            return 0
        }
        return try {
            runBlocking {
                session.withLease { volume ->
                    val writer = activeWriter ?: volume.beginFile(0L).also { activeWriter = it }
                    volume.writeChunk(writer, data, 0, size)
                }
            }
            expectedOffset += size
            size
        } catch (e: ErrnoException) {
            errorOccurred = true
            throw e
        } catch (t: Throwable) {
            errorOccurred = true
            Trace.e("LuksProxyCallback: write failed at offset $offset size $size", t)
            throw ErrnoException("pwrite", OsConstants.EIO)
        }
    }

    override fun onFsync() {
        if (errorOccurred) {
            throw ErrnoException("fsync", OsConstants.EIO)
        }
        if (isWriteMode && activeWriter != null) {
            try {
                runBlocking {
                    session.withLease {
                        // Validate active lease and session health
                    }
                }
            } catch (t: Throwable) {
                errorOccurred = true
                Trace.e("LuksProxyCallback: fsync failed", t)
                throw ErrnoException("fsync", OsConstants.EIO)
            }
        }
    }

    override fun onRelease() {
        if (isWriteMode && !isFinished) {
            if (!errorOccurred && activeWriter != null) {
                try {
                    runBlocking {
                        session.withLease { volume ->
                            activeWriter?.let { writer ->
                                volume.finishFile(writer, parentPath, fileName)
                            }
                            isFinished = true
                            Trace.i("LuksProxyCallback: finished file write for $documentId ($expectedOffset bytes)")
                        }
                    }
                } catch (t: Throwable) {
                    errorOccurred = true
                    Trace.e("LuksProxyCallback: onRelease finish failed for $documentId", t)
                    try {
                        activeWriter?.let { writer ->
                            runBlocking {
                                session.withLease { volume ->
                                    volume.abandonFile(writer)
                                }
                            }
                        }
                    } catch (_: Throwable) {
                        try {
                            activeWriter?.abandon()
                        } catch (_: Throwable) {}
                    }
                } finally {
                    activeWriter = null
                }
            } else if (activeWriter != null) {
                Trace.i("LuksProxyCallback: abandoning file write for $documentId due to error")
                try {
                    activeWriter?.let { writer ->
                        runBlocking {
                            session.withLease { volume ->
                                volume.abandonFile(writer)
                            }
                        }
                    }
                } catch (_: Throwable) {
                    try {
                        activeWriter?.abandon()
                    } catch (_: Throwable) {}
                } finally {
                    activeWriter = null
                }
            }
        } else {
            // Read mode or already finished write mode cleanup
            try {
                activeWriter?.abandon()
            } catch (_: Throwable) {}
            activeWriter = null
        }
    }
}

/** Specialized read proxy callback. */
open class LuksReadProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "r", context = context, session = session)

/** Specialized write proxy callback. */
open class LuksWriteProxyCallback(
    session: SessionController,
    documentId: String,
    context: Context? = null,
) : LuksProxyCallback(documentId = documentId, mode = "w", context = context, session = session)
