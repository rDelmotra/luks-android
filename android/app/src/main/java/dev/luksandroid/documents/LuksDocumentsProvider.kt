package dev.luksandroid.documents

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.webkit.MimeTypeMap
import dev.luksandroid.LuksException
import dev.luksandroid.R
import dev.luksandroid.Trace
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.SessionController
import dev.luksandroid.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.FileNotFoundException
import java.util.concurrent.CancellationException

/**
 * Android [DocumentsProvider] exposing the unlocked LUKS volume to the platform Files app
 * and Storage Access Framework.
 */
open class LuksDocumentsProvider(
    val session: SessionController,
    val scope: CoroutineScope,
) : DocumentsProvider() {

    constructor() : this(LuksSession, CoroutineScope(Dispatchers.Default + SupervisorJob()))
    constructor(session: SessionController) : this(session, CoroutineScope(Dispatchers.Default + SupervisorJob()))

    companion object {
        const val AUTHORITY = "dev.luksandroid.documents"
        const val ROOT_ID = "luks_root"
        const val ROOT_DOCUMENT_ID = "/"
        private const val DEFAULT_ROOT_TITLE = "LUKS Drive"

        val DEFAULT_ROOT_PROJECTION: Array<String> = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
            Root.COLUMN_TITLE,
            Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_SUMMARY,
            Root.COLUMN_AVAILABLE_BYTES,
            Root.COLUMN_CAPACITY_BYTES,
            Root.COLUMN_MIME_TYPES,
        )

        val DEFAULT_DOCUMENT_PROJECTION: Array<String> = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
            Document.COLUMN_SIZE,
        )

        private val VALID_MODES = setOf("r", "w", "wt", "wa", "rw", "rwt")

        fun mapLuksException(e: LuksException): Throwable = when (e.code) {
            LuksException.NOT_FOUND -> FileNotFoundException("Document not found")
            LuksException.ALREADY_EXISTS -> IllegalStateException("Item already exists")
            LuksException.UNSUPPORTED,
            LuksException.WRONG_TARGET,
            LuksException.ITEM_TOO_LARGE -> UnsupportedOperationException("Operation not supported by filesystem")
            LuksException.NO_SPACE -> IllegalStateException("No space left on device")
            LuksException.WRITER_BUSY -> IllegalStateException("Volume writer is busy")
            LuksException.CANCELLED -> CancellationException("Operation was cancelled")
            else -> IllegalStateException("I/O error occurred")
        }

        fun getMimeType(name: String): String {
            val ext = name.substringAfterLast('.', "").lowercase()
            if (ext.isEmpty()) return "application/octet-stream"
            val fromMap = runCatching { MimeTypeMap.getSingleton()?.getMimeTypeFromExtension(ext) }.getOrNull()
            if (!fromMap.isNullOrBlank()) return fromMap
            return when (ext) {
                "txt" -> "text/plain"
                "jpg", "jpeg" -> "image/jpeg"
                "png" -> "image/png"
                "mp4" -> "video/mp4"
                "pdf" -> "application/pdf"
                "json" -> "application/json"
                "zip" -> "application/zip"
                else -> "application/octet-stream"
            }
        }

        private fun resolveColumns(projection: Array<out String>?, defaultProjection: Array<String>): Array<String> {
            return if (projection != null && projection.isNotEmpty()) {
                projection.map { it }.toTypedArray()
            } else {
                defaultProjection
            }
        }
    }

    var contextOverride: Context? = null
    val providerContext: Context? get() = contextOverride ?: runCatching { context }.getOrNull()

    open fun createMatrixCursor(columns: Array<String>): MatrixCursor {
        return MatrixCursor(columns)
    }

    override fun attachInfo(context: Context?, info: android.content.pm.ProviderInfo?) {
        contextOverride = context
        runCatching { super.attachInfo(context, info) }
    }

    override fun onCreate(): Boolean {
        providerContext?.let { ctx ->
            scope.launch {
                session.state.collect { state ->
                    runCatching {
                        val uri = runCatching { DocumentsContract.buildRootsUri(AUTHORITY) }.getOrNull()
                        if (uri != null) {
                            ctx.contentResolver?.notifyChange(uri, null)
                        }
                    }
                    // N.8: grants outlive the locked volume unless proactively revoked here.
                    // §4.4 requires revocation on "delete, rename, and lock/detach for
                    // everything issued" -- delete/rename already revoke their own URI;
                    // this covers every other transition away from Unlocked.
                    if (state is SessionState.Locked ||
                        state is SessionState.Detached ||
                        state is SessionState.Failed
                    ) {
                        revokeAllIssuedGrants()
                        // Pending (not-yet-materialized) documents reference a volume session
                        // that no longer exists past this transition -- see PendingDocuments.
                        PendingDocuments.clear()
                    }
                }
            }
        }
        return true
    }

    /** Document IDs the provider has handed out via query/open, and so may carry a grant. */
    private val issuedDocumentIds = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    private fun trackIssued(docId: String) {
        issuedDocumentIds.add(docId)
    }

    /**
     * Revokes URI permission grants for every document this provider has issued.
     * There is no API to block a persistable grant (`takePersistableUriPermission`) from
     * being taken in the first place, so proactive revocation on lock/detach/failure is
     * the only lever. Mirrors the AOSP `ExternalStorageProvider.onDocIdDeleted` pattern of
     * revoking with a full permission mask rather than only the flags this provider granted.
     */
    private fun revokeAllIssuedGrants() {
        val ctx = providerContext ?: return
        val ids = issuedDocumentIds.toList()
        issuedDocumentIds.clear()
        for (id in ids) {
            runCatching {
                // Matches the deleteDocument/renameDocument revoke pattern: call
                // revokeUriPermission unconditionally rather than gating on a non-null
                // Uri. buildDocumentUri should never fail for a well-formed authority and
                // document id, and there is nothing more targeted to fall back to here.
                val uri = DocumentsContract.buildDocumentUri(AUTHORITY, id)
                ctx.revokeUriPermission(uri, 0.inv())
            }
        }
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val cols = resolveColumns(projection, DEFAULT_ROOT_PROJECTION)
        val result = MatrixCursor(cols)
        val state = session.state.value
        if (state !is SessionState.Unlocked) {
            return result
        }

        val volume = session.volume ?: state.volume
        val statFs = runCatching {
            runBlocking {
                session.withLease { it.statFs() }
            }
        }.getOrNull()

        // FLAG_SUPPORTS_CREATE is only advertised when the loaded .so actually links the
        // write path (nativeWriteSupported(), asked via volume.canWrite) -- a release build
        // without dangerous-write-support must never claim a capability it cannot deliver.
        // Directory creation (createDocument with MIME_TYPE_DIR) is real and durable; file
        // creation goes through the pending-document registry -- see createDocument.
        val flags = Root.FLAG_LOCAL_ONLY or
                Root.FLAG_SUPPORTS_IS_CHILD or
                Root.FLAG_SUPPORTS_EJECT or
                (if (volume.canWrite) Root.FLAG_SUPPORTS_CREATE else 0)

        val title = volume.info.label.ifBlank { DEFAULT_ROOT_TITLE }

        val rowValues = arrayOfNulls<Any>(cols.size)
        for (i in cols.indices) {
            rowValues[i] = when (cols[i]) {
                Root.COLUMN_ROOT_ID -> ROOT_ID
                Root.COLUMN_DOCUMENT_ID -> ROOT_DOCUMENT_ID
                Root.COLUMN_TITLE -> title
                Root.COLUMN_FLAGS -> flags
                Root.COLUMN_ICON -> R.mipmap.ic_launcher
                Root.COLUMN_SUMMARY -> "${volume.info.fsType.uppercase()} Volume"
                Root.COLUMN_MIME_TYPES -> "*/*"
                Root.COLUMN_AVAILABLE_BYTES -> statFs?.availableBytes
                Root.COLUMN_CAPACITY_BYTES -> statFs?.totalBytes ?: volume.info.sizeBytes
                else -> null
            }
        }
        result.addRow(rowValues)

        return result
    }

    override fun queryDocument(documentId: String?, projection: Array<out String>?): Cursor {
        val docId = documentId ?: throw FileNotFoundException("Document not found")
        val cols = resolveColumns(projection, DEFAULT_DOCUMENT_PROJECTION)
        val result = MatrixCursor(cols)

        val pending = if (docId != ROOT_DOCUMENT_ID) PendingDocuments.get(docId) else null
        if (pending != null) {
            // Synthesizes a 0-byte row for a document that exists only in the pending
            // registry -- nothing has touched the volume yet (see the ARCHITECTURE note on
            // createDocument). FLAG_SUPPORTS_WRITE is the one flag an existing on-disk file
            // never gets (see the comment further down): overwrite is out of scope, but a
            // still-pending document is exactly what a write-mode openDocument requires.
            trackIssued(docId)
            val rowValues = arrayOfNulls<Any>(cols.size)
            for (i in cols.indices) {
                rowValues[i] = when (cols[i]) {
                    Document.COLUMN_DOCUMENT_ID -> docId
                    Document.COLUMN_MIME_TYPE -> getMimeType(pending.name)
                    Document.COLUMN_DISPLAY_NAME -> pending.name
                    Document.COLUMN_LAST_MODIFIED -> 0L
                    Document.COLUMN_FLAGS -> Document.FLAG_SUPPORTS_WRITE or Document.FLAG_SUPPORTS_DELETE
                    Document.COLUMN_SIZE -> 0L
                    else -> null
                }
            }
            result.addRow(rowValues)
            return result
        }

        safeCall {
            runBlocking {
                session.withLease { volume ->
                    val rowValues = arrayOfNulls<Any>(cols.size)
                    if (docId == ROOT_DOCUMENT_ID) {
                        for (i in cols.indices) {
                            rowValues[i] = when (cols[i]) {
                                Document.COLUMN_DOCUMENT_ID -> ROOT_DOCUMENT_ID
                                Document.COLUMN_MIME_TYPE -> Document.MIME_TYPE_DIR
                                Document.COLUMN_DISPLAY_NAME -> volume.info.label.ifBlank { DEFAULT_ROOT_TITLE }
                                Document.COLUMN_LAST_MODIFIED -> 0L
                                Document.COLUMN_FLAGS ->
                                    if (volume.canWrite) Document.FLAG_DIR_SUPPORTS_CREATE else 0
                                Document.COLUMN_SIZE -> 0L
                                else -> null
                            }
                        }
                    } else {
                        trackIssued(docId)
                        val info = volume.fileInfo(docId)
                        val displayName = docId.substringAfterLast('/')
                        val isDir = info.type == "dir"
                        val mimeType = if (isDir) {
                            Document.MIME_TYPE_DIR
                        } else {
                            getMimeType(displayName)
                        }
                        // FLAG_DIR_SUPPORTS_CREATE only when the .so actually links the write
                        // path (see queryRoots). FLAG_SUPPORTS_WRITE for an existing on-disk
                        // file is never advertised -- overwrite is out of scope (see
                        // openDocument); it is only ever set for a still-pending document,
                        // handled in the branch above before this block is ever reached.
                        var flags = Document.FLAG_SUPPORTS_DELETE or Document.FLAG_SUPPORTS_RENAME
                        if (isDir && volume.canWrite) {
                            flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
                        }

                        for (i in cols.indices) {
                            rowValues[i] = when (cols[i]) {
                                Document.COLUMN_DOCUMENT_ID -> docId
                                Document.COLUMN_MIME_TYPE -> mimeType
                                Document.COLUMN_DISPLAY_NAME -> displayName
                                Document.COLUMN_LAST_MODIFIED -> info.mtime * 1000L
                                Document.COLUMN_FLAGS -> flags
                                Document.COLUMN_SIZE -> if (isDir) 0L else info.size
                                else -> null
                            }
                        }
                    }
                    result.addRow(rowValues)
                }
            }
        }

        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String?,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val parentId = parentDocumentId ?: throw FileNotFoundException("Document not found")
        val cols = resolveColumns(projection, DEFAULT_DOCUMENT_PROJECTION)
        val result = MatrixCursor(cols)

        safeCall {
            runBlocking {
                session.withLease { volume ->
                    val entries = volume.listDir(parentId)
                    for (entry in entries) {
                        val docId = if (parentId == "/") "/${entry.name}" else "$parentId/${entry.name}"
                        trackIssued(docId)
                        val isDir = entry.isDir || entry.isSubvolume
                        val mimeType = if (isDir) {
                            Document.MIME_TYPE_DIR
                        } else {
                            getMimeType(entry.name)
                        }
                        // Mirrors queryDocument's flag logic -- see the comment there.
                        var flags = Document.FLAG_SUPPORTS_DELETE or Document.FLAG_SUPPORTS_RENAME
                        if (isDir && volume.canWrite) {
                            flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
                        }

                        val fileInfo = runCatching { volume.fileInfo(docId) }.getOrNull()
                        val size = if (isDir) 0L else (fileInfo?.size ?: 0L)
                        val lastModified = (fileInfo?.mtime ?: 0L) * 1000L

                        val rowValues = arrayOfNulls<Any>(cols.size)
                        for (i in cols.indices) {
                            rowValues[i] = when (cols[i]) {
                                Document.COLUMN_DOCUMENT_ID -> docId
                                Document.COLUMN_MIME_TYPE -> mimeType
                                Document.COLUMN_DISPLAY_NAME -> entry.name
                                Document.COLUMN_LAST_MODIFIED -> lastModified
                                Document.COLUMN_FLAGS -> flags
                                Document.COLUMN_SIZE -> size
                                else -> null
                            }
                        }
                        result.addRow(rowValues)
                    }
                }
            }
        }

        return result
    }

    override fun isChildDocument(parentDocumentId: String?, documentId: String?): Boolean {
        if (parentDocumentId == null || documentId == null || parentDocumentId == documentId) return false
        return if (parentDocumentId == "/") {
            documentId.startsWith("/") && documentId.length > 1
        } else {
            documentId.startsWith("$parentDocumentId/") && documentId.length > parentDocumentId.length + 1
        }
    }

    override fun openDocument(
        documentId: String?,
        mode: String?,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val docId = documentId ?: throw FileNotFoundException("Document not found")
        val openMode = mode ?: "r"
        if (openMode !in VALID_MODES) {
            throw IllegalArgumentException("Unsupported open mode")
        }

        if (openMode != "r") {
            // Only a streaming create-then-write can be served: "wa" (append), "rw" and
            // "rwt" have no counterpart in an append-only, single-writer streaming
            // primitive -- refuse them outright, distinctly from the two gates below.
            if (openMode != "w" && openMode != "wt") {
                throw UnsupportedOperationException("Append and read-write modes are not supported")
            }

            // Fail closed, same pattern as createDocument: a build without
            // dangerous-write-support must refuse here rather than reach a native symbol
            // that does not exist in that .so.
            val writeSupported = runCatching {
                runBlocking { session.withLease { it.canWrite } }
            }.getOrDefault(false)
            if (!writeSupported) {
                throw UnsupportedOperationException("Write support is not built into this app")
            }

            // Overwrite is out of scope: a write-mode open is only ever served for a
            // document this provider registered via createDocument and has not yet
            // materialized. Everything else -- an existing on-disk file, an unknown id --
            // is refused, distinctly from the write-support gate above.
            if (!PendingDocuments.isPending(docId)) {
                throw UnsupportedOperationException("Overwriting an existing file is not supported")
            }
        }

        trackIssued(docId)
        val ctx = providerContext ?: throw IllegalStateException("Provider not attached to Context")
        val storageManager = ctx.getSystemService(StorageManager::class.java)
            ?: throw IllegalStateException("StorageManager not available")

        signal?.setOnCancelListener {
            Trace.i("LuksDocumentsProvider: openDocument cancelled")
        }

        val parsedMode = ParcelFileDescriptor.parseMode(openMode)
        val callback = LuksProxyCallback(docId, openMode, ctx, session)

        return storageManager.openProxyFileDescriptor(
            parsedMode,
            callback,
            LuksProxyHandlerThread.handler
        )
    }

    override fun createDocument(
        parentDocumentId: String?,
        mimeType: String?,
        displayName: String?
    ): String {
        val parentId = parentDocumentId ?: throw FileNotFoundException("Document not found")
        val name = displayName ?: throw IllegalArgumentException("Invalid display name")
        if (name.isBlank() || name.contains('/') || name == "." || name == "..") {
            throw IllegalArgumentException("Invalid display name")
        }

        // Fail closed first, before touching anything else: a build without
        // dangerous-write-support must refuse here rather than reach a native call that
        // does not exist in that .so (UnsatisfiedLinkError, not a catchable LuksException).
        // volume.canWrite is the safe indirection onto nativeWriteSupported() -- see its
        // doc comment in LuksHandles.kt.
        val writeSupported = runCatching {
            runBlocking { session.withLease { it.canWrite } }
        }.getOrDefault(false)
        if (!writeSupported) {
            throw UnsupportedOperationException("Write support is not built into this app")
        }

        if (mimeType == Document.MIME_TYPE_DIR) {
            // Directories have a real create-empty primitive (nativeCreateDirectory), so
            // this materializes for real, immediately -- unlike file creation, which has no
            // such primitive and is deferred (see the pending-document registry added for
            // that case).
            return safeCall {
                runBlocking {
                    session.withLease { volume ->
                        volume.createDirectory(parentId, name)
                        val docId = if (parentId == "/") "/$name" else "$parentId/$name"
                        trackIssued(docId)
                        notifyDocumentChange(parentId)
                        docId
                    }
                }
            }
        }

        // File creation has no create-empty-then-append primitive: SAF requires
        // createDocument to return an id for a document that exists NOW, but finish_file
        // (the only primitive that materializes a file) needs content to write against.
        // Register a PENDING document instead -- touching nothing on disk -- and return its
        // id. The real file is materialized at onRelease of the write proxy opened against
        // that id (see openDocument, LuksProxyCallback.onRelease).
        val docId = PendingDocuments.register(parentId, name)
        trackIssued(docId)
        return docId
    }

    override fun deleteDocument(documentId: String?) {
        val docId = documentId ?: throw FileNotFoundException("Document not found")
        if (docId == ROOT_DOCUMENT_ID) {
            throw UnsupportedOperationException("Cannot delete root document")
        }
        if (PendingDocuments.remove(docId) != null) {
            // Nothing was ever written to disk -- this simply cancels the pending create.
            return
        }
        safeCall {
            runBlocking {
                session.withLease { volume ->
                    volume.deleteFile(docId)
                    runCatching {
                        val uri = runCatching { DocumentsContract.buildDocumentUri(AUTHORITY, docId) }.getOrNull()
                        providerContext?.revokeUriPermission(
                            uri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        )
                    }
                    val lastSlash = docId.lastIndexOf('/')
                    val parentPath = if (lastSlash <= 0) "/" else docId.substring(0, lastSlash)
                    notifyDocumentChange(parentPath)
                }
            }
        }
    }

    override fun renameDocument(documentId: String?, displayName: String?): String {
        val docId = documentId ?: throw FileNotFoundException("Document not found")
        if (docId == ROOT_DOCUMENT_ID) {
            throw UnsupportedOperationException("Cannot rename root document")
        }
        val newName = displayName ?: throw IllegalArgumentException("Invalid display name")
        if (newName.isBlank() || newName.contains('/') || newName == "." || newName == "..") {
            throw IllegalArgumentException("Invalid display name")
        }

        return safeCall {
            runBlocking {
                session.withLease { volume ->
                    val lastSlash = docId.lastIndexOf('/')
                    val parentPath = if (lastSlash <= 0) "/" else docId.substring(0, lastSlash)
                    val oldName = docId.substring(lastSlash + 1)
                    volume.rename(parentPath, oldName, parentPath, newName)
                    val newDocId = if (parentPath == "/") "/$newName" else "$parentPath/$newName"
                    runCatching {
                        val oldUri = runCatching { DocumentsContract.buildDocumentUri(AUTHORITY, docId) }.getOrNull()
                        providerContext?.revokeUriPermission(
                            oldUri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        )
                    }
                    notifyDocumentChange(parentPath)
                    newDocId
                }
            }
        }
    }

    override fun ejectRoot(rootId: String?) {
        if (rootId != ROOT_ID) {
            throw IllegalArgumentException("Invalid root identifier")
        }
        runBlocking {
            session.lock()
        }
        runCatching {
            val rootsUri = runCatching { DocumentsContract.buildRootsUri(AUTHORITY) }.getOrNull()
            if (rootsUri != null) {
                providerContext?.contentResolver?.notifyChange(rootsUri, null)
            }
        }
    }

    private fun notifyDocumentChange(documentId: String) {
        providerContext?.let { ctx ->
            runCatching {
                val uri = runCatching { DocumentsContract.buildDocumentUri(AUTHORITY, documentId) }.getOrNull()
                if (uri != null) {
                    ctx.contentResolver?.notifyChange(uri, null)
                }
            }
            runCatching {
                val childrenUri = runCatching { DocumentsContract.buildChildDocumentsUri(AUTHORITY, documentId) }.getOrNull()
                if (childrenUri != null) {
                    ctx.contentResolver?.notifyChange(childrenUri, null)
                }
            }
        }
    }

    private inline fun <T> safeCall(block: () -> T): T {
        try {
            return block()
        } catch (e: LuksException) {
            throw mapLuksException(e)
        } catch (e: IllegalStateException) {
            throw IllegalStateException("Session is not active")
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid argument")
        } catch (e: FileNotFoundException) {
            throw e
        } catch (e: UnsupportedOperationException) {
            throw e
        } catch (e: SecurityException) {
            throw e
        } catch (e: Exception) {
            throw IllegalStateException("Operation failed")
        }
    }
}
