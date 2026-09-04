package dev.luksandroid.transfer

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import android.webkit.MimeTypeMap
import java.io.OutputStream

/**
 * [ExportDestination] over a SAF tree the user picked with `OpenDocumentTree`.
 *
 * Deliberately minimal, for the same reason as [SafChildSource]: this file
 * cannot be unit-tested (`Uri.parse` returns null under this module's test
 * setup), so correctness here is verified on a physical device. Every line of
 * logic that can live in [TreeExporter] instead, where it is tested, does --
 * which is why this class holds no collision policy, no naming rules, and no
 * traversal state.
 *
 * Never use `DocumentFile` here or anywhere in this feature: `listFiles()`
 * costs one binder round trip per child, where the query in [children] costs
 * one per directory. See notes/feature-directory-transfer.md §2.1.
 */
class SafExportDestination(
    private val contentResolver: ContentResolver,
    private val treeUri: Uri,
) : ExportDestination {

    private fun documentUri(documentId: String): Uri =
        DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)

    override fun children(dirId: String): List<RawChild> {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, dirId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
        )
        val result = mutableListOf<RawChild>()
        contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            val idCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
            val mtimeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            while (cursor.moveToNext()) {
                val mime = cursor.getString(mimeCol)
                result += RawChild(
                    id = cursor.getString(idCol),
                    name = cursor.getString(nameCol),
                    isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR,
                    sizeBytes = if (cursor.isNull(sizeCol)) SIZE_UNKNOWN else cursor.getLong(sizeCol),
                    mtime = cursor.getLong(mtimeCol),
                )
            }
        }
        return result
    }

    override fun createDirectory(parentId: String, name: String): CreatedDocument =
        create(parentId, DocumentsContract.Document.MIME_TYPE_DIR, name)

    override fun createFile(parentId: String, name: String, mimeType: String): CreatedDocument =
        create(parentId, mimeType, name)

    /**
     * The provider decides the final display name, not us: on a collision it
     * de-duplicates rather than failing, and it may append an extension it
     * derives from the MIME type. So the name is read back from the created
     * document instead of assumed -- see [CreatedDocument].
     */
    private fun create(parentId: String, mimeType: String, name: String): CreatedDocument {
        val parentUri = documentUri(parentId)
        val uri = DocumentsContract.createDocument(contentResolver, parentUri, mimeType, name)
            ?: throw java.io.IOException("the destination refused to create '$name' in $parentId")
        return CreatedDocument(DocumentsContract.getDocumentId(uri), displayNameOf(uri) ?: name)
    }

    private fun displayNameOf(uri: Uri): String? {
        val projection = arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) return cursor.getString(0)
        }
        return null
    }

    override fun openOutput(docId: String): OutputStream =
        contentResolver.openOutputStream(documentUri(docId))
            ?: throw java.io.IOException("the destination refused to open '$docId' for writing")

    override fun delete(docId: String) {
        if (!DocumentsContract.deleteDocument(contentResolver, documentUri(docId))) {
            throw java.io.IOException("the destination refused to delete '$docId'")
        }
    }

    override fun rename(docId: String, newName: String): CreatedDocument {
        val uri = DocumentsContract.renameDocument(contentResolver, documentUri(docId), newName)
        // A provider may return null to mean "renamed in place, the URI did not
        // change" rather than to signal failure, so the original URI is the
        // fallback rather than an error.
            ?: documentUri(docId)
        return CreatedDocument(DocumentsContract.getDocumentId(uri), displayNameOf(uri) ?: newName)
    }

    companion object {
        /**
         * The MIME type a file should be created with, from its extension.
         *
         * Supplying this matters: a provider that is handed
         * `application/octet-stream` for `photo.jpg` may create `photo.jpg.bin`,
         * having decided the name lacked the extension its type implies.
         */
        fun mimeTypeFor(name: String): String {
            val ext = name.substringAfterLast('.', "").lowercase()
            if (ext.isEmpty()) return "application/octet-stream"
            return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
                ?: "application/octet-stream"
        }
    }
}
