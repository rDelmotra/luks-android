package dev.luksandroid.transfer

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract

/**
 * [ChildSource] over a SAF tree, via a raw [ContentResolver.query] with an
 * explicit projection.
 *
 * Deliberately minimal: this file cannot be unit-tested (`Uri.parse` returns
 * null under this module's test setup -- see notes/feature-directory-transfer.md,
 * "Testing constraint, discovered 2026-08-23" -- so correctness here is
 * verified on a physical device, not in CI). Every line of logic that *can*
 * live in [DirectoryWalker] instead, where it is tested, does.
 *
 * Never use `DocumentFile` here or anywhere in this feature: `listFiles()`
 * costs one binder round trip per child, where this query costs one per
 * directory. See notes/feature-directory-transfer.md §2.1.
 */
class SafChildSource(
    private val contentResolver: ContentResolver,
    private val treeUri: Uri,
) : ChildSource {

    override fun children(parentId: String): List<RawChild> {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
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
}
