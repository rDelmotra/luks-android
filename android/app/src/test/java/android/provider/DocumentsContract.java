package android.provider;

import android.net.Uri;

public class DocumentsContract {
    public static final String EXTRA_PROMPT = "android.provider.extra.PROMPT";

    public static final class Document {
        public static final String COLUMN_DOCUMENT_ID = "document_id";
        public static final String COLUMN_DISPLAY_NAME = "_display_name";
        public static final String COLUMN_MIME_TYPE = "mime_type";
        public static final String COLUMN_LAST_MODIFIED = "last_modified";
        public static final String COLUMN_ICON = "icon";
        public static final String COLUMN_FLAGS = "flags";
        public static final String COLUMN_SIZE = "_size";
        public static final String COLUMN_SUMMARY = "summary";

        public static final String MIME_TYPE_DIR = "vnd.android.document/directory";

        public static final int FLAG_DIR_SUPPORTS_CREATE = 0x08;
        public static final int FLAG_SUPPORTS_WRITE = 0x02;
        public static final int FLAG_SUPPORTS_DELETE = 0x04;
        public static final int FLAG_SUPPORTS_RENAME = 0x40;
    }

    public static final class Root {
        public static final String COLUMN_ROOT_ID = "root_id";
        public static final String COLUMN_FLAGS = "flags";
        public static final String COLUMN_ICON = "icon";
        public static final String COLUMN_TITLE = "title";
        public static final String COLUMN_SUMMARY = "summary";
        public static final String COLUMN_DOCUMENT_ID = "document_id";
        public static final String COLUMN_AVAILABLE_BYTES = "available_bytes";
        public static final String COLUMN_CAPACITY_BYTES = "capacity_bytes";
        public static final String COLUMN_MIME_TYPES = "mime_types";

        public static final int FLAG_LOCAL_ONLY = 0x02;
        public static final int FLAG_SUPPORTS_CREATE = 0x01;
        public static final int FLAG_SUPPORTS_IS_CHILD = 0x10;
        public static final int FLAG_SUPPORTS_EJECT = 0x20;
    }

    public static Uri buildRootsUri(String authority) {
        return Uri.parse("content://" + authority + "/root");
    }

    public static Uri buildRootUri(String authority, String rootId) {
        return Uri.parse("content://" + authority + "/root/" + rootId);
    }

    public static Uri buildDocumentUri(String authority, String documentId) {
        return Uri.parse("content://" + authority + "/document/" + documentId);
    }

    public static Uri buildChildDocumentsUri(String authority, String parentDocumentId) {
        return Uri.parse("content://" + authority + "/document/" + parentDocumentId + "/children");
    }
}
