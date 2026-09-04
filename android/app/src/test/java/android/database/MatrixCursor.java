package android.database;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * JVM test shadow implementation of android.database.MatrixCursor.
 * Allows unit testing DocumentsProvider queries without Robolectric or an emulator.
 */
public class MatrixCursor implements Cursor {

    private final String[] columnNames;
    private final List<Object[]> data;
    private int rowCount = 0;
    private int position = -1;
    private boolean isClosed = false;

    public MatrixCursor(String[] columnNames, int initialCapacity) {
        this.columnNames = columnNames != null ? columnNames.clone() : new String[0];
        this.data = new ArrayList<>(initialCapacity);
    }

    public MatrixCursor(String[] columnNames) {
        this(columnNames, 16);
    }

    public class RowBuilder {
        private final int rowIndex;
        private int colIndex = 0;

        RowBuilder(int rowIndex) {
            this.rowIndex = rowIndex;
        }

        public RowBuilder add(Object columnValue) {
            if (colIndex >= columnNames.length) {
                throw new CursorIndexOutOfBoundsException("No more columns");
            }
            data.get(rowIndex)[colIndex++] = columnValue;
            return this;
        }

        public RowBuilder add(String columnName, Object columnValue) {
            int idx = getColumnIndex(columnName);
            if (idx >= 0) {
                data.get(rowIndex)[idx] = columnValue;
            }
            return this;
        }
    }

    public RowBuilder newRow() {
        Object[] row = new Object[columnNames.length];
        data.add(row);
        int idx = rowCount++;
        return new RowBuilder(idx);
    }

    public void addRow(Object[] columnValues) {
        if (columnValues.length > columnNames.length) {
            throw new IllegalArgumentException("columnNames.length = " + columnNames.length + ", columnValues.length = " + columnValues.length);
        }
        Object[] row = new Object[columnNames.length];
        System.arraycopy(columnValues, 0, row, 0, columnValues.length);
        data.add(row);
        rowCount++;
    }

    public void addRow(Iterable<?> columnValues) {
        List<Object> list = new ArrayList<>();
        for (Object o : columnValues) {
            list.add(o);
        }
        addRow(list.toArray());
    }

    @Override
    public int getCount() {
        return rowCount;
    }

    @Override
    public int getPosition() {
        return position;
    }

    @Override
    public boolean move(int offset) {
        return moveToPosition(position + offset);
    }

    @Override
    public boolean moveToPosition(int position) {
        if (position >= rowCount) {
            this.position = rowCount;
            return false;
        }
        if (position < 0) {
            this.position = -1;
            return false;
        }
        this.position = position;
        return true;
    }

    @Override
    public boolean moveToFirst() {
        return moveToPosition(0);
    }

    @Override
    public boolean moveToLast() {
        return moveToPosition(rowCount - 1);
    }

    @Override
    public boolean moveToNext() {
        return moveToPosition(position + 1);
    }

    @Override
    public boolean moveToPrevious() {
        return moveToPosition(position - 1);
    }

    @Override
    public boolean isFirst() {
        return position == 0 && rowCount != 0;
    }

    @Override
    public boolean isLast() {
        return position == rowCount - 1 && rowCount != 0;
    }

    @Override
    public boolean isBeforeFirst() {
        return rowCount == 0 || position == -1;
    }

    @Override
    public boolean isAfterLast() {
        return rowCount == 0 || position == rowCount;
    }

    @Override
    public int getColumnIndex(String columnName) {
        for (int i = 0; i < columnNames.length; i++) {
            if (columnNames[i].equalsIgnoreCase(columnName)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public int getColumnIndexOrThrow(String columnName) throws IllegalArgumentException {
        int index = getColumnIndex(columnName);
        if (index < 0) {
            throw new IllegalArgumentException("column '" + columnName + "' does not exist. Available: " + Arrays.toString(columnNames));
        }
        return index;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    @Override
    public String[] getColumnNames() {
        return columnNames.clone();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    private Object get(int columnIndex) {
        if (position < 0 || position >= rowCount) {
            throw new CursorIndexOutOfBoundsException("Requested index: " + position + ", total: " + rowCount);
        }
        if (columnIndex < 0 || columnIndex >= columnNames.length) {
            throw new CursorIndexOutOfBoundsException("Requested column: " + columnIndex + ", total: " + columnNames.length);
        }
        return data.get(position)[columnIndex];
    }

    @Override
    public byte[] getBlob(int columnIndex) {
        return (byte[]) get(columnIndex);
    }

    @Override
    public String getString(int columnIndex) {
        Object val = get(columnIndex);
        return val != null ? val.toString() : null;
    }

    @Override
    public void copyStringToBuffer(int columnIndex, CharArrayBuffer buffer) {
    }

    @Override
    public short getShort(int columnIndex) {
        Object val = get(columnIndex);
        if (val instanceof Number) return ((Number) val).shortValue();
        return val != null ? Short.parseShort(val.toString()) : 0;
    }

    @Override
    public int getInt(int columnIndex) {
        Object val = get(columnIndex);
        if (val instanceof Number) return ((Number) val).intValue();
        return val != null ? Integer.parseInt(val.toString()) : 0;
    }

    @Override
    public long getLong(int columnIndex) {
        Object val = get(columnIndex);
        if (val instanceof Number) return ((Number) val).longValue();
        return val != null ? Long.parseLong(val.toString()) : 0L;
    }

    @Override
    public float getFloat(int columnIndex) {
        Object val = get(columnIndex);
        if (val instanceof Number) return ((Number) val).floatValue();
        return val != null ? Float.parseFloat(val.toString()) : 0.0f;
    }

    @Override
    public double getDouble(int columnIndex) {
        Object val = get(columnIndex);
        if (val instanceof Number) return ((Number) val).doubleValue();
        return val != null ? Double.parseDouble(val.toString()) : 0.0;
    }

    @Override
    public int getType(int columnIndex) {
        Object val = get(columnIndex);
        if (val == null) return Cursor.FIELD_TYPE_NULL;
        if (val instanceof byte[]) return Cursor.FIELD_TYPE_BLOB;
        if (val instanceof Float || val instanceof Double) return Cursor.FIELD_TYPE_FLOAT;
        if (val instanceof Number) return Cursor.FIELD_TYPE_INTEGER;
        return Cursor.FIELD_TYPE_STRING;
    }

    @Override
    public boolean isNull(int columnIndex) {
        return get(columnIndex) == null;
    }

    @Override
    public void deactivate() {}

    @Override
    public boolean requery() {
        return true;
    }

    @Override
    public void close() {
        isClosed = true;
    }

    @Override
    public boolean isClosed() {
        return isClosed;
    }

    @Override
    public void registerContentObserver(ContentObserver observer) {}

    @Override
    public void unregisterContentObserver(ContentObserver observer) {}

    @Override
    public void registerDataSetObserver(DataSetObserver observer) {}

    @Override
    public void unregisterDataSetObserver(DataSetObserver observer) {}

    @Override
    public void setNotificationUri(android.content.ContentResolver cr, android.net.Uri uri) {}

    @Override
    public android.net.Uri getNotificationUri() {
        return null;
    }

    @Override
    public boolean getWantsAllOnMoveCalls() {
        return false;
    }

    @Override
    public void setExtras(android.os.Bundle extras) {}

    @Override
    public android.os.Bundle getExtras() {
        return android.os.Bundle.EMPTY;
    }

    @Override
    public android.os.Bundle respond(android.os.Bundle extras) {
        return android.os.Bundle.EMPTY;
    }
}
