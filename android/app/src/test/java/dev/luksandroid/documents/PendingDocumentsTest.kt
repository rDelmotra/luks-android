package dev.luksandroid.documents

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingDocumentsTest {

    // PendingDocuments is a process-wide singleton object -- every test clears it on the
    // way out so state never leaks into an unrelated test class.
    @After
    fun tearDown() {
        PendingDocuments.clear()
    }

    @Test
    fun register_returnsPathScopedId_andIsPending() {
        val docId = PendingDocuments.register("/", "notes.txt")
        assertEquals("/notes.txt", docId)
        assertTrue(PendingDocuments.isPending(docId))

        val nested = PendingDocuments.register("/Documents", "draft.md")
        assertEquals("/Documents/draft.md", nested)
        assertTrue(PendingDocuments.isPending(nested))
    }

    @Test
    fun get_returnsParentPathAndName() {
        val docId = PendingDocuments.register("/Documents", "draft.md")
        val pending = PendingDocuments.get(docId)
        assertEquals("/Documents", pending?.parentPath)
        assertEquals("draft.md", pending?.name)
    }

    @Test
    fun get_returnsNullForUnknownOrUnregisteredId() {
        assertNull(PendingDocuments.get("/never_registered.txt"))
        assertFalse(PendingDocuments.isPending("/never_registered.txt"))
    }

    @Test
    fun remove_dropsTheEntryAndReturnsIt() {
        val docId = PendingDocuments.register("/", "temp.bin")
        val removed = PendingDocuments.remove(docId)
        assertEquals("/", removed?.parentPath)
        assertEquals("temp.bin", removed?.name)
        assertFalse(PendingDocuments.isPending(docId))
        assertNull(PendingDocuments.get(docId))
    }

    @Test
    fun remove_ofUnknownIdIsANoOpReturningNull() {
        assertNull(PendingDocuments.remove("/nothing_here.txt"))
    }

    @Test
    fun clear_dropsEveryEntry() {
        val a = PendingDocuments.register("/", "a.txt")
        val b = PendingDocuments.register("/dir", "b.txt")

        PendingDocuments.clear()

        assertFalse(PendingDocuments.isPending(a))
        assertFalse(PendingDocuments.isPending(b))
    }
}
