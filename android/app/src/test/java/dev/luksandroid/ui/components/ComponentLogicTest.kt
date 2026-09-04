package dev.luksandroid.ui.components

import dev.luksandroid.SubvolumeInfo
import dev.luksandroid.formatTimestamp
import dev.luksandroid.ui.browser.isPathInsideReadOnlySubvolume
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ComponentLogicTest {

    @Test
    fun `test breadcrumbs parsing at root`() {
        val crumbs = parseBreadcrumbs("/")
        assertEquals(1, crumbs.size)
        assertEquals("/", crumbs[0].name)
        assertEquals("/", crumbs[0].path)
        assertTrue(crumbs[0].isLast)
    }

    @Test
    fun `test breadcrumbs parsing nested path`() {
        val crumbs = parseBreadcrumbs("/media/photos/vacation")
        assertEquals(4, crumbs.size)
        assertEquals("/", crumbs[0].name)
        assertEquals("/", crumbs[0].path)
        assertFalse(crumbs[0].isLast)

        assertEquals("media", crumbs[1].name)
        assertEquals("/media", crumbs[1].path)
        assertFalse(crumbs[1].isLast)

        assertEquals("photos", crumbs[2].name)
        assertEquals("/media/photos", crumbs[2].path)
        assertFalse(crumbs[2].isLast)

        assertEquals("vacation", crumbs[3].name)
        assertEquals("/media/photos/vacation", crumbs[3].path)
        assertTrue(crumbs[3].isLast)
    }

    @Test
    fun `test parentOfPath navigation`() {
        assertEquals("/", parentOfPath("/"))
        assertEquals("/", parentOfPath("/media"))
        assertEquals("/media", parentOfPath("/media/photos"))
        assertEquals("/media/photos", parentOfPath("/media/photos/vacation/"))
    }

    @Test
    fun `test validate folder name`() {
        assertNull(validateFolderName("valid_folder"))
        assertNull(validateFolderName("Documents 2026"))
        assertNotNull(validateFolderName(""))
        assertNotNull(validateFolderName("   "))
        assertNotNull(validateFolderName("."))
        assertNotNull(validateFolderName(".."))
        assertNotNull(validateFolderName("folder/sub"))
        assertNotNull(validateFolderName("folder\\sub"))
        assertNotNull(validateFolderName("null\u0000char"))
        assertNotNull(validateFolderName("a".repeat(256)))
    }

    @Test
    fun `test validate new name for rename`() {
        assertNull(validateNewName("new_name.txt", "old_name.txt"))
        assertNotNull(validateNewName("old_name.txt", "old_name.txt"))
        assertNotNull(validateNewName("", "old_name.txt"))
        assertNotNull(validateNewName(".", "old_name.txt"))
        assertNotNull(validateNewName("..", "old_name.txt"))
        assertNotNull(validateNewName("name/with/slash", "old_name.txt"))
    }

    @Test
    fun `test subvolume read-only detection on btrfs`() {
        val subvols = listOf(
            SubvolumeInfo(id = 5L, name = "root", path = "/", readOnly = false),
            SubvolumeInfo(id = 256L, name = "@home", path = "/home", readOnly = false),
            SubvolumeInfo(id = 257L, name = "@snapshots", path = "/snapshots", readOnly = true),
        )

        // Root path is not read-only subvolume
        val (roRoot, _) = isPathInsideReadOnlySubvolume("/", "btrfs", subvols)
        assertFalse(roRoot)

        // Path inside @home (id 256 != 5) is outside root tree
        val (roHome, reasonHome) = isPathInsideReadOnlySubvolume("/home/user", "btrfs", subvols)
        assertTrue(roHome)
        assertNotNull(reasonHome)

        // Path inside @snapshots is read-only
        val (roSnap, reasonSnap) = isPathInsideReadOnlySubvolume("/snapshots/backup1", "btrfs", subvols)
        assertTrue(roSnap)
        assertNotNull(reasonSnap)

        // On ext4, subvolumes are ignored
        val (roExt4, _) = isPathInsideReadOnlySubvolume("/home", "ext4", subvols)
        assertFalse(roExt4)
    }

    @Test
    fun `test format timestamp`() {
        assertEquals("", formatTimestamp(0L))
        assertEquals("", formatTimestamp(-1L))
        val formatted = formatTimestamp(1700000000L)
        assertTrue(formatted.isNotEmpty())
        assertTrue(formatted.contains("-"))
    }
}
