package dev.luksandroid.ui.browser

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers [renameTargetExists], the guard `handleRename` in BrowserScreen.kt
 * consults before ever calling the native rename.
 *
 * The defect this guards against: the native rename implementations
 * (core/src/fs/btrfs/write/txn/rename.rs, core/src/fs/ext4/file.rs) use POSIX
 * semantics — renaming onto an existing name silently frees/unlinks that
 * destination file. Without this guard, a typo in the rename dialog
 * (renaming "draft.txt" to an existing "notes.txt") destroys "notes.txt" with
 * no warning and no undo.
 */
class RenameCollisionTest {

    @Test
    fun `refuses when target name already exists in the directory`() {
        val existing = listOf("draft.txt", "notes.txt", "photos")
        assertTrue(renameTargetExists(existing, currentName = "draft.txt", newName = "notes.txt"))
    }

    @Test
    fun `allows rename when target name is not taken`() {
        val existing = listOf("draft.txt", "notes.txt", "photos")
        assertFalse(renameTargetExists(existing, currentName = "draft.txt", newName = "final.txt"))
    }

    @Test
    fun `comparison is case-sensitive, matching ext4 btrfs semantics`() {
        // "Notes.txt" and "notes.txt" are distinct files on ext4/btrfs and
        // must be allowed to coexist -- this must NOT be reported as a
        // collision just because the names differ only by case.
        val existing = listOf("draft.txt", "notes.txt")
        assertFalse(renameTargetExists(existing, currentName = "draft.txt", newName = "Notes.txt"))
    }

    @Test
    fun `renaming an item to its own current name is not a collision`() {
        // The native core treats same-path rename as a no-op (rename.rs's
        // same-path check); this guard must be consistent with that, even
        // though the current name is also present in existingNames (it's the
        // item's own entry).
        val existing = listOf("draft.txt", "notes.txt")
        assertFalse(renameTargetExists(existing, currentName = "draft.txt", newName = "draft.txt"))
    }

    @Test
    fun `empty directory never collides`() {
        assertFalse(renameTargetExists(emptyList(), currentName = "draft.txt", newName = "notes.txt"))
    }
}
