//! Btrfs write support (Pass B: Bookkeeping tree parsing & allocator free-space map).
//!
//! All writer modules are placed in this directory and gated behind
//! `dangerous-write-support` so a default shipping build contains no write code.

pub mod alloc;
pub mod batch;
pub mod chunk_alloc;
pub mod commit;
pub mod cow;
pub mod exclude;
pub mod extent_tree;
pub mod file;
pub mod gate;
pub mod interval_set;
pub mod node;
pub mod txn;

pub use alloc::{BlockGroupFreeSpace, FreeRange, FreeSpaceMap};
pub use batch::Batch;
pub use chunk_alloc::{
    allocate_data_chunk_transaction, decide_data_chunk_size, find_free_dev_extent, next_logical,
    read_dev_extents,
};
pub use commit::commit_transaction;
pub use cow::cow_tree_mutate;
pub use exclude::compute_sb_exclusions;
pub use extent_tree::{
    AllocatedExtent, BlockGroupItem, ExtentItem, ExtentTree, InlineBackref, MetadataItem,
};
pub use interval_set::IntervalSet;
pub use node::{InteriorEntry, InteriorNode, Leaf, LeafItem};
pub use txn::Transaction;

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::FS_TREE_OBJECTID;
use crate::fs::btrfs::Btrfs;

/// How deep `delete_file`'s directory recursion may descend before refusing.
/// See `delete_file_at_depth`.
const MAX_DELETE_DEPTH: usize = 1024;

impl<D: WriteAt> Btrfs<D> {
    /// Commit any active batch session before performing non-batch operations.
    pub fn commit_active_batch(&mut self) -> Result<()> {
        if self.has_open_writer {
            return Err(LuksError::CorruptFs(
                "attempted to commit active batch while a file writer is open",
            ));
        }
        if let Some(batch) = self.active_batch.take() {
            if batch.has_uncommitted_files() {
                let txn = batch.commit(self)?;
                commit_transaction(self, txn)?;
            }
        }
        Ok(())
    }

    /// Drop any active batch **without** committing it, returning whether one
    /// was discarded.
    ///
    /// For use when the drive's state is no longer trustworthy. A batch holds
    /// allocator bookkeeping — `block_group.used` bumps, `handed_out` ranges —
    /// that only becomes true on disk if its commit succeeds. After a
    /// transport failure that commit cannot be trusted to have landed, so
    /// carrying the batch forward lets a later, unrelated commit publish
    /// counters describing writes that never happened. That is the 2026-09-01
    /// field corruption's shape.
    ///
    /// Discarding loses the batch's uncommitted files. That is the intended
    /// trade: those files' data blocks are unreferenced bytes, which btrfs
    /// treats as free space, whereas a mismatched `used` counter is a
    /// filesystem `btrfs check` rejects.
    pub fn discard_active_batch(&mut self) -> bool {
        self.has_open_writer = false;
        self.active_batch.take().is_some()
    }

    /// Access the active batch session if one is currently open.
    pub fn active_batch(&self) -> Option<&Batch> {
        self.active_batch.as_ref()
    }

    /// Update the modification timestamp (`mtime`) of the file at `path`.
    pub fn set_mtime(&mut self, path: &str, mtime_sec: u64, mtime_nsec: u32) -> Result<()> {
        self.commit_active_batch()?;
        let located = self.resolve_no_follow(self.fs_tree(), path)?;
        if located.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "btrfs subvolume write not yet supported".into(),
            ));
        }
        let txn = Transaction::update_inode_mtime(
            self,
            located.inode.objectid,
            mtime_sec,
            mtime_nsec,
        )?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Create an empty regular file named `filename` in the directory at `parent_dir_path`.
    pub fn create_file(&mut self, parent_dir_path: &str, filename: &str) -> Result<()> {
        self.commit_active_batch()?;
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::create_empty_file(self, parent_dir_path, filename, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Create a new directory named `name` inside `parent_path`.
    /// Performs this in a transaction and returns the new directory's inode number.
    pub fn create_directory(&mut self, parent_path: &str, name: &str) -> Result<u64> {
        self.commit_active_batch()?;
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let (txn, new_ino) = Transaction::create_directory(self, parent_path, name, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(new_ino)
    }

    /// Create a new directory named `name` inside `parent_ino`.
    /// Performs this in a transaction and returns the new directory's inode number.
    pub fn create_directory_in_dir(&mut self, parent_ino: u64, name: &str) -> Result<u64> {
        self.commit_active_batch()?;
        let located_parent = self.read_inode(self.fs_tree().bytenr, parent_ino)?;
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let (txn, new_ino) = Transaction::create_directory_in_dir(
            self,
            parent_ino,
            located_parent.uid,
            located_parent.gid,
            name,
            now_sec,
            now_nsec,
        )?;
        commit_transaction(self, txn)?;
        Ok(new_ino)
    }

    /// Rename or move an entry from `old_parent/old_name` to `new_parent/new_name`.
    pub fn rename(
        &mut self,
        old_parent: &str,
        old_name: &str,
        new_parent: &str,
        new_name: &str,
    ) -> Result<()> {
        self.commit_active_batch()?;
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::rename(self, old_parent, old_name, new_parent, new_name, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Write `data` into the regular file at `path`.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.commit_active_batch()?;
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = match Transaction::write_file_data(self, path, data, now_sec, now_nsec) {
            Ok(txn) => txn,
            Err(LuksError::FilesystemFull) => {
                self.allocate_data_chunk()?;
                Transaction::write_file_data(self, path, data, now_sec, now_nsec)?
            }
            Err(e) => return Err(e),
        };
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Create a regular file named `filename` in `parent_dir_path` containing `data`.
    /// Performs this in a transaction and returns the new inode number.
    pub fn create_file_with_data(
        &mut self,
        parent_dir_path: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<u64> {
        let mut writer = self.begin_file(data.len() as u64)?;
        if !data.is_empty() {
            if let Err(e) = self.write_chunk(&mut writer, data) {
                let _ = self.abandon_file(writer);
                return Err(e);
            }
        }
        let ino = self.finish_file(writer, parent_dir_path, filename)?;
        self.commit_active_batch()?;
        Ok(ino)
    }

    /// Delete the file or directory at `path`. A directory is emptied first,
    /// depth-first, one committed transaction per child — the same shape as
    /// deleting each child by hand, so a mid-tree failure (an unsupported
    /// child type, a symlink, a subvolume boundary) leaves exactly what it
    /// would if a caller had stopped there themselves, rather than a
    /// half-applied larger operation.
    pub fn delete_file(&mut self, path: &str) -> Result<()> {
        self.commit_active_batch()?;
        // `.` and `..` are never real stored entries on btrfs (see
        // `list_dir_by_inode`'s doc comment), but `resolve_no_follow` silently
        // drops `.` components while this function's own root check only
        // trims `/`. Left unchecked, a path like "/foo/." resolves to "/foo"
        // itself rather than erroring, so this function would recurse into
        // and delete every child of "/foo" before the low-level transaction
        // finally failed trying to remove an entry literally named ".",
        // reporting failure after having already deleted everything inside.
        // "/." reaches the same way for the whole volume. Refused outright
        // before any resolution happens, rather than trusting a raw string
        // split to agree with what `resolve_no_follow` considers "root" or
        // "this directory".
        if path.split('/').any(|c| c == "." || c == "..") {
            return Err(LuksError::UnsupportedFsFeature(
                "delete path containing '.' or '..' components".into(),
            ));
        }
        self.delete_file_at_depth(path, 0)
    }

    fn delete_file_at_depth(&mut self, path: &str, depth: usize) -> Result<()> {
        // A real directory tree is nowhere near this deep; the bound exists
        // only to turn a cycle in corrupt on-disk data (a child entry whose
        // location aliases one of its own ancestors) into a clean error
        // instead of an unbounded recursion that aborts the process.
        if depth > MAX_DELETE_DEPTH {
            return Err(LuksError::CorruptFs(
                "directory delete recursed past a sane depth — likely a cycle",
            ));
        }

        // Checked here too, not just by `Transaction::delete_file` below: that
        // guard only runs after this function would already have recursed
        // into every top-level child and deleted the whole volume out from
        // under it.
        if path.trim_matches('/').is_empty() {
            return Err(LuksError::IsADirectory("/".into()));
        }

        let located = self.resolve_no_follow(self.fs_tree(), path)?;
        if located.inode.file_type().is_dir() && located.tree.objectid == FS_TREE_OBJECTID {
            let children = self.list_dir_by_inode(located.tree.bytenr, located.inode.objectid)?;
            let base = path.trim_end_matches('/');
            for child in children {
                let child_path = if base.is_empty() {
                    format!("/{}", child.name)
                } else {
                    format!("{base}/{}", child.name)
                };
                self.delete_file_at_depth(&child_path, depth + 1)?;
            }
        }

        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::delete_file(self, path, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Allocate a new single DATA chunk, commit the transaction,
    /// and return the new logical start address.
    pub fn allocate_data_chunk(&mut self) -> Result<u64> {
        self.allocate_data_chunk_excluding(&[])
    }

    /// Same as [`Btrfs::allocate_data_chunk`], but excludes `reserved`
    /// logical ranges (a writer's already-decided-but-uncommitted data
    /// runs) from the allocator used for this chunk's own metadata CoW, so
    /// the new metadata blocks cannot land inside them.
    pub(crate) fn allocate_data_chunk_excluding(&mut self, reserved: &[(u64, u64)]) -> Result<u64> {
        if self.active_batch.is_some() {
            self.commit_active_batch()?;
        }
        let (txn, new_chunk) = Transaction::allocate_data_chunk_excluding(self, reserved)?;
        self.chunks.insert(new_chunk.clone());
        let logical = new_chunk.logical;
        commit_transaction(self, txn)?;
        Ok(logical)
    }
}
