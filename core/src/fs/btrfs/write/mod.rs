//! Btrfs write support (Pass B: Bookkeeping tree parsing & allocator free-space map).
//!
//! All writer modules are placed in this directory and gated behind
//! `dangerous-write-support` so a default shipping build contains no write code.

pub mod alloc;
pub mod commit;
pub mod cow;
pub mod extent_tree;
pub mod file;
pub mod gate;
pub mod node;
pub mod txn;

pub use alloc::{BlockGroupFreeSpace, FreeRange, FreeSpaceMap};
pub use commit::commit_transaction;
pub use cow::cow_tree_mutate;
pub use extent_tree::{
    AllocatedExtent, BlockGroupItem, ExtentItem, ExtentTree, InlineBackref, MetadataItem,
};
pub use node::{InteriorEntry, InteriorNode, Leaf, LeafItem};
pub use txn::Transaction;

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::FS_TREE_OBJECTID;
use crate::fs::btrfs::Btrfs;

impl<D: WriteAt> Btrfs<D> {
    /// Update the modification timestamp (`mtime`) of the file at `path`.
    pub fn set_mtime(&mut self, path: &str, mtime_sec: u64, mtime_nsec: u32) -> Result<()> {
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
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::create_empty_file(self, parent_dir_path, filename, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Write `data` into the regular file at `path`.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::write_file_data(self, path, data, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }

    /// Create a regular file named `filename` in `parent_dir_path` containing `data`.
    /// Performs this in a single atomic transaction and returns the new inode number.
    pub fn create_file_with_data(
        &mut self,
        parent_dir_path: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<u64> {
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let (txn, new_ino) = Transaction::create_file_with_data(self, parent_dir_path, filename, data, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(new_ino)
    }

    /// Delete the regular file at `path`.
    pub fn delete_file(&mut self, path: &str) -> Result<()> {
        let (now_sec, now_nsec) = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        };
        let txn = Transaction::delete_file(self, path, now_sec, now_nsec)?;
        commit_transaction(self, txn)?;
        Ok(())
    }
}
