//! Btrfs write support (Pass B: Bookkeeping tree parsing & allocator free-space map).
//!
//! All writer modules are placed in this directory and gated behind
//! `dangerous-write-support` so a default shipping build contains no write code.

pub mod alloc;
pub mod chunk_alloc;
pub mod commit;
pub mod cow;
pub mod exclude;
pub mod extent_tree;
pub mod file;
pub mod gate;
pub mod node;
pub mod txn;

pub use alloc::{BlockGroupFreeSpace, FreeRange, FreeSpaceMap};
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

    /// Create a new directory named `name` inside `parent_path`.
    /// Performs this in a transaction and returns the new directory's inode number.
    pub fn create_directory(&mut self, parent_path: &str, name: &str) -> Result<u64> {
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
            self.write_chunk(&mut writer, data)?;
        }
        self.finish_file(writer, parent_dir_path, filename)
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

    /// Allocate a new single DATA chunk, commit the transaction,
    /// and return the new logical start address.
    pub fn allocate_data_chunk(&mut self) -> Result<u64> {
        let (txn, new_chunk) = Transaction::allocate_data_chunk(self)?;
        self.chunks.insert(new_chunk.clone());
        let logical = new_chunk.logical;
        commit_transaction(self, txn)?;
        Ok(logical)
    }
}
