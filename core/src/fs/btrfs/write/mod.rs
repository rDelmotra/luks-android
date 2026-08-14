//! Btrfs write support (Pass B: Bookkeeping tree parsing & allocator free-space map).
//!
//! All writer modules are placed in this directory and gated behind
//! `dangerous-write-support` so a default shipping build contains no write code.

pub mod alloc;
pub mod commit;
pub mod cow;
pub mod extent_tree;
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
}
