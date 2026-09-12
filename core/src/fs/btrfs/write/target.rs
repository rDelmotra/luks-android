//! Target filesystem tree identification and encapsulation.
//!
//! A btrfs subvolume is a distinct filesystem B-tree with its own independent
//! inode numbering and backreference ownership. `TargetTree` encapsulates the
//! target tree being modified by a transaction or batch, preventing accidental
//! confusion between tree objectids, inode numbers, and root addresses.

use crate::fs::btrfs::tree::FS_TREE_OBJECTID;
use crate::fs::btrfs::TreeRoot;

/// The filesystem tree a transaction or batch targets.
///
/// Not interchangeable with a bare tree id, an inode number, or `FS_TREE_OBJECTID`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TargetTree {
    pub objectid: u64,
    pub root: TreeRoot,
}

impl TargetTree {
    /// Create a `TargetTree` targeting the specified resolved `TreeRoot`.
    pub fn new(root: TreeRoot) -> Self {
        Self {
            objectid: root.objectid,
            root,
        }
    }

    /// Explicitly target the primary `FS_TREE` (objectid 5).
    pub fn from_fs_tree(root: TreeRoot) -> Self {
        Self {
            objectid: FS_TREE_OBJECTID,
            root,
        }
    }

    /// Whether this target tree is the primary top-level `FS_TREE` (objectid 5).
    pub fn is_fs_tree(&self) -> bool {
        self.objectid == FS_TREE_OBJECTID
    }

    /// Logical bytenr of the root node of this tree.
    pub fn bytenr(&self) -> u64 {
        self.root.bytenr
    }

    /// Current height level of the root node of this tree.
    pub fn level(&self) -> u8 {
        self.root.level
    }

    /// Generation of the root node of this tree.
    pub fn generation(&self) -> u64 {
        self.root.generation
    }

    /// Root directory inode number (always 256 for btrfs fs trees).
    pub fn root_dirid(&self) -> u64 {
        self.root.root_dirid
    }

    /// Whether this tree / subvolume is marked read-only.
    pub fn is_read_only(&self) -> bool {
        self.root.is_read_only()
    }

    /// Update the root location and generation after a CoW tree descent.
    pub fn update_root(&mut self, bytenr: u64, level: u8, generation: u64) {
        self.root.bytenr = bytenr;
        self.root.level = level;
        self.root.generation = generation;
    }
}
