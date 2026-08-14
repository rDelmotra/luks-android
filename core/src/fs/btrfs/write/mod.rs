//! Btrfs write support (Pass B: Bookkeeping tree parsing & allocator free-space map).
//!
//! All writer modules are placed in this directory and gated behind
//! `dangerous-write-support` so a default shipping build contains no write code.

pub mod alloc;
pub mod extent_tree;

pub use alloc::{BlockGroupFreeSpace, FreeRange, FreeSpaceMap};
pub use extent_tree::{
    AllocatedExtent, BlockGroupItem, ExtentItem, ExtentTree, InlineBackref, MetadataItem,
};
