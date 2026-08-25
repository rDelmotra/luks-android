//! Btrfs transaction coordination and fixed-point convergence loop.
//!
//! A transaction computes all CoW path copies and extent tree bookkeeping
//! completely in memory until no further metadata blocks need allocation.
//!
//! Each `Transaction::*` constructor lives in its own submodule (split out of
//! a single 3,200+ line file for reviewability):
//! - `mtime`: `update_inode_mtime`
//! - `create`: `create_empty_file`, `create_directory`, `create_directory_in_dir`
//! - `rename`: `rename` (927 lines on its own; further split into private
//!   helpers within that module)
//! - `data`: `write_file_data`, `create_file_with_data`
//! - `delete`: `delete_file`
//! - `chunk`: `allocate_data_chunk` (thin driver over `chunk_alloc`)
//!
//! The extent-tree reconciliation free functions previously colocated here
//! (`record_cow_result`, `find_item_in_tree`, `find_max_inode`,
//! `converge_and_finalize`) now live in `super::extent_tree`, which already
//! owns the `ExtentTree`/`BlockGroupItem` types they mutate. They are
//! re-exported below so existing `write::txn::{...}` import paths keep
//! resolving unchanged.

mod chunk;
mod create;
mod data;
mod delete;
mod mtime;
mod rename;

use std::collections::HashMap;

use crate::fs::btrfs::TreeRoot;

#[allow(unused_imports)]
pub(crate) use crate::fs::btrfs::write::extent_tree::{
    converge_and_finalize, find_max_inode, record_cow_result,
};

/// A completed, self-consistent in-memory btrfs transaction.
#[derive(Clone)]
pub struct Transaction {
    pub new_generation: u64,
    pub final_root_bytenr: u64,
    pub final_root_level: u8,
    pub final_chunk_root: Option<(u64, u8)>,
    pub final_bytes_used: u64,
    pub new_fs_tree: TreeRoot,
    pub pending_blocks: HashMap<u64, Vec<u8>>,
    pub pending_data: Vec<(u64, Vec<u8>)>,
    pub final_allocator: Option<crate::fs::btrfs::write::alloc::FreeSpaceMap>,
}
