//! `Transaction::update_inode_mtime`.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{Key, FS_TREE_OBJECTID, INODE_ITEM_KEY};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::cow_tree_mutate;
use crate::fs::btrfs::write::extent_tree::{converge_and_finalize, record_cow_result, ExtentTree};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::Btrfs;

use super::Transaction;

impl Transaction {
    /// Prepare a transaction that updates the `mtime` and `ctime` of an existing file inode.
    pub fn update_inode_mtime<D: ReadAt>(
        fs: &Btrfs<D>,
        inode_number: u64,
        mtime_sec: u64,
        mtime_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::<(u64, u8, u64)>::new(); // (bytenr, level, owner)
        let mut blocks_to_remove = Vec::<(u64, u8)>::new(); // (bytenr, level)

        // 1. CoW the FS tree to modify the target INODE_ITEM.
        let inode_key = Key::new(inode_number, INODE_ITEM_KEY, 0);
        let fs_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs.fs_tree().bytenr,
            fs.fs_tree().level,
            FS_TREE_OBJECTID,
            &inode_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&inode_key)
                    .ok_or_else(|| LuksError::NotFound("inode not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 160 {
                    return Err(LuksError::CorruptFs("inode item truncated"));
                }
                // transid (last modified generation)
                data[8..16].copy_from_slice(&new_generation.to_le_bytes());
                // sequence
                let seq = u64::from_le_bytes(data[72..80].try_into().unwrap()).wrapping_add(1);
                data[72..80].copy_from_slice(&seq.to_le_bytes());
                // ctime
                data[124..132].copy_from_slice(&mtime_sec.to_le_bytes());
                data[132..136].copy_from_slice(&mtime_nsec.to_le_bytes());
                // mtime
                data[136..144].copy_from_slice(&mtime_sec.to_le_bytes());
                data[144..148].copy_from_slice(&mtime_nsec.to_le_bytes());
                Ok(())
            },
        )?;

        record_cow_result(
            &fs_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_res.new_root_bytenr;
        new_fs_tree.level = fs_res.new_root_level;
        new_fs_tree.generation = new_generation;

        converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            None,
            None,
            None,
            None,
            pending_blocks,
            Vec::new(),
            allocator,
            blocks_to_add,
            blocks_to_remove,
            Vec::new(),
            Vec::new(),
        )
    }
}
