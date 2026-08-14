//! Btrfs transaction coordination and fixed-point convergence loop.
//!
//! A transaction computes all CoW path copies and extent tree bookkeeping
//! completely in memory until no further metadata blocks need allocation.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::superblock::BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE;
use crate::fs::btrfs::tree::{
    Key, EXTENT_TREE_OBJECTID, FREE_SPACE_TREE_OBJECTID, FS_TREE_OBJECTID, INODE_ITEM_KEY,
    METADATA_ITEM_KEY, ROOT_ITEM_KEY, ROOT_TREE_OBJECTID,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::cow_tree_mutate;
use crate::fs::btrfs::write::extent_tree::{ExtentTree, MetadataItem};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::node::Leaf;
use crate::fs::btrfs::{Btrfs, TreeRoot};

/// A completed, self-consistent in-memory btrfs transaction.
pub struct Transaction {
    pub new_generation: u64,
    pub final_root_bytenr: u64,
    pub final_root_level: u8,
    pub new_fs_tree: TreeRoot,
    pub pending_blocks: HashMap<u64, Vec<u8>>,
}

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
        let mut allocator = FreeSpaceMap::from_extent_tree(&extent_tree)?;
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

        for &(b, lvl) in &fs_res.allocated {
            blocks_to_add.push((b, lvl, FS_TREE_OBJECTID));
        }
        for &(b, lvl) in &fs_res.freed {
            blocks_to_remove.push((b, lvl));
            allocator.free_metadata(b, sb.node_size)?;
        }
        for (b, data) in fs_res.emitted_blocks {
            pending_blocks.insert(b, data);
        }

        let fs_root_bytenr = fs_res.new_root_bytenr;
        let fs_root_level = fs_res.new_root_level;

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        let mut root_tree_bytenr = sb.root;
        let mut root_tree_level = sb.root_level;
        let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
        let mut extent_root_bytenr = extent_root.bytenr;
        let mut extent_root_level = extent_root.level;

        // 2. Update FS_TREE root item in ROOT_TREE.
        let fs_root_key = Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &fs_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&fs_root_key)
                    .ok_or_else(|| LuksError::NotFound("fs root item not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&fs_root_bytenr.to_le_bytes());
                data[238] = fs_root_level;
                Ok(())
            },
        )?;

        for &(b, lvl) in &root_res.allocated {
            blocks_to_add.push((b, lvl, ROOT_TREE_OBJECTID));
        }
        for &(b, lvl) in &root_res.freed {
            blocks_to_remove.push((b, lvl));
            allocator.free_metadata(b, sb.node_size)?;
        }
        for (b, data) in root_res.emitted_blocks {
            pending_blocks.insert(b, data);
        }
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;

        let mut fst_bytenr_opt: Option<u64> = None;

        // 3. Fixed-point loop to record allocations and update root pointers until convergence.
        for _iteration in 0..10 {
            if blocks_to_add.is_empty() && blocks_to_remove.is_empty() {
                // Convergence achieved
                break;
            }

            let to_remove = std::mem::take(&mut blocks_to_remove);
            for (old_b, old_lvl) in to_remove {
                let del_key = Key::new(old_b, METADATA_ITEM_KEY, old_lvl as u64);
                let ext_res = cow_tree_mutate(
                    fs,
                    &pending_blocks,
                    extent_root_bytenr,
                    extent_root_level,
                    EXTENT_TREE_OBJECTID,
                    &del_key,
                    new_generation,
                    &mut allocator,
                    |leaf| {
                        let _ = leaf.delete_item(&del_key)?;
                        Ok(())
                    },
                )?;

                for &(b, lvl) in &ext_res.allocated {
                    blocks_to_add.push((b, lvl, EXTENT_TREE_OBJECTID));
                }
                for &(b, lvl) in &ext_res.freed {
                    blocks_to_remove.push((b, lvl));
                    allocator.free_metadata(b, sb.node_size)?;
                }
                for (b, data) in ext_res.emitted_blocks {
                    pending_blocks.insert(b, data);
                }
                extent_root_bytenr = ext_res.new_root_bytenr;
                extent_root_level = ext_res.new_root_level;
            }

            let to_add = std::mem::take(&mut blocks_to_add);
            for (alloc_bytenr, alloc_level, alloc_owner) in to_add {
                let (meta_key, meta_data) = MetadataItem::emit_tree_block(
                    alloc_bytenr,
                    alloc_level,
                    new_generation,
                    alloc_owner,
                );
                let ext_res = cow_tree_mutate(
                    fs,
                    &pending_blocks,
                    extent_root_bytenr,
                    extent_root_level,
                    EXTENT_TREE_OBJECTID,
                    &meta_key,
                    new_generation,
                    &mut allocator,
                    |leaf| leaf.insert_item(meta_key, meta_data, sb.node_size),
                )?;

                for &(b, lvl) in &ext_res.allocated {
                    blocks_to_add.push((b, lvl, EXTENT_TREE_OBJECTID));
                }
                for &(b, lvl) in &ext_res.freed {
                    blocks_to_remove.push((b, lvl));
                    allocator.free_metadata(b, sb.node_size)?;
                }
                for (b, data) in ext_res.emitted_blocks {
                    pending_blocks.insert(b, data);
                }
                extent_root_bytenr = ext_res.new_root_bytenr;
                extent_root_level = ext_res.new_root_level;
            }

            // Update Free Space Tree if present on this filesystem
            if sb.compat_ro_flags & BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE != 0 {
                if let Ok(fst_root) = fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
                    let fst_target = match fst_bytenr_opt {
                        Some(b) => b,
                        None => {
                            let b = allocator.allocate_metadata(sb.node_size)?;
                            blocks_to_add.push((b, 0, FREE_SPACE_TREE_OBJECTID));
                            blocks_to_remove.push((fst_root.bytenr, 0));
                            allocator.free_metadata(fst_root.bytenr, sb.node_size)?;
                            fst_bytenr_opt = Some(b);
                            b
                        }
                    };

                    let old_fst_node = crate::fs::btrfs::write::cow::read_node(fs, &pending_blocks, fst_root.bytenr)?;
                    let chunk_tree_uuid = old_fst_node.chunk_tree_uuid();
                    let flags = old_fst_node.flags();

                    let fst_leaf = Leaf {
                        bytenr: fst_target,
                        flags,
                        metadata_uuid: sb.metadata_uuid,
                        chunk_tree_uuid,
                        generation: new_generation,
                        owner: FREE_SPACE_TREE_OBJECTID,
                        csum_type: sb.csum_type,
                        items: allocator.emit_free_space_tree_items(),
                    };
                    let fst_raw = fst_leaf.emit(sb.node_size)?;
                    pending_blocks.insert(fst_target, fst_raw);

                    // Update ROOT_ITEM for FREE_SPACE_TREE in ROOT_TREE
                    let fst_root_key = Key::new(FREE_SPACE_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
                    let root_res = cow_tree_mutate(
                        fs,
                        &pending_blocks,
                        root_tree_bytenr,
                        root_tree_level,
                        ROOT_TREE_OBJECTID,
                        &fst_root_key,
                        new_generation,
                        &mut allocator,
                        |leaf| {
                            let idx = leaf.find_item(&fst_root_key).ok_or_else(|| {
                                LuksError::NotFound("fst root item not found".into())
                            })?;
                            let data = &mut leaf.items[idx].data;
                            if data.len() < 239 {
                                return Err(LuksError::CorruptFs("root item truncated"));
                            }
                            data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                            data[176..184].copy_from_slice(&fst_target.to_le_bytes());
                            data[238] = 0; // level 0
                            Ok(())
                        },
                    )?;

                    for &(b, lvl) in &root_res.allocated {
                        blocks_to_add.push((b, lvl, ROOT_TREE_OBJECTID));
                    }
                    for &(b, lvl) in &root_res.freed {
                        blocks_to_remove.push((b, lvl));
                        allocator.free_metadata(b, sb.node_size)?;
                    }
                    for (b, data) in root_res.emitted_blocks {
                        pending_blocks.insert(b, data);
                    }
                    root_tree_bytenr = root_res.new_root_bytenr;
                    root_tree_level = root_res.new_root_level;
                }
            }

            // Update EXTENT_TREE root item in ROOT_TREE.
            let ext_root_key = Key::new(EXTENT_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
            let root_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                root_tree_bytenr,
                root_tree_level,
                ROOT_TREE_OBJECTID,
                &ext_root_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&ext_root_key)
                        .ok_or_else(|| LuksError::NotFound("extent root item not found".into()))?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 239 {
                        return Err(LuksError::CorruptFs("extent root item truncated"));
                    }
                    data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                    data[176..184].copy_from_slice(&extent_root_bytenr.to_le_bytes());
                    data[238] = extent_root_level;
                    Ok(())
                },
            )?;

            for &(b, lvl) in &root_res.allocated {
                blocks_to_add.push((b, lvl, ROOT_TREE_OBJECTID));
            }
            for &(b, lvl) in &root_res.freed {
                blocks_to_remove.push((b, lvl));
                allocator.free_metadata(b, sb.node_size)?;
            }
            for (b, data) in root_res.emitted_blocks {
                pending_blocks.insert(b, data);
            }
            root_tree_bytenr = root_res.new_root_bytenr;
            root_tree_level = root_res.new_root_level;
        }

        Ok(Transaction {
            new_generation,
            final_root_bytenr: root_tree_bytenr,
            final_root_level: root_tree_level,
            new_fs_tree,
            pending_blocks,
        })
    }
}
