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
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate, CowResult};
use crate::fs::btrfs::write::extent_tree::{ExtentTree, MetadataItem};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::node::Leaf;
use crate::fs::btrfs::{Btrfs, TreeRoot};

/// A completed, self-consistent in-memory btrfs transaction.
pub struct Transaction {
    pub new_generation: u64,
    pub final_root_bytenr: u64,
    pub final_root_level: u8,
    pub final_bytes_used: u64,
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
            pending_blocks,
            allocator,
            blocks_to_add,
            blocks_to_remove,
        )
    }

    /// Prepare a transaction that creates a new empty regular file inside `parent_path`.
    pub fn create_empty_file<D: ReadAt>(
        fs: &Btrfs<D>,
        parent_path: &str,
        filename: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        let located_parent = fs.resolve_no_follow(fs.fs_tree(), parent_path)?;
        if !located_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(parent_path.to_string()));
        }
        if located_parent.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume file creation not yet supported".into(),
            ));
        }

        let parent_ino = located_parent.inode.objectid;

        // Check if file already exists in parent directory
        let name_hash = crate::fs::btrfs::crc32c::name_hash(filename.as_bytes());
        let dir_item_key = Key::new(parent_ino, crate::fs::btrfs::tree::DIR_ITEM_KEY, name_hash);
        if let Some(data) = fs.find_item(fs.fs_tree().bytenr, &dir_item_key)? {
            let entries = crate::fs::btrfs::inode::parse_dir_entries(&data)?;
            if entries.iter().any(|e| e.name == filename.as_bytes()) {
                return Err(LuksError::AlreadyExists(format!(
                    "file '{}' already exists in '{}'",
                    filename, parent_path
                )));
            }
        }

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree(&extent_tree)?;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::<(u64, u8, u64)>::new();
        let mut blocks_to_remove = Vec::<(u64, u8)>::new();

        // Find highest existing inode objectid and next directory index
        let max_ino = find_max_inode(fs)?;
        let new_ino = if max_ino < 256 { 256 } else { max_ino + 1 };

        let mut max_dir_index = 1u64;
        fs.for_each_item(
            fs.fs_tree().bytenr,
            parent_ino,
            crate::fs::btrfs::tree::DIR_INDEX_KEY,
            &mut |key, _| {
                if key.offset > max_dir_index {
                    max_dir_index = key.offset;
                }
                Ok(true)
            },
        )?;
        let dir_index = max_dir_index + 1;

        let mut fs_root_bytenr = fs.fs_tree().bytenr;
        let mut fs_root_level = fs.fs_tree().level;

        // 1. Update parent directory INODE_ITEM (size += name_len * 2, sequence += 1, transid, mtime/ctime)
        let parent_inode_key = Key::new(parent_ino, INODE_ITEM_KEY, 0);
        let name_len = filename.len() as u64;
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &parent_inode_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&parent_inode_key)
                    .ok_or_else(|| LuksError::NotFound("parent inode not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 160 {
                    return Err(LuksError::CorruptFs("parent inode item truncated"));
                }
                data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                let cur_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
                data[16..24].copy_from_slice(&(cur_size + name_len * 2).to_le_bytes()); // size
                let seq = u64::from_le_bytes(data[72..80].try_into().unwrap()).wrapping_add(1);
                data[72..80].copy_from_slice(&seq.to_le_bytes()); // sequence
                data[124..132].copy_from_slice(&now_sec.to_le_bytes()); // ctime
                data[132..136].copy_from_slice(&now_nsec.to_le_bytes());
                data[136..144].copy_from_slice(&now_sec.to_le_bytes()); // mtime
                data[144..148].copy_from_slice(&now_nsec.to_le_bytes());
                Ok(())
            },
        )?;
        record_cow_result(
            &res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 2. Insert DIR_ITEM into parent directory
        let dir_item_data = crate::fs::btrfs::write::node::build_dir_item(
            new_ino,
            new_generation,
            1, // REG_FILE
            filename,
        );
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            dir_item_key,
            dir_item_data.clone(),
            new_generation,
            &mut allocator,
        )?;
        record_cow_result(
            &res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 3. Insert DIR_INDEX into parent directory
        let dir_index_key = Key::new(parent_ino, crate::fs::btrfs::tree::DIR_INDEX_KEY, dir_index);
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            dir_index_key,
            dir_item_data,
            new_generation,
            &mut allocator,
        )?;
        record_cow_result(
            &res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 4. Insert INODE_ITEM for new_ino
        let new_inode_key = Key::new(new_ino, INODE_ITEM_KEY, 0);
        let new_inode_data = crate::fs::btrfs::write::node::build_empty_inode_item(
            new_generation,
            0o100644,
            located_parent.inode.uid,
            located_parent.inode.gid,
            1, // nlink
            now_sec,
            now_nsec,
        );
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            new_inode_key,
            new_inode_data,
            new_generation,
            &mut allocator,
        )?;
        record_cow_result(
            &res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 5. Insert INODE_REF for new_ino
        let inode_ref_key = Key::new(new_ino, crate::fs::btrfs::tree::INODE_REF_KEY, parent_ino);
        let inode_ref_data = crate::fs::btrfs::write::node::build_inode_ref(dir_index, filename);
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            inode_ref_key,
            inode_ref_data,
            new_generation,
            &mut allocator,
        )?;
        record_cow_result(
            &res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            pending_blocks,
            allocator,
            blocks_to_add,
            blocks_to_remove,
        )
    }
}

fn record_cow_result(
    res: &CowResult,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8)>,
    allocator: &mut FreeSpaceMap,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    node_size: u32,
    owner: u64,
) -> Result<()> {
    for &(b, lvl) in &res.allocated {
        blocks_to_add.push((b, lvl, owner));
    }
    for &(b, lvl) in &res.freed {
        blocks_to_remove.push((b, lvl));
        allocator.free_metadata(b, node_size)?;
    }
    for (b, data) in &res.emitted_blocks {
        pending_blocks.insert(*b, data.clone());
    }
    Ok(())
}

fn find_max_inode<D: ReadAt>(fs: &Btrfs<D>) -> Result<u64> {
    let mut current_bytenr = fs.fs_tree().bytenr;
    let mut current_level = fs.fs_tree().level;

    while current_level > 0 {
        let node = fs.read_node(current_bytenr)?;
        if node.nr_items == 0 {
            return Ok(256);
        }
        let last_idx = node.nr_items - 1;
        let ptr = node.key_ptr(last_idx)?;
        current_bytenr = ptr.blockptr;
        current_level -= 1;
    }

    let leaf_node = fs.read_node(current_bytenr)?;
    let mut max_ino = 256;
    for i in 0..leaf_node.nr_items {
        let key = leaf_node.key(i)?;
        if key.objectid >= 256 && key.objectid < 0xFFFF_FFFF_FFFF_FF00 {
            if key.objectid > max_ino {
                max_ino = key.objectid;
            }
        }
    }
    Ok(max_ino)
}

fn converge_and_finalize<D: ReadAt>(
    fs: &Btrfs<D>,
    new_generation: u64,
    new_fs_tree: TreeRoot,
    mut pending_blocks: HashMap<u64, Vec<u8>>,
    mut allocator: FreeSpaceMap,
    mut blocks_to_add: Vec<(u64, u8, u64)>,
    mut blocks_to_remove: Vec<(u64, u8)>,
) -> Result<Transaction> {
    let sb = fs.superblock();
    let mut root_tree_bytenr = sb.root;
    let mut root_tree_level = sb.root_level;
    let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
    let mut extent_root_bytenr = extent_root.bytenr;
    let mut extent_root_level = extent_root.level;

    // 1. Update FS_TREE root item in ROOT_TREE.
    let fs_root_key = Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
    let fs_root_bytenr = new_fs_tree.bytenr;
    let fs_root_level = new_fs_tree.level;

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

    record_cow_result(
        &root_res,
        &mut blocks_to_add,
        &mut blocks_to_remove,
        &mut allocator,
        &mut pending_blocks,
        sb.node_size,
        ROOT_TREE_OBJECTID,
    )?;
    root_tree_bytenr = root_res.new_root_bytenr;
    root_tree_level = root_res.new_root_level;

    let mut fst_bytenr_opt: Option<u64> = None;

    // 2. Fixed-point loop to record allocations and update root pointers until convergence.
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

            record_cow_result(
                &ext_res,
                &mut blocks_to_add,
                &mut blocks_to_remove,
                &mut allocator,
                &mut pending_blocks,
                sb.node_size,
                EXTENT_TREE_OBJECTID,
            )?;
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

            record_cow_result(
                &ext_res,
                &mut blocks_to_add,
                &mut blocks_to_remove,
                &mut allocator,
                &mut pending_blocks,
                sb.node_size,
                EXTENT_TREE_OBJECTID,
            )?;
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

                let old_fst_node =
                    crate::fs::btrfs::write::cow::read_node(fs, &pending_blocks, fst_root.bytenr)?;
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

                record_cow_result(
                    &root_res,
                    &mut blocks_to_add,
                    &mut blocks_to_remove,
                    &mut allocator,
                    &mut pending_blocks,
                    sb.node_size,
                    ROOT_TREE_OBJECTID,
                )?;
                root_tree_bytenr = root_res.new_root_bytenr;
                root_tree_level = root_res.new_root_level;
            }
        }

        // Update BLOCK_GROUP_ITEM in EXTENT_TREE for each block group
        let bg_updates: Vec<_> = allocator
            .block_groups
            .iter()
            .map(|bg| (bg.block_group.start, bg.block_group.length, bg.block_group.used))
            .collect();

        for (bg_start, bg_len, bg_used) in bg_updates {
            let bg_key = Key::new(
                bg_start,
                crate::fs::btrfs::tree::BLOCK_GROUP_ITEM_KEY,
                bg_len,
            );
            let ext_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                &bg_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf.find_item(&bg_key).ok_or_else(|| {
                        LuksError::NotFound("block group item not found in extent tree".into())
                    })?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 24 {
                        return Err(LuksError::CorruptFs("block group item truncated"));
                    }
                    data[0..8].copy_from_slice(&bg_used.to_le_bytes());
                    Ok(())
                },
            )?;

            record_cow_result(
                &ext_res,
                &mut blocks_to_add,
                &mut blocks_to_remove,
                &mut allocator,
                &mut pending_blocks,
                sb.node_size,
                EXTENT_TREE_OBJECTID,
            )?;
            extent_root_bytenr = ext_res.new_root_bytenr;
            extent_root_level = ext_res.new_root_level;
        }

        // Update EXTENT_TREE root item in ROOT_TREE
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

        record_cow_result(
            &root_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            ROOT_TREE_OBJECTID,
        )?;
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;
    }

    let final_bytes_used = allocator
        .block_groups
        .iter()
        .map(|bg| bg.block_group.used)
        .sum();

    Ok(Transaction {
        new_generation,
        final_root_bytenr: root_tree_bytenr,
        final_root_level: root_tree_level,
        final_bytes_used,
        new_fs_tree,
        pending_blocks,
    })
}
