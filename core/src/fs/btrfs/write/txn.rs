//! Btrfs transaction coordination and fixed-point convergence loop.
//!
//! A transaction computes all CoW path copies and extent tree bookkeeping
//! completely in memory until no further metadata blocks need allocation.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::superblock::BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE;
use crate::fs::btrfs::tree::{
    Key, CSUM_TREE_OBJECTID, DIR_INDEX_KEY, DIR_ITEM_KEY, EXTENT_CSUM_KEY, EXTENT_CSUM_OBJECTID,
    EXTENT_DATA_KEY, EXTENT_ITEM_KEY, EXTENT_TREE_OBJECTID, FREE_SPACE_TREE_OBJECTID,
    FS_TREE_OBJECTID, INODE_ITEM_KEY, INODE_REF_KEY, METADATA_ITEM_KEY, ROOT_ITEM_KEY,
    ROOT_TREE_OBJECTID,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate, CowResult};
use crate::fs::btrfs::write::extent_tree::{ExtentItem, ExtentTree, MetadataItem};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::node::Leaf;
use crate::fs::btrfs::{Btrfs, TreeRoot};

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
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
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

    /// Prepare a transaction that creates a new directory named `name` inside `parent_path`.
    pub fn create_directory<D: ReadAt>(
        fs: &Btrfs<D>,
        parent_path: &str,
        name: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<(Self, u64)> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        let located_parent = fs.resolve_no_follow(fs.fs_tree(), parent_path)?;
        if !located_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(parent_path.to_string()));
        }
        if located_parent.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume directory creation not yet supported".into(),
            ));
        }

        let parent_ino = located_parent.inode.objectid;
        Self::create_directory_in_dir(
            fs,
            parent_ino,
            located_parent.inode.uid,
            located_parent.inode.gid,
            name,
            now_sec,
            now_nsec,
        )
    }

    /// Prepare a transaction that creates a new directory named `name` inside `parent_ino`.
    pub fn create_directory_in_dir<D: ReadAt>(
        fs: &Btrfs<D>,
        parent_ino: u64,
        parent_uid: u32,
        parent_gid: u32,
        name: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<(Self, u64)> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        // Check if entry already exists in parent directory
        let name_hash = crate::fs::btrfs::crc32c::name_hash(name.as_bytes());
        let dir_item_key = Key::new(parent_ino, crate::fs::btrfs::tree::DIR_ITEM_KEY, name_hash);
        if let Some(data) = fs.find_item(fs.fs_tree().bytenr, &dir_item_key)? {
            let entries = crate::fs::btrfs::inode::parse_dir_entries(&data)?;
            if entries.iter().any(|e| e.name == name.as_bytes()) {
                return Err(LuksError::AlreadyExists(format!(
                    "entry '{}' already exists in parent directory {}",
                    name, parent_ino
                )));
            }
        }

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
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
        let name_len = name.len() as u64;
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

        // 2. Insert DIR_ITEM into parent directory with file_type = 2 (FT_DIR)
        let dir_item_entry = crate::fs::btrfs::write::node::build_dir_item(
            new_ino,
            new_generation,
            2, // FT_DIR
            name,
        );
        let existing_dir_item = find_item_in_tree(fs, &pending_blocks, fs_root_bytenr, &dir_item_key)?;
        if let Some(existing_data) = existing_dir_item {
            let mut merged_data = existing_data;
            merged_data.extend_from_slice(&dir_item_entry);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &dir_item_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&dir_item_key)
                        .ok_or_else(|| LuksError::NotFound("dir item not found".into()))?;
                    leaf.items[idx].data = merged_data.clone();
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
        } else {
            let res = cow_tree_insert(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                dir_item_key,
                dir_item_entry.clone(),
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
        }

        // 3. Insert DIR_INDEX into parent directory
        let dir_index_key = Key::new(parent_ino, crate::fs::btrfs::tree::DIR_INDEX_KEY, dir_index);
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            dir_index_key,
            dir_item_entry,
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

        // 4. Insert INODE_ITEM for new_ino (mode = 0o040755, nlink = 1, size = 0)
        let new_inode_key = Key::new(new_ino, INODE_ITEM_KEY, 0);
        let new_inode_data = crate::fs::btrfs::write::node::build_empty_inode_item(
            new_generation,
            0o040755,
            parent_uid,
            parent_gid,
            1, // nlink = 1
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
        let inode_ref_data = crate::fs::btrfs::write::node::build_inode_ref(dir_index, name);
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

        let txn = converge_and_finalize(
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
        )?;

        Ok((txn, new_ino))
    }

    /// Prepare a transaction that renames/moves `old_name` in `old_parent_path` to `new_name` in `new_parent_path`.
    pub fn rename<D: ReadAt>(
        fs: &Btrfs<D>,
        old_parent_path: &str,
        old_name: &str,
        new_parent_path: &str,
        new_name: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        if old_name.is_empty()
            || new_name.is_empty()
            || old_name == "."
            || old_name == ".."
            || new_name == "."
            || new_name == ".."
            || old_name.contains('/')
            || new_name.contains('/')
        {
            return Err(LuksError::NotFound("invalid filename for rename".into()));
        }

        let located_old_parent = fs.resolve_no_follow(fs.fs_tree(), old_parent_path)?;
        let located_new_parent = fs.resolve_no_follow(fs.fs_tree(), new_parent_path)?;

        if located_old_parent.tree.objectid != FS_TREE_OBJECTID
            || located_new_parent.tree.objectid != FS_TREE_OBJECTID
        {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume rename not supported".into(),
            ));
        }

        if !located_old_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(old_parent_path.to_string()));
        }
        if !located_new_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(new_parent_path.to_string()));
        }

        let old_parent_ino = located_old_parent.inode.objectid;
        let new_parent_ino = located_new_parent.inode.objectid;

        // Lookup old_name in old_parent
        let old_entry = fs
            .lookup(fs.fs_tree().bytenr, old_parent_ino, old_name)?
            .ok_or_else(|| LuksError::NotFound(format!("{}/{}", old_parent_path, old_name)))?;

        let child_ino = old_entry.location.objectid;
        let child_is_dir = old_entry.file_type.is_dir();
        let child_file_type = match old_entry.file_type {
            crate::fs::FileType::Directory => 2u8,
            crate::fs::FileType::CharDevice => 3u8,
            crate::fs::FileType::BlockDevice => 4u8,
            crate::fs::FileType::Fifo => 5u8,
            crate::fs::FileType::Socket => 6u8,
            crate::fs::FileType::Symlink => 7u8,
            _ => 1u8,
        };

        // Same source and destination: no-op
        if old_parent_ino == new_parent_ino && old_name == new_name {
            return Self::update_inode_mtime(fs, child_ino, now_sec, now_nsec);
        }

        // Cycle check: moving directory into itself or descendant
        if child_is_dir {
            if child_ino == new_parent_ino {
                return Err(LuksError::UnsupportedFsFeature(format!(
                    "cannot move directory '{}' into itself",
                    old_name
                )));
            }

            let mut curr = new_parent_ino;
            let mut depth = 0;
            while curr != 256 && curr != fs.fs_tree().root_dirid && depth < 256 {
                if curr == child_ino {
                    return Err(LuksError::UnsupportedFsFeature(format!(
                        "cannot move directory '{}' into its own descendant",
                        old_name
                    )));
                }

                let mut parent_of_curr = None;
                let ref_search_key = Key::new(curr, INODE_REF_KEY, 0);
                let cursor = fs.search(fs.fs_tree().bytenr, &ref_search_key)?;
                while cursor.valid() {
                    let k = cursor.key()?;
                    if k.objectid != curr || k.item_type != INODE_REF_KEY {
                        break;
                    }
                    parent_of_curr = Some(k.offset);
                    break;
                }

                match parent_of_curr {
                    Some(p) => curr = p,
                    None => break,
                }
                depth += 1;
            }

            if curr == child_ino {
                return Err(LuksError::UnsupportedFsFeature(format!(
                    "cannot move directory '{}' into its own descendant",
                    old_name
                )));
            }
        }

        // Destination collision check
        let dest_entry_opt = fs.lookup(fs.fs_tree().bytenr, new_parent_ino, new_name)?;
        let mut dest_replacement: Option<(u64, bool, u64, Vec<(u64, u64)>)> = None;

        if let Some(dest_entry) = dest_entry_opt {
            let dest_ino = dest_entry.location.objectid;
            if dest_ino == child_ino {
                // Same file
                return Self::update_inode_mtime(fs, child_ino, now_sec, now_nsec);
            }

            let dest_is_dir = dest_entry.file_type.is_dir();
            if dest_is_dir {
                if !child_is_dir {
                    return Err(LuksError::IsADirectory(format!("{}/{}", new_parent_path, new_name)));
                }

                // Check if directory is empty
                let mut has_entries = false;
                fs.for_each_item(fs.fs_tree().bytenr, dest_ino, DIR_INDEX_KEY, &mut |_, _| {
                    has_entries = true;
                    Ok(false)
                })?;
                let dest_inode = fs.read_inode(fs.fs_tree().bytenr, dest_ino)?;
                if has_entries || dest_inode.size > 0 {
                    return Err(LuksError::UnsupportedFsFeature(format!(
                        "destination directory '{}/{}' is not empty",
                        new_parent_path, new_name
                    )));
                }

                // Find dest_dir_index
                let inode_ref_key = Key::new(dest_ino, INODE_REF_KEY, new_parent_ino);
                let dest_dir_index = if let Some(ref_data) = fs.find_item(fs.fs_tree().bytenr, &inode_ref_key)? {
                    if ref_data.len() >= 8 {
                        u64::from_le_bytes(ref_data[0..8].try_into().unwrap())
                    } else {
                        0
                    }
                } else {
                    0
                };
                dest_replacement = Some((dest_ino, true, dest_dir_index, Vec::new()));
            } else {
                if child_is_dir {
                    return Err(LuksError::NotADirectory(format!("{}/{}", new_parent_path, new_name)));
                }

                let dest_inode = fs.read_inode(fs.fs_tree().bytenr, dest_ino)?;
                if dest_inode.nlink > 1 {
                    return Err(LuksError::UnsupportedFsFeature(
                        "overwriting files with hardlinks (nlink > 1) is not supported".into(),
                    ));
                }

                // Collect dest extents to free
                let mut data_extents_to_free = Vec::new();
                let mut cursor = fs.search(fs.fs_tree().bytenr, &Key::new(dest_ino, 0, 0))?;
                while cursor.valid() {
                    let key = cursor.key()?;
                    if key.objectid != dest_ino {
                        break;
                    }
                    if key.item_type == EXTENT_DATA_KEY {
                        let data = cursor.data()?;
                        let file_ext = crate::fs::btrfs::extent::FileExtent::parse(key.offset, data)?;
                        if !file_ext.is_zeros() && file_ext.disk_bytenr > 0 && file_ext.disk_num_bytes > 0 {
                            data_extents_to_free.push((file_ext.disk_bytenr, file_ext.disk_num_bytes));
                        }
                    }
                    cursor.advance()?;
                }
                data_extents_to_free.sort_unstable();
                data_extents_to_free.dedup();

                let inode_ref_key = Key::new(dest_ino, INODE_REF_KEY, new_parent_ino);
                let dest_dir_index = if let Some(ref_data) = fs.find_item(fs.fs_tree().bytenr, &inode_ref_key)? {
                    if ref_data.len() >= 8 {
                        u64::from_le_bytes(ref_data[0..8].try_into().unwrap())
                    } else {
                        0
                    }
                } else {
                    0
                };
                dest_replacement = Some((dest_ino, false, dest_dir_index, data_extents_to_free));
            }
        }

        // Find old_dir_index of child in old_parent
        let inode_ref_key = Key::new(child_ino, INODE_REF_KEY, old_parent_ino);
        let old_dir_index = if let Some(ref_data) = fs.find_item(fs.fs_tree().bytenr, &inode_ref_key)? {
            if ref_data.len() >= 8 {
                u64::from_le_bytes(ref_data[0..8].try_into().unwrap())
            } else {
                0
            }
        } else {
            0
        };
        let old_dir_index = if old_dir_index != 0 {
            old_dir_index
        } else {
            let mut found_idx = 0;
            fs.for_each_item(fs.fs_tree().bytenr, old_parent_ino, DIR_INDEX_KEY, &mut |key, data| {
                if let Ok(entries) = crate::fs::btrfs::inode::parse_dir_entries(data) {
                    for e in entries {
                        if e.name == old_name.as_bytes() && e.location.objectid == child_ino {
                            found_idx = key.offset;
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            })?;
            if found_idx == 0 {
                return Err(LuksError::CorruptFs("old dir index not found for renamed entry"));
            }
            found_idx
        };

        // Find next dir_index for new_parent
        let mut max_dir_index = 1u64;
        fs.for_each_item(fs.fs_tree().bytenr, new_parent_ino, DIR_INDEX_KEY, &mut |key, _| {
            if key.offset > max_dir_index {
                max_dir_index = key.offset;
            }
            Ok(true)
        })?;
        let new_dir_index = max_dir_index + 1;

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::<(u64, u8, u64)>::new();
        let mut blocks_to_remove = Vec::<(u64, u8)>::new();

        let mut fs_root_bytenr = fs.fs_tree().bytenr;
        let mut fs_root_level = fs.fs_tree().level;

        let mut data_extents_to_free = Vec::new();
        let dest_replaced = dest_replacement.is_some();

        // 1. If replacing destination, delete destination inode items and free its data
        if let Some((dest_ino, _dest_is_dir, dest_dir_index, freed_extents)) = dest_replacement {
            data_extents_to_free = freed_extents;

            // Delete all items of dest_ino from fs_tree
            let mut dest_item_keys = Vec::new();
            let mut cursor = fs.search(fs.fs_tree().bytenr, &Key::new(dest_ino, 0, 0))?;
            while cursor.valid() {
                let key = cursor.key()?;
                if key.objectid != dest_ino {
                    break;
                }
                dest_item_keys.push(key);
                cursor.advance()?;
            }

            for item_key in &dest_item_keys {
                let res = cow_tree_mutate(
                    fs,
                    &pending_blocks,
                    fs_root_bytenr,
                    fs_root_level,
                    FS_TREE_OBJECTID,
                    item_key,
                    new_generation,
                    &mut allocator,
                    |leaf| {
                        leaf.delete_item(item_key)?;
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
            }

            // Delete dest's DIR_INDEX from new_parent
            if dest_dir_index != 0 {
                let dest_dir_index_key = Key::new(new_parent_ino, DIR_INDEX_KEY, dest_dir_index);
                let res = cow_tree_mutate(
                    fs,
                    &pending_blocks,
                    fs_root_bytenr,
                    fs_root_level,
                    FS_TREE_OBJECTID,
                    &dest_dir_index_key,
                    new_generation,
                    &mut allocator,
                    |leaf| {
                        leaf.delete_item(&dest_dir_index_key)?;
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
            }

            // Remove dest entry from new_parent DIR_ITEM
            let dest_name_hash = crate::fs::btrfs::crc32c::name_hash(new_name.as_bytes());
            let dest_dir_item_key = Key::new(new_parent_ino, DIR_ITEM_KEY, dest_name_hash);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &dest_dir_item_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&dest_dir_item_key)
                        .ok_or_else(|| LuksError::NotFound("dest dir item not found".into()))?;
                    let existing_data = &leaf.items[idx].data;
                    let mut new_data = Vec::new();
                    let mut cur = &existing_data[..];
                    while !cur.is_empty() {
                        if cur.len() < 30 {
                            return Err(LuksError::CorruptFs("dir item truncated"));
                        }
                        let data_len = u16::from_le_bytes([cur[25], cur[26]]) as usize;
                        let name_len = u16::from_le_bytes([cur[27], cur[28]]) as usize;
                        let total = 30 + name_len + data_len;
                        if total > cur.len() {
                            return Err(LuksError::CorruptFs("dir item overruns"));
                        }
                        let name = &cur[30..30 + name_len];
                        let item_child_ino = u64::from_le_bytes(cur[0..8].try_into().unwrap());
                        if !(name == new_name.as_bytes() && item_child_ino == dest_ino) {
                            new_data.extend_from_slice(&cur[..total]);
                        }
                        cur = &cur[total..];
                    }
                    if new_data.is_empty() {
                        leaf.delete_item(&dest_dir_item_key)?;
                    } else {
                        leaf.items[idx].data = new_data;
                    }
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
        }

        // 2. Delete old name DIR_ITEM and DIR_INDEX from old_parent
        let old_name_hash = crate::fs::btrfs::crc32c::name_hash(old_name.as_bytes());
        let old_dir_item_key = Key::new(old_parent_ino, DIR_ITEM_KEY, old_name_hash);
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &old_dir_item_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&old_dir_item_key)
                    .ok_or_else(|| LuksError::NotFound("old dir item not found".into()))?;
                let existing_data = &leaf.items[idx].data;
                let mut new_data = Vec::new();
                let mut cur = &existing_data[..];
                while !cur.is_empty() {
                    if cur.len() < 30 {
                        return Err(LuksError::CorruptFs("dir item truncated"));
                    }
                    let data_len = u16::from_le_bytes([cur[25], cur[26]]) as usize;
                    let name_len = u16::from_le_bytes([cur[27], cur[28]]) as usize;
                    let total = 30 + name_len + data_len;
                    if total > cur.len() {
                        return Err(LuksError::CorruptFs("dir item overruns"));
                    }
                    let name = &cur[30..30 + name_len];
                    let item_child_ino = u64::from_le_bytes(cur[0..8].try_into().unwrap());
                    if !(name == old_name.as_bytes() && item_child_ino == child_ino) {
                        new_data.extend_from_slice(&cur[..total]);
                    }
                    cur = &cur[total..];
                }
                if new_data.is_empty() {
                    leaf.delete_item(&old_dir_item_key)?;
                } else {
                    leaf.items[idx].data = new_data;
                }
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

        let old_dir_index_key = Key::new(old_parent_ino, DIR_INDEX_KEY, old_dir_index);
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &old_dir_index_key,
            new_generation,
            &mut allocator,
            |leaf| {
                leaf.delete_item(&old_dir_index_key)?;
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

        // 3. Insert new name DIR_ITEM and DIR_INDEX into new_parent
        let new_name_hash = crate::fs::btrfs::crc32c::name_hash(new_name.as_bytes());
        let new_dir_item_key = Key::new(new_parent_ino, DIR_ITEM_KEY, new_name_hash);
        let new_dir_item_entry = crate::fs::btrfs::write::node::build_dir_item(
            child_ino,
            new_generation,
            child_file_type,
            new_name,
        );

        let existing_new_dir_item = find_item_in_tree(fs, &pending_blocks, fs_root_bytenr, &new_dir_item_key)?;
        if let Some(existing_data) = existing_new_dir_item {
            let mut merged_data = existing_data;
            merged_data.extend_from_slice(&new_dir_item_entry);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &new_dir_item_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&new_dir_item_key)
                        .ok_or_else(|| LuksError::NotFound("dir item not found".into()))?;
                    leaf.items[idx].data = merged_data.clone();
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
        } else {
            let res = cow_tree_insert(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                new_dir_item_key,
                new_dir_item_entry.clone(),
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
        }

        let new_dir_index_key = Key::new(new_parent_ino, DIR_INDEX_KEY, new_dir_index);
        let res = cow_tree_insert(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            new_dir_index_key,
            new_dir_item_entry,
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

        // 4. Update child INODE_REF
        let new_inode_ref_data = crate::fs::btrfs::write::node::build_inode_ref(new_dir_index, new_name);
        if old_parent_ino == new_parent_ino {
            let child_ref_key = Key::new(child_ino, INODE_REF_KEY, old_parent_ino);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &child_ref_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&child_ref_key)
                        .ok_or_else(|| LuksError::NotFound("child inode ref not found".into()))?;
                    leaf.items[idx].data = new_inode_ref_data.clone();
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
        } else {
            let old_child_ref_key = Key::new(child_ino, INODE_REF_KEY, old_parent_ino);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &old_child_ref_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    leaf.delete_item(&old_child_ref_key)?;
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

            let new_child_ref_key = Key::new(child_ino, INODE_REF_KEY, new_parent_ino);
            let res = cow_tree_insert(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                new_child_ref_key,
                new_inode_ref_data,
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
        }

        // 5. Update child INODE_ITEM (ctime, sequence, transid)
        let child_inode_key = Key::new(child_ino, INODE_ITEM_KEY, 0);
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &child_inode_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&child_inode_key)
                    .ok_or_else(|| LuksError::NotFound("child inode not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 160 {
                    return Err(LuksError::CorruptFs("child inode item truncated"));
                }
                data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                let seq = u64::from_le_bytes(data[72..80].try_into().unwrap()).wrapping_add(1);
                data[72..80].copy_from_slice(&seq.to_le_bytes()); // sequence
                data[124..132].copy_from_slice(&now_sec.to_le_bytes()); // ctime
                data[132..136].copy_from_slice(&now_nsec.to_le_bytes());
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

        // 6. Update parent INODE_ITEM(s)
        let old_name_len = old_name.len() as u64;
        let new_name_len = new_name.len() as u64;

        if old_parent_ino == new_parent_ino {
            let parent_inode_key = Key::new(old_parent_ino, INODE_ITEM_KEY, 0);
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
                    let removed_size = old_name_len * 2 + if dest_replaced { new_name_len * 2 } else { 0 };
                    let adjusted_size = cur_size.saturating_sub(removed_size) + new_name_len * 2;
                    data[16..24].copy_from_slice(&adjusted_size.to_le_bytes()); // size
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
        } else {
            // Update old_parent INODE_ITEM
            let old_parent_inode_key = Key::new(old_parent_ino, INODE_ITEM_KEY, 0);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &old_parent_inode_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&old_parent_inode_key)
                        .ok_or_else(|| LuksError::NotFound("old parent inode not found".into()))?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 160 {
                        return Err(LuksError::CorruptFs("old parent inode item truncated"));
                    }
                    data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                    let cur_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
                    let adjusted_size = cur_size.saturating_sub(old_name_len * 2);
                    data[16..24].copy_from_slice(&adjusted_size.to_le_bytes()); // size
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

            // Update new_parent INODE_ITEM
            let new_parent_inode_key = Key::new(new_parent_ino, INODE_ITEM_KEY, 0);
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                &new_parent_inode_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf
                        .find_item(&new_parent_inode_key)
                        .ok_or_else(|| LuksError::NotFound("new parent inode not found".into()))?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 160 {
                        return Err(LuksError::CorruptFs("new parent inode item truncated"));
                    }
                    data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                    let cur_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
                    let removed_size = if dest_replaced { new_name_len * 2 } else { 0 };
                    let adjusted_size = cur_size.saturating_sub(removed_size) + new_name_len * 2;
                    data[16..24].copy_from_slice(&adjusted_size.to_le_bytes()); // size
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
        }

        // 7. Free data extents and remove csums if destination was replaced
        let mut csum_root_opt = None;
        if !data_extents_to_free.is_empty() {
            for &(bytenr, num_bytes) in &data_extents_to_free {
                allocator.free_data(bytenr, num_bytes)?;
            }

            if let Ok(csum_root) = fs.tree_root(CSUM_TREE_OBJECTID) {
                let mut csum_keys_to_delete = Vec::new();
                for &(disk_bytenr, disk_num_bytes) in &data_extents_to_free {
                    let search_key = Key::new(
                        EXTENT_CSUM_OBJECTID,
                        EXTENT_CSUM_KEY,
                        disk_bytenr,
                    );
                    let mut cursor = fs.search_le(csum_root.bytenr, &search_key)?;
                    while cursor.valid() {
                        let key = cursor.key()?;
                        if key.objectid != EXTENT_CSUM_OBJECTID
                            || key.item_type != EXTENT_CSUM_KEY
                        {
                            if key < Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, 0) {
                                cursor.advance()?;
                                continue;
                            }
                            break;
                        }
                        if key.offset >= disk_bytenr + disk_num_bytes {
                            break;
                        }
                        if key.offset >= disk_bytenr {
                            csum_keys_to_delete.push(key);
                        }
                        cursor.advance()?;
                    }
                }
                csum_keys_to_delete.sort_unstable();
                csum_keys_to_delete.dedup();

                if !csum_keys_to_delete.is_empty() {
                    let mut csum_root_bytenr = csum_root.bytenr;
                    let mut csum_root_level = csum_root.level;

                    for csum_key in csum_keys_to_delete {
                        let res = cow_tree_mutate(
                            fs,
                            &pending_blocks,
                            csum_root_bytenr,
                            csum_root_level,
                            CSUM_TREE_OBJECTID,
                            &csum_key,
                            new_generation,
                            &mut allocator,
                            |leaf| {
                                leaf.delete_item(&csum_key)?;
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
                            CSUM_TREE_OBJECTID,
                        )?;
                        csum_root_bytenr = res.new_root_bytenr;
                        csum_root_level = res.new_root_level;
                    }

                    csum_root_opt = Some((csum_root_bytenr, csum_root_level));
                }
            }
        }

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            csum_root_opt,
            None,
            None,
            None,
            pending_blocks,
            Vec::new(),
            allocator,
            blocks_to_add,
            blocks_to_remove,
            Vec::new(),
            data_extents_to_free,
        )
    }

    /// Prepare a transaction that writes `data` into the file at `file_path`.
    pub fn write_file_data<D: ReadAt>(
        fs: &Btrfs<D>,
        file_path: &str,
        data: &[u8],
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        let located = fs.resolve_no_follow(fs.fs_tree(), file_path)?;
        if located.inode.file_type().is_dir() {
            return Err(LuksError::IsADirectory(file_path.to_string()));
        }
        if located.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume file write not yet supported".into(),
            ));
        }

        let ino = located.inode.objectid;
        let sb = fs.superblock();
        let new_generation = sb.generation + 1;
        let sector_size = sb.sector_size;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::<(u64, u8, u64)>::new();
        let mut blocks_to_remove = Vec::<(u64, u8)>::new();
        let mut data_extents_to_add = Vec::<(u64, u64, u64, u64, u64)>::new();

        // 1. Allocate data extent
        let data_len = data.len() as u64;
        let disk_num_bytes = if data_len == 0 {
            0
        } else {
            ((data_len + sector_size as u64 - 1) / sector_size as u64) * sector_size as u64
        };

        let mut pending_data = Vec::new();
        let disk_bytenr = if disk_num_bytes > 0 {
            let bytenr = allocator.allocate_data(disk_num_bytes, sector_size)?;
            let mut padded = vec![0u8; disk_num_bytes as usize];
            padded[..data.len()].copy_from_slice(data);
            pending_data.push((bytenr, padded));
            data_extents_to_add.push((bytenr, disk_num_bytes, FS_TREE_OBJECTID, ino, 0));
            bytenr
        } else {
            0
        };

        let mut fs_root_bytenr = fs.fs_tree().bytenr;
        let mut fs_root_level = fs.fs_tree().level;

        // 2. CoW FS_TREE: Update INODE_ITEM (size, nbytes, sequence, transid, mtime/ctime)
        let inode_key = Key::new(ino, INODE_ITEM_KEY, 0);
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &inode_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&inode_key)
                    .ok_or_else(|| LuksError::NotFound("inode not found".into()))?;
                let item_data = &mut leaf.items[idx].data;
                if item_data.len() < 160 {
                    return Err(LuksError::CorruptFs("inode item truncated"));
                }
                item_data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                item_data[16..24].copy_from_slice(&data_len.to_le_bytes()); // size
                item_data[24..32].copy_from_slice(&disk_num_bytes.to_le_bytes()); // nbytes
                let seq = u64::from_le_bytes(item_data[72..80].try_into().unwrap()).wrapping_add(1);
                item_data[72..80].copy_from_slice(&seq.to_le_bytes()); // sequence
                item_data[124..132].copy_from_slice(&now_sec.to_le_bytes()); // ctime
                item_data[132..136].copy_from_slice(&now_nsec.to_le_bytes());
                item_data[136..144].copy_from_slice(&now_sec.to_le_bytes()); // mtime
                item_data[144..148].copy_from_slice(&now_nsec.to_le_bytes());
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

        // 3. CoW FS_TREE: Insert EXTENT_DATA item if disk_num_bytes > 0
        if disk_num_bytes > 0 {
            let extent_data_key = Key::new(ino, crate::fs::btrfs::tree::EXTENT_DATA_KEY, 0);
            let extent_payload = crate::fs::btrfs::write::node::build_regular_file_extent(
                new_generation,
                disk_num_bytes,
                disk_bytenr,
                disk_num_bytes,
                disk_num_bytes,
            );
            let res = cow_tree_insert(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                extent_data_key,
                extent_payload,
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
        }

        // 4. CoW CSUM_TREE: insert the EXTENT_CSUM items covering this extent.
        //
        // Items, plural, and that is the fix for the ~15 MiB ceiling. One
        // `EXTENT_CSUM` item per file has to fit in one leaf, so on the
        // standard geometry it caps a file at 16228 / 4 × 4096 ≈ 15.8 MiB —
        // reached by a 20 MB phone→stick write on 2026-08-16 and reported, in
        // the most misleading way available, as "no space left on the
        // filesystem". `build_extent_csum_items` tiles the extent across as
        // many items as the geometry needs, which is what the key's logical
        // address is *for* and what real btrfs does (measured 2026-08-15 on a
        // kernel-written 50 MB file).
        let mut csum_root_opt = None;
        if disk_num_bytes > 0 {
            if let Ok(csum_root) = fs.tree_root(CSUM_TREE_OBJECTID) {
                let csum_items = crate::fs::btrfs::write::node::build_extent_csum_items(
                    sb.csum_type,
                    sb.node_size,
                    sector_size,
                    disk_bytenr,
                    disk_num_bytes,
                    data,
                )?;

                let mut csum_root_bytenr = csum_root.bytenr;
                let mut csum_root_level = csum_root.level;

                for (range_start, csum_payload) in csum_items {
                    let csum_key = Key::new(
                        crate::fs::btrfs::tree::EXTENT_CSUM_OBJECTID,
                        crate::fs::btrfs::tree::EXTENT_CSUM_KEY,
                        range_start,
                    );
                    let res = cow_tree_insert(
                        fs,
                        &pending_blocks,
                        csum_root_bytenr,
                        csum_root_level,
                        CSUM_TREE_OBJECTID,
                        csum_key,
                        csum_payload,
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
                        CSUM_TREE_OBJECTID,
                    )?;
                    csum_root_bytenr = res.new_root_bytenr;
                    csum_root_level = res.new_root_level;
                }

                csum_root_opt = Some((csum_root_bytenr, csum_root_level));
            }
        }


        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            csum_root_opt,
            None,
            None,
            None,
            pending_blocks,
            pending_data,
            allocator,
            blocks_to_add,
            blocks_to_remove,
            data_extents_to_add,
            Vec::new(),
        )
    }

    /// Prepare a transaction that creates a new regular file with initial data inside `parent_path`.
    pub fn create_file_with_data<D: ReadAt>(
        fs: &Btrfs<D>,
        parent_path: &str,
        filename: &str,
        data: &[u8],
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<(Self, u64)> {
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
        if let Some(item_data) = fs.find_item(fs.fs_tree().bytenr, &dir_item_key)? {
            let entries = crate::fs::btrfs::inode::parse_dir_entries(&item_data)?;
            if entries.iter().any(|e| e.name == filename.as_bytes()) {
                return Err(LuksError::AlreadyExists(format!(
                    "file '{}' already exists in '{}'",
                    filename, parent_path
                )));
            }
        }

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;
        let sector_size = sb.sector_size;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
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

        let mut data_extents_to_add = Vec::<(u64, u64, u64, u64, u64)>::new();

        // 1. Allocate data extent
        let data_len = data.len() as u64;
        let disk_num_bytes = if data_len == 0 {
            0
        } else {
            ((data_len + sector_size as u64 - 1) / sector_size as u64) * sector_size as u64
        };

        let mut pending_data = Vec::new();
        let disk_bytenr = if disk_num_bytes > 0 {
            let bytenr = allocator.allocate_data(disk_num_bytes, sector_size)?;
            let mut padded = vec![0u8; disk_num_bytes as usize];
            padded[..data.len()].copy_from_slice(data);
            pending_data.push((bytenr, padded));
            data_extents_to_add.push((bytenr, disk_num_bytes, FS_TREE_OBJECTID, new_ino, 0));
            bytenr
        } else {
            0
        };

        // 2. Update parent directory INODE_ITEM (size += name_len * 2, sequence += 1, transid, mtime/ctime)
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
                let item_data = &mut leaf.items[idx].data;
                if item_data.len() < 160 {
                    return Err(LuksError::CorruptFs("parent inode item truncated"));
                }
                item_data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                let cur_size = u64::from_le_bytes(item_data[16..24].try_into().unwrap());
                item_data[16..24].copy_from_slice(&(cur_size + name_len * 2).to_le_bytes()); // size
                let seq = u64::from_le_bytes(item_data[72..80].try_into().unwrap()).wrapping_add(1);
                item_data[72..80].copy_from_slice(&seq.to_le_bytes()); // sequence
                item_data[124..132].copy_from_slice(&now_sec.to_le_bytes()); // ctime
                item_data[132..136].copy_from_slice(&now_nsec.to_le_bytes());
                item_data[136..144].copy_from_slice(&now_sec.to_le_bytes()); // mtime
                item_data[144..148].copy_from_slice(&now_nsec.to_le_bytes());
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

        // 3. Insert DIR_ITEM into parent directory
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

        // 4. Insert DIR_INDEX into parent directory
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

        // 5. Insert INODE_ITEM for new_ino
        let new_inode_key = Key::new(new_ino, INODE_ITEM_KEY, 0);
        let mut new_inode_data = crate::fs::btrfs::write::node::build_empty_inode_item(
            new_generation,
            0o100644,
            located_parent.inode.uid,
            located_parent.inode.gid,
            1, // nlink
            now_sec,
            now_nsec,
        );
        new_inode_data[16..24].copy_from_slice(&data_len.to_le_bytes()); // size
        new_inode_data[24..32].copy_from_slice(&disk_num_bytes.to_le_bytes()); // nbytes

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

        // 6. Insert INODE_REF for new_ino
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

        // 7. CoW FS_TREE: Insert EXTENT_DATA item if disk_num_bytes > 0
        if disk_num_bytes > 0 {
            let extent_data_key = Key::new(new_ino, crate::fs::btrfs::tree::EXTENT_DATA_KEY, 0);
            let extent_payload = crate::fs::btrfs::write::node::build_regular_file_extent(
                new_generation,
                disk_num_bytes,
                disk_bytenr,
                disk_num_bytes,
                disk_num_bytes,
            );
            let res = cow_tree_insert(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                extent_data_key,
                extent_payload,
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
        }

        // 8. CoW CSUM_TREE: insert the EXTENT_CSUM items covering this extent.
        let mut csum_root_opt = None;
        if disk_num_bytes > 0 {
            if let Ok(csum_root) = fs.tree_root(CSUM_TREE_OBJECTID) {
                let csum_items = crate::fs::btrfs::write::node::build_extent_csum_items(
                    sb.csum_type,
                    sb.node_size,
                    sector_size,
                    disk_bytenr,
                    disk_num_bytes,
                    data,
                )?;

                let mut csum_root_bytenr = csum_root.bytenr;
                let mut csum_root_level = csum_root.level;

                for (range_start, csum_payload) in csum_items {
                    let csum_key = Key::new(
                        crate::fs::btrfs::tree::EXTENT_CSUM_OBJECTID,
                        crate::fs::btrfs::tree::EXTENT_CSUM_KEY,
                        range_start,
                    );
                    let res = cow_tree_insert(
                        fs,
                        &pending_blocks,
                        csum_root_bytenr,
                        csum_root_level,
                        CSUM_TREE_OBJECTID,
                        csum_key,
                        csum_payload,
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
                        CSUM_TREE_OBJECTID,
                    )?;
                    csum_root_bytenr = res.new_root_bytenr;
                    csum_root_level = res.new_root_level;
                }

                csum_root_opt = Some((csum_root_bytenr, csum_root_level));
            }
        }

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        let txn = converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            csum_root_opt,
            None,
            None,
            None,
            pending_blocks,
            pending_data,
            allocator,
            blocks_to_add,
            blocks_to_remove,
            data_extents_to_add,
            Vec::new(),
        )?;
        Ok((txn, new_ino))
    }

    /// Prepare a transaction that deletes an existing regular file at `path`.
    pub fn delete_file<D: ReadAt>(
        fs: &Btrfs<D>,
        path: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(&fs.superblock())?;
        gate::check_writeable_subvolume(&fs.fs_tree())?;

        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(LuksError::IsADirectory("/".into()));
        }

        let (parent_path, filename) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };

        let located_parent = fs.resolve_no_follow(fs.fs_tree(), parent_path)?;
        if !located_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(parent_path.to_string()));
        }
        if located_parent.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume file deletion not yet supported".into(),
            ));
        }

        let located_target = fs.resolve_no_follow(fs.fs_tree(), path)?;
        if located_target.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume file deletion not yet supported".into(),
            ));
        }
        if located_target.inode.file_type().is_dir() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }
        if !located_target.inode.file_type().is_file() {
            return Err(LuksError::UnsupportedFsFeature(
                "deleting non-regular files is not supported".into(),
            ));
        }
        if located_target.inode.nlink > 1 {
            return Err(LuksError::UnsupportedFsFeature(
                "deleting files with hardlinks (nlink > 1) is not supported".into(),
            ));
        }

        let parent_ino = located_parent.inode.objectid;
        let target_ino = located_target.inode.objectid;

        // 1. Locate DIR_ITEM and verify it exists
        let name_hash = crate::fs::btrfs::crc32c::name_hash(filename.as_bytes());
        let dir_item_key = Key::new(parent_ino, DIR_ITEM_KEY, name_hash);
        let dir_item_raw = fs
            .find_item(fs.fs_tree().bytenr, &dir_item_key)?
            .ok_or_else(|| LuksError::NotFound(path.to_string()))?;
        let dir_entries = crate::fs::btrfs::inode::parse_dir_entries(&dir_item_raw)?;
        if !dir_entries
            .iter()
            .any(|e| e.name == filename.as_bytes() && e.location.objectid == target_ino)
        {
            return Err(LuksError::NotFound(path.to_string()));
        }

        // 2. Find dir_index for DIR_INDEX
        let inode_ref_key = Key::new(target_ino, INODE_REF_KEY, parent_ino);
        let dir_index = if let Some(ref_data) = fs.find_item(fs.fs_tree().bytenr, &inode_ref_key)? {
            if ref_data.len() >= 8 {
                u64::from_le_bytes(ref_data[0..8].try_into().unwrap())
            } else {
                0
            }
        } else {
            0
        };
        let dir_index = if dir_index != 0 {
            dir_index
        } else {
            let mut found_idx = 0;
            fs.for_each_item(
                fs.fs_tree().bytenr,
                parent_ino,
                DIR_INDEX_KEY,
                &mut |key, data| {
                    if let Ok(entries) = crate::fs::btrfs::inode::parse_dir_entries(data) {
                        for e in entries {
                            if e.name == filename.as_bytes() && e.location.objectid == target_ino {
                                found_idx = key.offset;
                                return Ok(false);
                            }
                        }
                    }
                    Ok(true)
                },
            )?;
            if found_idx == 0 {
                return Err(LuksError::CorruptFs("dir index not found for file"));
            }
            found_idx
        };
        let dir_index_key = Key::new(parent_ino, DIR_INDEX_KEY, dir_index);

        // 3. Scan all items for target_ino
        let mut target_items: Vec<(Key, Vec<u8>)> = Vec::new();
        let mut cursor = fs.search(fs.fs_tree().bytenr, &Key::new(target_ino, 0, 0))?;
        while cursor.valid() {
            let key = cursor.key()?;
            if key.objectid != target_ino {
                break;
            }
            target_items.push((key, cursor.data()?.to_vec()));
            cursor.advance()?;
        }

        // 4. Collect data extents to free
        let mut data_extents_to_free: Vec<(u64, u64)> = Vec::new();
        for (key, data) in &target_items {
            if key.item_type == EXTENT_DATA_KEY {
                let file_ext = crate::fs::btrfs::extent::FileExtent::parse(key.offset, data)?;
                if !file_ext.is_zeros() && file_ext.disk_bytenr > 0 && file_ext.disk_num_bytes > 0 {
                    data_extents_to_free.push((file_ext.disk_bytenr, file_ext.disk_num_bytes));
                }
            }
        }
        data_extents_to_free.sort_unstable();
        data_extents_to_free.dedup();

        let sb = fs.superblock();
        let new_generation = sb.generation + 1;

        let extent_tree = ExtentTree::read(fs)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::<(u64, u8, u64)>::new();
        let mut blocks_to_remove = Vec::<(u64, u8)>::new();

        let mut fs_root_bytenr = fs.fs_tree().bytenr;
        let mut fs_root_level = fs.fs_tree().level;

        // 5. CoW FS_TREE: Update parent directory DIR_ITEM
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &dir_item_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&dir_item_key)
                    .ok_or_else(|| LuksError::NotFound("dir item not found".into()))?;
                let existing_data = &leaf.items[idx].data;
                let mut new_dir_item_data = Vec::new();
                let mut cur = &existing_data[..];
                while !cur.is_empty() {
                    if cur.len() < 30 {
                        return Err(LuksError::CorruptFs("dir item truncated"));
                    }
                    let data_len = u16::from_le_bytes([cur[25], cur[26]]) as usize;
                    let name_len = u16::from_le_bytes([cur[27], cur[28]]) as usize;
                    let total = 30 + name_len + data_len;
                    if total > cur.len() {
                        return Err(LuksError::CorruptFs("dir item overruns"));
                    }
                    let name = &cur[30..30 + name_len];
                    let child_ino = u64::from_le_bytes(cur[0..8].try_into().unwrap());
                    if !(name == filename.as_bytes() && child_ino == target_ino) {
                        new_dir_item_data.extend_from_slice(&cur[..total]);
                    }
                    cur = &cur[total..];
                }
                if new_dir_item_data.is_empty() {
                    leaf.delete_item(&dir_item_key)?;
                } else {
                    leaf.items[idx].data = new_dir_item_data;
                }
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

        // 6. CoW FS_TREE: Delete parent directory DIR_INDEX
        let res = cow_tree_mutate(
            fs,
            &pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &dir_index_key,
            new_generation,
            &mut allocator,
            |leaf| {
                leaf.delete_item(&dir_index_key)?;
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

        // 7. CoW FS_TREE: Update parent directory INODE_ITEM
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
                let item_data = &mut leaf.items[idx].data;
                if item_data.len() < 160 {
                    return Err(LuksError::CorruptFs("parent inode item truncated"));
                }
                item_data[8..16].copy_from_slice(&new_generation.to_le_bytes()); // transid
                let cur_size = u64::from_le_bytes(item_data[16..24].try_into().unwrap());
                item_data[16..24]
                    .copy_from_slice(&(cur_size.saturating_sub(name_len * 2)).to_le_bytes()); // size
                let seq =
                    u64::from_le_bytes(item_data[72..80].try_into().unwrap()).wrapping_add(1);
                item_data[72..80].copy_from_slice(&seq.to_le_bytes()); // sequence
                item_data[124..132].copy_from_slice(&now_sec.to_le_bytes()); // ctime
                item_data[132..136].copy_from_slice(&now_nsec.to_le_bytes());
                item_data[136..144].copy_from_slice(&now_sec.to_le_bytes()); // mtime
                item_data[144..148].copy_from_slice(&now_nsec.to_le_bytes());
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

        // 8. CoW FS_TREE: Delete all items with objectid == target_ino
        for (item_key, _) in &target_items {
            let res = cow_tree_mutate(
                fs,
                &pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                FS_TREE_OBJECTID,
                item_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    leaf.delete_item(item_key)?;
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
        }

        // 9. Free data extents in allocator
        for &(bytenr, num_bytes) in &data_extents_to_free {
            allocator.free_data(bytenr, num_bytes)?;
        }

        // 10. CoW CSUM_TREE: Delete EXTENT_CSUM items covering freed data extents
        let mut csum_root_opt = None;
        if !data_extents_to_free.is_empty() {
            if let Ok(csum_root) = fs.tree_root(CSUM_TREE_OBJECTID) {
                let mut csum_keys_to_delete = Vec::new();
                for &(disk_bytenr, disk_num_bytes) in &data_extents_to_free {
                    let search_key = Key::new(
                        EXTENT_CSUM_OBJECTID,
                        EXTENT_CSUM_KEY,
                        disk_bytenr,
                    );
                    let mut cursor = fs.search_le(csum_root.bytenr, &search_key)?;
                    while cursor.valid() {
                        let key = cursor.key()?;
                        if key.objectid != EXTENT_CSUM_OBJECTID
                            || key.item_type != EXTENT_CSUM_KEY
                        {
                            if key < Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, 0) {
                                cursor.advance()?;
                                continue;
                            }
                            break;
                        }
                        if key.offset >= disk_bytenr + disk_num_bytes {
                            break;
                        }
                        if key.offset >= disk_bytenr {
                            csum_keys_to_delete.push(key);
                        }
                        cursor.advance()?;
                    }
                }
                csum_keys_to_delete.sort_unstable();
                csum_keys_to_delete.dedup();

                if !csum_keys_to_delete.is_empty() {
                    let mut csum_root_bytenr = csum_root.bytenr;
                    let mut csum_root_level = csum_root.level;

                    for csum_key in csum_keys_to_delete {
                        let res = cow_tree_mutate(
                            fs,
                            &pending_blocks,
                            csum_root_bytenr,
                            csum_root_level,
                            CSUM_TREE_OBJECTID,
                            &csum_key,
                            new_generation,
                            &mut allocator,
                            |leaf| {
                                leaf.delete_item(&csum_key)?;
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
                            CSUM_TREE_OBJECTID,
                        )?;
                        csum_root_bytenr = res.new_root_bytenr;
                        csum_root_level = res.new_root_level;
                    }

                    csum_root_opt = Some((csum_root_bytenr, csum_root_level));
                }
            }
        }

        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        converge_and_finalize(
            fs,
            new_generation,
            new_fs_tree,
            csum_root_opt,
            None,
            None,
            None,
            pending_blocks,
            Vec::new(),
            allocator,
            blocks_to_add,
            blocks_to_remove,
            Vec::new(),
            data_extents_to_free,
        )
    }

    /// Prepare a transaction that allocates a new single DATA chunk.
    pub fn allocate_data_chunk<D: ReadAt>(
        fs: &Btrfs<D>,
    ) -> Result<(Self, crate::fs::btrfs::chunk::Chunk)> {
        crate::fs::btrfs::write::chunk_alloc::allocate_data_chunk_transaction(fs)
    }
}

pub(crate) fn record_cow_result(
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

/// Find an item with `key` in the tree rooted at `root_bytenr`, consulting `pending_blocks` if available.
pub(crate) fn find_item_in_tree<D: ReadAt>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    root_bytenr: u64,
    key: &Key,
) -> Result<Option<Vec<u8>>> {
    let mut curr_bytenr = root_bytenr;
    let mut depth = 0;
    while depth < 16 {
        let node = crate::fs::btrfs::write::cow::read_node(fs, pending, curr_bytenr)?;
        if node.is_leaf() {
            for i in 0..node.nr_items {
                if node.key(i)? == *key {
                    return Ok(Some(node.item_data(i)?.to_vec()));
                }
            }
            return Ok(None);
        }
        if node.nr_items == 0 {
            return Ok(None);
        }
        let mut child_bytenr = None;
        for i in (0..node.nr_items).rev() {
            let k = node.key(i)?;
            if *key >= k {
                child_bytenr = Some(node.key_ptr(i)?.blockptr);
                break;
            }
        }
        match child_bytenr {
            Some(ptr) => curr_bytenr = ptr,
            None => return Ok(None),
        }
        depth += 1;
    }
    Ok(None)
}

/// Highest real inode number present in the FS tree, or `256` if there are
/// none (the lowest inode objectid btrfs hands out; `1..255` are reserved).
///
/// Descending only the rightmost key pointer at every level (the previous
/// implementation) assumes the largest real inode lives in the rightmost
/// leaf. Sort order does put it there *if* that leaf holds any real inodes —
/// but btrfs's reserved objectids (`ORPHAN_OBJECTID` = `-5`,
/// `FREE_INO_OBJECTID`, etc.) count down from `u64::MAX` and sort after every
/// real inode, so a leaf that holds only reserved-objectid items (e.g. an
/// `ORPHAN_ITEM`, left behind by deleting a file that's still open) sorts
/// last and pushes every real inode out of "the rightmost leaf". The old code
/// would then filter every item out and silently return 256, handing the
/// caller an inode number already in use.
///
/// The fix: start a cursor at the top of the *real*-inode range
/// (`0xFFFF_FFFF_FFFF_FEFF`, the highest legal offset/type at the highest
/// non-reserved objectid) and walk backwards, crossing leaf boundaries via
/// `Cursor::retreat`, until an item with a plausible-inode objectid turns up
/// or the tree is exhausted. This is a genuine search rather than a bet on
/// tree shape, so it is correct regardless of how many reserved-objectid
/// items trail off the end.
///
/// Filtering is on objectid alone, not on `INODE_ITEM_KEY`: every item that
/// belongs to inode N (`INODE_ITEM`, `INODE_REF`, `DIR_ITEM`, `EXTENT_DATA`,
/// ...) shares N as its objectid, and because keys sort by objectid first,
/// the maximum objectid over *any* item type equals the maximum objectid
/// over `INODE_ITEM`s specifically — but reaching it doesn't require the
/// INODE_ITEM to be the last item of that inode's run, so type-filtering
/// would just mean extra retreats for the same answer. Restricting to
/// `INODE_ITEM_KEY` only would still be correct, just costs more steps when
/// an inode's non-INODE_ITEM items (e.g. a later DIR_ITEM/EXTENT_DATA,
/// type > 1) sort after it.
pub(crate) fn find_max_inode<D: ReadAt>(fs: &Btrfs<D>) -> Result<u64> {
    const MAX_REAL_INODE_KEY: Key = Key {
        objectid: 0xFFFF_FFFF_FFFF_FEFF,
        item_type: u8::MAX,
        offset: u64::MAX,
    };

    let mut cursor = fs.search_le(fs.fs_tree().bytenr, &MAX_REAL_INODE_KEY)?;
    loop {
        if !cursor.valid() {
            return Ok(256);
        }
        let key = cursor.key()?;
        if key.objectid >= 256 && key.objectid < 0xFFFF_FFFF_FFFF_FF00 {
            return Ok(key.objectid);
        }
        cursor.retreat()?;
    }
}

pub(crate) fn converge_and_finalize<D: ReadAt>(
    fs: &Btrfs<D>,
    new_generation: u64,
    new_fs_tree: TreeRoot,
    csum_root_opt: Option<(u64, u8)>,
    dev_root_opt: Option<(u64, u8)>,
    chunk_root_opt: Option<(u64, u8)>,
    extent_root_opt: Option<(u64, u8)>,
    mut pending_blocks: HashMap<u64, Vec<u8>>,
    pending_data: Vec<(u64, Vec<u8>)>,
    mut allocator: FreeSpaceMap,
    mut blocks_to_add: Vec<(u64, u8, u64)>,
    mut blocks_to_remove: Vec<(u64, u8)>,
    data_extents_to_add: Vec<(u64, u64, u64, u64, u64)>,
    data_extents_to_remove: Vec<(u64, u64)>,
) -> Result<Transaction> {
    let sb = fs.superblock();
    let mut root_tree_bytenr = sb.root;
    let mut root_tree_level = sb.root_level;
    let (mut extent_root_bytenr, mut extent_root_level) = match extent_root_opt {
        Some((b, l)) => (b, l),
        None => {
            let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
            (extent_root.bytenr, extent_root.level)
        }
    };

    // 1. Update FS_TREE root item in ROOT_TREE if modified.
    if new_fs_tree.bytenr != fs.fs_tree().bytenr {
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
    }

    // 2. Update CSUM_TREE root item in ROOT_TREE if modified
    if let Some((csum_bytenr, csum_level)) = csum_root_opt {
        let csum_root_key = Key::new(CSUM_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &csum_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&csum_root_key)
                    .ok_or_else(|| LuksError::NotFound("csum root item not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&csum_bytenr.to_le_bytes());
                data[238] = csum_level;
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

    // 2b. Update DEV_TREE root item in ROOT_TREE if modified
    if let Some((dev_bytenr, dev_level)) = dev_root_opt {
        let dev_root_key = Key::new(crate::fs::btrfs::tree::DEV_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &dev_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&dev_root_key)
                    .ok_or_else(|| LuksError::NotFound("dev root item not found in root tree".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("dev root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&dev_bytenr.to_le_bytes());
                data[238] = dev_level;
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

    // 3. Insert newly allocated data extents into EXTENT_TREE
    for (bytenr, len, root, ino, offset) in data_extents_to_add {
        let (data_key, data_payload) =
            ExtentItem::emit_data_extent(bytenr, len, new_generation, root, ino, offset);
        let ext_res = cow_tree_insert(
            fs,
            &pending_blocks,
            extent_root_bytenr,
            extent_root_level,
            EXTENT_TREE_OBJECTID,
            data_key,
            data_payload,
            new_generation,
            &mut allocator,
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

    // 3b. Delete freed data extents from EXTENT_TREE
    for (bytenr, len) in data_extents_to_remove {
        let ext_key = Key::new(bytenr, EXTENT_ITEM_KEY, len);
        let ext_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            extent_root_bytenr,
            extent_root_level,
            EXTENT_TREE_OBJECTID,
            &ext_key,
            new_generation,
            &mut allocator,
            |leaf| {
                leaf.delete_item(&ext_key)?;
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

    let mut fst_bytenr_opt: Option<u64> = None;

    // 4. Fixed-point loop to record allocations and update root pointers until convergence.
    // High-fragmentation 4K-node filesystems or multi-extent transfers can take
    // up to ~15 rounds of extent-tree CoW feedback before reaching 0 pending blocks.
    const MAX_CONVERGENCE_ROUNDS: u32 = 30;
    let mut converged = false;
    for _iteration in 0..MAX_CONVERGENCE_ROUNDS {
        if blocks_to_add.is_empty() && blocks_to_remove.is_empty() {
            // Convergence achieved
            converged = true;
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
            // `cow_tree_insert`, not `cow_tree_mutate`: this is a brand new key
            // (the block was just allocated, so no METADATA_ITEM for it can
            // already exist), not an edit of one already in the leaf.
            // `cow_tree_mutate`'s leaf branch has no split path at all — it
            // calls `mutate_fn` and unconditionally emits, so once the extent
            // tree's target leaf was full this failed closed with
            // `FilesystemFull` even with the rest of the filesystem empty.
            // Measured 2026-08-15: a probe against a *freshly mkfs'd, mostly
            // empty* mixed-4k.img (no prior fragmentation) hit exactly this
            // error via this call site at the 319th file created, long
            // before the FS tree itself needed an interior split — meaning
            // the "adversarial 5,557-file run hit FilesystemFull" this
            // project's plan attributed to running out of physical space was
            // very likely this bug, not exhausted media. `cow_tree_insert`
            // already carries the leaf-split and root-height-increment logic
            // this needs, and is already used for extent-tree data-extent
            // inserts a few lines above — this just makes metadata-item
            // inserts consistent with that.
            let ext_res = cow_tree_insert(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                meta_key,
                meta_data,
                new_generation,
                &mut allocator,
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

        // Update Free Space Tree if present on this filesystem.
        //
        // Rewritten wholesale from the allocator's own view rather than
        // edited in place, and therefore emitted as a single leaf — which is
        // only correct for a single-leaf tree, so that shape is refused up
        // front rather than silently mangled. Leaving the tree stale instead
        // is not an option: `btrfs check` cross-checks its contents against
        // the extent tree even with FREE_SPACE_TREE_VALID cleared (measured
        // 2026-08-14; see the §2 correction in feature-btrfs-write.md).
        if sb.compat_ro_flags & BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE != 0 {
            if let Ok(fst_root) = fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
                gate::check_free_space_tree_shape(&fst_root)?;

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
                // The same single-leaf limit, caught from the other side: the
                // tree can start as one leaf and still not fit in one once
                // this write fragments free space. `emit` would report this
                // as a bare FilesystemFull, which reads as "the drive is
                // full" — a different and much more alarming claim than the
                // true one, and `RULES.md` requires an error to name its own
                // operation.
                if fst_leaf.free_space(sb.node_size) == 0 {
                    return Err(LuksError::UnsupportedFsFeature(
                        "btrfs free-space tree no longer fits in a single leaf".into(),
                    ));
                }
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

    // The loop above has a round cap so a bug cannot spin forever. Until now it
    // simply *exited* at the cap, which is the silent-failure shape this repo
    // keeps paying for: leftover `blocks_to_add` means blocks were allocated
    // and handed to the commit with no `METADATA_ITEM` recording them, so
    // `btrfs check` would report backref errors on a filesystem we had just
    // declared written. Refuse instead, and say which side did not settle.
    //
    // Live rather than theoretical now: splitting checksums across many items
    // (a 400 MB file needs ~25) multiplies the blocks each round has to record,
    // so the assumption that three rounds always suffice stopped being free.
    if !converged && !(blocks_to_add.is_empty() && blocks_to_remove.is_empty()) {
        return Err(LuksError::CorruptFs(
            "btrfs transaction did not converge: extent-tree bookkeeping still \
             had blocks to record after the round limit",
        ));
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
        final_chunk_root: chunk_root_opt,
        final_bytes_used,
        new_fs_tree,
        pending_blocks,
        pending_data,
    })
}
