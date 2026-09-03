//! `Transaction::create_empty_file`, `create_directory`, `create_directory_in_dir`.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{Key, FS_TREE_OBJECTID, INODE_ITEM_KEY};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::extent_tree::{
    converge_and_finalize, find_item_in_tree, find_max_inode, record_cow_result, ExtentTree,
};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::Btrfs;

use super::Transaction;

impl Transaction {
    /// Prepare a transaction that creates a new empty regular file inside `parent_path`.
    pub fn create_empty_file<D: ReadAt>(
        fs: &Btrfs<D>,
        parent_path: &str,
        filename: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<Self> {
        gate::check_writeable_fs(fs.superblock())?;
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

        crate::forensic::record_btrfs(crate::forensic::BtrfsEvent::CreateFile {
            parent_ino,
            new_ino,
        });

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
        gate::check_writeable_fs(fs.superblock())?;
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
        gate::check_writeable_fs(fs.superblock())?;
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

        crate::forensic::record_btrfs(crate::forensic::BtrfsEvent::Mkdir {
            parent_ino,
            new_ino,
        });

        Ok((txn, new_ino))
    }
}
