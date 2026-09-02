//! `Transaction::delete_file`.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{
    Key, CSUM_TREE_OBJECTID, DIR_INDEX_KEY, DIR_ITEM_KEY, EXTENT_CSUM_KEY, EXTENT_CSUM_OBJECTID,
    EXTENT_DATA_KEY, FS_TREE_OBJECTID, INODE_ITEM_KEY, INODE_REF_KEY,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::cow_tree_mutate;
use crate::fs::btrfs::write::extent_tree::{converge_and_finalize, record_cow_result, ExtentTree};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::Btrfs;

use super::Transaction;

impl Transaction {
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
        let target_is_dir = located_target.inode.file_type().is_dir();
        if target_is_dir {
            // DIR_INDEX and DIR_ITEM always come in pairs per entry (see
            // `list_dir_by_inode`), so one DIR_INDEX item proves the
            // directory has at least one child. Below, deleting a directory
            // reuses the same generic "every item keyed under this objectid"
            // sweep as deleting a file's own metadata — for a directory that
            // sweep would also catch its children's DIR_ITEM/DIR_INDEX
            // entries (they're keyed under the *parent's* objectid), erasing
            // the names without freeing what they pointed to. Refusing a
            // non-empty directory here is what prevents that.
            let mut has_children = false;
            fs.for_each_item(
                fs.fs_tree().bytenr,
                located_target.inode.objectid,
                DIR_INDEX_KEY,
                &mut |_, _| {
                    has_children = true;
                    Ok(false)
                },
            )?;
            if has_children {
                return Err(LuksError::DirectoryNotEmpty(path.to_string()));
            }
        } else if !located_target.inode.file_type().is_file() {
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
                if file_ext.has_disk_bytes() {
                    data_extents_to_free.push((file_ext.disk_bytenr, file_ext.disk_num_bytes));
                }
            }
        }
        data_extents_to_free.sort_unstable();
        data_extents_to_free.dedup();

        // G1: Refuse to free shared extents (refs > 1). This prevents
        // data corruption when deleting files that share extents via
        // reflink, deduplication, or snapshots.
        // We read the extent tree early to check refs before proceeding.
        {
            let extent_tree_for_refs = ExtentTree::read(fs)?;
            for &(bytenr, _num_bytes) in &data_extents_to_free {
                if let Some(ext) = extent_tree_for_refs.extents.iter().find(|e| e.bytenr == bytenr) {
                    if ext.refs > 1 {
                        return Err(LuksError::UnsupportedFsFeature(
                            "deleting a file with shared data extents (refs > 1) is not supported".into(),
                        ));
                    }
                }
            }
        }

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

        crate::forensic::record_btrfs(crate::forensic::BtrfsEvent::DeleteFile {
            parent_ino,
            ino: target_ino,
        });

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
}
