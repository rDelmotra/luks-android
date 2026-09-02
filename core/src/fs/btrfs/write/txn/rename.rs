//! `Transaction::rename`.
//!
//! Split into a resolution phase (path lookup, cycle detection, destination
//! collision analysis — read-only) and three CoW phases (destination
//! overwrite, dirent/INODE_REF swap, final bookkeeping), each a private
//! helper function taking the same transaction-building state
//! (`pending_blocks`, `allocator`, `blocks_to_add`/`blocks_to_remove`,
//! `fs_root_bytenr`/`fs_root_level`) that the original inline code threaded
//! through by hand. The helpers only repackage that existing dataflow into
//! parameters; none of them change what is computed or in what order.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{
    Key, CSUM_TREE_OBJECTID, DIR_INDEX_KEY, DIR_ITEM_KEY, EXTENT_CSUM_KEY, EXTENT_CSUM_OBJECTID,
    EXTENT_DATA_KEY, FS_TREE_OBJECTID, INODE_ITEM_KEY, INODE_REF_KEY,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::extent_tree::{
    converge_and_finalize, find_item_in_tree, record_cow_result, ExtentTree,
};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::Btrfs;

use super::Transaction;

/// Everything the resolution phase determined, needed by the CoW phases.
struct RenamePlan {
    old_parent_ino: u64,
    new_parent_ino: u64,
    child_ino: u64,
    child_file_type: u8,
    /// `(dest_ino, dest_is_dir, dest_dir_index, data_extents_to_free)` if the
    /// destination name already exists and will be overwritten/replaced.
    dest_replacement: Option<(u64, bool, u64, Vec<(u64, u64)>)>,
    old_dir_index: u64,
    new_dir_index: u64,
}

/// Outcome of the resolution phase: either the rename is a no-op (already
/// resolved to a completed `update_inode_mtime` transaction) or a `RenamePlan`
/// for the CoW phases to execute.
enum RenameResolution {
    NoOp(Transaction),
    Proceed(RenamePlan),
}

impl Transaction {
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

        let plan = match resolve_rename(
            fs,
            old_parent_path,
            old_name,
            new_parent_path,
            new_name,
            now_sec,
            now_nsec,
        )? {
            RenameResolution::NoOp(txn) => return Ok(txn),
            RenameResolution::Proceed(plan) => plan,
        };

        crate::forensic::record_btrfs(crate::forensic::BtrfsEvent::Rename {
            from_parent: plan.old_parent_ino,
            to_parent: plan.new_parent_ino,
            ino: plan.child_ino,
        });

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
        let dest_replaced = plan.dest_replacement.is_some();

        // 1. If replacing destination, delete destination inode items and free its data
        if let Some((dest_ino, _dest_is_dir, dest_dir_index, freed_extents)) = plan.dest_replacement {
            data_extents_to_free = freed_extents;

            let (b, l) = rename_delete_destination(
                fs,
                &mut pending_blocks,
                fs_root_bytenr,
                fs_root_level,
                new_generation,
                &mut allocator,
                &mut blocks_to_add,
                &mut blocks_to_remove,
                sb.node_size,
                dest_ino,
                dest_dir_index,
                plan.new_parent_ino,
                new_name,
            )?;
            fs_root_bytenr = b;
            fs_root_level = l;
        }

        // 2 & 3 & 4. Delete old dirent, insert new dirent, update child INODE_REF.
        let (b, l) = rename_swap_dirent(
            fs,
            &mut pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            new_generation,
            &mut allocator,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            sb.node_size,
            plan.old_parent_ino,
            old_name,
            plan.old_dir_index,
            plan.new_parent_ino,
            new_name,
            plan.new_dir_index,
            plan.child_ino,
            plan.child_file_type,
        )?;
        fs_root_bytenr = b;
        fs_root_level = l;

        // 5, 6 & 7. Update child/parent INODE_ITEMs, free extents and csums.
        let (b, l, csum_root_opt) = rename_finalize_bookkeeping(
            fs,
            &mut pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            new_generation,
            &mut allocator,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            sb.node_size,
            plan.child_ino,
            plan.old_parent_ino,
            plan.new_parent_ino,
            old_name.len() as u64,
            new_name.len() as u64,
            dest_replaced,
            now_sec,
            now_nsec,
            &data_extents_to_free,
        )?;
        fs_root_bytenr = b;
        fs_root_level = l;

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
}

/// Path resolution, cycle detection, and destination-collision analysis for
/// `rename`. Entirely read-only against `fs` — no CoW state exists yet.
fn resolve_rename<D: ReadAt>(
    fs: &Btrfs<D>,
    old_parent_path: &str,
    old_name: &str,
    new_parent_path: &str,
    new_name: &str,
    now_sec: u64,
    now_nsec: u32,
) -> Result<RenameResolution> {
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
        return Ok(RenameResolution::NoOp(Transaction::update_inode_mtime(
            fs, child_ino, now_sec, now_nsec,
        )?));
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
            return Ok(RenameResolution::NoOp(Transaction::update_inode_mtime(
                fs, child_ino, now_sec, now_nsec,
            )?));
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
                    if file_ext.has_disk_bytes() {
                        data_extents_to_free.push((file_ext.disk_bytenr, file_ext.disk_num_bytes));
                    }
                }
                cursor.advance()?;
            }
            data_extents_to_free.sort_unstable();
            data_extents_to_free.dedup();

            // G1: Refuse to free shared extents on rename-overwrite.
            {
                let extent_tree_for_refs = ExtentTree::read(fs)?;
                for &(bytenr, _num_bytes) in &data_extents_to_free {
                    if let Some(ext) = extent_tree_for_refs.extents.iter().find(|e| e.bytenr == bytenr) {
                        if ext.refs > 1 {
                            return Err(LuksError::UnsupportedFsFeature(
                                "overwriting a file with shared data extents (refs > 1) is not supported".into(),
                            ));
                        }
                    }
                }
            }

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

    Ok(RenameResolution::Proceed(RenamePlan {
        old_parent_ino,
        new_parent_ino,
        child_ino,
        child_file_type,
        dest_replacement,
        old_dir_index,
        new_dir_index,
    }))
}

/// Step 1: delete the overwritten destination's items, its `DIR_INDEX` in
/// `new_parent_ino`, and its entry inside `new_parent_ino`'s `DIR_ITEM`.
#[allow(clippy::too_many_arguments)]
fn rename_delete_destination<D: ReadAt>(
    fs: &Btrfs<D>,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    mut fs_root_bytenr: u64,
    mut fs_root_level: u8,
    new_generation: u64,
    allocator: &mut FreeSpaceMap,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8)>,
    node_size: u32,
    dest_ino: u64,
    dest_dir_index: u64,
    new_parent_ino: u64,
    new_name: &str,
) -> Result<(u64, u8)> {
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
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            item_key,
            new_generation,
            allocator,
            |leaf| {
                leaf.delete_item(item_key)?;
                Ok(())
            },
        )?;
        record_cow_result(
            &res,
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
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
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &dest_dir_index_key,
            new_generation,
            allocator,
            |leaf| {
                leaf.delete_item(&dest_dir_index_key)?;
                Ok(())
            },
        )?;
        record_cow_result(
            &res,
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
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
        pending_blocks,
        fs_root_bytenr,
        fs_root_level,
        FS_TREE_OBJECTID,
        &dest_dir_item_key,
        new_generation,
        allocator,
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
        blocks_to_add,
        blocks_to_remove,
        allocator,
        pending_blocks,
        node_size,
        FS_TREE_OBJECTID,
    )?;
    fs_root_bytenr = res.new_root_bytenr;
    fs_root_level = res.new_root_level;

    Ok((fs_root_bytenr, fs_root_level))
}

/// Steps 2-4: delete `old_name`'s `DIR_ITEM`/`DIR_INDEX` from `old_parent_ino`,
/// insert `new_name`'s `DIR_ITEM`/`DIR_INDEX` into `new_parent_ino`, and update
/// the child's `INODE_REF`.
#[allow(clippy::too_many_arguments)]
fn rename_swap_dirent<D: ReadAt>(
    fs: &Btrfs<D>,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    mut fs_root_bytenr: u64,
    mut fs_root_level: u8,
    new_generation: u64,
    allocator: &mut FreeSpaceMap,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8)>,
    node_size: u32,
    old_parent_ino: u64,
    old_name: &str,
    old_dir_index: u64,
    new_parent_ino: u64,
    new_name: &str,
    new_dir_index: u64,
    child_ino: u64,
    child_file_type: u8,
) -> Result<(u64, u8)> {
    // 2. Delete old name DIR_ITEM and DIR_INDEX from old_parent
    let old_name_hash = crate::fs::btrfs::crc32c::name_hash(old_name.as_bytes());
    let old_dir_item_key = Key::new(old_parent_ino, DIR_ITEM_KEY, old_name_hash);
    let res = cow_tree_mutate(
        fs,
        pending_blocks,
        fs_root_bytenr,
        fs_root_level,
        FS_TREE_OBJECTID,
        &old_dir_item_key,
        new_generation,
        allocator,
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
        blocks_to_add,
        blocks_to_remove,
        allocator,
        pending_blocks,
        node_size,
        FS_TREE_OBJECTID,
    )?;
    fs_root_bytenr = res.new_root_bytenr;
    fs_root_level = res.new_root_level;

    let old_dir_index_key = Key::new(old_parent_ino, DIR_INDEX_KEY, old_dir_index);
    let res = cow_tree_mutate(
        fs,
        pending_blocks,
        fs_root_bytenr,
        fs_root_level,
        FS_TREE_OBJECTID,
        &old_dir_index_key,
        new_generation,
        allocator,
        |leaf| {
            leaf.delete_item(&old_dir_index_key)?;
            Ok(())
        },
    )?;
    record_cow_result(
        &res,
        blocks_to_add,
        blocks_to_remove,
        allocator,
        pending_blocks,
        node_size,
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

    let existing_new_dir_item = find_item_in_tree(fs, pending_blocks, fs_root_bytenr, &new_dir_item_key)?;
    if let Some(existing_data) = existing_new_dir_item {
        let mut merged_data = existing_data;
        merged_data.extend_from_slice(&new_dir_item_entry);
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &new_dir_item_key,
            new_generation,
            allocator,
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
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    } else {
        let res = cow_tree_insert(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            new_dir_item_key,
            new_dir_item_entry.clone(),
            new_generation,
            allocator,
        )?;
        record_cow_result(
            &res,
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    }

    let new_dir_index_key = Key::new(new_parent_ino, DIR_INDEX_KEY, new_dir_index);
    let res = cow_tree_insert(
        fs,
        pending_blocks,
        fs_root_bytenr,
        fs_root_level,
        FS_TREE_OBJECTID,
        new_dir_index_key,
        new_dir_item_entry,
        new_generation,
        allocator,
    )?;
    record_cow_result(
        &res,
        blocks_to_add,
        blocks_to_remove,
        allocator,
        pending_blocks,
        node_size,
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
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &child_ref_key,
            new_generation,
            allocator,
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
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    } else {
        let old_child_ref_key = Key::new(child_ino, INODE_REF_KEY, old_parent_ino);
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &old_child_ref_key,
            new_generation,
            allocator,
            |leaf| {
                leaf.delete_item(&old_child_ref_key)?;
                Ok(())
            },
        )?;
        record_cow_result(
            &res,
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        let new_child_ref_key = Key::new(child_ino, INODE_REF_KEY, new_parent_ino);
        let res = cow_tree_insert(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            new_child_ref_key,
            new_inode_ref_data,
            new_generation,
            allocator,
        )?;
        record_cow_result(
            &res,
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    }

    Ok((fs_root_bytenr, fs_root_level))
}

/// Steps 5-7: update the child's `INODE_ITEM`, update the parent(s)'
/// `INODE_ITEM`(s), and free any data extents/csums freed by a destination
/// overwrite.
#[allow(clippy::too_many_arguments)]
fn rename_finalize_bookkeeping<D: ReadAt>(
    fs: &Btrfs<D>,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    mut fs_root_bytenr: u64,
    mut fs_root_level: u8,
    new_generation: u64,
    allocator: &mut FreeSpaceMap,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8)>,
    node_size: u32,
    child_ino: u64,
    old_parent_ino: u64,
    new_parent_ino: u64,
    old_name_len: u64,
    new_name_len: u64,
    dest_replaced: bool,
    now_sec: u64,
    now_nsec: u32,
    data_extents_to_free: &[(u64, u64)],
) -> Result<(u64, u8, Option<(u64, u8)>)> {
    // 5. Update child INODE_ITEM (ctime, sequence, transid)
    let child_inode_key = Key::new(child_ino, INODE_ITEM_KEY, 0);
    let res = cow_tree_mutate(
        fs,
        pending_blocks,
        fs_root_bytenr,
        fs_root_level,
        FS_TREE_OBJECTID,
        &child_inode_key,
        new_generation,
        allocator,
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
        blocks_to_add,
        blocks_to_remove,
        allocator,
        pending_blocks,
        node_size,
        FS_TREE_OBJECTID,
    )?;
    fs_root_bytenr = res.new_root_bytenr;
    fs_root_level = res.new_root_level;

    // 6. Update parent INODE_ITEM(s)
    if old_parent_ino == new_parent_ino {
        let parent_inode_key = Key::new(old_parent_ino, INODE_ITEM_KEY, 0);
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &parent_inode_key,
            new_generation,
            allocator,
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
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    } else {
        // Update old_parent INODE_ITEM
        let old_parent_inode_key = Key::new(old_parent_ino, INODE_ITEM_KEY, 0);
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &old_parent_inode_key,
            new_generation,
            allocator,
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
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // Update new_parent INODE_ITEM
        let new_parent_inode_key = Key::new(new_parent_ino, INODE_ITEM_KEY, 0);
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &new_parent_inode_key,
            new_generation,
            allocator,
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
            blocks_to_add,
            blocks_to_remove,
            allocator,
            pending_blocks,
            node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;
    }

    // 7. Free data extents and remove csums if destination was replaced
    let mut csum_root_opt = None;
    if !data_extents_to_free.is_empty() {
        for &(bytenr, num_bytes) in data_extents_to_free {
            allocator.free_data(bytenr, num_bytes)?;
        }

        if let Ok(csum_root) = fs.tree_root(CSUM_TREE_OBJECTID) {
            let mut csum_keys_to_delete = Vec::new();
            for &(disk_bytenr, disk_num_bytes) in data_extents_to_free {
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
                        pending_blocks,
                        csum_root_bytenr,
                        csum_root_level,
                        CSUM_TREE_OBJECTID,
                        &csum_key,
                        new_generation,
                        allocator,
                        |leaf| {
                            leaf.delete_item(&csum_key)?;
                            Ok(())
                        },
                    )?;
                    record_cow_result(
                        &res,
                        blocks_to_add,
                        blocks_to_remove,
                        allocator,
                        pending_blocks,
                        node_size,
                        CSUM_TREE_OBJECTID,
                    )?;
                    csum_root_bytenr = res.new_root_bytenr;
                    csum_root_level = res.new_root_level;
                }

                csum_root_opt = Some((csum_root_bytenr, csum_root_level));
            }
        }
    }

    Ok((fs_root_bytenr, fs_root_level, csum_root_opt))
}
