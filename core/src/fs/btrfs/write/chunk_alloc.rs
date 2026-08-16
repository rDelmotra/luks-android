//! btrfs chunk allocation search algorithms (Pass H.2).
//!
//! Implements the three read-only search algorithms (§7 steps 1-3) required for
//! chunk allocation:
//! 1. [`next_logical`]: Finds the highest logical end across existing chunks.
//! 2. [`decide_data_chunk_size`]: Calculates chunk size using kernel stripe sizing rules.
//! 3. [`find_free_dev_extent`]: First-fit search for physical device holes.
//!
//! Also provides [`read_dev_extents`] to retrieve existing physical extents from DEV_TREE.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::chunk::{Chunk, ChunkMap, DevExtent, BLOCK_GROUP_DATA};
use crate::fs::btrfs::superblock::BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE;
use crate::fs::btrfs::tree::{
    Key, CHUNK_TREE_OBJECTID, DEV_EXTENT_KEY, DEV_ITEMS_OBJECTID, DEV_ITEM_KEY, DEV_TREE_OBJECTID,
    EXTENT_TREE_OBJECTID, FIRST_CHUNK_TREE_OBJECTID, FREE_SPACE_TREE_OBJECTID,
};
use crate::fs::btrfs::write::alloc::{BlockGroupFreeSpace, FreeRange, FreeSpaceMap};
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::exclude::compute_sb_exclusions;
use crate::fs::btrfs::write::extent_tree::{BlockGroupItem, ExtentTree};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::txn::{converge_and_finalize, record_cow_result, Transaction};
use crate::fs::btrfs::Btrfs;

/// 64 KiB alignment / minimum stripe boundary.
pub const SZ_64K: u64 = 64 * 1024;
/// 16 MiB chunk sizing granularity in the kernel.
pub const SZ_16M: u64 = 16 * 1024 * 1024;
/// 64 MiB default minimum stripe size for DATA.
pub const SZ_64M: u64 = 64 * 1024 * 1024;
/// 1 GiB per-stripe cap.
pub const SZ_1G: u64 = 1024 * 1024 * 1024;
/// 10 GiB maximum chunk limit.
pub const SZ_10G: u64 = 10 * 1024 * 1024 * 1024;

/// Reserved 1 MiB at device start for superblock and bootloader (`BTRFS_BLOCK_RESERVED_1M_FOR_SUPER`).
pub const BTRFS_BLOCK_RESERVED_1M_FOR_SUPER: u64 = 1024 * 1024;

/// Default minimum stripe size for DATA chunks (64 MiB).
pub const MIN_DATA_CHUNK_SIZE: u64 = SZ_64M;
/// Absolute floor for stripe allocation (64 KiB).
pub const MIN_STRIPE_SIZE_FLOOR: u64 = SZ_64K;

/// Search 1: Compute the next contiguous logical address above all existing chunks.
///
/// In btrfs, logical allocations are contiguous and appended to the existing address space.
/// Returns the highest `chunk.logical + chunk.length` among all chunks in `chunk_map`.
/// If `chunk_map` is empty, returns `0`.
pub fn next_logical(chunk_map: &ChunkMap) -> u64 {
    chunk_map
        .chunks()
        .iter()
        .map(|c| c.logical.saturating_add(c.length))
        .max()
        .unwrap_or(0)
}

/// Search 2: Decide the size of a single-profile DATA chunk based on total device size.
///
/// Implements the exact kernel rule from `decide_stripe_size_regular` (`fs/btrfs/volumes.c`):
/// - Calculates 10% of `total_rw_bytes`, capped at 10 GiB.
/// - Rounds up to a 16 MiB multiple.
/// - Caps at 1 GiB per stripe.
/// - Rounds down to a 64 KiB multiple.
pub fn decide_data_chunk_size(total_rw_bytes: u64) -> u64 {
    let max_chunk = (total_rw_bytes / 10).min(SZ_10G);
    let mut stripe = SZ_1G;
    let data_stripes = 1u64;
    if stripe * data_stripes > max_chunk {
        let target = (max_chunk.saturating_add(SZ_16M - 1)) / SZ_16M * SZ_16M;
        stripe = target.min(stripe);
    }
    stripe = stripe.min(SZ_1G);
    stripe = (stripe / SZ_64K) * SZ_64K;
    stripe * data_stripes
}

/// Search 3: First-fit physical hole search across a device's extents.
///
/// Walks existing `DEV_EXTENT` items in physical order:
/// - Starts at `1 MiB` (`BTRFS_BLOCK_RESERVED_1M_FOR_SUPER`).
/// - Implements **first-fit**: returns the first physical hole >= `requested_chunk_size`.
/// - If no hole >= `requested_chunk_size` is found, shrinks to the largest available hole
///   >= `min_stripe_size` (aligned down to 64 KiB).
/// - Returns `Err(LuksError::FilesystemFull)` if no usable hole >= `min_stripe_size` exists.
///
/// Returns `Ok((physical_offset, allocated_length))`.
pub fn find_free_dev_extent(
    dev_extents: &[(u64, u64)],
    total_dev_bytes: u64,
    requested_chunk_size: u64,
    min_stripe_size: u64,
) -> Result<(u64, u64)> {
    if total_dev_bytes <= BTRFS_BLOCK_RESERVED_1M_FOR_SUPER {
        return Err(LuksError::FilesystemFull);
    }

    let mut sorted = dev_extents.to_vec();
    sorted.sort_by_key(|(off, _)| *off);

    let mut cur_offset = BTRFS_BLOCK_RESERVED_1M_FOR_SUPER;
    let mut max_hole: Option<(u64, u64)> = None;

    for (ext_offset, ext_len) in sorted {
        if ext_len == 0 {
            continue;
        }

        if ext_offset > cur_offset {
            let hole_len = ext_offset - cur_offset;
            if hole_len >= requested_chunk_size {
                return Ok((cur_offset, requested_chunk_size));
            }
            if max_hole.map_or(true, |(_, max_len)| hole_len > max_len) {
                max_hole = Some((cur_offset, hole_len));
            }
        }

        cur_offset = cur_offset.max(ext_offset.saturating_add(ext_len));
    }

    if cur_offset < total_dev_bytes {
        let hole_len = total_dev_bytes - cur_offset;
        if hole_len >= requested_chunk_size {
            return Ok((cur_offset, requested_chunk_size));
        }
        if max_hole.map_or(true, |(_, max_len)| hole_len > max_len) {
            max_hole = Some((cur_offset, hole_len));
        }
    }

    if let Some((hole_start, hole_len)) = max_hole {
        let usable_len = (hole_len / SZ_64K) * SZ_64K;
        if usable_len >= min_stripe_size && usable_len > 0 {
            return Ok((hole_start, usable_len));
        }
    }

    Err(LuksError::FilesystemFull)
}

/// Read all `DEV_EXTENT` items for `devid` from the `DEV_TREE` (root 4).
///
/// Returns sorted `(physical_offset, length)` tuples by traversing the device tree.
pub fn read_dev_extents<D: ReadAt>(fs: &Btrfs<D>, devid: u64) -> Result<Vec<(u64, u64)>> {
    let dev_tree = fs.tree_root(DEV_TREE_OBJECTID)?;
    let mut extents = Vec::new();

    fs.walk_tree(dev_tree.bytenr, &mut |key, data| {
        if key.item_type == DEV_EXTENT_KEY && key.objectid == devid {
            let dev_extent = DevExtent::parse(&key, data)?;
            extents.push((dev_extent.physical_offset, dev_extent.length));
        }
        Ok(())
    })?;

    extents.sort_by_key(|(offset, _)| *offset);
    Ok(extents)
}

/// Prepare the in-memory CoW transaction to allocate a new single DATA chunk.
///
/// Implements §7 steps 4-10:
/// 1. Runs refusal gates (§8).
/// 2. Executes read-only search algorithms (§7 steps 1-3) to find next logical address,
///    decide chunk size, and find a physical hole on the device.
/// 3. CoW mutates `DEV_TREE` (Root 4) to insert `DEV_EXTENT`.
/// 4. CoW mutates `CHUNK_TREE` (Root 3) to increment `DEV_ITEM.bytes_used` and insert `CHUNK_ITEM`.
/// 5. CoW mutates `EXTENT_TREE` (Root 2) to insert `BLOCK_GROUP_ITEM`.
/// 6. Seeds `FreeSpaceMap` with the new block group and recomputes superblock mirror exclusions.
/// 7. Calls `converge_and_finalize` to update root tree & extent tree.
///
/// Returns `Ok((Transaction, Chunk))`.
pub fn allocate_data_chunk_transaction<D: ReadAt>(
    fs: &Btrfs<D>,
) -> Result<(Transaction, Chunk)> {
    // 1. Refusal gates (§8)
    gate::check_writeable_fs(fs.superblock())?;
    gate::check_chunk_allocation_profile(BLOCK_GROUP_DATA)?;
    gate::check_free_space_tree_no_bitmaps(fs)?;
    let sb = fs.superblock();
    if sb.compat_ro_flags & BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE != 0 {
        if let Ok(fst_root) = fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
            gate::check_free_space_tree_shape(&fst_root)?;
        }
    }

    // 2. Search (§7 steps 1-3)
    let logical = next_logical(fs.chunk_map());
    let devid = sb.dev_id;
    let dev_extents = read_dev_extents(fs, devid)?;
    let decided_size = decide_data_chunk_size(sb.total_bytes);
    let (physical, alloc_len) = find_free_dev_extent(
        &dev_extents,
        sb.total_bytes,
        decided_size,
        MIN_STRIPE_SIZE_FLOOR,
    )?;

    if alloc_len < MIN_STRIPE_SIZE_FLOOR {
        return Err(LuksError::FilesystemFull);
    }

    let chunk_tree_uuid = fs.chunk_tree_uuid()?;
    let dev_uuid = fs
        .chunk_map()
        .chunks()
        .iter()
        .find_map(|c| c.stripes.iter().find(|s| s.devid == devid).map(|s| s.dev_uuid))
        .ok_or_else(|| LuksError::CorruptFs("no existing chunk found for device id"))?;

    let new_chunk = Chunk::new_single(
        logical,
        alloc_len,
        BLOCK_GROUP_DATA,
        devid,
        physical,
        dev_uuid,
    );

    let new_generation = sb.generation + 1;
    let extent_tree = ExtentTree::read(fs)?;
    let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())?;
    let mut pending_blocks = HashMap::new();
    let mut blocks_to_add = Vec::<(u64, u8, u64)>::new();
    let mut blocks_to_remove = Vec::<(u64, u8)>::new();

    // 3. DEV_TREE (Root 4): insert DEV_EXTENT
    let dev_tree = fs.tree_root(DEV_TREE_OBJECTID)?;
    let mut dev_tree_bytenr = dev_tree.bytenr;
    let mut dev_tree_level = dev_tree.level;

    let dev_extent = DevExtent::new(devid, physical, logical, alloc_len, chunk_tree_uuid);
    let (dev_ext_key, dev_ext_payload) = dev_extent.emit();
    let dev_res = cow_tree_insert(
        fs,
        &pending_blocks,
        dev_tree_bytenr,
        dev_tree_level,
        DEV_TREE_OBJECTID,
        dev_ext_key,
        dev_ext_payload,
        new_generation,
        &mut allocator,
    )?;
    record_cow_result(
        &dev_res,
        &mut blocks_to_add,
        &mut blocks_to_remove,
        &mut allocator,
        &mut pending_blocks,
        sb.node_size,
        DEV_TREE_OBJECTID,
    )?;
    dev_tree_bytenr = dev_res.new_root_bytenr;
    dev_tree_level = dev_res.new_root_level;

    // 4. CHUNK_TREE (Root 3):
    let mut chunk_root_bytenr = sb.chunk_root;
    let mut chunk_root_level = sb.chunk_root_level;

    // 4a. Update DEV_ITEM in CHUNK_TREE: bytes_used += alloc_len
    let dev_item_key = Key::new(DEV_ITEMS_OBJECTID, DEV_ITEM_KEY, devid);
    let chunk_res1 = cow_tree_mutate(
        fs,
        &pending_blocks,
        chunk_root_bytenr,
        chunk_root_level,
        CHUNK_TREE_OBJECTID,
        &dev_item_key,
        new_generation,
        &mut allocator,
        |leaf| {
            let idx = leaf
                .find_item(&dev_item_key)
                .ok_or_else(|| LuksError::NotFound("dev item not found in chunk tree".into()))?;
            let data = &mut leaf.items[idx].data;
            if data.len() < 24 {
                return Err(LuksError::CorruptFs("dev item truncated"));
            }
            let cur_used = u64::from_le_bytes(data[0x10..0x18].try_into().unwrap());
            let new_used = cur_used
                .checked_add(alloc_len)
                .ok_or(LuksError::CorruptFs("dev item bytes_used overflow"))?;
            data[0x10..0x18].copy_from_slice(&new_used.to_le_bytes());
            Ok(())
        },
    )?;
    record_cow_result(
        &chunk_res1,
        &mut blocks_to_add,
        &mut blocks_to_remove,
        &mut allocator,
        &mut pending_blocks,
        sb.node_size,
        CHUNK_TREE_OBJECTID,
    )?;
    chunk_root_bytenr = chunk_res1.new_root_bytenr;
    chunk_root_level = chunk_res1.new_root_level;

    // 4b. Insert CHUNK_ITEM in CHUNK_TREE
    let (chunk_key, chunk_payload) = new_chunk.emit();
    let chunk_res2 = cow_tree_insert(
        fs,
        &pending_blocks,
        chunk_root_bytenr,
        chunk_root_level,
        CHUNK_TREE_OBJECTID,
        chunk_key,
        chunk_payload,
        new_generation,
        &mut allocator,
    )?;
    record_cow_result(
        &chunk_res2,
        &mut blocks_to_add,
        &mut blocks_to_remove,
        &mut allocator,
        &mut pending_blocks,
        sb.node_size,
        CHUNK_TREE_OBJECTID,
    )?;
    chunk_root_bytenr = chunk_res2.new_root_bytenr;
    chunk_root_level = chunk_res2.new_root_level;

    // 5. EXTENT_TREE (Root 2): insert BLOCK_GROUP_ITEM
    let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
    let mut extent_root_bytenr = extent_root.bytenr;
    let mut extent_root_level = extent_root.level;

    let chunk_objectid = extent_tree
        .block_groups
        .first()
        .map(|bg| bg.chunk_objectid)
        .unwrap_or(FIRST_CHUNK_TREE_OBJECTID);

    let new_bg_item = BlockGroupItem {
        start: logical,
        length: alloc_len,
        used: 0,
        chunk_objectid,
        flags: BLOCK_GROUP_DATA,
    };
    let (bg_key, bg_payload) = new_bg_item.emit();
    let ext_res = cow_tree_insert(
        fs,
        &pending_blocks,
        extent_root_bytenr,
        extent_root_level,
        EXTENT_TREE_OBJECTID,
        bg_key,
        bg_payload,
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

    // 6. FreeSpaceMap seeding and exclusion calculation (§2.7, §3.3)
    let new_bg_free = BlockGroupFreeSpace {
        block_group: new_bg_item,
        allocated_extents: Vec::new(),
        free_ranges: vec![FreeRange {
            start: logical,
            length: alloc_len,
        }],
        pinned_freed: Vec::new(),
        excluded_ranges: Vec::new(),
        total_allocated_bytes: 0,
        total_free_bytes: alloc_len,
    };
    allocator.block_groups.push(new_bg_free);

    let mut temp_chunk_map = fs.chunk_map().clone();
    temp_chunk_map.insert(new_chunk.clone());
    let exclusions = compute_sb_exclusions(&temp_chunk_map);
    allocator.exclude_ranges(&exclusions);

    // 7. Converge and finalize transaction
    let txn = converge_and_finalize(
        fs,
        new_generation,
        fs.fs_tree(),
        None,
        Some((dev_tree_bytenr, dev_tree_level)),
        Some((chunk_root_bytenr, chunk_root_level)),
        Some((extent_root_bytenr, extent_root_level)),
        pending_blocks,
        Vec::new(),
        allocator,
        blocks_to_add,
        blocks_to_remove,
        Vec::new(),
        Vec::new(),
    )?;

    Ok((txn, new_chunk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::btrfs::chunk::{Chunk, Stripe};

    #[test]
    fn test_decide_data_chunk_size_nine_verified_sizes() {
        const GIB: u64 = 1024 * 1024 * 1024;
        const MIB: u64 = 1024 * 1024;

        // Exact 9 verified kernel measurements from §2.1
        assert_eq!(decide_data_chunk_size(3 * GIB), 320 * MIB);
        assert_eq!(decide_data_chunk_size(3 * GIB), 335_544_320);

        assert_eq!(decide_data_chunk_size(4 * GIB), 416 * MIB);
        assert_eq!(decide_data_chunk_size(4 * GIB), 436_207_616);

        assert_eq!(decide_data_chunk_size(5 * GIB), 512 * MIB);
        assert_eq!(decide_data_chunk_size(5 * GIB), 536_870_912);

        assert_eq!(decide_data_chunk_size(6 * GIB), 624 * MIB);
        assert_eq!(decide_data_chunk_size(6 * GIB), 654_311_424);

        assert_eq!(decide_data_chunk_size(7 * GIB), 720 * MIB);
        assert_eq!(decide_data_chunk_size(7 * GIB), 754_974_720);

        assert_eq!(decide_data_chunk_size(8 * GIB), 832 * MIB);
        assert_eq!(decide_data_chunk_size(8 * GIB), 872_415_232);

        assert_eq!(decide_data_chunk_size(9 * GIB), 928 * MIB);
        assert_eq!(decide_data_chunk_size(9 * GIB), 973_078_528);

        assert_eq!(decide_data_chunk_size(12 * GIB), 1024 * MIB);
        assert_eq!(decide_data_chunk_size(12 * GIB), 1_073_741_824);

        assert_eq!(decide_data_chunk_size(16 * GIB), 1024 * MIB);
        assert_eq!(decide_data_chunk_size(32 * GIB), 1024 * MIB);
        assert_eq!(decide_data_chunk_size(64 * GIB), 1024 * MIB);
    }

    #[test]
    fn test_next_logical_empty_and_populated() {
        let empty_map = ChunkMap::default();
        assert_eq!(next_logical(&empty_map), 0);

        let mut map = ChunkMap::default();
        let chunk1 = Chunk {
            logical: 4_194_304,
            length: 8_388_608,
            owner: 2,
            stripe_len: 65536,
            chunk_type: 1,
            io_align: 65536,
            io_width: 65536,
            sector_size: 4096,
            sub_stripes: 1,
            stripes: vec![Stripe::new(1, 1_048_576, [0u8; 16])],
        };
        map.insert(chunk1);
        assert_eq!(next_logical(&map), 4_194_304 + 8_388_608);

        let chunk2 = Chunk {
            logical: 298_844_160,
            length: 436_207_616,
            owner: 2,
            stripe_len: 65536,
            chunk_type: 1,
            io_align: 65536,
            io_width: 65536,
            sector_size: 4096,
            sub_stripes: 1,
            stripes: vec![Stripe::new(1, 13_631_488, [0u8; 16])],
        };
        map.insert(chunk2);
        assert_eq!(next_logical(&map), 298_844_160 + 436_207_616);
    }

    #[test]
    fn test_find_free_dev_extent_first_fit_and_fallback() {
        const MIB: u64 = 1024 * 1024;
        let total_dev = 1000 * MIB;

        // 1. Empty device -> starts at 1 MiB
        let (off, len) = find_free_dev_extent(&[], total_dev, 400 * MIB, 64 * MIB).unwrap();
        assert_eq!(off, 1 * MIB);
        assert_eq!(len, 400 * MIB);

        // 2. Existing extent at 1MB..101MB -> next hole at 101MB
        let extents = vec![(1 * MIB, 100 * MIB)];
        let (off, len) = find_free_dev_extent(&extents, total_dev, 400 * MIB, 64 * MIB).unwrap();
        assert_eq!(off, 101 * MIB);
        assert_eq!(len, 400 * MIB);

        // 3. First-fit choice:
        // Gap 1: 1MB..11MB (10MB) - too small for 50MB
        // Gap 2: 61MB..161MB (100MB) - fits 50MB
        // Gap 3: 201MB..501MB (300MB) - larger, but second
        let extents_multi = vec![
            (11 * MIB, 50 * MIB),
            (161 * MIB, 40 * MIB),
        ];
        let (off, len) = find_free_dev_extent(&extents_multi, total_dev, 50 * MIB, 10 * MIB).unwrap();
        assert_eq!(off, 61 * MIB); // First fit selected!
        assert_eq!(len, 50 * MIB);

        // 4. Fallback to largest hole when requested size does not fit:
        // Request 500MB, but available holes are 10MB, 100MB, 499MB.
        // Largest hole (201MB..700MB, total_dev=700MB) is 499MB.
        let total_dev_small = 700 * MIB;
        let (off, len) = find_free_dev_extent(&extents_multi, total_dev_small, 500 * MIB, 64 * MIB).unwrap();
        assert_eq!(off, 201 * MIB);
        assert_eq!(len, 499 * MIB);

        // 5. Filesystem full when largest hole is below min_stripe_size
        let extents_tight = vec![(1 * MIB, 995 * MIB)];
        let res = find_free_dev_extent(&extents_tight, 1000 * MIB, 50 * MIB, 10 * MIB);
        assert!(matches!(res, Err(LuksError::FilesystemFull)));
    }
}
