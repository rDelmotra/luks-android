//! btrfs chunk allocation search algorithms (Pass H.2).
//!
//! Implements the three read-only search algorithms (§7 steps 1-3) required for
//! chunk allocation:
//! 1. [`next_logical`]: Finds the highest logical end across existing chunks.
//! 2. [`decide_data_chunk_size`]: Calculates chunk size using kernel stripe sizing rules.
//! 3. [`find_free_dev_extent`]: First-fit search for physical device holes.
//!
//! Also provides [`read_dev_extents`] to retrieve existing physical extents from DEV_TREE.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::chunk::{ChunkMap, DevExtent};
use crate::fs::btrfs::tree::{DEV_EXTENT_KEY, DEV_TREE_OBJECTID};
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
