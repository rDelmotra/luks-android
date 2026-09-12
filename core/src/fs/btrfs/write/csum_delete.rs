//! Checksum deletion and trimming for freed data extents.
//!
//! When data extents are freed (via file deletion or file replacement on rename),
//! any corresponding checksums in `CSUM_TREE` must be removed.
//!
//! In Btrfs, adjacent extents often share packed [`EXTENT_CSUM_KEY`] items where
//! multiple sector checksums are stored contiguously in a single B-tree item.
//! Trimming an extent from a packed item requires:
//! - Full removal: if the freed extent covers the entire checksum item.
//! - Tail truncation: if the freed extent covers the end of the item (in-place payload shrink).
//! - Head truncation: if the freed extent covers the start of the item (delete old key, insert new key at start of remaining slice).
//! - Hole punch / middle split: if the freed extent is in the interior of the item (truncate left slice, insert right slice).

use std::collections::{BTreeMap, HashMap};

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{CSUM_TREE_OBJECTID, EXTENT_CSUM_KEY, EXTENT_CSUM_OBJECTID};
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::extent_tree::record_cow_result;
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::{Btrfs, Key};

/// Delete or trim checksums covering `data_extents_to_free` from `CSUM_TREE`.
///
/// Returns `Ok(Some((new_root_bytenr, new_root_level)))` if `CSUM_TREE` was modified,
/// or `Ok(None)` if no checksum items intersected the freed ranges.
pub fn delete_extent_csums<D: ReadAt>(
    fs: &Btrfs<D>,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    mut csum_root_bytenr: u64,
    mut csum_root_level: u8,
    data_extents_to_free: &[(u64, u64)],
    new_generation: u64,
    allocator: &mut FreeSpaceMap,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8, u64)>,
) -> Result<Option<(u64, u8)>> {
    let mut freed_ranges = Vec::new();
    for &(bytenr, num_bytes) in data_extents_to_free {
        if num_bytes > 0 {
            freed_ranges.push((bytenr, bytenr.saturating_add(num_bytes)));
        }
    }
    if freed_ranges.is_empty() {
        return Ok(None);
    }
    freed_ranges.sort_unstable_by_key(|&(start, _)| start);

    // Merge overlapping or contiguous freed ranges
    let mut merged_freed: Vec<(u64, u64)> = Vec::with_capacity(freed_ranges.len());
    for (start, end) in freed_ranges {
        if let Some(last) = merged_freed.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged_freed.push((start, end));
    }

    let sector_size = fs.superblock().sector_size as u64;
    let csum_size = fs.superblock().csum_type.size();
    if sector_size == 0 || csum_size == 0 {
        return Err(LuksError::CorruptFs("invalid sector_size or csum_size"));
    }

    // Step 1: Find all EXTENT_CSUM items in CSUM_TREE that intersect any range in merged_freed.
    let mut items_to_modify: BTreeMap<Key, Vec<u8>> = BTreeMap::new();

    for &(f_start, f_end) in &merged_freed {
        let search_key = Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, f_start);
        let mut cursor = fs.search_le(csum_root_bytenr, &search_key)?;
        if !cursor.valid() {
            cursor = fs.search(csum_root_bytenr, &search_key)?;
        } else {
            let key = cursor.key()?;
            if key.objectid == EXTENT_CSUM_OBJECTID && key.item_type == EXTENT_CSUM_KEY {
                let data_len = cursor.data()?.len();
                let item_start = key.offset;
                let item_end = item_start.saturating_add((data_len / csum_size) as u64 * sector_size);
                if item_end <= f_start {
                    cursor.advance()?;
                }
            } else {
                cursor.advance()?;
            }
        }

        while cursor.valid() {
            let key = cursor.key()?;
            if key.objectid != EXTENT_CSUM_OBJECTID || key.item_type != EXTENT_CSUM_KEY {
                if key < Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, 0) {
                    cursor.advance()?;
                    continue;
                }
                break;
            }
            if key.offset >= f_end {
                break;
            }
            let data = cursor.data()?.to_vec();
            let item_start = key.offset;
            let item_end = item_start.saturating_add((data.len() / csum_size) as u64 * sector_size);
            if item_end > f_start {
                items_to_modify.insert(key, data);
            }
            cursor.advance()?;
        }
    }

    if items_to_modify.is_empty() {
        return Ok(None);
    }

    // Step 2: Compute surviving sub-intervals and planned mutations.
    let mut deletes: Vec<Key> = Vec::new();
    let mut truncates: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut inserts: Vec<(Key, Vec<u8>)> = Vec::new();

    for (old_key, payload) in items_to_modify {
        let item_start = old_key.offset;
        let num_sectors = payload.len() / csum_size;
        let item_end = item_start.saturating_add(num_sectors as u64 * sector_size);

        let current_intervals = compute_surviving_intervals(item_start, item_end, &merged_freed);

        if current_intervals.is_empty() {
            // Entire checksum item was freed
            deletes.push(old_key);
        } else {
            let (first_s, first_e) = current_intervals[0];
            let first_start_sec = (first_s - item_start) / sector_size;
            let first_end_sec = (first_e - item_start) / sector_size;
            let first_data = payload[(first_start_sec as usize * csum_size)..(first_end_sec as usize * csum_size)].to_vec();

            if first_s == item_start {
                if first_data.len() < payload.len() {
                    // Tail truncation
                    truncates.push((old_key, first_data));
                }
            } else {
                // Head was freed: delete old key, insert new key at first_s
                deletes.push(old_key);
                inserts.push((
                    Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, first_s),
                    first_data,
                ));
            }

            // Any additional sub-intervals (from middle hole punch / multiple holes)
            for &(s, e) in &current_intervals[1..] {
                let start_sec = (s - item_start) / sector_size;
                let end_sec = (e - item_start) / sector_size;
                let data = payload[(start_sec as usize * csum_size)..(end_sec as usize * csum_size)].to_vec();
                inserts.push((
                    Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, s),
                    data,
                ));
            }
        }
    }

    if deletes.is_empty() && truncates.is_empty() && inserts.is_empty() {
        return Ok(None);
    }

    let mut modified = false;
    let node_size = fs.superblock().node_size;

    // Execute mutations:
    // 1. Deletions
    for key in deletes {
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            csum_root_bytenr,
            csum_root_level,
            CSUM_TREE_OBJECTID,
            &key,
            new_generation,
            allocator,
            |leaf| {
                leaf.delete_item(&key)?;
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
        modified = true;
    }

    // 2. Truncations
    for (key, new_data) in truncates {
        let res = cow_tree_mutate(
            fs,
            pending_blocks,
            csum_root_bytenr,
            csum_root_level,
            CSUM_TREE_OBJECTID,
            &key,
            new_generation,
            allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&key)
                    .ok_or_else(|| LuksError::NotFound("csum item to truncate not found in leaf".into()))?;
                leaf.items[idx].data = new_data;
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
        modified = true;
    }

    // 3. Insertions
    for (key, data) in inserts {
        let res = cow_tree_insert(
            fs,
            pending_blocks,
            csum_root_bytenr,
            csum_root_level,
            CSUM_TREE_OBJECTID,
            key,
            data,
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
            CSUM_TREE_OBJECTID,
        )?;
        csum_root_bytenr = res.new_root_bytenr;
        csum_root_level = res.new_root_level;
        modified = true;
    }

    if modified {
        Ok(Some((csum_root_bytenr, csum_root_level)))
    } else {
        Ok(None)
    }
}

/// Compute surviving sub-intervals of `[item_start, item_end)` after subtracting `freed_ranges`.
pub(crate) fn compute_surviving_intervals(
    item_start: u64,
    item_end: u64,
    freed_ranges: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    if item_start >= item_end {
        return Vec::new();
    }
    let mut current_intervals = vec![(item_start, item_end)];

    for &(f_start, f_end) in freed_ranges {
        if f_start >= f_end {
            continue;
        }
        let mut next_intervals = Vec::new();
        for (s, e) in current_intervals {
            let overlap_start = s.max(f_start);
            let overlap_end = e.min(f_end);
            if overlap_start < overlap_end {
                if s < overlap_start {
                    next_intervals.push((s, overlap_start));
                }
                if overlap_end < e {
                    next_intervals.push((overlap_end, e));
                }
            } else {
                next_intervals.push((s, e));
            }
        }
        current_intervals = next_intervals;
    }

    current_intervals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_surviving_intervals_full_removal() {
        let freed = [(1000, 2000)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert!(surviving.is_empty(), "exact match must leave no surviving intervals");

        let subsuming_freed = [(500, 2500)];
        let surviving2 = compute_surviving_intervals(1000, 2000, &subsuming_freed);
        assert!(surviving2.is_empty(), "subsuming free must leave no surviving intervals");
    }

    #[test]
    fn test_compute_surviving_intervals_tail_truncation() {
        let freed = [(1500, 2500)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert_eq!(surviving.len(), 1);
        assert_eq!(surviving[0], (1000, 1500));
    }

    #[test]
    fn test_compute_surviving_intervals_head_truncation() {
        let freed = [(500, 1500)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert_eq!(surviving.len(), 1);
        assert_eq!(surviving[0], (1500, 2000));
    }

    #[test]
    fn test_compute_surviving_intervals_middle_hole_punch() {
        let freed = [(1400, 1600)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert_eq!(surviving.len(), 2);
        assert_eq!(surviving[0], (1000, 1400));
        assert_eq!(surviving[1], (1600, 2000));
    }

    #[test]
    fn test_compute_surviving_intervals_multiple_holes() {
        let freed = [(1200, 1400), (1600, 1800)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert_eq!(surviving.len(), 3);
        assert_eq!(surviving[0], (1000, 1200));
        assert_eq!(surviving[1], (1400, 1600));
        assert_eq!(surviving[2], (1800, 2000));
    }

    #[test]
    fn test_compute_surviving_intervals_no_overlap() {
        let freed = [(100, 500), (2500, 3000)];
        let surviving = compute_surviving_intervals(1000, 2000, &freed);
        assert_eq!(surviving.len(), 1);
        assert_eq!(surviving[0], (1000, 2000));
    }
}

