//! Free-space tracking and allocation derived from the btrfs extent tree.
//!
//! Ground truth for free space is derived from the `ExtentTree` and chunk map,
//! with exclusions applied for superblock mirrors (64 KiB, 64 MiB, 256 GiB).
//! The derived allocations are actively emitted to the `FREE_SPACE_TREE`
//! during commit to maintain full parity with the Linux kernel.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{FREE_SPACE_EXTENT_KEY, FREE_SPACE_TREE_OBJECTID};
use crate::fs::btrfs::write::extent_tree::{AllocatedExtent, BlockGroupItem, ExtentTree};
use crate::fs::btrfs::Btrfs;

/// A contiguous range of unallocated bytes in logical address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeRange {
    pub start: u64,
    pub length: u64,
}

/// The free-space view of a single block group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockGroupFreeSpace {
    pub block_group: BlockGroupItem,
    pub allocated_extents: Vec<AllocatedExtent>,
    pub free_ranges: Vec<FreeRange>,
    pub pinned_freed: Vec<FreeRange>,
    pub excluded_ranges: Vec<FreeRange>,
    pub total_allocated_bytes: u64,
    pub total_free_bytes: u64,
}

/// The overall free-space map of the filesystem across all block groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeSpaceMap {
    pub block_groups: Vec<BlockGroupFreeSpace>,
}

/// Whether a block group with the given `flags` can hold DATA extents —
/// true for `BLOCK_GROUP_DATA` and for a genuinely MIXED
/// (`BLOCK_GROUP_DATA | BLOCK_GROUP_METADATA`) block group.
///
/// A METADATA-only block group must return `false`: `flags` having the
/// METADATA bit set is not, by itself, evidence of DATA capacity.
pub fn bg_holds_data(flags: u64) -> bool {
    flags & crate::fs::btrfs::chunk::BLOCK_GROUP_DATA != 0
}

impl FreeSpaceMap {
    /// Derive the free space map from the ground-truth extent tree.
    pub fn from_extent_tree(extent_tree: &ExtentTree) -> Result<Self> {
        let mut bg_free_spaces = Vec::new();

        for bg in &extent_tree.block_groups {
            let bg_start = bg.start;
            let bg_end = bg.start.checked_add(bg.length).ok_or_else(|| {
                LuksError::CorruptFs("block group range overflow")
            })?;

            let mut bg_extents = Vec::new();
            let mut free_ranges = Vec::new();
            let mut total_allocated = 0u64;
            let mut cursor = bg_start;

            for ext in &extent_tree.extents {
                if ext.bytenr < bg_start || ext.bytenr >= bg_end {
                    continue;
                }

                bg_extents.push(ext.clone());

                if ext.bytenr > cursor {
                    free_ranges.push(FreeRange {
                        start: cursor,
                        length: ext.bytenr - cursor,
                    });
                }
                total_allocated += ext.length;
                cursor = ext.bytenr + ext.length;
            }

            if cursor < bg_end {
                free_ranges.push(FreeRange {
                    start: cursor,
                    length: bg_end - cursor,
                });
            }

            let total_free: u64 = free_ranges.iter().map(|r| r.length).sum();

            // Self-consistency cross-check:
            // 1. Total allocated extents in this group must match the `used` field in `BLOCK_GROUP_ITEM`.
            // 2. Allocated + Free must equal the total length of the block group.
            if total_allocated != bg.used {
                return Err(LuksError::CorruptFs(
                    "extent tree allocations do not match block group used counter",
                ));
            }
            if total_allocated + total_free != bg.length {
                return Err(LuksError::CorruptFs(
                    "sum of allocated and free space does not match block group length",
                ));
            }

            bg_free_spaces.push(BlockGroupFreeSpace {
                block_group: bg.clone(),
                allocated_extents: bg_extents,
                free_ranges,
                pinned_freed: Vec::new(),
                excluded_ranges: Vec::new(),
                total_allocated_bytes: total_allocated,
                total_free_bytes: total_free,
            });
        }

        Ok(FreeSpaceMap {
            block_groups: bg_free_spaces,
        })
    }

    /// Derive the free space map from the extent tree and subtract superblock mirror exclusions.
    pub fn from_extent_tree_and_chunk_map(
        extent_tree: &ExtentTree,
        chunk_map: &crate::fs::btrfs::chunk::ChunkMap,
    ) -> Result<Self> {
        let mut map = Self::from_extent_tree(extent_tree)?;
        let exclusions = crate::fs::btrfs::write::exclude::compute_sb_exclusions(chunk_map);
        map.exclude_ranges(&exclusions);
        Ok(map)
    }

    /// Subtract excluded logical ranges (e.g. superblock mirrors) from available free ranges.
    ///
    /// The excluded bytes will not be handed out by `allocate_metadata` or `allocate_data_chunk`.
    pub fn exclude_ranges(&mut self, exclusions: &[std::ops::Range<u64>]) {
        for excl in exclusions {
            if excl.start >= excl.end {
                continue;
            }
            for bg in &mut self.block_groups {
                let bg_start = bg.block_group.start;
                let bg_end = bg_start.saturating_add(bg.block_group.length);
                if excl.end <= bg_start || excl.start >= bg_end {
                    continue;
                }

                let e_start = excl.start.max(bg_start);
                let e_end = excl.end.min(bg_end);
                if e_start >= e_end {
                    continue;
                }

                let mut new_free = Vec::new();
                for r in &bg.free_ranges {
                    let r_start = r.start;
                    let r_end = r.start.saturating_add(r.length);

                    if e_end <= r_start || e_start >= r_end {
                        // No overlap
                        new_free.push(*r);
                    } else {
                        // Overlap: record the excluded slice that overlapped with this free range
                        let overlap_start = e_start.max(r_start);
                        let overlap_end = e_end.min(r_end);
                        if overlap_start < overlap_end {
                            bg.excluded_ranges.push(FreeRange {
                                start: overlap_start,
                                length: overlap_end - overlap_start,
                            });
                        }

                        // Keep part before e_start if any
                        if r_start < e_start {
                            new_free.push(FreeRange {
                                start: r_start,
                                length: e_start - r_start,
                            });
                        }
                        // Keep part after e_end if any
                        if r_end > e_end {
                            new_free.push(FreeRange {
                                start: e_end,
                                length: r_end - e_end,
                            });
                        }
                    }
                }
                bg.free_ranges = new_free;
                bg.total_free_bytes = bg.free_ranges.iter().map(|r| r.length).sum();

                // Maintain excluded_ranges sorted and merged
                bg.excluded_ranges.sort_by_key(|r| r.start);
                let mut merged_excl: Vec<FreeRange> = Vec::new();
                for r in bg.excluded_ranges.drain(..) {
                    if let Some(last) = merged_excl.last_mut() {
                        if last.start + last.length >= r.start {
                            let end = (last.start + last.length).max(r.start + r.length);
                            last.length = end - last.start;
                            continue;
                        }
                    }
                    merged_excl.push(r);
                }
                bg.excluded_ranges = merged_excl;
            }
        }
    }

    /// All free ranges flattened across all block groups, sorted by address.
    pub fn all_free_ranges(&self) -> Vec<FreeRange> {
        let mut ranges = Vec::new();
        for bg in &self.block_groups {
            ranges.extend_from_slice(&bg.free_ranges);
        }
        ranges.sort_by_key(|r| r.start);
        ranges
    }

    /// Find an available free range in a block group matching `flags_mask`.
    pub fn find_free_range(
        &self,
        flags_mask: u64,
        min_bytes: u64,
        alignment: u64,
    ) -> Option<FreeRange> {
        for bg in &self.block_groups {
            if bg.block_group.flags & flags_mask == flags_mask {
                for range in &bg.free_ranges {
                    let aligned_start = (range.start + alignment - 1) & !(alignment - 1);
                    if aligned_start + min_bytes <= range.start + range.length {
                        return Some(FreeRange {
                            start: aligned_start,
                            length: min_bytes,
                        });
                    }
                }
            }
        }
        None
    }

    /// Allocate a metadata block of `size` bytes for the tree with the given `owner` objectid.
    ///
    /// For `CHUNK_TREE_OBJECTID` (3), allocates from a SYSTEM block group so that the chunk
    /// tree remains addressable via `sys_chunk_array` at mount time.
    /// For all other trees, allocates from a METADATA (or MIXED) block group.
    pub fn allocate_metadata_for_owner(&mut self, size: u32, owner: u64) -> Result<u64> {
        let needed = size as u64;
        let alignment = size as u64;
        let target_flag = if owner == crate::fs::btrfs::tree::CHUNK_TREE_OBJECTID {
            crate::fs::btrfs::chunk::BLOCK_GROUP_SYSTEM
        } else {
            crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA
        };

        for bg in &mut self.block_groups {
            let is_match = (bg.block_group.flags & target_flag != 0)
                || (bg.block_group.flags & (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                    == (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                    && target_flag == crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA);

            if !is_match {
                continue;
            }

            for i in 0..bg.free_ranges.len() {
                let range = bg.free_ranges[i];
                let aligned_start = (range.start + alignment - 1) & !(alignment - 1);
                if aligned_start + needed <= range.start + range.length {
                    let allocated_start = aligned_start;
                    let before_len = allocated_start - range.start;
                    let after_len = (range.start + range.length) - (allocated_start + needed);

                    bg.free_ranges.remove(i);
                    let insert_pos = i;
                    if after_len > 0 {
                        bg.free_ranges.insert(
                            insert_pos,
                            FreeRange {
                                start: allocated_start + needed,
                                length: after_len,
                            },
                        );
                    }
                    if before_len > 0 {
                        bg.free_ranges.insert(
                            insert_pos,
                            FreeRange {
                                start: range.start,
                                length: before_len,
                            },
                        );
                    }

                    bg.total_allocated_bytes += needed;
                    bg.total_free_bytes -= needed;
                    bg.block_group.used += needed;

                    return Ok(allocated_start);
                }
            }
        }

        Err(LuksError::FilesystemFull)
    }

    /// Allocate a metadata block of `size` bytes from a METADATA (or MIXED) block group.
    pub fn allocate_metadata(&mut self, size: u32) -> Result<u64> {
        self.allocate_metadata_for_owner(size, 0)
    }

    /// Allocate a data chunk of up to `max_size` bytes from a DATA (or MIXED) block group,
    /// aligned to `sector_size` (e.g. 4096).
    ///
    /// Finds the best/largest available free range in a `BLOCK_GROUP_DATA` (or MIXED) block group,
    /// carves out up to `max_size` (aligned to `sector_size`), updating free ranges,
    /// `total_allocated_bytes`, `total_free_bytes`, and `block_group.used`.
    ///
    /// Returns `Ok((bytenr, allocated_len))`.
    /// Returns `Err(LuksError::FilesystemFull)` only if 0 bytes could be allocated across all data block groups.
    pub fn allocate_data_chunk(&mut self, max_size: u64, sector_size: u32) -> Result<(u64, u64)> {
        if max_size == 0 {
            return Err(LuksError::FilesystemFull);
        }
        let alignment = sector_size as u64;
        let max_aligned = (max_size / alignment) * alignment;
        if max_aligned == 0 {
            return Err(LuksError::FilesystemFull);
        }

        let mut best_choice: Option<(usize, usize, u64, u64)> = None; // (bg_idx, range_idx, aligned_start, alloc_len)

        for (bg_idx, bg) in self.block_groups.iter().enumerate() {
            // Check for data or mixed block group
            let is_data = bg_holds_data(bg.block_group.flags);

            if !is_data {
                continue;
            }

            for (range_idx, range) in bg.free_ranges.iter().enumerate() {
                let aligned_start = (range.start + alignment - 1) & !(alignment - 1);
                let range_end = range.start.saturating_add(range.length);
                if aligned_start >= range_end {
                    continue;
                }
                let avail = range_end - aligned_start;
                let usable = (avail / alignment) * alignment;
                if usable == 0 {
                    continue;
                }
                let alloc_len = usable.min(max_aligned);

                match best_choice {
                    None => {
                        best_choice = Some((bg_idx, range_idx, aligned_start, alloc_len));
                        if alloc_len == max_aligned {
                            break;
                        }
                    }
                    Some((_, _, _, best_len)) => {
                        if alloc_len > best_len {
                            best_choice = Some((bg_idx, range_idx, aligned_start, alloc_len));
                            if alloc_len == max_aligned {
                                break;
                            }
                        }
                    }
                }
            }
            if let Some((_, _, _, best_len)) = best_choice {
                if best_len == max_aligned {
                    break;
                }
            }
        }

        let (bg_idx, range_idx, allocated_start, alloc_len) =
            best_choice.ok_or(LuksError::FilesystemFull)?;

        let bg = &mut self.block_groups[bg_idx];
        let range = bg.free_ranges[range_idx];
        let before_len = allocated_start - range.start;
        let after_len = (range.start + range.length) - (allocated_start + alloc_len);

        bg.free_ranges.remove(range_idx);
        let insert_pos = range_idx;
        if after_len > 0 {
            bg.free_ranges.insert(
                insert_pos,
                FreeRange {
                    start: allocated_start + alloc_len,
                    length: after_len,
                },
            );
        }
        if before_len > 0 {
            bg.free_ranges.insert(
                insert_pos,
                FreeRange {
                    start: range.start,
                    length: before_len,
                },
            );
        }

        bg.total_allocated_bytes += alloc_len;
        bg.total_free_bytes -= alloc_len;
        bg.block_group.used += alloc_len;

        Ok((allocated_start, alloc_len))
    }

    /// Allocate a data extent of `size` bytes from a DATA (or MIXED) block group,
    /// aligned to `sector_size` (e.g. 4096).
    ///
    /// `size` is a `u64` deliberately. It was a `u32`, and the caller passed
    /// `disk_num_bytes as u32` — so a file of 4 GiB or more wrapped to a small
    /// allocation while the commit still wrote the full-length buffer at that
    /// address, overwriting whatever followed. Nothing on the 4 GiB test stick
    /// could reach that size, so it was latent rather than observed; it is
    /// fixed here rather than left for the first drive big enough to hit it.
    pub fn allocate_data(&mut self, size: u64, sector_size: u32) -> Result<u64> {
        let needed = size;
        let alignment = sector_size as u64;

        for bg in &mut self.block_groups {
            // Check for data or mixed block group
            let is_data = bg_holds_data(bg.block_group.flags);

            if !is_data {
                continue;
            }

            for i in 0..bg.free_ranges.len() {
                let range = bg.free_ranges[i];
                let aligned_start = (range.start + alignment - 1) & !(alignment - 1);
                if aligned_start + needed <= range.start + range.length {
                    let allocated_start = aligned_start;
                    let before_len = allocated_start - range.start;
                    let after_len = (range.start + range.length) - (allocated_start + needed);

                    bg.free_ranges.remove(i);
                    let insert_pos = i;
                    if after_len > 0 {
                        bg.free_ranges.insert(
                            insert_pos,
                            FreeRange {
                                start: allocated_start + needed,
                                length: after_len,
                            },
                        );
                    }
                    if before_len > 0 {
                        bg.free_ranges.insert(
                            insert_pos,
                            FreeRange {
                                start: range.start,
                                length: before_len,
                            },
                        );
                    }

                    bg.total_allocated_bytes += needed;
                    bg.total_free_bytes -= needed;
                    bg.block_group.used += needed;

                    return Ok(allocated_start);
                }
            }
        }

        Err(LuksError::FilesystemFull)
    }

    /// Mark a specific `[bytenr, bytenr + length)` range as allocated in this map.
    ///
    /// Carves the specified range out of the containing block group's `free_ranges`,
    /// updating `total_allocated_bytes`, `total_free_bytes`, and `block_group.used`.
    ///
    /// Returns `Err(LuksError::OutOfBounds)` if the range does not fall within any block group,
    /// or `Err(LuksError::CorruptFs)` if the range is not currently recorded as free.
    pub fn mark_allocated(&mut self, bytenr: u64, length: u64) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let end = bytenr
            .checked_add(length)
            .ok_or(LuksError::OutOfBounds)?;

        for bg in &mut self.block_groups {
            let bg_start = bg.block_group.start;
            let bg_end = bg_start.saturating_add(bg.block_group.length);

            if bytenr >= bg_start && end <= bg_end {
                // Found containing block group. Look for matching free range.
                for i in 0..bg.free_ranges.len() {
                    let range = bg.free_ranges[i];
                    let r_start = range.start;
                    let r_end = range.start.saturating_add(range.length);

                    if bytenr >= r_start && end <= r_end {
                        let before_len = bytenr - r_start;
                        let after_len = r_end - end;

                        bg.free_ranges.remove(i);
                        let insert_pos = i;
                        if after_len > 0 {
                            bg.free_ranges.insert(
                                insert_pos,
                                FreeRange {
                                    start: end,
                                    length: after_len,
                                },
                            );
                        }
                        if before_len > 0 {
                            bg.free_ranges.insert(
                                insert_pos,
                                FreeRange {
                                    start: r_start,
                                    length: before_len,
                                },
                            );
                        }

                        bg.total_allocated_bytes += length;
                        bg.total_free_bytes -= length;
                        bg.block_group.used += length;

                        return Ok(());
                    }
                }

                return Err(LuksError::CorruptFs(
                    "range to mark allocated was not present in block group free ranges",
                ));
            }
        }

        Err(LuksError::OutOfBounds)
    }

    /// Mark a data extent of `size` bytes starting at `bytenr` as freed in this transaction.
    ///
    /// The extent is recorded in `pinned_freed` rather than returned to `free_ranges`
    /// to avoid reusing it within the same transaction.
    ///
    /// This function used to accept any range that merely *fit inside* a
    /// block group, with no check that it had ever been allocated. A logic
    /// error elsewhere stopped registering a writer's data runs while
    /// `abandon_file` still freed them, decrementing `used` for bytes the
    /// extent tree never counted; `saturating_sub` and a discarded return
    /// value at the call site made it silent until `btrfs check` reported
    /// "block group [13631488 8388608] used 2105344 but extent items used
    /// 2109440". The four checks below turn that class of bug into an
    /// immediate `CorruptFs` instead of quiet on-disk drift.
    ///
    /// Deliberately NOT checked here: whether `bytenr` was handed out by the
    /// *current* batch. `delete.rs` and `rename.rs` free extents read back
    /// from the on-disk extent tree, allocated in prior transactions and
    /// never present in this batch's ledger — an ownership check here would
    /// reject every legitimate delete. That validation belongs at the caller
    /// (see PLAN Stage B2), not in this structural gate.
    pub fn free_data(&mut self, bytenr: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let freed_len = size;

        // Check 1: the range itself must not overflow address space.
        let end = bytenr
            .checked_add(freed_len)
            .ok_or(LuksError::CorruptFs("free_data range overflows u64"))?;

        for bg in &mut self.block_groups {
            if bytenr >= bg.block_group.start && end <= bg.block_group.start + bg.block_group.length {
                // Check 3: cannot free more than the block group has allocated.
                if bg.block_group.used < freed_len {
                    return Err(LuksError::CorruptFs(
                        "free_data would free more bytes than the block group has allocated",
                    ));
                }

                // Check 4: reject a double free within this transaction —
                // a range already pending release cannot be freed again
                // before it is unpinned by a commit.
                for pinned in &bg.pinned_freed {
                    let pinned_end = pinned.start + pinned.length;
                    if bytenr < pinned_end && pinned.start < end {
                        return Err(LuksError::CorruptFs(
                            "free_data range overlaps a range already pending release in this transaction",
                        ));
                    }
                }

                let pos = bg.pinned_freed.partition_point(|r| r.start < bytenr);
                bg.pinned_freed.insert(
                    pos,
                    FreeRange {
                        start: bytenr,
                        length: freed_len,
                    },
                );

                let mut merged: Vec<FreeRange> = Vec::new();
                for r in bg.pinned_freed.drain(..) {
                    if let Some(last) = merged.last_mut() {
                        if last.start + last.length == r.start {
                            last.length += r.length;
                            continue;
                        }
                    }
                    merged.push(r);
                }
                bg.pinned_freed = merged;

                // Safe: check 3 above already proved `freed_len <= used`, so
                // this cannot underflow. Using plain subtraction rather than
                // `saturating_sub` means an inconsistency the check missed
                // will panic loudly instead of silently drifting `used` out
                // of sync with the extent tree, which is what actually
                // corrupted a drive (see the doc comment above).
                bg.block_group.used -= freed_len;
                return Ok(());
            }
        }

        // Check 2: the range must belong to some block group. Silently
        // returning `Ok(())` here is exactly what let a phantom free pass
        // unnoticed before.
        Err(LuksError::CorruptFs(
            "free_data range is not contained in any block group",
        ))
    }

    /// Mark a metadata block of `size` bytes starting at `bytenr` as freed in this transaction.
    ///
    /// The block is recorded in `pinned_freed` rather than returned to `free_ranges`
    /// to avoid reusing it within the same transaction.
    pub fn free_metadata(&mut self, bytenr: u64, size: u32) -> Result<()> {
        let freed_len = size as u64;
        for bg in &mut self.block_groups {
            if bytenr >= bg.block_group.start
                && bytenr + freed_len <= bg.block_group.start + bg.block_group.length
            {
                let pos = bg.pinned_freed.partition_point(|r| r.start < bytenr);
                bg.pinned_freed.insert(
                    pos,
                    FreeRange {
                        start: bytenr,
                        length: freed_len,
                    },
                );

                let mut merged: Vec<FreeRange> = Vec::new();
                for r in bg.pinned_freed.drain(..) {
                    if let Some(last) = merged.last_mut() {
                        if last.start + last.length == r.start {
                            last.length += r.length;
                            continue;
                        }
                    }
                    merged.push(r);
                }
                bg.pinned_freed = merged;

                bg.block_group.used = bg.block_group.used.saturating_sub(freed_len);
                return Ok(());
            }
        }
        Ok(())
    }

    /// Unpin freed ranges after a transaction has committed, returning them to available `free_ranges`
    /// for the next transaction (excluding any superblock mirror exclusion zones).
    pub fn unpin_freed(&mut self) {
        for bg in &mut self.block_groups {
            if bg.pinned_freed.is_empty() {
                continue;
            }
            let mut all_free = Vec::new();
            all_free.extend_from_slice(&bg.free_ranges);
            all_free.extend_from_slice(&bg.pinned_freed);
            bg.pinned_freed.clear();
            all_free.sort_by_key(|r| r.start);

            let mut merged: Vec<FreeRange> = Vec::new();
            for r in all_free {
                if let Some(last) = merged.last_mut() {
                    if last.start + last.length >= r.start {
                        let end = (last.start + last.length).max(r.start + r.length);
                        last.length = end - last.start;
                        continue;
                    }
                }
                merged.push(r);
            }

            // Subtract excluded ranges (superblock mirrors)
            for excl in &bg.excluded_ranges {
                let e_start = excl.start;
                let e_end = excl.start + excl.length;
                let mut new_merged = Vec::new();
                for r in merged {
                    let r_start = r.start;
                    let r_end = r.start + r.length;
                    if e_end <= r_start || e_start >= r_end {
                        new_merged.push(r);
                    } else {
                        if r_start < e_start {
                            new_merged.push(FreeRange {
                                start: r_start,
                                length: e_start - r_start,
                            });
                        }
                        if r_end > e_end {
                            new_merged.push(FreeRange {
                                start: e_end,
                                length: r_end - e_end,
                            });
                        }
                    }
                }
                merged = new_merged;
            }

            bg.free_ranges = merged;
            bg.total_free_bytes = bg.free_ranges.iter().map(|r| r.length).sum();
        }
    }

    /// Emit the complete list of `FREE_SPACE_INFO` and `FREE_SPACE_EXTENT` items
    /// for the Free Space Tree, combining existing free ranges with blocks freed
    /// in this transaction.
    pub fn emit_free_space_tree_items(&self) -> Vec<crate::fs::btrfs::write::node::LeafItem> {
        let mut items = Vec::new();
        for bg in &self.block_groups {
            let mut combined = Vec::new();
            combined.extend_from_slice(&bg.free_ranges);
            combined.extend_from_slice(&bg.pinned_freed);
            combined.extend_from_slice(&bg.excluded_ranges);
            combined.sort_by_key(|r| r.start);

            let mut merged: Vec<FreeRange> = Vec::new();
            for r in combined {
                if let Some(last) = merged.last_mut() {
                    if last.start + last.length >= r.start {
                        let end = (last.start + last.length).max(r.start + r.length);
                        last.length = end - last.start;
                        continue;
                    }
                }
                merged.push(r);
            }

            let mut info_data = vec![0u8; 8];
            info_data[0..4].copy_from_slice(&(merged.len() as u32).to_le_bytes());
            info_data[4..8].copy_from_slice(&0u32.to_le_bytes());

            items.push(crate::fs::btrfs::write::node::LeafItem {
                key: crate::fs::btrfs::tree::Key::new(
                    bg.block_group.start,
                    crate::fs::btrfs::tree::FREE_SPACE_INFO_KEY,
                    bg.block_group.length,
                ),
                data: info_data,
            });

            for r in &merged {
                items.push(crate::fs::btrfs::write::node::LeafItem {
                    key: crate::fs::btrfs::tree::Key::new(
                        r.start,
                        crate::fs::btrfs::tree::FREE_SPACE_EXTENT_KEY,
                        r.length,
                    ),
                    data: Vec::new(),
                });
            }
        }
        items
    }
}

/// Read the independent `FREE_SPACE_TREE` if it exists on this filesystem.
///
/// Returns `Ok(Some(ranges))` if a free space tree is present, or `Ok(None)`
/// if the filesystem does not use one or if the root item is absent.
pub fn read_free_space_tree<D: ReadAt>(fs: &Btrfs<D>) -> Result<Option<Vec<FreeRange>>> {
    let root = match fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
        Ok(r) => r,
        Err(LuksError::CorruptFs(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut ranges = Vec::new();
    fs.walk_tree(root.bytenr, &mut |key, _data| {
        if key.item_type == FREE_SPACE_EXTENT_KEY {
            ranges.push(FreeRange {
                start: key.objectid,
                length: key.offset,
            });
        }
        Ok(())
    })?;

    ranges.sort_by_key(|r| r.start);
    Ok(Some(ranges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::btrfs::chunk::{BLOCK_GROUP_DATA, BLOCK_GROUP_METADATA};
    use crate::fs::btrfs::write::extent_tree::BlockGroupItem;

    #[test]
    fn bg_holds_data_rejects_metadata_only_block_group() {
        // The predicate this fixed: a METADATA-only block group must not be
        // treated as DATA-capable.
        assert!(!bg_holds_data(BLOCK_GROUP_METADATA));

        // Genuinely DATA and genuinely MIXED groups must still pass.
        assert!(bg_holds_data(BLOCK_GROUP_DATA));
        assert!(bg_holds_data(BLOCK_GROUP_DATA | BLOCK_GROUP_METADATA));

        // Control: the expression `bg_holds_data` replaced (`file.rs:65-71`,
        // `alloc.rs:325-327` before this fix) — `flags & DATA != 0 || flags &
        // (DATA|METADATA) != 0` — is true for a METADATA-only block group
        // because its second disjunct only checks "either bit set", not
        // "both bits set". This asserts that old expression really did
        // misclassify METADATA-only as data-capable, so the fix above is
        // known to fail on a real regression rather than passing vacuously.
        let old_buggy_is_data = |flags: u64| {
            (flags & BLOCK_GROUP_DATA != 0)
                || (flags & (BLOCK_GROUP_DATA | BLOCK_GROUP_METADATA) != 0)
        };
        assert!(
            old_buggy_is_data(BLOCK_GROUP_METADATA),
            "control failed: the old expression must misclassify METADATA-only as data-capable"
        );
    }

    fn create_test_data_bg(start: u64, length: u64, free_ranges: Vec<FreeRange>) -> BlockGroupFreeSpace {
        let total_free: u64 = free_ranges.iter().map(|r| r.length).sum();
        BlockGroupFreeSpace {
            block_group: BlockGroupItem {
                start,
                length,
                used: length - total_free,
                chunk_objectid: 256,
                flags: BLOCK_GROUP_DATA,
            },
            allocated_extents: Vec::new(),
            free_ranges,
            pinned_freed: Vec::new(),
            excluded_ranges: Vec::new(),
            total_allocated_bytes: length - total_free,
            total_free_bytes: total_free,
        }
    }

    #[test]
    fn allocate_data_chunk_picks_largest_available_range() {
        let bg = create_test_data_bg(
            0,
            1_000_000,
            vec![
                FreeRange {
                    start: 16_384,
                    length: 16_384,
                },
                FreeRange {
                    start: 65_536,
                    length: 65_536,
                },
                FreeRange {
                    start: 262_144,
                    length: 32_768,
                },
            ],
        );
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // 1. Request 48KB: should allocate from 64KB range at 65,536
        let (bytenr, len) = map.allocate_data_chunk(49_152, 4096).unwrap();
        assert_eq!(bytenr, 65_536);
        assert_eq!(len, 49_152);
        assert_eq!(map.block_groups[0].total_free_bytes, 114_688 - 49_152);

        // 2. Request 48KB: largest remaining is 32KB at 262,144, so it returns 32KB
        let (bytenr, len) = map.allocate_data_chunk(49_152, 4096).unwrap();
        assert_eq!(bytenr, 262_144);
        assert_eq!(len, 32_768);

        // 3. Request 32KB: remaining ranges are two 16KB ranges (16,384 and 114,688).
        // It should return 16KB from the first one.
        let (bytenr, len) = map.allocate_data_chunk(32_768, 4096).unwrap();
        assert_eq!(bytenr, 16_384);
        assert_eq!(len, 16_384);

        // 4. Request remaining 16KB
        let (bytenr, len) = map.allocate_data_chunk(16_384, 4096).unwrap();
        assert_eq!(bytenr, 114_688);
        assert_eq!(len, 16_384);

        // 5. Total free space exhausted
        assert_eq!(map.block_groups[0].total_free_bytes, 0);
        assert!(map.block_groups[0].free_ranges.is_empty());
        assert!(matches!(
            map.allocate_data_chunk(4096, 4096).unwrap_err(),
            LuksError::FilesystemFull
        ));
    }

    #[test]
    fn free_data_and_merging() {
        let bg = create_test_data_bg(0, 1_000_000, Vec::new());
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        map.free_data(10_000, 4096).unwrap();
        assert_eq!(
            map.block_groups[0].pinned_freed,
            vec![FreeRange {
                start: 10_000,
                length: 4096
            }]
        );

        // Adjacent free should merge
        map.free_data(14_096, 4096).unwrap();
        assert_eq!(
            map.block_groups[0].pinned_freed,
            vec![FreeRange {
                start: 10_000,
                length: 8192
            }]
        );

        // Disjoint free
        map.free_data(30_000, 4096).unwrap();
        assert_eq!(
            map.block_groups[0].pinned_freed,
            vec![
                FreeRange {
                    start: 10_000,
                    length: 8192
                },
                FreeRange {
                    start: 30_000,
                    length: 4096
                }
            ]
        );

        // Bridge or prepend to second range
        map.free_data(25_904, 4096).unwrap();
        assert_eq!(
            map.block_groups[0].pinned_freed,
            vec![
                FreeRange {
                    start: 10_000,
                    length: 8192
                },
                FreeRange {
                    start: 25_904,
                    length: 8192
                }
            ]
        );
    }

    #[test]
    fn allocate_data_chunk_unaligned_free_range() {
        let bg = create_test_data_bg(
            0,
            1_000_000,
            vec![FreeRange {
                start: 4000,
                length: 10_000, // 4000..14000
            }],
        );
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // Aligned start at 4096, usable is 8192 (4096..12288)
        let (bytenr, len) = map.allocate_data_chunk(4096, 4096).unwrap();
        assert_eq!(bytenr, 4096);
        assert_eq!(len, 4096);

        // Before fragment 4000..4096 (len 96) and after fragment 8192..14000 (len 5808)
        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 4000,
                    length: 96
                },
                FreeRange {
                    start: 8192,
                    length: 5808
                },
            ]
        );
    }

    #[test]
    fn test_exclude_ranges_split_and_trim() {
        let bg = create_test_data_bg(
            0,
            1_000_000,
            vec![FreeRange {
                start: 10_000,
                length: 20_000, // 10_000..30_000
            }],
        );
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // Exclude 18_000..22_000 (split) and 28_000..35_000 (trim end)
        map.exclude_ranges(&[18_000..22_000, 28_000..35_000]);

        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 10_000,
                    length: 8000, // 10_000..18_000
                },
                FreeRange {
                    start: 22_000,
                    length: 6000, // 22_000..28_000
                },
            ]
        );
        assert_eq!(map.block_groups[0].total_free_bytes, 14_000);
        assert_eq!(
            map.block_groups[0].excluded_ranges,
            vec![
                FreeRange {
                    start: 18_000,
                    length: 4000,
                },
                FreeRange {
                    start: 28_000,
                    length: 2000, // clamped to free range end 30_000
                },
            ]
        );

        // Verify emit_free_space_tree_items merges them back cleanly to 10_000..30_000
        let items = map.emit_free_space_tree_items();
        // 1 info item + 1 extent item
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].key.objectid, 10_000);
        assert_eq!(items[1].key.offset, 20_000);
    }

    #[test]
    fn test_exclude_ranges_prevents_allocation_on_mirror() {
        let mut bg = create_test_data_bg(
            30_000_000,
            40_000_000,
            vec![FreeRange {
                start: 58_000_000,
                length: 2_000_000, // 58_000_000..60_000_000
            }],
        );
        bg.block_group.flags = BLOCK_GROUP_METADATA;

        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // Exclude Mirror 1 range at 58_720_256..58_785_792 (64 KiB)
        map.exclude_ranges(&[58_720_256..58_785_792]);

        // Range before mirror is 58_000_000..58_720_256 (720_256 bytes)
        // Range after mirror is 58_785_792..60_000_000 (1_214_208 bytes)
        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 58_000_000,
                    length: 720_256,
                },
                FreeRange {
                    start: 58_785_792,
                    length: 1_214_208,
                },
            ]
        );

        // Exhaust the first range with metadata allocations
        while let Ok(bytenr) = map.allocate_metadata(16384) {
            assert!(
                bytenr + 16384 <= 58_720_256 || bytenr >= 58_785_792,
                "allocation {bytenr:#x} must not overlap excluded mirror [58720256, 58785792)"
            );
        }
    }

    /// Mirrors `test_exclude_ranges_prevents_allocation_on_mirror`, but for
    /// the Bug B fix: on a MIXED (DATA|METADATA) block group, a writer's
    /// reserved-but-uncommitted data run — excluded via `exclude_ranges`
    /// exactly as `chunk_alloc::allocate_data_chunk_transaction_excluding`
    /// does before its DEV_TREE/CHUNK_TREE/EXTENT_TREE CoW — must never be
    /// handed back out by `allocate_metadata`, since both draw from the same
    /// `free_ranges` pool on a combined block group.
    #[test]
    fn test_exclude_ranges_prevents_metadata_landing_in_reserved_data_run_on_mixed_bg() {
        let mut bg = create_test_data_bg(
            10_000_000,
            20_000_000,
            vec![FreeRange {
                start: 10_000_000,
                length: 20_000_000, // 10_000_000..30_000_000
            }],
        );
        bg.block_group.flags = BLOCK_GROUP_DATA | BLOCK_GROUP_METADATA;

        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // A writer has already chosen (but not committed) a 1 MiB data run
        // in the middle of the free range.
        let reserved_start = 15_000_000u64;
        let reserved_len = 1_048_576u64;
        map.exclude_ranges(&[reserved_start..reserved_start + reserved_len]);

        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 10_000_000,
                    length: reserved_start - 10_000_000,
                },
                FreeRange {
                    start: reserved_start + reserved_len,
                    length: 30_000_000 - (reserved_start + reserved_len),
                },
            ]
        );

        // Metadata allocation must never touch the reserved run, all the
        // way to exhaustion of what remains.
        while let Ok(bytenr) = map.allocate_metadata(4096) {
            assert!(
                bytenr + 4096 <= reserved_start || bytenr >= reserved_start + reserved_len,
                "metadata allocation {bytenr:#x} must not land inside the writer's \
                 reserved data run [{reserved_start:#x}, {:#x})",
                reserved_start + reserved_len
            );
        }
    }

    /// Stage B1 vacuity control: a legitimate free (range inside a block
    /// group, within `used`, not already pinned) must still succeed and
    /// must still decrement `used` by exactly the freed length. This proves
    /// the four new rejections below are not accidentally rejecting
    /// everything.
    #[test]
    fn free_data_legitimate_free_succeeds_and_decrements_used() {
        let bg = create_test_data_bg(0, 1_000_000, Vec::new()); // used = 1_000_000
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        assert_eq!(map.block_groups[0].block_group.used, 1_000_000);
        map.free_data(10_000, 4096).expect("legitimate free must succeed");
        assert_eq!(map.block_groups[0].block_group.used, 1_000_000 - 4096);
        assert_eq!(
            map.block_groups[0].pinned_freed,
            vec![FreeRange {
                start: 10_000,
                length: 4096
            }]
        );
    }

    /// Stage B1 check 1: `bytenr + size` overflowing `u64` must be rejected
    /// rather than wrapping into a bogus range.
    #[test]
    fn free_data_rejects_range_overflow() {
        let bg = create_test_data_bg(0, 1_000_000, Vec::new());
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        let err = map.free_data(u64::MAX - 10, 100).unwrap_err();
        assert!(matches!(err, LuksError::CorruptFs(_)));
    }

    /// Stage B1 check 2: a range that falls inside no block group must be a
    /// hard error, not the silent `Ok(())` that let a phantom free through
    /// undetected. This is the exact defect that produced "block group
    /// [13631488 8388608] used 2105344 but extent items used 2109440".
    #[test]
    fn free_data_rejects_range_outside_any_block_group() {
        let bg = create_test_data_bg(0, 1_000_000, Vec::new());
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        let err = map.free_data(5_000_000, 4096).unwrap_err();
        assert!(matches!(err, LuksError::CorruptFs(_)));
    }

    /// Stage B1 check 3: freeing more bytes than the block group's `used`
    /// counter records must be rejected rather than silently saturating
    /// `used` to zero and hiding the inconsistency.
    #[test]
    fn free_data_rejects_freeing_more_than_used() {
        let mut bg = create_test_data_bg(0, 1_000_000, Vec::new());
        bg.block_group.used = 2048; // less than the range we'll try to free
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        let err = map.free_data(10_000, 4096).unwrap_err();
        assert!(matches!(err, LuksError::CorruptFs(_)));
        // used must be left untouched on rejection, not partially decremented.
        assert_eq!(map.block_groups[0].block_group.used, 2048);
    }

    /// Stage B1 check 4: freeing a range that overlaps one already in
    /// `pinned_freed` is a double free within the same transaction and must
    /// be rejected.
    #[test]
    fn free_data_rejects_double_free_overlap() {
        let bg = create_test_data_bg(0, 1_000_000, Vec::new());
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        map.free_data(10_000, 4096).expect("first free must succeed");
        // Overlaps [10_000, 14_096) at the tail end.
        let err = map.free_data(12_000, 4096).unwrap_err();
        assert!(matches!(err, LuksError::CorruptFs(_)));

        // Exact duplicate free is also an overlap.
        let err = map.free_data(10_000, 4096).unwrap_err();
        assert!(matches!(err, LuksError::CorruptFs(_)));
    }

    #[test]
    fn test_mark_allocated() {
        let bg = create_test_data_bg(
            10_000_000,
            20_000_000,
            vec![
                FreeRange {
                    start: 10_000_000,
                    length: 1_000_000,
                },
                FreeRange {
                    start: 15_000_000,
                    length: 2_000_000,
                },
            ],
        );
        let mut map = FreeSpaceMap {
            block_groups: vec![bg],
        };

        // Initially: length = 20M, free = 3M, allocated = 17M
        assert_eq!(map.block_groups[0].total_allocated_bytes, 17_000_000);
        assert_eq!(map.block_groups[0].total_free_bytes, 3_000_000);

        // 1. Carve from middle of second range (16_000_000..16_500_000)
        map.mark_allocated(16_000_000, 500_000).expect("mark allocated middle");
        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 10_000_000,
                    length: 1_000_000,
                },
                FreeRange {
                    start: 15_000_000,
                    length: 1_000_000,
                },
                FreeRange {
                    start: 16_500_000,
                    length: 500_000,
                },
            ]
        );
        assert_eq!(map.block_groups[0].total_allocated_bytes, 17_500_000);
        assert_eq!(map.block_groups[0].total_free_bytes, 2_500_000);
        assert_eq!(map.block_groups[0].block_group.used, 17_500_000);

        // 2. Carve entire first range (10_000_000..11_000_000)
        map.mark_allocated(10_000_000, 1_000_000).expect("mark allocated exact");
        assert_eq!(
            map.block_groups[0].free_ranges,
            vec![
                FreeRange {
                    start: 15_000_000,
                    length: 1_000_000,
                },
                FreeRange {
                    start: 16_500_000,
                    length: 500_000,
                },
            ]
        );
        assert_eq!(map.block_groups[0].total_allocated_bytes, 18_500_000);
        assert_eq!(map.block_groups[0].total_free_bytes, 1_500_000);

        // 3. Mark already allocated range -> error
        assert!(map.mark_allocated(10_000_000, 1_000_000).is_err());
        // 4. Mark out of bounds range -> error
        assert!(map.mark_allocated(50_000_000, 1_000_000).is_err());
    }
}
