//! Free-space tracking and allocation derived from the btrfs extent tree.
//!
//! Because this implementation skips maintaining the redundant `FREE_SPACE_TREE`
//! on write (clearing `FREE_SPACE_TREE_VALID` to let Linux rebuild it), the
//! ground truth for all free space is computed directly from the `ExtentTree`.
//!
//! In this pass (Pass B), we compute the free-space map from the extent tree
//! and cross-check it against the filesystem's `FREE_SPACE_TREE` to prove exact
//! parity between our derived view and the kernel's index.

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
    pub total_allocated_bytes: u64,
    pub total_free_bytes: u64,
}

/// The overall free-space map of the filesystem across all block groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeSpaceMap {
    pub block_groups: Vec<BlockGroupFreeSpace>,
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
                total_allocated_bytes: total_allocated,
                total_free_bytes: total_free,
            });
        }

        Ok(FreeSpaceMap {
            block_groups: bg_free_spaces,
        })
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

    /// Allocate a metadata block of `size` bytes.
    ///
    /// Finds a metadata (or mixed data/metadata) block group with sufficient space,
    /// carves out the range, updates the free space accounting, and returns the
    /// logical start address.
    pub fn allocate_metadata(&mut self, size: u32) -> Result<u64> {
        let needed = size as u64;
        let alignment = size as u64;

        for bg in &mut self.block_groups {
            // Check for metadata or mixed block group
            let is_metadata = (bg.block_group.flags & crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA != 0)
                || (bg.block_group.flags & (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                    == (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA));

            if !is_metadata {
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
            let is_data = (bg.block_group.flags & crate::fs::btrfs::chunk::BLOCK_GROUP_DATA != 0)
                || (bg.block_group.flags & (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                    == (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA));

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

    /// Emit the complete list of `FREE_SPACE_INFO` and `FREE_SPACE_EXTENT` items
    /// for the Free Space Tree, combining existing free ranges with blocks freed
    /// in this transaction.
    pub fn emit_free_space_tree_items(&self) -> Vec<crate::fs::btrfs::write::node::LeafItem> {
        let mut items = Vec::new();
        for bg in &self.block_groups {
            let mut combined = Vec::new();
            combined.extend_from_slice(&bg.free_ranges);
            combined.extend_from_slice(&bg.pinned_freed);
            combined.sort_by_key(|r| r.start);

            let mut merged: Vec<FreeRange> = Vec::new();
            for r in combined {
                if let Some(last) = merged.last_mut() {
                    if last.start + last.length == r.start {
                        last.length += r.length;
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
