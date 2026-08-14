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

            // Find all allocated extents belonging to this block group.
            let mut bg_extents = Vec::new();
            for ext in &extent_tree.extents {
                if ext.bytenr >= bg_start && ext.bytenr < bg_end {
                    let ext_end = ext.bytenr.checked_add(ext.length).ok_or_else(|| {
                        LuksError::CorruptFs("extent range overflow")
                    })?;
                    if ext_end > bg_end {
                        return Err(LuksError::CorruptFs(
                            "extent spans across block group boundary",
                        ));
                    }
                    bg_extents.push(ext.clone());
                }
            }

            // Compute free ranges by walking gaps between allocations.
            let mut free_ranges = Vec::new();
            let mut cursor = bg_start;
            let mut total_allocated = 0u64;

            for ext in &bg_extents {
                if ext.bytenr < cursor {
                    return Err(LuksError::CorruptFs("overlapping allocated extents in extent tree"));
                }
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
