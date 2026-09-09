//! Phase 1: Tier B Accounting Oracle.
//!
//! Provides in-process, independent verification of Btrfs bookkeeping and
//! space accounting across the entire filesystem:
//!
//! 1. **Invariant A-1 (Tree Walk Bijection)**: Recursively walks every tree from
//!    the superblock (`ROOT_TREE`, `CHUNK_TREE`, and every tree registered as a
//!    `ROOT_ITEM` in the Root Tree: `FS_TREE`, `EXTENT_TREE`, `CSUM_TREE`,
//!    `DEV_TREE`, `UUID_TREE`, `FREE_SPACE_TREE`, and all subvolumes/snapshots).
//!    Asserts that every visited metadata tree block exists in the Extent Tree
//!    with matching size, and every referenced file data extent exists in the
//!    Extent Tree with matching size.
//! 2. **Invariant A-2 (No Orphan / Leaked Extents)**: Asserts that every
//!    `EXTENT_ITEM` and `METADATA_ITEM` in the Extent Tree is referenced by at
//!    least one live tree (no leaked allocations).
//! 3. **Invariant A-3 (No Overlapping Live Extents)**: Asserts that no two live
//!    extents (data or metadata) overlap on disk (`ext[i].end <= ext[i+1].start`).
//! 4. **Invariant A-4 (Block Group Sum Parity)**: For every `BLOCK_GROUP_ITEM`,
//!    asserts that `bg.used` equals the exact sum of live extents lying within
//!    that block group's address range.
//! 5. **Invariant A-5 (Superblock Sum Parity)**: Asserts that `sb.bytes_used`
//!    equals the sum of all block group `used` counters and the sum of all
//!    referenced live extent lengths.
//! 6. **Invariant A-6 (Allocator Consistency)**: When checked against an active
//!    `FreeSpaceMap`, asserts that no live extent overlaps with any `FreeRange`
//!    or `pinned_freed` range held by the allocator.

#![allow(dead_code)]
#![cfg(feature = "dangerous-write-support")]

use std::collections::HashMap;

use luks_core::device::ReadAt;
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::extent::{ExtentKind, FileExtent};
use luks_core::fs::btrfs::tree::{
    CHUNK_TREE_OBJECTID, EXTENT_DATA_KEY, ROOT_ITEM_KEY, ROOT_TREE_OBJECTID,
};
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;

/// Detailed breakdown of an accounting check failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingError {
    /// Superblock `bytes_used` does not match sum of block group `used` or referenced extents.
    SuperblockMismatch {
        superblock_bytes_used: u64,
        total_bg_used: u64,
        total_referenced_bytes: u64,
    },
    /// A block group's `used` counter does not match the sum of extents within it.
    BlockGroupUsedMismatch {
        bg_start: u64,
        bg_len: u64,
        bg_used: u64,
        calculated_used: u64,
    },
    /// A tree block or data extent is referenced by a live tree but missing from the extent tree.
    MissingExtentInExtentTree {
        bytenr: u64,
        length: u64,
        tree: u64,
        is_metadata: bool,
    },
    /// An extent is recorded in the extent tree but not referenced by any live tree (orphan/leak).
    UnreferencedExtentInExtentTree {
        bytenr: u64,
        length: u64,
        is_metadata: bool,
    },
    /// An extent's length in the extent tree does not match its referenced length.
    ExtentLengthMismatch {
        bytenr: u64,
        extent_tree_len: u64,
        referenced_len: u64,
    },
    /// Two live extents overlap on disk.
    OverlappingExtents {
        first_bytenr: u64,
        first_len: u64,
        second_bytenr: u64,
        second_len: u64,
    },
    /// An extent spills outside its containing block group.
    ExtentOutOfBounds {
        bytenr: u64,
        length: u64,
        bg_start: u64,
        bg_end: u64,
    },
    /// Extent type (data vs metadata) is incompatible with containing block group flags.
    ExtentTypeMismatch {
        bytenr: u64,
        is_data: bool,
        bg_flags: u64,
        bg_start: u64,
    },
    /// A live extent overlaps with a range the allocator considers free or pinned.
    AllocatorOverlap {
        bytenr: u64,
        length: u64,
        range_start: u64,
        range_len: u64,
        is_pinned: bool,
    },
    /// Underlying filesystem read/corruption error.
    CorruptFs(String),
}

impl std::fmt::Display for AccountingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SuperblockMismatch {
                superblock_bytes_used,
                total_bg_used,
                total_referenced_bytes,
            } => write!(
                f,
                "Superblock bytes_used mismatch: sb has {superblock_bytes_used} bytes, \
                 sum of block groups is {total_bg_used} bytes, \
                 sum of referenced extents is {total_referenced_bytes} bytes"
            ),
            Self::BlockGroupUsedMismatch {
                bg_start,
                bg_len,
                bg_used,
                calculated_used,
            } => write!(
                f,
                "Block group at [{bg_start:#x}..{:#x}] used counter mismatch: \
                 recorded used={bg_used}, calculated extent sum={calculated_used}",
                bg_start + bg_len
            ),
            Self::MissingExtentInExtentTree {
                bytenr,
                length,
                tree,
                is_metadata,
            } => write!(
                f,
                "Missing extent in Extent Tree: tree {tree} references {} at {bytenr:#x} (len {length}), \
                 but no matching EXTENT_ITEM/METADATA_ITEM exists",
                if *is_metadata { "tree block" } else { "data extent" }
            ),
            Self::UnreferencedExtentInExtentTree {
                bytenr,
                length,
                is_metadata,
            } => write!(
                f,
                "Unreferenced extent in Extent Tree: {} at {bytenr:#x} (len {length}) \
                 is recorded as allocated, but no live tree references it (leak/orphan)",
                if *is_metadata { "METADATA_ITEM" } else { "EXTENT_ITEM" }
            ),
            Self::ExtentLengthMismatch {
                bytenr,
                extent_tree_len,
                referenced_len,
            } => write!(
                f,
                "Extent length mismatch at {bytenr:#x}: extent tree records {extent_tree_len} bytes, \
                 live tree references {referenced_len} bytes"
            ),
            Self::OverlappingExtents {
                first_bytenr,
                first_len,
                second_bytenr,
                second_len,
            } => write!(
                f,
                "Overlapping extents detected on disk: extent at [{first_bytenr:#x}..{:#x}] (len {first_len}) \
                 overlaps with extent at [{second_bytenr:#x}..{:#x}] (len {second_len})",
                first_bytenr + first_len,
                second_bytenr + second_len
            ),
            Self::ExtentOutOfBounds {
                bytenr,
                length,
                bg_start,
                bg_end,
            } => write!(
                f,
                "Extent [{bytenr:#x}..{:#x}] (len {length}) spills outside block group [{bg_start:#x}..{bg_end:#x}]",
                bytenr + length
            ),
            Self::ExtentTypeMismatch {
                bytenr,
                is_data,
                bg_flags,
                bg_start,
            } => write!(
                f,
                "Extent at {bytenr:#x} type mismatch: {} extent placed in block group at {bg_start:#x} with flags {bg_flags:#x}",
                if *is_data { "DATA" } else { "METADATA" }
            ),
            Self::AllocatorOverlap {
                bytenr,
                length,
                range_start,
                range_len,
                is_pinned,
            } => write!(
                f,
                "Live extent [{bytenr:#x}..{:#x}] (len {length}) overlaps with allocator {} range [{range_start:#x}..{:#x}] (len {range_len})",
                bytenr + length,
                if *is_pinned { "pinned_freed" } else { "free" },
                range_start + range_len
            ),
            Self::CorruptFs(msg) => write!(f, "Filesystem corruption during accounting check: {msg}"),
        }
    }
}

impl std::error::Error for AccountingError {}

impl From<LuksError> for AccountingError {
    fn from(err: LuksError) -> Self {
        Self::CorruptFs(err.to_string())
    }
}

/// Summary report produced by a successful accounting verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingReport {
    pub superblock_bytes_used: u64,
    pub total_block_group_used: u64,
    pub total_referenced_bytes: u64,
    pub block_groups: Vec<BlockGroupSummary>,
    pub total_metadata_blocks: usize,
    pub total_data_extents: usize,
    pub trees_checked: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockGroupSummary {
    pub start: u64,
    pub length: u64,
    pub flags: u64,
    pub used: u64,
    pub metadata_extents_count: usize,
    pub data_extents_count: usize,
}

#[derive(Debug, Clone)]
struct ReferencedBlock {
    bytenr: u64,
    length: u64,
    level: u8,
    generation: u64,
    tree_id: u64,
}

#[derive(Debug, Clone)]
struct ReferencedDataExtent {
    disk_bytenr: u64,
    length: u64,
    tree_id: u64,
    inode: u64,
    file_offset: u64,
}

pub struct AccountingOracle;

impl AccountingOracle {
    /// Perform full accounting verification against a mounted Btrfs filesystem.
    pub fn check<D: ReadAt>(fs: &Btrfs<D>) -> std::result::Result<AccountingReport, AccountingError> {
        Self::check_internal(fs, None)
    }

    /// Perform full accounting verification and cross-check against an active `FreeSpaceMap`.
    pub fn check_with_allocator<D: ReadAt>(
        fs: &Btrfs<D>,
        allocator: &FreeSpaceMap,
    ) -> std::result::Result<AccountingReport, AccountingError> {
        Self::check_internal(fs, Some(allocator))
    }

    /// Assert that the filesystem is completely accounting-clean, panicking on any violation.
    pub fn assert_clean<D: ReadAt>(fs: &Btrfs<D>) -> AccountingReport {
        match Self::check(fs) {
            Ok(report) => report,
            Err(e) => panic!("Accounting Oracle Invariant Violation: {e}"),
        }
    }

    fn check_internal<D: ReadAt>(
        fs: &Btrfs<D>,
        allocator: Option<&FreeSpaceMap>,
    ) -> std::result::Result<AccountingReport, AccountingError> {
        let sb = fs.superblock();
        let node_size = sb.node_size as u64;
        let sb_bytes_used = sb.bytes_used;

        // 1. Discover all tree roots
        let mut tree_roots: Vec<(u64, u64, u8)> = Vec::new();

        // Superblock roots
        tree_roots.push((ROOT_TREE_OBJECTID, sb.root, sb.root_level));
        tree_roots.push((CHUNK_TREE_OBJECTID, sb.chunk_root, sb.chunk_root_level));
        if sb.log_root != 0 {
            if let Ok(log_node) = fs.read_node(sb.log_root) {
                tree_roots.push((6, sb.log_root, log_node.level));
            }
        }

        // Walk Root Tree to find all other trees (FS, EXTENT, CSUM, DEV, UUID, FST, subvolumes)
        let mut root_tree_visited = Vec::new();
        Self::collect_root_items_from_tree(fs, sb.root, sb.root_level, &mut tree_roots, &mut root_tree_visited)?;

        // Sort and dedup tree roots
        tree_roots.sort_by_key(|&(id, bytenr, _)| (id, bytenr));
        tree_roots.dedup_by_key(|&mut (id, bytenr, _)| (id, bytenr));

        let mut referenced_metadata: HashMap<u64, ReferencedBlock> = HashMap::new();
        let mut referenced_data: HashMap<u64, ReferencedDataExtent> = HashMap::new();
        let mut visited_nodes: HashMap<u64, u8> = HashMap::new();
        let mut checked_tree_ids: Vec<u64> = Vec::new();

        // 2. Recursively walk every tree and collect all referenced blocks and data extents
        for &(tree_id, root_bytenr, root_level) in &tree_roots {
            checked_tree_ids.push(tree_id);
            Self::walk_tree_recursive(
                fs,
                root_bytenr,
                root_level,
                tree_id,
                node_size,
                &mut referenced_metadata,
                &mut referenced_data,
                &mut visited_nodes,
            )?;
        }
        checked_tree_ids.sort_unstable();
        checked_tree_ids.dedup();

        // 3. Read the Extent Tree (ground-truth allocations and block groups)
        let extent_tree = ExtentTree::read(fs)?;

        // 4. Invariant A-1: Check that every referenced metadata block and data extent
        //    exists in ExtentTree with exact matching length.
        for (&bytenr, block) in &referenced_metadata {
            match extent_tree.extents.binary_search_by_key(&bytenr, |e| e.bytenr) {
                Ok(idx) => {
                    let ext = &extent_tree.extents[idx];
                    if !ext.is_tree_block {
                        return Err(AccountingError::ExtentTypeMismatch {
                            bytenr,
                            is_data: false,
                            bg_flags: 0,
                            bg_start: 0,
                        });
                    }
                    if ext.length != block.length {
                        return Err(AccountingError::ExtentLengthMismatch {
                            bytenr,
                            extent_tree_len: ext.length,
                            referenced_len: block.length,
                        });
                    }
                }
                Err(_) => {
                    return Err(AccountingError::MissingExtentInExtentTree {
                        bytenr,
                        length: block.length,
                        tree: block.tree_id,
                        is_metadata: true,
                    });
                }
            }
        }

        for (&disk_bytenr, data_ext) in &referenced_data {
            match extent_tree.extents.binary_search_by_key(&disk_bytenr, |e| e.bytenr) {
                Ok(idx) => {
                    let ext = &extent_tree.extents[idx];
                    if !ext.is_data {
                        return Err(AccountingError::ExtentTypeMismatch {
                            bytenr: disk_bytenr,
                            is_data: true,
                            bg_flags: 0,
                            bg_start: 0,
                        });
                    }
                    if ext.length != data_ext.length {
                        return Err(AccountingError::ExtentLengthMismatch {
                            bytenr: disk_bytenr,
                            extent_tree_len: ext.length,
                            referenced_len: data_ext.length,
                        });
                    }
                }
                Err(_) => {
                    return Err(AccountingError::MissingExtentInExtentTree {
                        bytenr: disk_bytenr,
                        length: data_ext.length,
                        tree: data_ext.tree_id,
                        is_metadata: false,
                    });
                }
            }
        }

        // 5. Invariant A-3: Check that no two live extents overlap on disk.
        // `extent_tree.extents` is sorted by `bytenr`.
        if extent_tree.extents.len() > 1 {
            for i in 0..extent_tree.extents.len() - 1 {
                let curr = &extent_tree.extents[i];
                let next = &extent_tree.extents[i + 1];
                if curr.bytenr + curr.length > next.bytenr {
                    return Err(AccountingError::OverlappingExtents {
                        first_bytenr: curr.bytenr,
                        first_len: curr.length,
                        second_bytenr: next.bytenr,
                        second_len: next.length,
                    });
                }
            }
        }

        // 6. Invariant A-2: Check that every allocated extent in ExtentTree is referenced
        //    by at least one live tree (no leaked allocations / orphan extents).
        for ext in &extent_tree.extents {
            if ext.is_tree_block {
                if !referenced_metadata.contains_key(&ext.bytenr) {
                    return Err(AccountingError::UnreferencedExtentInExtentTree {
                        bytenr: ext.bytenr,
                        length: ext.length,
                        is_metadata: true,
                    });
                }
            } else if ext.is_data {
                if !referenced_data.contains_key(&ext.bytenr) {
                    return Err(AccountingError::UnreferencedExtentInExtentTree {
                        bytenr: ext.bytenr,
                        length: ext.length,
                        is_metadata: false,
                    });
                }
            }
        }

        // 7. Invariant A-4 & Invariant A-5: Block Group and Superblock sum checks
        let mut total_bg_used = 0u64;
        let mut total_referenced_bytes = 0u64;
        let mut bg_summaries = Vec::new();

        for bg in &extent_tree.block_groups {
            let bg_end = bg.start.checked_add(bg.length).ok_or_else(|| {
                AccountingError::CorruptFs("block group boundary overflow".into())
            })?;
            let mut bg_calculated_used = 0u64;
            let mut meta_count = 0;
            let mut data_count = 0;

            for ext in &extent_tree.extents {
                if ext.bytenr >= bg.start && ext.bytenr < bg_end {
                    if ext.bytenr + ext.length > bg_end {
                        return Err(AccountingError::ExtentOutOfBounds {
                            bytenr: ext.bytenr,
                            length: ext.length,
                            bg_start: bg.start,
                            bg_end,
                        });
                    }

                    // Type compatibility check
                    if ext.is_data {
                        if !bg.is_data() {
                            return Err(AccountingError::ExtentTypeMismatch {
                                bytenr: ext.bytenr,
                                is_data: true,
                                bg_flags: bg.flags,
                                bg_start: bg.start,
                            });
                        }
                        data_count += 1;
                    }
                    if ext.is_tree_block {
                        if !bg.is_metadata() && !bg.is_system() && !bg.is_data() {
                            return Err(AccountingError::ExtentTypeMismatch {
                                bytenr: ext.bytenr,
                                is_data: false,
                                bg_flags: bg.flags,
                                bg_start: bg.start,
                            });
                        }
                        meta_count += 1;
                    }

                    bg_calculated_used += ext.length;
                }
            }

            if bg_calculated_used != bg.used {
                return Err(AccountingError::BlockGroupUsedMismatch {
                    bg_start: bg.start,
                    bg_len: bg.length,
                    bg_used: bg.used,
                    calculated_used: bg_calculated_used,
                });
            }

            total_bg_used += bg.used;
            total_referenced_bytes += bg_calculated_used;

            bg_summaries.push(BlockGroupSummary {
                start: bg.start,
                length: bg.length,
                flags: bg.flags,
                used: bg.used,
                metadata_extents_count: meta_count,
                data_extents_count: data_count,
            });
        }

        if sb_bytes_used != total_bg_used || sb_bytes_used != total_referenced_bytes {
            return Err(AccountingError::SuperblockMismatch {
                superblock_bytes_used: sb_bytes_used,
                total_bg_used,
                total_referenced_bytes,
            });
        }

        // 8. Invariant A-6: Optional FreeSpaceMap consistency check
        if let Some(alloc) = allocator {
            for bg_free in &alloc.block_groups {
                // Assert sum of allocated + free in allocator matches block group length
                if bg_free.total_allocated_bytes != bg_free.block_group.used {
                    return Err(AccountingError::BlockGroupUsedMismatch {
                        bg_start: bg_free.block_group.start,
                        bg_len: bg_free.block_group.length,
                        bg_used: bg_free.block_group.used,
                        calculated_used: bg_free.total_allocated_bytes,
                    });
                }

                // Check free ranges do not overlap any live extent
                for fr in &bg_free.free_ranges {
                    let fr_end = fr.start + fr.length;
                    for ext in &extent_tree.extents {
                        let ext_end = ext.bytenr + ext.length;
                        if ext.bytenr < fr_end && ext_end > fr.start {
                            return Err(AccountingError::AllocatorOverlap {
                                bytenr: ext.bytenr,
                                length: ext.length,
                                range_start: fr.start,
                                range_len: fr.length,
                                is_pinned: false,
                            });
                        }
                    }
                }

                // Check pinned freed ranges do not overlap any live extent
                for pf in &bg_free.pinned_freed {
                    let pf_end = pf.start + pf.length;
                    for ext in &extent_tree.extents {
                        let ext_end = ext.bytenr + ext.length;
                        if ext.bytenr < pf_end && ext_end > pf.start {
                            return Err(AccountingError::AllocatorOverlap {
                                bytenr: ext.bytenr,
                                length: ext.length,
                                range_start: pf.start,
                                range_len: pf.length,
                                is_pinned: true,
                            });
                        }
                    }
                }
            }
        }

        Ok(AccountingReport {
            superblock_bytes_used: sb_bytes_used,
            total_block_group_used: total_bg_used,
            total_referenced_bytes,
            block_groups: bg_summaries,
            total_metadata_blocks: referenced_metadata.len(),
            total_data_extents: referenced_data.len(),
            trees_checked: checked_tree_ids,
        })
    }

    /// Walk the Root Tree to collect all registered tree roots (`ROOT_ITEM_KEY`).
    fn collect_root_items_from_tree<D: ReadAt>(
        fs: &Btrfs<D>,
        bytenr: u64,
        expected_level: u8,
        tree_roots: &mut Vec<(u64, u64, u8)>,
        visited: &mut Vec<u64>,
    ) -> Result<()> {
        if visited.contains(&bytenr) {
            return Ok(());
        }
        visited.push(bytenr);

        let node = fs.read_node(bytenr)?;
        if node.level != expected_level {
            return Err(LuksError::CorruptFs("root tree node level mismatch"));
        }

        if node.is_leaf() {
            for i in 0..node.nr_items {
                let key = node.key(i)?;
                if key.item_type == ROOT_ITEM_KEY {
                    let data = node.item_data(i)?;
                    if data.len() >= 239 {
                        let root_bytenr = u64::from_le_bytes(data[176..184].try_into().unwrap());
                        let level = data[238];
                        if root_bytenr > 0 {
                            tree_roots.push((key.objectid, root_bytenr, level));
                        }
                    }
                }
            }
        } else {
            for i in 0..node.nr_items {
                let ptr = node.key_ptr(i)?;
                Self::collect_root_items_from_tree(fs, ptr.blockptr, node.level - 1, tree_roots, visited)?;
            }
        }
        Ok(())
    }

    /// Recursively walks a B-tree from `bytenr`, collecting every node/leaf as metadata
    /// and every `EXTENT_DATA` item as a data extent.
    #[allow(clippy::too_many_arguments)]
    fn walk_tree_recursive<D: ReadAt>(
        fs: &Btrfs<D>,
        bytenr: u64,
        expected_level: u8,
        tree_id: u64,
        node_size: u64,
        referenced_metadata: &mut HashMap<u64, ReferencedBlock>,
        referenced_data: &mut HashMap<u64, ReferencedDataExtent>,
        visited_nodes: &mut HashMap<u64, u8>,
    ) -> Result<()> {
        if visited_nodes.contains_key(&bytenr) {
            return Ok(());
        }
        visited_nodes.insert(bytenr, expected_level);

        let node = fs.read_node(bytenr)?;
        if node.level != expected_level {
            return Err(LuksError::CorruptFs("tree node level mismatch"));
        }

        referenced_metadata.insert(
            bytenr,
            ReferencedBlock {
                bytenr,
                length: node_size,
                level: node.level,
                generation: node.generation,
                tree_id,
            },
        );

        if node.is_leaf() {
            for i in 0..node.nr_items {
                let key = node.key(i)?;
                if key.item_type == EXTENT_DATA_KEY {
                    let data = node.item_data(i)?;
                    if let Ok(file_ext) = FileExtent::parse(key.offset, data) {
                        if file_ext.kind != ExtentKind::Inline && file_ext.disk_bytenr > 0 {
                            referenced_data.insert(
                                file_ext.disk_bytenr,
                                ReferencedDataExtent {
                                    disk_bytenr: file_ext.disk_bytenr,
                                    length: file_ext.disk_num_bytes,
                                    tree_id,
                                    inode: key.objectid,
                                    file_offset: key.offset,
                                },
                            );
                        }
                    }
                }
            }
        } else {
            for i in 0..node.nr_items {
                let ptr = node.key_ptr(i)?;
                Self::walk_tree_recursive(
                    fs,
                    ptr.blockptr,
                    node.level - 1,
                    tree_id,
                    node_size,
                    referenced_metadata,
                    referenced_data,
                    visited_nodes,
                )?;
            }
        }
        Ok(())
    }
}
