//! Parsing the btrfs extent tree (bookkeeping tree).
//!
//! The extent tree records every allocated extent (data extents and metadata
//! tree blocks) and every block group on the filesystem.
//!
//! The reader never touches this tree because reading file contents only needs
//! the chunk tree (logical -> physical) and the subvolume trees (file extents).
//! A writer must understand the extent tree because allocating space requires
//! finding free ranges and recording new allocations.
//!
//! Ground truth item types parsed here:
//! - `EXTENT_ITEM` (`168`): Data (or legacy tree block) allocations. Key `(bytenr, 168, len)`.
//! - `METADATA_ITEM` (`169`): Skinny metadata allocations. Key `(bytenr, 169, level)`.
//! - `BLOCK_GROUP_ITEM` (`192`): Allocated chunk regions. Key `(start, 192, length)`.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::superblock::BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE;
use crate::fs::btrfs::tree::{
    Key, BLOCK_GROUP_ITEM_KEY, CSUM_TREE_OBJECTID, EXTENT_DATA_REF_KEY, EXTENT_ITEM_KEY,
    EXTENT_TREE_OBJECTID, FREE_SPACE_TREE_OBJECTID, FS_TREE_OBJECTID, METADATA_ITEM_KEY,
    ROOT_ITEM_KEY, ROOT_TREE_OBJECTID, SHARED_BLOCK_REF_KEY, SHARED_DATA_REF_KEY,
    TREE_BLOCK_REF_KEY,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate, read_node, CowResult};
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::node::Leaf;
use crate::fs::btrfs::write::txn::Transaction;
use crate::fs::btrfs::{Btrfs, TreeRoot};

/// Flag bits for `EXTENT_ITEM` / `METADATA_ITEM`.
pub const EXTENT_FLAG_DATA: u64 = 1 << 0;
pub const EXTENT_FLAG_TREE_BLOCK: u64 = 1 << 1;
pub const BLOCK_FLAG_FULL_BACKREF: u64 = 1 << 8;

/// Flag bits for `BLOCK_GROUP_ITEM`.
pub const BLOCK_GROUP_DATA: u64 = 1 << 0;
pub const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
pub const BLOCK_GROUP_METADATA: u64 = 1 << 2;
pub const BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BLOCK_GROUP_RAID1: u64 = 1 << 4;
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;
pub const BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BLOCK_GROUP_RAID6: u64 = 1 << 8;
pub const BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
pub const BLOCK_GROUP_RAID1C4: u64 = 1 << 10;

/// An inline backreference inside an `EXTENT_ITEM` or `METADATA_ITEM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineBackref {
    /// Skinny tree block reference (`TREE_BLOCK_REF_KEY` = 176).
    TreeBlock { root: u64 },
    /// File data extent reference (`EXTENT_DATA_REF_KEY` = 178).
    ExtentData {
        root: u64,
        objectid: u64,
        offset: u64,
        count: u32,
    },
    /// Shared tree block reference (`SHARED_BLOCK_REF_KEY` = 182).
    SharedBlock { parent: u64 },
    /// Shared data reference (`SHARED_DATA_REF_KEY` = 184).
    SharedData { parent: u64, count: u32 },
    /// Unrecognised backref type.
    Other { item_type: u8, data: Vec<u8> },
}

/// A parsed `BLOCK_GROUP_ITEM` describing a contiguous range of logical space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockGroupItem {
    /// Starting logical address of this block group.
    pub start: u64,
    /// Length in bytes of this block group.
    pub length: u64,
    /// Number of bytes currently in use.
    pub used: u64,
    /// Chunk objectid (typically 256 / `FIRST_CHUNK_TREE_OBJECTID`).
    pub chunk_objectid: u64,
    /// Type and profile flags (e.g. `DATA|single`, `METADATA|DUP`).
    pub flags: u64,
}

impl BlockGroupItem {
    pub fn parse(key: &Key, data: &[u8]) -> Result<Self> {
        if key.item_type != BLOCK_GROUP_ITEM_KEY {
            return Err(LuksError::CorruptFs("not a block group item key"));
        }
        if data.len() < 24 {
            return Err(LuksError::CorruptFs("btrfs block group item truncated"));
        }
        let used = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let chunk_objectid = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let flags = u64::from_le_bytes(data[16..24].try_into().unwrap());

        Ok(BlockGroupItem {
            start: key.objectid,
            length: key.offset,
            used,
            chunk_objectid,
            flags,
        })
    }

    pub fn is_data(&self) -> bool {
        self.flags & BLOCK_GROUP_DATA != 0
    }

    pub fn is_system(&self) -> bool {
        self.flags & BLOCK_GROUP_SYSTEM != 0
    }

    /// Emit a `BLOCK_GROUP_ITEM` key and 24-byte payload.
    pub fn emit(&self) -> (Key, Vec<u8>) {
        let key = Key::new(self.start, BLOCK_GROUP_ITEM_KEY, self.length);
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&self.used.to_le_bytes());
        data[8..16].copy_from_slice(&self.chunk_objectid.to_le_bytes());
        data[16..24].copy_from_slice(&self.flags.to_le_bytes());
        (key, data)
    }

    pub fn is_metadata(&self) -> bool {
        self.flags & BLOCK_GROUP_METADATA != 0
    }

    pub fn is_dup(&self) -> bool {
        self.flags & BLOCK_GROUP_DUP != 0
    }

    pub fn is_single(&self) -> bool {
        (self.flags & (BLOCK_GROUP_DUP | BLOCK_GROUP_RAID0 | BLOCK_GROUP_RAID1 | BLOCK_GROUP_RAID10 | BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6)) == 0
    }

    /// Format the flags as human-readable string matching `btrfs inspect-internal dump-tree`.
    pub fn profile_name(&self) -> String {
        let mut types = Vec::new();
        if self.is_data() {
            types.push("DATA");
        }
        if self.is_system() {
            types.push("SYSTEM");
        }
        if self.is_metadata() {
            types.push("METADATA");
        }
        let type_str = if types.is_empty() {
            "UNKNOWN".to_string()
        } else {
            types.join("|")
        };

        let profile = if self.is_dup() {
            "DUP"
        } else if self.flags & BLOCK_GROUP_RAID0 != 0 {
            "RAID0"
        } else if self.flags & BLOCK_GROUP_RAID1 != 0 {
            "RAID1"
        } else if self.flags & BLOCK_GROUP_RAID10 != 0 {
            "RAID10"
        } else {
            "single"
        };

        format!("{type_str}|{profile}")
    }
}

/// A parsed `EXTENT_ITEM` (data extent or non-skinny tree block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentItem {
    pub bytenr: u64,
    pub length: u64,
    pub refs: u64,
    pub generation: u64,
    pub flags: u64,
    pub backrefs: Vec<InlineBackref>,
}

impl ExtentItem {
    pub fn parse(key: &Key, data: &[u8]) -> Result<Self> {
        if key.item_type != EXTENT_ITEM_KEY {
            return Err(LuksError::CorruptFs("not an extent item key"));
        }
        if data.len() < 24 {
            return Err(LuksError::CorruptFs("btrfs extent item truncated"));
        }
        let refs = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let generation = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let flags = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let backrefs = parse_inline_backrefs(&data[24..])?;

        Ok(ExtentItem {
            bytenr: key.objectid,
            length: key.offset,
            refs,
            generation,
            flags,
            backrefs,
        })
    }

    /// Emit an `EXTENT_ITEM` key and payload for an allocated data extent with an inline `EXTENT_DATA_REF`.
    pub fn emit_data_extent(
        disk_bytenr: u64,
        disk_num_bytes: u64,
        generation: u64,
        root: u64,
        objectid: u64,
        offset: u64,
    ) -> (Key, Vec<u8>) {
        let key = Key::new(disk_bytenr, EXTENT_ITEM_KEY, disk_num_bytes);
        let mut data = vec![0u8; 53];
        // refs = 1
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        // generation
        data[8..16].copy_from_slice(&generation.to_le_bytes());
        // flags: EXTENT_FLAG_DATA (0x1)
        data[16..24].copy_from_slice(&EXTENT_FLAG_DATA.to_le_bytes());
        // inline backref: EXTENT_DATA_REF_KEY (178)
        data[24] = EXTENT_DATA_REF_KEY;
        data[25..33].copy_from_slice(&root.to_le_bytes());
        data[33..41].copy_from_slice(&objectid.to_le_bytes());
        data[41..49].copy_from_slice(&offset.to_le_bytes());
        data[49..53].copy_from_slice(&1u32.to_le_bytes()); // count = 1
        (key, data)
    }
}

/// A parsed `METADATA_ITEM` (skinny metadata tree block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataItem {
    pub bytenr: u64,
    /// Tree level (0 for leaf, 1+ for interior node).
    pub level: u8,
    pub refs: u64,
    pub generation: u64,
    pub flags: u64,
    pub backrefs: Vec<InlineBackref>,
}

impl MetadataItem {
    pub fn parse(key: &Key, data: &[u8]) -> Result<Self> {
        if key.item_type != METADATA_ITEM_KEY {
            return Err(LuksError::CorruptFs("not a metadata item key"));
        }
        if data.len() < 24 {
            return Err(LuksError::CorruptFs("btrfs metadata item truncated"));
        }
        let refs = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let generation = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let flags = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let backrefs = parse_inline_backrefs(&data[24..])?;

        Ok(MetadataItem {
            bytenr: key.objectid,
            level: key.offset as u8,
            refs,
            generation,
            flags,
            backrefs,
        })
    }

    /// Emit a `METADATA_ITEM` key and payload for an allocated tree block.
    pub fn emit_tree_block(
        bytenr: u64,
        level: u8,
        generation: u64,
        owner_root: u64,
    ) -> (Key, Vec<u8>) {
        let key = Key::new(bytenr, METADATA_ITEM_KEY, level as u64);
        let mut data = vec![0u8; 33];
        // refs = 1
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        // generation
        data[8..16].copy_from_slice(&generation.to_le_bytes());
        // flags: EXTENT_FLAG_TREE_BLOCK (0x2)
        data[16..24].copy_from_slice(&EXTENT_FLAG_TREE_BLOCK.to_le_bytes());
        // inline backref: TREE_BLOCK_REF_KEY (176)
        data[24] = TREE_BLOCK_REF_KEY;
        data[25..33].copy_from_slice(&owner_root.to_le_bytes());
        (key, data)
    }
}

fn parse_inline_backrefs(mut data: &[u8]) -> Result<Vec<InlineBackref>> {
    let mut backrefs = Vec::new();
    while !data.is_empty() {
        let backref_type = data[0];
        data = &data[1..];
        match backref_type {
            TREE_BLOCK_REF_KEY => {
                if data.len() < 8 {
                    return Err(LuksError::CorruptFs("tree block ref truncated"));
                }
                let root = u64::from_le_bytes(data[0..8].try_into().unwrap());
                data = &data[8..];
                backrefs.push(InlineBackref::TreeBlock { root });
            }
            EXTENT_DATA_REF_KEY => {
                if data.len() < 28 {
                    return Err(LuksError::CorruptFs("extent data ref truncated"));
                }
                let root = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let objectid = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let offset = u64::from_le_bytes(data[16..24].try_into().unwrap());
                let count = u32::from_le_bytes(data[24..28].try_into().unwrap());
                data = &data[28..];
                backrefs.push(InlineBackref::ExtentData {
                    root,
                    objectid,
                    offset,
                    count,
                });
            }
            SHARED_BLOCK_REF_KEY => {
                if data.len() < 8 {
                    return Err(LuksError::CorruptFs("shared block ref truncated"));
                }
                let parent = u64::from_le_bytes(data[0..8].try_into().unwrap());
                data = &data[8..];
                backrefs.push(InlineBackref::SharedBlock { parent });
            }
            SHARED_DATA_REF_KEY => {
                if data.len() < 12 {
                    return Err(LuksError::CorruptFs("shared data ref truncated"));
                }
                let parent = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let count = u32::from_le_bytes(data[8..12].try_into().unwrap());
                data = &data[12..];
                backrefs.push(InlineBackref::SharedData { parent, count });
            }
            other => {
                // Unknown backref type: capture remaining bytes and stop.
                backrefs.push(InlineBackref::Other {
                    item_type: other,
                    data: data.to_vec(),
                });
                break;
            }
        }
    }
    Ok(backrefs)
}

/// Unified representation of an allocated extent (data or metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatedExtent {
    pub bytenr: u64,
    pub length: u64,
    pub refs: u64,
    pub generation: u64,
    pub is_data: bool,
    pub is_tree_block: bool,
    pub level: u8,
    pub backrefs: Vec<InlineBackref>,
}

/// The entire bookkeeping extent tree as parsed from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentTree {
    pub block_groups: Vec<BlockGroupItem>,
    pub extents: Vec<AllocatedExtent>,
}

impl ExtentTree {
    /// Read the complete extent tree by walking the `EXTENT_TREE_OBJECTID` root.
    ///
    /// # Skinny metadata only
    ///
    /// Refuses a filesystem without `INCOMPAT_SKINNY_METADATA` rather than
    /// parse it. Without that flag, tree blocks are recorded as legacy
    /// `EXTENT_ITEM`s carrying an inline `tree_block_info` (a 17-byte owner
    /// key plus a 1-byte level) *before* the backref list this parser reads
    /// at a fixed offset — measured against a real `mkfs.btrfs
    /// -O ^skinny-metadata` image (2026-08-14): every backref silently came
    /// back as 18-byte-shifted garbage, `level` was always 0, and the
    /// free-space self-check still reported OK, because nothing here checks
    /// backref *content*. Refusing by name is the project convention
    /// (`feature-btrfs-write.md` §1) precisely for cases like this one.
    pub fn read<D: ReadAt>(fs: &Btrfs<D>) -> Result<Self> {
        if !fs.superblock().has_skinny_metadata() {
            return Err(LuksError::UnsupportedFsFeature(
                "non-skinny metadata (legacy EXTENT_ITEM tree blocks) — this filesystem can be read but not written"
                    .into(),
            ));
        }

        let root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
        let mut block_groups = Vec::new();
        let mut extents = Vec::new();
        let node_size = fs.superblock().node_size as u64;

        fs.walk_tree(root.bytenr, &mut |key, data| {
            match key.item_type {
                BLOCK_GROUP_ITEM_KEY => {
                    let bg = BlockGroupItem::parse(&key, data)?;
                    block_groups.push(bg);
                }
                EXTENT_ITEM_KEY => {
                    let item = ExtentItem::parse(&key, data)?;
                    let is_data = item.flags & EXTENT_FLAG_DATA != 0;
                    let is_tree_block = item.flags & EXTENT_FLAG_TREE_BLOCK != 0;
                    extents.push(AllocatedExtent {
                        bytenr: item.bytenr,
                        length: item.length,
                        refs: item.refs,
                        generation: item.generation,
                        is_data,
                        is_tree_block,
                        level: 0,
                        backrefs: item.backrefs,
                    });
                }
                METADATA_ITEM_KEY => {
                    let item = MetadataItem::parse(&key, data)?;
                    extents.push(AllocatedExtent {
                        bytenr: item.bytenr,
                        length: node_size,
                        refs: item.refs,
                        generation: item.generation,
                        is_data: false,
                        is_tree_block: true,
                        level: item.level,
                        backrefs: item.backrefs,
                    });
                }
                _ => {}
            }
            Ok(())
        })?;

        // Sort block groups and extents by address
        block_groups.sort_by_key(|bg| bg.start);
        extents.sort_by_key(|ext| ext.bytenr);

        Ok(ExtentTree {
            block_groups,
            extents,
        })
    }

    /// Total bytes marked as in-use across all extents.
    pub fn total_allocated_bytes(&self) -> u64 {
        self.extents.iter().map(|e| e.length).sum()
    }
}

// The four functions below were moved here (verbatim, plus import fixups)
// from `write/txn.rs` as part of splitting that 3,200+ line file for
// reviewability. They are conceptually extent-tree reconciliation — they
// mutate `ExtentTree`/`BlockGroupItem` state — rather than transaction
// building, so this module is their true home; `write::txn::mod` re-exports
// them so existing `write::txn::{record_cow_result, find_max_inode,
// converge_and_finalize}` import paths keep resolving unchanged.

pub(crate) fn record_cow_result(
    res: &CowResult,
    blocks_to_add: &mut Vec<(u64, u8, u64)>,
    blocks_to_remove: &mut Vec<(u64, u8)>,
    allocator: &mut FreeSpaceMap,
    pending_blocks: &mut HashMap<u64, Vec<u8>>,
    node_size: u32,
    owner: u64,
) -> Result<()> {
    for &(b, lvl) in &res.allocated {
        blocks_to_add.push((b, lvl, owner));
    }
    for &(b, lvl) in &res.freed {
        // A block allocated *and* freed inside one transaction needs no extent
        // item at all — it never existed as far as any committed tree is
        // concerned. Cancel the pending add instead of queueing a matching
        // remove: the convergence loop below drains removes before adds within
        // a round, so a block appearing in both lists would try to delete a
        // METADATA_ITEM that had not been inserted yet.
        //
        // Before the empty-leaf fix in cow.rs this could not happen — `freed`
        // only ever held pre-existing blocks, because a leaf already CoW'd this
        // transaction takes the `is_already_new` path and frees nothing. Now a
        // leaf can be CoW'd by one delete and emptied by the next, which is
        // exactly how four leaves emptied in a single generation on the test
        // stick.
        if let Some(pos) = blocks_to_add.iter().position(|&(add_b, _, _)| add_b == b) {
            blocks_to_add.remove(pos);
            // Drop the stale contents too: the address goes back to the
            // allocator here, so leaving it in `pending_blocks` would let a
            // later reuse of the same address read the emptied node back.
            pending_blocks.remove(&b);
        } else {
            blocks_to_remove.push((b, lvl));
        }
        allocator.free_metadata(b, node_size)?;
    }
    for (b, data) in &res.emitted_blocks {
        pending_blocks.insert(*b, data.clone());
    }
    Ok(())
}

/// Find an item with `key` in the tree rooted at `root_bytenr`, consulting `pending_blocks` if available.
pub(crate) fn find_item_in_tree<D: ReadAt>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    root_bytenr: u64,
    key: &Key,
) -> Result<Option<Vec<u8>>> {
    let mut curr_bytenr = root_bytenr;
    let mut depth = 0;
    while depth < 16 {
        let node = read_node(fs, pending, curr_bytenr)?;
        if node.is_leaf() {
            for i in 0..node.nr_items {
                if node.key(i)? == *key {
                    return Ok(Some(node.item_data(i)?.to_vec()));
                }
            }
            return Ok(None);
        }
        if node.nr_items == 0 {
            return Ok(None);
        }
        let mut child_bytenr = None;
        for i in (0..node.nr_items).rev() {
            let k = node.key(i)?;
            if *key >= k {
                child_bytenr = Some(node.key_ptr(i)?.blockptr);
                break;
            }
        }
        match child_bytenr {
            Some(ptr) => curr_bytenr = ptr,
            None => return Ok(None),
        }
        depth += 1;
    }
    Ok(None)
}

/// Highest real inode number present in the FS tree, or `256` if there are
/// none (the lowest inode objectid btrfs hands out; `1..255` are reserved).
///
/// Descending only the rightmost key pointer at every level (the previous
/// implementation) assumes the largest real inode lives in the rightmost
/// leaf. Sort order does put it there *if* that leaf holds any real inodes —
/// but btrfs's reserved objectids (`ORPHAN_OBJECTID` = `-5`,
/// `FREE_INO_OBJECTID`, etc.) count down from `u64::MAX` and sort after every
/// real inode, so a leaf that holds only reserved-objectid items (e.g. an
/// `ORPHAN_ITEM`, left behind by deleting a file that's still open) sorts
/// last and pushes every real inode out of "the rightmost leaf". The old code
/// would then filter every item out and silently return 256, handing the
/// caller an inode number already in use.
///
/// The fix: start a cursor at the top of the *real*-inode range
/// (`0xFFFF_FFFF_FFFF_FEFF`, the highest legal offset/type at the highest
/// non-reserved objectid) and walk backwards, crossing leaf boundaries via
/// `Cursor::retreat`, until an item with a plausible-inode objectid turns up
/// or the tree is exhausted. This is a genuine search rather than a bet on
/// tree shape, so it is correct regardless of how many reserved-objectid
/// items trail off the end.
///
/// Filtering is on objectid alone, not on `INODE_ITEM_KEY`: every item that
/// belongs to inode N (`INODE_ITEM`, `INODE_REF`, `DIR_ITEM`, `EXTENT_DATA`,
/// ...) shares N as its objectid, and because keys sort by objectid first,
/// the maximum objectid over *any* item type equals the maximum objectid
/// over `INODE_ITEM`s specifically — but reaching it doesn't require the
/// INODE_ITEM to be the last item of that inode's run, so type-filtering
/// would just mean extra retreats for the same answer. Restricting to
/// `INODE_ITEM_KEY` only would still be correct, just costs more steps when
/// an inode's non-INODE_ITEM items (e.g. a later DIR_ITEM/EXTENT_DATA,
/// type > 1) sort after it.
pub(crate) fn find_max_inode<D: ReadAt>(fs: &Btrfs<D>) -> Result<u64> {
    const MAX_REAL_INODE_KEY: Key = Key {
        objectid: 0xFFFF_FFFF_FFFF_FEFF,
        item_type: u8::MAX,
        offset: u64::MAX,
    };

    let mut cursor = fs.search_le(fs.fs_tree().bytenr, &MAX_REAL_INODE_KEY)?;
    loop {
        if !cursor.valid() {
            return Ok(256);
        }
        let key = cursor.key()?;
        if key.objectid >= 256 && key.objectid < 0xFFFF_FFFF_FFFF_FF00 {
            return Ok(key.objectid);
        }
        cursor.retreat()?;
    }
}

pub(crate) fn converge_and_finalize<D: ReadAt>(
    fs: &Btrfs<D>,
    new_generation: u64,
    new_fs_tree: TreeRoot,
    csum_root_opt: Option<(u64, u8)>,
    dev_root_opt: Option<(u64, u8)>,
    chunk_root_opt: Option<(u64, u8)>,
    extent_root_opt: Option<(u64, u8)>,
    mut pending_blocks: HashMap<u64, Vec<u8>>,
    pending_data: Vec<(u64, Vec<u8>)>,
    mut allocator: FreeSpaceMap,
    mut blocks_to_add: Vec<(u64, u8, u64)>,
    mut blocks_to_remove: Vec<(u64, u8)>,
    data_extents_to_add: Vec<(u64, u64, u64, u64, u64)>,
    data_extents_to_remove: Vec<(u64, u64)>,
) -> Result<Transaction> {
    let sb = fs.superblock();
    let mut root_tree_bytenr = sb.root;
    let mut root_tree_level = sb.root_level;
    let (mut extent_root_bytenr, mut extent_root_level) = match extent_root_opt {
        Some((b, l)) => (b, l),
        None => {
            let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
            (extent_root.bytenr, extent_root.level)
        }
    };

    // 1. Update FS_TREE root item in ROOT_TREE if modified.
    if new_fs_tree.bytenr != fs.fs_tree().bytenr {
        let fs_root_key = Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let fs_root_bytenr = new_fs_tree.bytenr;
        let fs_root_level = new_fs_tree.level;

        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &fs_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&fs_root_key)
                    .ok_or_else(|| LuksError::NotFound("fs root item not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&fs_root_bytenr.to_le_bytes());
                data[238] = fs_root_level;
                Ok(())
            },
        )?;

        record_cow_result(
            &root_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            ROOT_TREE_OBJECTID,
        )?;
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;
    }

    // 2. Update CSUM_TREE root item in ROOT_TREE if modified
    if let Some((csum_bytenr, csum_level)) = csum_root_opt {
        let csum_root_key = Key::new(CSUM_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &csum_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&csum_root_key)
                    .ok_or_else(|| LuksError::NotFound("csum root item not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&csum_bytenr.to_le_bytes());
                data[238] = csum_level;
                Ok(())
            },
        )?;

        record_cow_result(
            &root_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            ROOT_TREE_OBJECTID,
        )?;
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;
    }

    // 2b. Update DEV_TREE root item in ROOT_TREE if modified
    if let Some((dev_bytenr, dev_level)) = dev_root_opt {
        let dev_root_key = Key::new(crate::fs::btrfs::tree::DEV_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &dev_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&dev_root_key)
                    .ok_or_else(|| LuksError::NotFound("dev root item not found in root tree".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("dev root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&dev_bytenr.to_le_bytes());
                data[238] = dev_level;
                Ok(())
            },
        )?;

        record_cow_result(
            &root_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            ROOT_TREE_OBJECTID,
        )?;
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;
    }

    // 3. Insert newly allocated data extents into EXTENT_TREE
    for (bytenr, len, root, ino, offset) in data_extents_to_add {
        let (data_key, data_payload) =
            ExtentItem::emit_data_extent(bytenr, len, new_generation, root, ino, offset);
        let ext_res = cow_tree_insert(
            fs,
            &pending_blocks,
            extent_root_bytenr,
            extent_root_level,
            EXTENT_TREE_OBJECTID,
            data_key,
            data_payload,
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
    }

    // 3b. Delete freed data extents from EXTENT_TREE
    for (bytenr, len) in data_extents_to_remove {
        let ext_key = Key::new(bytenr, EXTENT_ITEM_KEY, len);
        let ext_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            extent_root_bytenr,
            extent_root_level,
            EXTENT_TREE_OBJECTID,
            &ext_key,
            new_generation,
            &mut allocator,
            |leaf| {
                leaf.delete_item(&ext_key)?;
                Ok(())
            },
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
    }

    // 4. Fixed-point loop to drain pending blocks_to_add and blocks_to_remove into EXTENT_TREE.
    // High-fragmentation 4K-node filesystems or multi-extent transfers drain in 1-3 rounds
    // now that FST and block-group updates are hoisted out of this loop.
    const MAX_CONVERGENCE_ROUNDS: u32 = 30;
    let mut _initial_rounds = 0;
    for _iteration in 0..MAX_CONVERGENCE_ROUNDS {
        if blocks_to_add.is_empty() && blocks_to_remove.is_empty() {
            break;
        }
        _initial_rounds += 1;

        let to_remove = std::mem::take(&mut blocks_to_remove);
        for (old_b, old_lvl) in to_remove {
            let del_key = Key::new(old_b, METADATA_ITEM_KEY, old_lvl as u64);
            let ext_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                &del_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let _ = leaf.delete_item(&del_key)?;
                    Ok(())
                },
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
        }

        let to_add = std::mem::take(&mut blocks_to_add);
        for (alloc_bytenr, alloc_level, alloc_owner) in to_add {
            let (meta_key, meta_data) = MetadataItem::emit_tree_block(
                alloc_bytenr,
                alloc_level,
                new_generation,
                alloc_owner,
            );
            let ext_res = cow_tree_insert(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                meta_key,
                meta_data,
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
        }
    }

    // 5. Single final pass for Free Space Tree (FST) and BLOCK_GROUP_ITEM updates.
    // Hoisted out of the fixed-point loop so FST and block group items are rewritten
    // exactly once per transaction rather than once per convergence round.

    // 5a. Update Free Space Tree if present on this filesystem.
    if sb.compat_ro_flags & BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE != 0 {
        if let Ok(fst_root) = fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
            gate::check_free_space_tree_shape(&fst_root)?;

            let fst_target = allocator.allocate_metadata(sb.node_size)?;
            blocks_to_add.push((fst_target, 0, FREE_SPACE_TREE_OBJECTID));
            blocks_to_remove.push((fst_root.bytenr, 0));
            allocator.free_metadata(fst_root.bytenr, sb.node_size)?;

            let old_fst_node =
                read_node(fs, &pending_blocks, fst_root.bytenr)?;
            let chunk_tree_uuid = old_fst_node.chunk_tree_uuid();
            let flags = old_fst_node.flags();

            let fst_leaf = Leaf {
                bytenr: fst_target,
                flags,
                metadata_uuid: sb.metadata_uuid,
                chunk_tree_uuid,
                generation: new_generation,
                owner: FREE_SPACE_TREE_OBJECTID,
                csum_type: sb.csum_type,
                items: allocator.emit_free_space_tree_items(),
            };
            if fst_leaf.free_space(sb.node_size) == 0 {
                return Err(LuksError::UnsupportedFsFeature(
                    "btrfs free-space tree no longer fits in a single leaf".into(),
                ));
            }
            let fst_raw = fst_leaf.emit(sb.node_size)?;
            pending_blocks.insert(fst_target, fst_raw);

            // Update ROOT_ITEM for FREE_SPACE_TREE in ROOT_TREE
            let fst_root_key = Key::new(FREE_SPACE_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
            let root_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                root_tree_bytenr,
                root_tree_level,
                ROOT_TREE_OBJECTID,
                &fst_root_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf.find_item(&fst_root_key).ok_or_else(|| {
                        LuksError::NotFound("fst root item not found".into())
                    })?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 239 {
                        return Err(LuksError::CorruptFs("root item truncated"));
                    }
                    data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                    data[176..184].copy_from_slice(&fst_target.to_le_bytes());
                    data[238] = 0; // level 0
                    Ok(())
                },
            )?;

            record_cow_result(
                &root_res,
                &mut blocks_to_add,
                &mut blocks_to_remove,
                &mut allocator,
                &mut pending_blocks,
                sb.node_size,
                ROOT_TREE_OBJECTID,
            )?;
            root_tree_bytenr = root_res.new_root_bytenr;
            root_tree_level = root_res.new_root_level;
        }
    }

    // 6. Short re-convergence loop to record metadata blocks allocated by FST/BGI updates,
    // keep BLOCK_GROUP_ITEM used counters synchronized with actual allocations,
    // and ensure the extent root pointer in ROOT_TREE is recorded.
    let mut converged = false;
    for _iteration in 0..MAX_CONVERGENCE_ROUNDS {
        let to_remove = std::mem::take(&mut blocks_to_remove);
        for (old_b, old_lvl) in to_remove {
            let del_key = Key::new(old_b, METADATA_ITEM_KEY, old_lvl as u64);
            let ext_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                &del_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let _ = leaf.delete_item(&del_key)?;
                    Ok(())
                },
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
        }

        let to_add = std::mem::take(&mut blocks_to_add);
        for (alloc_bytenr, alloc_level, alloc_owner) in to_add {
            let (meta_key, meta_data) = MetadataItem::emit_tree_block(
                alloc_bytenr,
                alloc_level,
                new_generation,
                alloc_owner,
            );
            let ext_res = cow_tree_insert(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                meta_key,
                meta_data,
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
        }

        // Update BLOCK_GROUP_ITEM in EXTENT_TREE for each block group
        let bg_updates: Vec<_> = allocator
            .block_groups
            .iter()
            .map(|bg| (bg.block_group.start, bg.block_group.length, bg.block_group.used))
            .collect();

        for (bg_start, bg_len, bg_used) in bg_updates {
            let bg_key = Key::new(
                bg_start,
                crate::fs::btrfs::tree::BLOCK_GROUP_ITEM_KEY,
                bg_len,
            );
            let ext_res = cow_tree_mutate(
                fs,
                &pending_blocks,
                extent_root_bytenr,
                extent_root_level,
                EXTENT_TREE_OBJECTID,
                &bg_key,
                new_generation,
                &mut allocator,
                |leaf| {
                    let idx = leaf.find_item(&bg_key).ok_or_else(|| {
                        LuksError::NotFound("block group item not found in extent tree".into())
                    })?;
                    let data = &mut leaf.items[idx].data;
                    if data.len() < 24 {
                        return Err(LuksError::CorruptFs("block group item truncated"));
                    }
                    data[0..8].copy_from_slice(&bg_used.to_le_bytes());
                    Ok(())
                },
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
        }

        // Update EXTENT_TREE root item in ROOT_TREE
        let ext_root_key = Key::new(EXTENT_TREE_OBJECTID, ROOT_ITEM_KEY, 0);
        let root_res = cow_tree_mutate(
            fs,
            &pending_blocks,
            root_tree_bytenr,
            root_tree_level,
            ROOT_TREE_OBJECTID,
            &ext_root_key,
            new_generation,
            &mut allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&ext_root_key)
                    .ok_or_else(|| LuksError::NotFound("extent root item not found".into()))?;
                let data = &mut leaf.items[idx].data;
                if data.len() < 239 {
                    return Err(LuksError::CorruptFs("extent root item truncated"));
                }
                data[160..168].copy_from_slice(&new_generation.to_le_bytes());
                data[176..184].copy_from_slice(&extent_root_bytenr.to_le_bytes());
                data[238] = extent_root_level;
                Ok(())
            },
        )?;

        record_cow_result(
            &root_res,
            &mut blocks_to_add,
            &mut blocks_to_remove,
            &mut allocator,
            &mut pending_blocks,
            sb.node_size,
            ROOT_TREE_OBJECTID,
        )?;
        root_tree_bytenr = root_res.new_root_bytenr;
        root_tree_level = root_res.new_root_level;

        if blocks_to_add.is_empty() && blocks_to_remove.is_empty() {
            converged = true;
            break;
        }
    }

    // The loop above has a round cap so a bug cannot spin forever. Until now it
    // simply *exited* at the cap, which is the silent-failure shape this repo
    // keeps paying for: leftover `blocks_to_add` means blocks were allocated
    // and handed to the commit with no `METADATA_ITEM` recording them, so
    // `btrfs check` would report backref errors on a filesystem we had just
    // declared written. Refuse instead, and say which side did not settle.
    //
    // Live rather than theoretical now: splitting checksums across many items
    // (a 400 MB file needs ~25) multiplies the blocks each round has to record,
    // so the assumption that three rounds always suffice stopped being free.
    if !converged && !(blocks_to_add.is_empty() && blocks_to_remove.is_empty()) {
        return Err(LuksError::CorruptFs(
            "btrfs transaction did not converge: extent-tree bookkeeping still \
             had blocks to record after the round limit",
        ));
    }

    let final_bytes_used = allocator
        .block_groups
        .iter()
        .map(|bg| bg.block_group.used)
        .sum();

    Ok(Transaction {
        new_generation,
        final_root_bytenr: root_tree_bytenr,
        final_root_level: root_tree_level,
        final_chunk_root: chunk_root_opt,
        final_bytes_used,
        new_fs_tree,
        pending_blocks,
        pending_data,
        final_allocator: Some(allocator),
    })
}
