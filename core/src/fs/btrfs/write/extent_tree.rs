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

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{
    Key, BLOCK_GROUP_ITEM_KEY, EXTENT_DATA_REF_KEY, EXTENT_ITEM_KEY, EXTENT_TREE_OBJECTID,
    METADATA_ITEM_KEY, SHARED_BLOCK_REF_KEY, SHARED_DATA_REF_KEY, TREE_BLOCK_REF_KEY,
};
use crate::fs::btrfs::Btrfs;

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
