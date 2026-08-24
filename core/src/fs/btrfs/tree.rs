//! btrfs B-tree nodes: the one container every tree in the filesystem uses.
//!
//! A node is `node_size` bytes with a 101-byte header. What follows depends
//! only on `level`:
//!
//! - **level 0 (leaf)** — a forward-growing array of 25-byte item descriptors,
//!   and the item *data* growing backwards from the end of the node. The two
//!   meet in the middle, which is what "free space" means in a btrfs leaf.
//! - **level > 0 (interior)** — 33-byte `(key, block pointer, generation)`
//!   triples, and nothing else.
//!
//! Every field offset here was read out of the chunk tree's root node in
//! `fixtures/btrfs/plain.img` and checked against `btrfs inspect-internal
//! dump-tree`, which independently reported the same four items at the same
//! offsets and sizes.

use super::superblock::CsumType;
use crate::error::{LuksError, Result};

/// Bytes before the first item descriptor or key pointer.
pub const HEADER_SIZE: usize = 101;
pub const ITEM_SIZE: usize = 25;
/// `key (17) + blockptr (8) + generation (8)`.
pub const KEY_PTR_SIZE: usize = 33;
/// `objectid (8) + type (1) + offset (8)`.
pub const KEY_SIZE: usize = 17;

// --- item types we name ----------------------------------------------------
pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const XATTR_ITEM_KEY: u8 = 24;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
/// One item holds a run of per-sector data checksums, keyed by the *disk*
/// address the run starts at — not by inode, and not by file offset.
pub const EXTENT_CSUM_KEY: u8 = 128;
pub const ROOT_ITEM_KEY: u8 = 132;
/// A subvolume's view of its parent: key `(subvol id, ROOT_BACKREF, parent id)`,
/// data naming the directory it appears in. The direction that matters for a
/// reader, because it turns a tree id into a path.
pub const ROOT_BACKREF_KEY: u8 = 144;
/// The mirror of [`ROOT_BACKREF_KEY`], filed under the parent.
pub const ROOT_REF_KEY: u8 = 156;
pub const EXTENT_ITEM_KEY: u8 = 168;
pub const METADATA_ITEM_KEY: u8 = 169;
pub const TREE_BLOCK_REF_KEY: u8 = 176;
pub const EXTENT_DATA_REF_KEY: u8 = 178;
pub const SHARED_BLOCK_REF_KEY: u8 = 182;
pub const SHARED_DATA_REF_KEY: u8 = 184;
pub const BLOCK_GROUP_ITEM_KEY: u8 = 192;
pub const FREE_SPACE_INFO_KEY: u8 = 198;
pub const FREE_SPACE_EXTENT_KEY: u8 = 199;
pub const FREE_SPACE_BITMAP_KEY: u8 = 200;
pub const DEV_EXTENT_KEY: u8 = 204;
pub const DEV_ITEM_KEY: u8 = 216;
pub const CHUNK_ITEM_KEY: u8 = 228;

/// A human name for an item type, for errors that would otherwise describe a
/// bare number.
///
/// `RULES.md`: *an error about an operation must name the operation.* A
/// capacity failure that says only "an item did not fit" leaves the reader to
/// supply which item from context, and context is exactly what was wrong the
/// last two times this project chased a misattributed error.
pub fn item_type_name(item_type: u8) -> &'static str {
    match item_type {
        INODE_ITEM_KEY => "inode item",
        INODE_REF_KEY => "inode ref",
        XATTR_ITEM_KEY => "xattr item",
        DIR_ITEM_KEY => "directory item",
        DIR_INDEX_KEY => "directory index",
        EXTENT_DATA_KEY => "file extent item",
        EXTENT_CSUM_KEY => "checksum item",
        ROOT_ITEM_KEY => "root item",
        ROOT_BACKREF_KEY => "root backref",
        ROOT_REF_KEY => "root ref",
        EXTENT_ITEM_KEY => "extent item",
        METADATA_ITEM_KEY => "metadata item",
        TREE_BLOCK_REF_KEY => "tree block ref",
        EXTENT_DATA_REF_KEY => "extent data ref",
        SHARED_BLOCK_REF_KEY => "shared block ref",
        SHARED_DATA_REF_KEY => "shared data ref",
        BLOCK_GROUP_ITEM_KEY => "block group item",
        FREE_SPACE_INFO_KEY => "free space info",
        FREE_SPACE_EXTENT_KEY => "free space extent",
        FREE_SPACE_BITMAP_KEY => "free space bitmap",
        DEV_EXTENT_KEY => "device extent",
        DEV_ITEM_KEY => "device item",
        CHUNK_ITEM_KEY => "chunk item",
        _ => "tree item",
    }
}

// --- objectids we name -----------------------------------------------------
pub const DEV_ITEMS_OBJECTID: u64 = 1;
pub const ROOT_TREE_OBJECTID: u64 = 1;
pub const EXTENT_TREE_OBJECTID: u64 = 2;
pub const CHUNK_TREE_OBJECTID: u64 = 3;
pub const DEV_TREE_OBJECTID: u64 = 4;
pub const FS_TREE_OBJECTID: u64 = 5;
pub const ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const CSUM_TREE_OBJECTID: u64 = 7;
pub const FREE_SPACE_TREE_OBJECTID: u64 = 10;
pub const BLOCK_GROUP_TREE_OBJECTID: u64 = 11;
pub const FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
/// The objectid every `EXTENT_CSUM` item is filed under: `-10` as a `u64`.
/// btrfs reserves the top of the objectid space by counting down, so this sorts
/// after every real tree and inode.
pub const EXTENT_CSUM_OBJECTID: u64 = u64::MAX - 9;
/// Objectid of the root directory inside any fs tree, and the point above
/// which every objectid is a file rather than a reserved tree id.
pub const FIRST_FREE_OBJECTID: u64 = 256;

/// A btrfs key. Ordering is lexicographic by `(objectid, item_type, offset)`,
/// and it is the only thing that orders a tree — every search, every range
/// scan, every "the next item after this one" is this comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

impl Key {
    pub fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Key {
            objectid,
            item_type,
            offset,
        }
    }

    fn parse(b: &[u8], at: usize) -> Self {
        Key {
            objectid: u64le(b, at),
            item_type: b[at + 8],
            offset: u64le(b, at + 9),
        }
    }
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// One entry of an interior node: where a subtree lives and the lowest key in
/// it.
#[derive(Debug, Clone, Copy)]
pub struct KeyPtr {
    pub key: Key,
    /// Logical address of the child node.
    pub blockptr: u64,
    pub generation: u64,
}

/// A verified tree node, holding the whole block.
///
/// The block is kept rather than parsed into owned items because item data is
/// read as byte slices, and for a leaf full of file extents that would mean
/// allocating and copying a node's worth of vectors to look at one of them.
#[derive(Clone)]
pub struct Node {
    raw: Vec<u8>,
    pub level: u8,
    pub nr_items: usize,
    pub owner: u64,
    pub generation: u64,
}

/// Hand-written so that printing a node does not dump 16 KiB of block, which
/// is what a derived `Debug` would do the first time anyone puts one in an
/// assertion message.
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("level", &self.level)
            .field("nr_items", &self.nr_items)
            .field("owner", &self.owner)
            .field("generation", &self.generation)
            .finish()
    }
}

impl Node {
    /// Parse `raw` as the node that should live at logical address `bytenr`.
    ///
    /// Four checks before anything is believed, because every offset used
    /// below comes out of this same block:
    ///
    /// 1. the checksum, which is the only real corruption detector btrfs gives
    ///    a reader;
    /// 2. `bytenr`, which catches reading the *right* kind of block from the
    ///    *wrong* address — the failure a bad chunk mapping produces, and one a
    ///    checksum alone cannot see, since a correctly-checksummed node from
    ///    elsewhere verifies perfectly;
    /// 3. the filesystem id, which catches a node left behind by a previous
    ///    filesystem in re-used space;
    /// 4. `nr_items` against the space actually available.
    pub fn parse(
        raw: Vec<u8>,
        bytenr: u64,
        csum_type: CsumType,
        metadata_uuid: &[u8; 16],
    ) -> Result<Self> {
        if raw.len() < HEADER_SIZE {
            return Err(LuksError::Truncated {
                needed: HEADER_SIZE,
                got: raw.len(),
            });
        }
        if !csum_type.verify(&raw[..32], &raw[32..]) {
            return Err(LuksError::FsChecksumMismatch("btrfs tree node"));
        }
        if u64le(&raw, 48) != bytenr {
            return Err(LuksError::CorruptFs(
                "btrfs tree node is not at the address that pointed to it",
            ));
        }
        if &raw[32..48] != metadata_uuid {
            return Err(LuksError::CorruptFs(
                "btrfs tree node belongs to a different filesystem",
            ));
        }

        let nr_items = u32le(&raw, 96) as usize;
        let level = raw[100];
        let per_entry = if level == 0 { ITEM_SIZE } else { KEY_PTR_SIZE };
        if HEADER_SIZE + nr_items * per_entry > raw.len() {
            return Err(LuksError::CorruptFs("btrfs node item count overruns"));
        }

        Ok(Node {
            level,
            nr_items,
            owner: u64le(&raw, 88),
            generation: u64le(&raw, 80),
            raw,
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn bytenr(&self) -> u64 {
        u64le(&self.raw, 48)
    }

    pub fn flags(&self) -> u64 {
        u64le(&self.raw, 56)
    }

    pub fn metadata_uuid(&self) -> [u8; 16] {
        let mut u = [0u8; 16];
        u.copy_from_slice(&self.raw[32..48]);
        u
    }

    pub fn chunk_tree_uuid(&self) -> [u8; 16] {
        let mut u = [0u8; 16];
        u.copy_from_slice(&self.raw[64..80]);
        u
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Key of entry `i`, in either kind of node.
    pub fn key(&self, i: usize) -> Result<Key> {
        if i >= self.nr_items {
            return Err(LuksError::CorruptFs("btrfs node index out of range"));
        }
        let stride = if self.is_leaf() { ITEM_SIZE } else { KEY_PTR_SIZE };
        Ok(Key::parse(&self.raw, HEADER_SIZE + i * stride))
    }

    /// Child pointer `i` of an interior node.
    pub fn key_ptr(&self, i: usize) -> Result<KeyPtr> {
        if self.is_leaf() {
            return Err(LuksError::CorruptFs("btrfs leaf has no child pointers"));
        }
        let at = HEADER_SIZE + i * KEY_PTR_SIZE;
        Ok(KeyPtr {
            key: self.key(i)?,
            blockptr: u64le(&self.raw, at + KEY_SIZE),
            generation: u64le(&self.raw, at + KEY_SIZE + 8),
        })
    }

    /// Data of item `i` of a leaf.
    ///
    /// `itemoff` is measured from the end of the header, not from the start of
    /// the node — an easy off-by-101 that yields data shifted by exactly the
    /// header size, which for many items still parses.
    pub fn item_data(&self, i: usize) -> Result<&[u8]> {
        if !self.is_leaf() {
            return Err(LuksError::CorruptFs("btrfs interior node has no item data"));
        }
        if i >= self.nr_items {
            return Err(LuksError::CorruptFs("btrfs node index out of range"));
        }
        let at = HEADER_SIZE + i * ITEM_SIZE;
        let offset = u32le(&self.raw, at + KEY_SIZE) as usize;
        let size = u32le(&self.raw, at + KEY_SIZE + 4) as usize;

        let start = HEADER_SIZE
            .checked_add(offset)
            .ok_or(LuksError::CorruptFs("btrfs item offset overflows"))?;
        let end = start
            .checked_add(size)
            .ok_or(LuksError::CorruptFs("btrfs item length overflows"))?;
        if end > self.raw.len() {
            return Err(LuksError::CorruptFs("btrfs item data past end of node"));
        }
        Ok(&self.raw[start..end])
    }

    /// Index of the first entry whose key is >= `key`, or `nr_items` if there
    /// is none. Items in a node are sorted, so this is a binary search.
    pub fn lower_bound(&self, key: &Key) -> Result<usize> {
        let (mut lo, mut hi) = (0usize, self.nr_items);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.key(mid)? < *key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Index of the child to descend into when looking for `key`.
    ///
    /// A key pointer holds the *lowest* key in its subtree, so the right child
    /// is the last one whose key is <= the target. Descending into
    /// `lower_bound` instead would skip the subtree the key is actually in
    /// whenever the key is not an exact match — the classic B-tree off-by-one,
    /// and it fails only for interior lookups, so a small filesystem whose
    /// trees are a single leaf never shows it.
    /// A key below everything in this node descends into child 0, which is not
    /// a corruption case: searching for `(inode, DIR_INDEX, 0)` in a tree whose
    /// first key is higher is an ordinary way to start a directory scan.
    pub fn child_for(&self, key: &Key) -> Result<usize> {
        if self.nr_items == 0 {
            return Err(LuksError::CorruptFs("btrfs interior node has no child pointers"));
        }
        let bound = self.lower_bound(key)?;
        if bound < self.nr_items && self.key(bound)? == *key {
            return Ok(bound);
        }
        Ok(bound.saturating_sub(1))
    }
}
