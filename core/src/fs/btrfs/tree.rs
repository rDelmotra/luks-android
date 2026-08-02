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
/// `key (17) + offset (4) + size (4)`.
const ITEM_SIZE: usize = 25;
/// `key (17) + blockptr (8) + generation (8)`.
const KEY_PTR_SIZE: usize = 33;
/// `objectid (8) + type (1) + offset (8)`.
pub const KEY_SIZE: usize = 17;

// --- item types we name ----------------------------------------------------
pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const XATTR_ITEM_KEY: u8 = 24;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
pub const ROOT_ITEM_KEY: u8 = 132;
/// A subvolume's view of its parent: key `(subvol id, ROOT_BACKREF, parent id)`,
/// data naming the directory it appears in. The direction that matters for a
/// reader, because it turns a tree id into a path.
pub const ROOT_BACKREF_KEY: u8 = 144;
/// The mirror of [`ROOT_BACKREF_KEY`], filed under the parent.
pub const ROOT_REF_KEY: u8 = 156;
pub const DEV_ITEM_KEY: u8 = 216;
pub const CHUNK_ITEM_KEY: u8 = 228;

// --- objectids we name -----------------------------------------------------
pub const DEV_ITEMS_OBJECTID: u64 = 1;
pub const ROOT_TREE_OBJECTID: u64 = 1;
pub const FS_TREE_OBJECTID: u64 = 5;
/// The root tree's own directory, which holds exactly one entry: `default`,
/// naming the subvolume a plain `mount` shows.
pub const ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
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
        let bound = self.lower_bound(key)?;
        if bound < self.nr_items && self.key(bound)? == *key {
            return Ok(bound);
        }
        Ok(bound.saturating_sub(1))
    }
}
