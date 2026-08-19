//! In-memory B-tree node surgery for btrfs.
//!
//! This module provides in-memory modification, insertion, deletion, splitting,
//! and emission of btrfs B-tree nodes (both level 0 leaf nodes and level > 0
//! interior nodes).
//!
//! No device writes occur here. Nodes are manipulated in memory and emitted as
//! byte-exact on-disk representations with valid CRC32C checksums, ready to be
//! checked by the existing [`Node`] reader.

use crate::error::{LuksError, Result};
use crate::fs::btrfs::superblock::CsumType;
use crate::fs::btrfs::tree::{
    Key, KeyPtr, Node, HEADER_SIZE, ITEM_SIZE, KEY_PTR_SIZE,
};

/// Flag indicating that a header is committed/written.
pub const HEADER_FLAG_WRITTEN: u64 = 1 << 0;

/// The largest item payload a leaf of `node_size` bytes can hold, ever.
///
/// One header, one item descriptor, and the rest is payload — this is the
/// format's hard ceiling (16258 bytes on the standard 16 KiB node), reached
/// only by a leaf holding exactly one item. Anything larger cannot be stored
/// by splitting, by freeing space, or by any other means, which is why
/// exceeding it is [`LuksError::BtrfsItemTooLarge`] and not
/// [`LuksError::FilesystemFull`].
pub fn max_item_payload_bytes(node_size: u32) -> usize {
    (node_size as usize)
        .saturating_sub(HEADER_SIZE)
        .saturating_sub(ITEM_SIZE)
}

/// A single `(key, data)` item in a leaf node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafItem {
    pub key: Key,
    pub data: Vec<u8>,
}

/// An editable in-memory representation of a btrfs B-tree leaf node (level 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub bytenr: u64,
    pub generation: u64,
    pub owner: u64,
    pub flags: u64,
    pub metadata_uuid: [u8; 16],
    pub chunk_tree_uuid: [u8; 16],
    pub csum_type: CsumType,
    pub items: Vec<LeafItem>,
}

impl Leaf {
    /// Create a new, empty leaf node.
    pub fn new(
        bytenr: u64,
        generation: u64,
        owner: u64,
        metadata_uuid: [u8; 16],
        csum_type: CsumType,
    ) -> Self {
        Leaf {
            bytenr,
            generation,
            owner,
            flags: HEADER_FLAG_WRITTEN,
            metadata_uuid,
            chunk_tree_uuid: [0u8; 16],
            csum_type,
            items: Vec::new(),
        }
    }

    /// Construct an editable `Leaf` by parsing all items from an existing reader `Node`.
    pub fn from_node(node: &Node, csum_type: CsumType) -> Result<Self> {
        if !node.is_leaf() {
            return Err(LuksError::CorruptFs("cannot convert interior node to leaf"));
        }

        let mut items = Vec::with_capacity(node.nr_items);
        for i in 0..node.nr_items {
            let key = node.key(i)?;
            let data = node.item_data(i)?.to_vec();
            items.push(LeafItem { key, data });
        }

        Ok(Leaf {
            bytenr: node.bytenr(),
            generation: node.generation,
            owner: node.owner,
            flags: node.flags(),
            metadata_uuid: node.metadata_uuid(),
            chunk_tree_uuid: node.chunk_tree_uuid(),
            csum_type,
            items,
        })
    }

    /// Total number of bytes consumed by item data payloads in this leaf.
    pub fn total_data_bytes(&self) -> usize {
        self.items.iter().map(|it| it.data.len()).sum()
    }

    /// Free space in bytes available for new item descriptors and data payloads.
    pub fn free_space(&self, node_size: u32) -> usize {
        let used = HEADER_SIZE + (self.items.len() * ITEM_SIZE) + self.total_data_bytes();
        if used > node_size as usize {
            0
        } else {
            node_size as usize - used
        }
    }

    /// Binary search for an item matching `key`.
    pub fn find_item(&self, key: &Key) -> Option<usize> {
        self.items.binary_search_by(|it| it.key.cmp(key)).ok()
    }

    /// Replace the data payload of an existing item matching `key`.
    pub fn replace_item(&mut self, key: &Key, new_data: Vec<u8>) -> Result<()> {
        let idx = self
            .find_item(key)
            .ok_or_else(|| LuksError::NotFound("item key not found in leaf".into()))?;
        self.items[idx].data = new_data;
        Ok(())
    }

    /// Insert a new `(key, data)` item into this leaf in sorted key order.
    ///
    /// Two different failures live here and they are deliberately **not** the
    /// same error:
    ///
    /// - [`LuksError::BtrfsItemTooLarge`] — the item is bigger than an *empty*
    ///   leaf, so no split and no amount of free disk can ever place it. This
    ///   is a dead end for the caller.
    /// - [`LuksError::FilesystemFull`] — the item would fit in an empty leaf
    ///   but not in *this* one. A caller that can split (`cow_descend_insert`)
    ///   recovers from this; it is a local condition, not a verdict on the
    ///   drive.
    ///
    /// Collapsing the first into the second is what made a 20 MB write report
    /// "no space left on the filesystem" on a drive with 676 MiB free
    /// (`INCIDENTS.md`, 2026-08-16).
    ///
    /// Returns `Err(LuksError::AlreadyExists)` if an item with the same key already exists.
    pub fn insert_item(&mut self, key: Key, data: Vec<u8>, node_size: u32) -> Result<()> {
        let needed = ITEM_SIZE + data.len();
        if data.len() > max_item_payload_bytes(node_size) {
            return Err(LuksError::BtrfsItemTooLarge {
                what: crate::fs::btrfs::tree::item_type_name(key.item_type),
                item_bytes: data.len(),
                node_size,
            });
        }
        if needed > self.free_space(node_size) {
            return Err(LuksError::FilesystemFull);
        }

        match self.items.binary_search_by(|it| it.key.cmp(&key)) {
            Ok(_) => Err(LuksError::AlreadyExists("duplicate key in leaf".into())),
            Err(pos) => {
                self.items.insert(pos, LeafItem { key, data });
                Ok(())
            }
        }
    }

    /// Delete an item matching `key`, returning the deleted data payload.
    pub fn delete_item(&mut self, key: &Key) -> Result<Vec<u8>> {
        let idx = self
            .find_item(key)
            .ok_or_else(|| LuksError::NotFound("item key not found in leaf".into()))?;
        Ok(self.items.remove(idx).data)
    }

    /// Split an overflowing leaf into `(left_leaf, right_leaf, pivot_key)`.
    ///
    /// The pivot key is the lowest key in `right_leaf` and is intended to be
    /// inserted into the parent interior node.
    pub fn split(&self, right_bytenr: u64) -> Result<(Leaf, Leaf, Key)> {
        if self.items.len() < 2 {
            return Err(LuksError::CorruptFs(
                "cannot split leaf with fewer than 2 items",
            ));
        }

        let mid = self.items.len() / 2;
        let left_items = self.items[..mid].to_vec();
        let right_items = self.items[mid..].to_vec();
        let pivot_key = right_items[0].key;

        let left = Leaf {
            bytenr: self.bytenr,
            generation: self.generation,
            owner: self.owner,
            flags: self.flags,
            metadata_uuid: self.metadata_uuid,
            chunk_tree_uuid: self.chunk_tree_uuid,
            csum_type: self.csum_type,
            items: left_items,
        };

        let right = Leaf {
            bytenr: right_bytenr,
            generation: self.generation,
            owner: self.owner,
            flags: self.flags,
            metadata_uuid: self.metadata_uuid,
            chunk_tree_uuid: self.chunk_tree_uuid,
            csum_type: self.csum_type,
            items: right_items,
        };

        Ok((left, right, pivot_key))
    }

    /// Serialize this leaf into the canonical on-disk byte representation.
    ///
    /// Computes the exact item descriptors, reverse-packs the item data payloads
    /// from `node_size - HEADER_SIZE` downwards, zeroes the unallocated gap,
    /// and generates a valid header checksum.
    pub fn emit(&self, node_size: u32) -> Result<Vec<u8>> {
        let size = node_size as usize;
        let nr_items = self.items.len();
        let needed = HEADER_SIZE + nr_items * ITEM_SIZE + self.total_data_bytes();
        if needed > size {
            return Err(LuksError::FilesystemFull);
        }

        let mut raw = vec![0u8; size];

        // 1. Header (offsets 32..101)
        raw[32..48].copy_from_slice(&self.metadata_uuid);
        raw[48..56].copy_from_slice(&self.bytenr.to_le_bytes());
        raw[56..64].copy_from_slice(&self.flags.to_le_bytes());
        raw[64..80].copy_from_slice(&self.chunk_tree_uuid);
        raw[80..88].copy_from_slice(&self.generation.to_le_bytes());
        raw[88..96].copy_from_slice(&self.owner.to_le_bytes());
        raw[96..100].copy_from_slice(&(nr_items as u32).to_le_bytes());
        raw[100] = 0; // level 0 for leaf

        // 2. Item descriptors and item data
        let mut data_offset = size - HEADER_SIZE;
        for (i, item) in self.items.iter().enumerate() {
            let item_len = item.data.len();
            data_offset -= item_len;

            // Write item descriptor at HEADER_SIZE + i * ITEM_SIZE
            let desc_pos = HEADER_SIZE + i * ITEM_SIZE;
            raw[desc_pos..desc_pos + 8].copy_from_slice(&item.key.objectid.to_le_bytes());
            raw[desc_pos + 8] = item.key.item_type;
            raw[desc_pos + 9..desc_pos + 17].copy_from_slice(&item.key.offset.to_le_bytes());
            raw[desc_pos + 17..desc_pos + 21]
                .copy_from_slice(&(data_offset as u32).to_le_bytes());
            raw[desc_pos + 21..desc_pos + 25].copy_from_slice(&(item_len as u32).to_le_bytes());

            // Write item data payload at HEADER_SIZE + data_offset
            let data_pos = HEADER_SIZE + data_offset;
            raw[data_pos..data_pos + item_len].copy_from_slice(&item.data);
        }

        // 3. Header checksum over raw[32..size]
        let csum = self.csum_type.calculate(&raw[32..size]);
        raw[..32].copy_from_slice(&csum);

        Ok(raw)
    }
}

/// An entry in an interior node (level > 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteriorEntry {
    pub key: Key,
    pub blockptr: u64,
    pub generation: u64,
}

/// An editable in-memory representation of a btrfs B-tree interior node (level > 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteriorNode {
    pub bytenr: u64,
    pub generation: u64,
    pub owner: u64,
    pub level: u8,
    pub flags: u64,
    pub metadata_uuid: [u8; 16],
    pub chunk_tree_uuid: [u8; 16],
    pub csum_type: CsumType,
    pub entries: Vec<InteriorEntry>,
}

impl InteriorNode {
    /// Create a new, empty interior node at a specified tree `level` (> 0).
    pub fn new(
        bytenr: u64,
        generation: u64,
        owner: u64,
        level: u8,
        metadata_uuid: [u8; 16],
        csum_type: CsumType,
    ) -> Result<Self> {
        if level == 0 {
            return Err(LuksError::CorruptFs(
                "interior node level must be greater than 0",
            ));
        }
        Ok(InteriorNode {
            bytenr,
            generation,
            owner,
            level,
            flags: HEADER_FLAG_WRITTEN,
            metadata_uuid,
            chunk_tree_uuid: [0u8; 16],
            csum_type,
            entries: Vec::new(),
        })
    }

    /// Construct an editable `InteriorNode` by parsing all key pointers from an existing reader `Node`.
    pub fn from_node(node: &Node, csum_type: CsumType) -> Result<Self> {
        if node.is_leaf() {
            return Err(LuksError::CorruptFs("cannot convert leaf to interior node"));
        }

        let mut entries = Vec::with_capacity(node.nr_items);
        for i in 0..node.nr_items {
            let ptr: KeyPtr = node.key_ptr(i)?;
            entries.push(InteriorEntry {
                key: ptr.key,
                blockptr: ptr.blockptr,
                generation: ptr.generation,
            });
        }

        Ok(InteriorNode {
            bytenr: node.bytenr(),
            generation: node.generation,
            owner: node.owner,
            level: node.level,
            flags: node.flags(),
            metadata_uuid: node.metadata_uuid(),
            chunk_tree_uuid: node.chunk_tree_uuid(),
            csum_type,
            entries,
        })
    }

    /// Free space in bytes available for new key pointer entries.
    pub fn free_space(&self, node_size: u32) -> usize {
        let used = HEADER_SIZE + (self.entries.len() * KEY_PTR_SIZE);
        if used > node_size as usize {
            0
        } else {
            node_size as usize - used
        }
    }

    /// Insert a child key pointer into this interior node in sorted key order.
    pub fn insert_entry(
        &mut self,
        key: Key,
        blockptr: u64,
        generation: u64,
        node_size: u32,
    ) -> Result<()> {
        if KEY_PTR_SIZE > self.free_space(node_size) {
            return Err(LuksError::FilesystemFull);
        }

        let pos = match self.entries.binary_search_by(|e| e.key.cmp(&key)) {
            Ok(p) => p,
            Err(p) => p,
        };
        self.entries
            .insert(pos, InteriorEntry { key, blockptr, generation });
        Ok(())
    }

    /// Update an existing child pointer pointing at `old_blockptr`.
    pub fn update_entry_by_blockptr(
        &mut self,
        old_blockptr: u64,
        new_key: Option<Key>,
        new_blockptr: u64,
        new_generation: u64,
    ) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.blockptr == old_blockptr)
            .ok_or_else(|| LuksError::NotFound("interior node block pointer not found".into()))?;

        if let Some(k) = new_key {
            entry.key = k;
        }
        entry.blockptr = new_blockptr;
        entry.generation = new_generation;
        self.entries.sort_by_key(|e| e.key);
        Ok(())
    }

    /// Split an overflowing interior node into `(left_interior, right_interior, pivot_key)`.
    pub fn split(&self, right_bytenr: u64) -> Result<(InteriorNode, InteriorNode, Key)> {
        if self.entries.len() < 2 {
            return Err(LuksError::CorruptFs(
                "cannot split interior node with fewer than 2 entries",
            ));
        }

        let mid = self.entries.len() / 2;
        let left_entries = self.entries[..mid].to_vec();
        let right_entries = self.entries[mid..].to_vec();
        let pivot_key = right_entries[0].key;

        let left = InteriorNode {
            bytenr: self.bytenr,
            generation: self.generation,
            owner: self.owner,
            level: self.level,
            flags: self.flags,
            metadata_uuid: self.metadata_uuid,
            chunk_tree_uuid: self.chunk_tree_uuid,
            csum_type: self.csum_type,
            entries: left_entries,
        };

        let right = InteriorNode {
            bytenr: right_bytenr,
            generation: self.generation,
            owner: self.owner,
            level: self.level,
            flags: self.flags,
            metadata_uuid: self.metadata_uuid,
            chunk_tree_uuid: self.chunk_tree_uuid,
            csum_type: self.csum_type,
            entries: right_entries,
        };

        Ok((left, right, pivot_key))
    }

    /// Serialize this interior node into the canonical on-disk byte representation.
    pub fn emit(&self, node_size: u32) -> Result<Vec<u8>> {
        let size = node_size as usize;
        let nr_items = self.entries.len();
        let needed = HEADER_SIZE + nr_items * KEY_PTR_SIZE;
        if needed > size {
            return Err(LuksError::FilesystemFull);
        }

        let mut raw = vec![0u8; size];

        // 1. Header (offsets 32..101)
        raw[32..48].copy_from_slice(&self.metadata_uuid);
        raw[48..56].copy_from_slice(&self.bytenr.to_le_bytes());
        raw[56..64].copy_from_slice(&self.flags.to_le_bytes());
        raw[64..80].copy_from_slice(&self.chunk_tree_uuid);
        raw[80..88].copy_from_slice(&self.generation.to_le_bytes());
        raw[88..96].copy_from_slice(&self.owner.to_le_bytes());
        raw[96..100].copy_from_slice(&(nr_items as u32).to_le_bytes());
        raw[100] = self.level;

        // 2. Entries (KeyPtr triples)
        for (i, entry) in self.entries.iter().enumerate() {
            let pos = HEADER_SIZE + i * KEY_PTR_SIZE;
            raw[pos..pos + 8].copy_from_slice(&entry.key.objectid.to_le_bytes());
            raw[pos + 8] = entry.key.item_type;
            raw[pos + 9..pos + 17].copy_from_slice(&entry.key.offset.to_le_bytes());
            raw[pos + 17..pos + 25].copy_from_slice(&entry.blockptr.to_le_bytes());
            raw[pos + 25..pos + 33].copy_from_slice(&entry.generation.to_le_bytes());
        }

        // 3. Header checksum over raw[32..size]
        let csum = self.csum_type.calculate(&raw[32..size]);
        raw[..32].copy_from_slice(&csum);

        Ok(raw)
    }
}

// --- Item payload builders ---------------------------------------------------

/// Build a 160-byte `btrfs_inode_item` payload for a new empty file.
pub fn build_empty_inode_item(
    generation: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    sec: u64,
    nsec: u32,
) -> Vec<u8> {
    let mut data = vec![0u8; 160];
    data[0..8].copy_from_slice(&generation.to_le_bytes()); // generation
    data[8..16].copy_from_slice(&generation.to_le_bytes()); // transid
    data[16..24].copy_from_slice(&0u64.to_le_bytes()); // size = 0
    data[24..32].copy_from_slice(&0u64.to_le_bytes()); // nbytes = 0
    data[32..40].copy_from_slice(&0u64.to_le_bytes()); // block_group = 0
    data[40..44].copy_from_slice(&nlink.to_le_bytes()); // nlink
    data[44..48].copy_from_slice(&uid.to_le_bytes()); // uid
    data[48..52].copy_from_slice(&gid.to_le_bytes()); // gid
    data[52..56].copy_from_slice(&mode.to_le_bytes()); // mode
    data[56..64].copy_from_slice(&0u64.to_le_bytes()); // rdev = 0
    data[64..72].copy_from_slice(&0u64.to_le_bytes()); // flags = 0
    data[72..80].copy_from_slice(&1u64.to_le_bytes()); // sequence = 1
    // Timestamps: atime (112), ctime (124), mtime (136), otime (148)
    for offset in [112, 124, 136, 148] {
        data[offset..offset + 8].copy_from_slice(&sec.to_le_bytes());
        data[offset + 8..offset + 12].copy_from_slice(&nsec.to_le_bytes());
    }
    data
}

/// Build a `btrfs_inode_ref` payload `(index, name_len, name)`.
pub fn build_inode_ref(dir_index: u64, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut data = vec![0u8; 10 + name_bytes.len()];
    data[0..8].copy_from_slice(&dir_index.to_le_bytes());
    data[8..10].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    data[10..].copy_from_slice(name_bytes);
    data
}

/// Build a `btrfs_dir_item` payload `(location, transid, data_len, name_len, type, name)`.
pub fn build_dir_item(
    child_ino: u64,
    transid: u64,
    file_type: u8,
    name: &str,
) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut data = vec![0u8; 30 + name_bytes.len()];
    data[0..8].copy_from_slice(&child_ino.to_le_bytes());
    data[8] = crate::fs::btrfs::tree::INODE_ITEM_KEY;
    data[9..17].copy_from_slice(&0u64.to_le_bytes());
    data[17..25].copy_from_slice(&transid.to_le_bytes());
    data[25..27].copy_from_slice(&0u16.to_le_bytes()); // data_len = 0
    data[27..29].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    data[29] = file_type;
    data[30..].copy_from_slice(name_bytes);
    data
}

/// Build a 53-byte `btrfs_file_extent_item` payload for a regular uncompressed data extent.
pub fn build_regular_file_extent(
    generation: u64,
    ram_bytes: u64,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    num_bytes: u64,
) -> Vec<u8> {
    let mut data = vec![0u8; 53];
    data[0..8].copy_from_slice(&generation.to_le_bytes()); // generation
    data[8..16].copy_from_slice(&ram_bytes.to_le_bytes()); // ram_bytes
    data[16] = 0; // compression = NONE
    data[17] = 0; // encryption = NONE
    data[18..20].copy_from_slice(&0u16.to_le_bytes()); // other_encoding = 0
    data[20] = 1; // type = BTRFS_FILE_EXTENT_REG
    data[21..29].copy_from_slice(&disk_bytenr.to_le_bytes()); // disk_bytenr
    data[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes()); // disk_num_bytes
    data[37..45].copy_from_slice(&0u64.to_le_bytes()); // offset = 0
    data[45..53].copy_from_slice(&num_bytes.to_le_bytes()); // num_bytes
    data
}

/// Build the checksum payload for `disk_num_bytes` of data starting at sector boundary.
///
/// Computes a checksum for every `sector_size` (e.g. 4096) bytes.
///
/// This produces the checksums for one **contiguous run**, with no regard for
/// whether the result fits in a tree node — [`build_extent_csum_items`] is what
/// callers writing a whole file want, because past ~15 MiB the answer here is
/// too large to store as a single item.
pub fn build_extent_csum_payload(
    csum_type: crate::fs::btrfs::superblock::CsumType,
    sector_size: u32,
    disk_num_bytes: u64,
    data: &[u8],
) -> Vec<u8> {
    let sector = sector_size as usize;
    let nr_sectors = (disk_num_bytes as usize).div_ceil(sector);
    let mut payload = Vec::with_capacity(nr_sectors * csum_type.size());

    for i in 0..nr_sectors {
        let start = i * sector;
        let mut sector_buf = vec![0u8; sector];
        if start < data.len() {
            let copy_end = (start + sector).min(data.len());
            sector_buf[..copy_end - start].copy_from_slice(&data[start..copy_end]);
        }
        let csum = csum_type.calculate(&sector_buf);
        payload.extend_from_slice(&csum[..csum_type.size()]);
    }

    payload
}

/// Bytes the kernel leaves unused in a leaf that holds one maximum-sized
/// `EXTENT_CSUM` item.
///
/// **Measured, not derived from kernel source** (2026-08-15), on two different
/// geometries so that it is a rule rather than a coincidence:
///
/// | `nodesize` | largest `EXTENT_CSUM` itemsize observed | leaf free space |
/// |---|---|---|
/// | 16384 | 16228 | 30 |
/// | 4096  | 3940  | 30 |
///
/// Both are exactly `node_size - HEADER_SIZE - ITEM_SIZE - 30`. Filesystems
/// carrying those items were graded by `btrfs check`, a real kernel mount and
/// `btrfs scrub`, so this size is known-accepted rather than merely believed
/// legal. Matching what the kernel itself emits is deliberately more
/// conservative than the format's own ceiling (`node_size - HEADER_SIZE -
/// ITEM_SIZE`, which would fill a leaf to exactly zero free bytes): staying
/// inside the shape real btrfs produces is worth 30 bytes per item.
const CSUM_ITEM_LEAF_HEADROOM: usize = 30;

/// The largest `EXTENT_CSUM` item this filesystem's geometry allows, in bytes,
/// rounded down to a whole number of checksums.
///
/// Returns 0 if the node is too small to hold any checksum at all, which no
/// real geometry produces but which callers must not divide by.
pub fn max_csum_item_bytes(node_size: u32, csum_size: usize) -> usize {
    let usable = (node_size as usize)
        .saturating_sub(HEADER_SIZE)
        .saturating_sub(ITEM_SIZE)
        .saturating_sub(CSUM_ITEM_LEAF_HEADROOM);
    if csum_size == 0 {
        return 0;
    }
    (usable / csum_size) * csum_size
}

/// Split a data extent's per-sector checksums into as many `EXTENT_CSUM` items
/// as this node geometry needs, returning `(logical address, payload)` pairs.
///
/// # Why this exists
///
/// A single `EXTENT_CSUM` item has to fit in one leaf, so one item per file
/// caps every write at `max_csum_item_bytes / csum_size` sectors — **~15 MiB**
/// on the standard 16 KiB/4 KiB geometry. That ceiling is what a 20 MB
/// phone→stick write hit on 2026-08-16, and it surfaced as "no space left on
/// the filesystem" (`INCIDENTS.md`).
///
/// Real btrfs splits checksums across many items, which is why the key carries
/// a **logical address** rather than an inode: each item covers the contiguous
/// range `[key.offset, key.offset + n * sector_size)` and the items tile the
/// extent end to end. Confirmed by measurement (2026-08-15) rather than
/// inferred — on a kernel-written 50 MB file the item keys advance by exactly
/// `itemsize / csum_size * sector_size` (16228/4 × 4096 = 16617472), and item
/// sizes vary freely below the cap, so nothing requires a uniform stride.
///
/// Data shorter than `disk_num_bytes` is treated as zero-padded to the sector,
/// matching what the commit writes to the device.
pub fn build_extent_csum_items(
    csum_type: crate::fs::btrfs::superblock::CsumType,
    node_size: u32,
    sector_size: u32,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    data: &[u8],
) -> Result<Vec<(u64, Vec<u8>)>> {
    let csum_size = csum_type.size();
    let max_item = max_csum_item_bytes(node_size, csum_size);
    if max_item == 0 {
        return Err(LuksError::BtrfsItemTooLarge {
            what: "checksum item",
            item_bytes: csum_size,
            node_size,
        });
    }

    let sectors_per_item = max_item / csum_size;
    let sector = sector_size as usize;
    let nr_sectors = (disk_num_bytes as usize).div_ceil(sector);

    let mut items = Vec::with_capacity(nr_sectors.div_ceil(sectors_per_item));
    let mut first = 0usize;
    while first < nr_sectors {
        let count = sectors_per_item.min(nr_sectors - first);
        let mut payload = Vec::with_capacity(count * csum_size);

        for i in first..first + count {
            let start = i * sector;
            let mut sector_buf = vec![0u8; sector];
            if start < data.len() {
                let copy_end = (start + sector).min(data.len());
                sector_buf[..copy_end - start].copy_from_slice(&data[start..copy_end]);
            }
            let csum = csum_type.calculate(&sector_buf);
            payload.extend_from_slice(&csum[..csum_size]);
        }

        items.push((disk_bytenr + (first * sector) as u64, payload));
        first += count;
    }

    Ok(items)
}

/// Split pre-calculated per-sector checksums into as many `EXTENT_CSUM` items
/// as this node geometry needs, returning `(logical address, payload)` pairs.
///
/// Each sector's CRC32c is packed as 4 little-endian bytes (`crc.to_le_bytes()`).
/// Items are split when the payload reaches `max_csum_item_bytes(node_size, 4)`
/// or when there is a discontinuity in logical sector addresses.
pub fn build_extent_csum_items_from_checksums(
    node_size: u32,
    checksums: &[(u64, u32)],
) -> Result<Vec<(u64, Vec<u8>)>> {
    if checksums.is_empty() {
        return Ok(Vec::new());
    }

    let max_item = max_csum_item_bytes(node_size, 4);
    if max_item == 0 {
        return Err(LuksError::BtrfsItemTooLarge {
            what: "checksum item",
            item_bytes: 4,
            node_size,
        });
    }
    let sectors_per_item = max_item / 4;

    let mut items = Vec::new();
    let mut current_item_start = 0u64;
    let mut current_payload = Vec::with_capacity(sectors_per_item * 4);
    let mut current_count = 0usize;
    let mut next_expected_bytenr = 0u64;

    for &(bytenr, crc) in checksums {
        if current_payload.is_empty() {
            current_item_start = bytenr;
            current_payload.extend_from_slice(&crc.to_le_bytes());
            current_count = 1;
            next_expected_bytenr = bytenr.saturating_add(4096);
        } else if bytenr == next_expected_bytenr && current_count < sectors_per_item {
            current_payload.extend_from_slice(&crc.to_le_bytes());
            current_count += 1;
            next_expected_bytenr = bytenr.saturating_add(4096);
        } else {
            items.push((current_item_start, current_payload));
            current_item_start = bytenr;
            current_payload = Vec::with_capacity(sectors_per_item * 4);
            current_payload.extend_from_slice(&crc.to_le_bytes());
            current_count = 1;
            next_expected_bytenr = bytenr.saturating_add(4096);
        }
    }

    if !current_payload.is_empty() {
        items.push((current_item_start, current_payload));
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::btrfs::superblock::CsumType;

    #[test]
    fn test_max_csum_item_bytes_calculation() {
        // Standard 16384 node size, CRC32C (4 bytes):
        // 16384 - 101 (header) - 25 (item) - 30 (headroom) = 16228 bytes.
        // 16228 / 4 = 4057 sectors (each sector is 4096 bytes -> 16,617,472 bytes per item).
        let max_16k = max_csum_item_bytes(16384, 4);
        assert_eq!(max_16k, 16228);

        // 4096 node size, CRC32C (4 bytes):
        // 4096 - 101 - 25 - 30 = 3940 bytes.
        // 3940 / 4 = 985 sectors.
        let max_4k = max_csum_item_bytes(4096, 4);
        assert_eq!(max_4k, 3940);
    }

    #[test]
    fn test_build_extent_csum_items_splitting() {
        let node_size = 16384;
        let sector_size = 4096;
        let disk_bytenr = 100_000_000u64;

        // 20 MiB file: 20 * 1024 * 1024 = 20,971,520 bytes = 5120 sectors.
        // Item 0: 4057 sectors = 16,617,472 bytes.
        // Item 1: 5120 - 4057 = 1063 sectors = 4,354,048 bytes.
        let disk_num_bytes = 20 * 1024 * 1024;
        let test_data = vec![0xABu8; disk_num_bytes as usize];

        let items = build_extent_csum_items(
            CsumType::Crc32c,
            node_size,
            sector_size,
            disk_bytenr,
            disk_num_bytes,
            &test_data,
        )
        .expect("build csum items");

        assert_eq!(items.len(), 2);

        // Item 0
        assert_eq!(items[0].0, disk_bytenr);
        assert_eq!(items[0].1.len(), 4057 * 4); // 16228 bytes

        // Item 1
        let expected_item1_start = disk_bytenr + (4057 * 4096);
        assert_eq!(items[1].0, expected_item1_start);
        assert_eq!(items[1].1.len(), 1063 * 4); // 4252 bytes
    }

    #[test]
    fn test_build_extent_csum_items_50mb() {
        let node_size = 16384;
        let sector_size = 4096;
        let disk_bytenr = 200_000_000u64;

        // 50 MiB = 52,428,800 bytes = 12,800 sectors.
        // 12,800 / 4057 = 3 full items of 4057 sectors + 1 item of 629 sectors = 4 items.
        let disk_num_bytes = 50 * 1024 * 1024;
        let test_data = vec![0x55u8; disk_num_bytes as usize];

        let items = build_extent_csum_items(
            CsumType::Crc32c,
            node_size,
            sector_size,
            disk_bytenr,
            disk_num_bytes,
            &test_data,
        )
        .expect("build csum items 50mb");

        assert_eq!(items.len(), 4);
        assert_eq!(items[0].0, disk_bytenr);
        assert_eq!(items[0].1.len(), 4057 * 4);
        assert_eq!(items[1].0, disk_bytenr + 4057 * 4096);
        assert_eq!(items[1].1.len(), 4057 * 4);
        assert_eq!(items[2].0, disk_bytenr + 2 * 4057 * 4096);
        assert_eq!(items[2].1.len(), 4057 * 4);
        assert_eq!(items[3].0, disk_bytenr + 3 * 4057 * 4096);
        assert_eq!(items[3].1.len(), 629 * 4);
    }

    #[test]
    fn test_build_extent_csum_items_from_checksums_matches_build_extent_csum_items() {
        let node_size = 16384;
        let sector_size = 4096;
        let disk_bytenr = 100_000_000u64;
        let disk_num_bytes = 20 * 1024 * 1024;
        let test_data = vec![0xABu8; disk_num_bytes as usize];

        let from_data = build_extent_csum_items(
            CsumType::Crc32c,
            node_size,
            sector_size,
            disk_bytenr,
            disk_num_bytes,
            &test_data,
        )
        .expect("build csum items from data");

        let nr_sectors = (disk_num_bytes as usize) / (sector_size as usize);
        let mut checksums = Vec::with_capacity(nr_sectors);
        for i in 0..nr_sectors {
            let start = i * sector_size as usize;
            let crc = crate::fs::btrfs::crc32c::crc32c(&test_data[start..start + sector_size as usize]);
            checksums.push((disk_bytenr + (i * sector_size as usize) as u64, crc));
        }

        let from_checksums = build_extent_csum_items_from_checksums(node_size, &checksums)
            .expect("build csum items from checksums");

        assert_eq!(from_data, from_checksums);
    }

    #[test]
    fn test_build_extent_csum_items_from_checksums_discontinuous_extents() {
        let node_size = 16384;
        let checksums = vec![
            (10_000_000, 0x11111111),
            (10_004_096, 0x22222222),
            (20_000_000, 0x33333333),
            (20_004_096, 0x44444444),
        ];

        let items = build_extent_csum_items_from_checksums(node_size, &checksums)
            .expect("build csum items discontinuous");

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, 10_000_000);
        assert_eq!(items[0].1.len(), 8);
        assert_eq!(&items[0].1[0..4], &0x11111111u32.to_le_bytes());
        assert_eq!(&items[0].1[4..8], &0x22222222u32.to_le_bytes());

        assert_eq!(items[1].0, 20_000_000);
        assert_eq!(items[1].1.len(), 8);
        assert_eq!(&items[1].1[0..4], &0x33333333u32.to_le_bytes());
        assert_eq!(&items[1].1[4..8], &0x44444444u32.to_le_bytes());
    }

    #[test]
    fn test_build_extent_csum_items_from_checksums_empty() {
        let items = build_extent_csum_items_from_checksums(16384, &[])
            .expect("build empty");
        assert!(items.is_empty());
    }
}

