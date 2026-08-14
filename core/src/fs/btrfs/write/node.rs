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
    /// Returns `Err(LuksError::FilesystemFull)` if the item does not fit in `node_size`.
    /// Returns `Err(LuksError::AlreadyExists)` if an item with the same key already exists.
    pub fn insert_item(&mut self, key: Key, data: Vec<u8>, node_size: u32) -> Result<()> {
        let needed = ITEM_SIZE + data.len();
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
