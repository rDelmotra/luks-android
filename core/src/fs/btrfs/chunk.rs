//! The chunk tree: logical addresses to physical ones.
//!
//! This is the layer ext4 has no equivalent of. An ext4 inode names physical
//! block numbers directly; every pointer in btrfs — tree roots, node children,
//! file extents — is a *logical* address in a flat address space that the chunk
//! tree maps onto real devices. Nothing above this module can read anything
//! until the map exists.
//!
//! Which creates a circularity: the chunk tree's own address is logical too.
//! btrfs breaks it by copying just enough chunk items into the superblock, in
//! `sys_chunk_array` — a bootstrap map whose only job is to cover the chunk
//! tree itself. So the sequence is: parse the array, use it to read the chunk
//! tree, replace the map with the full one.

use super::superblock::Superblock;
use crate::error::{LuksError, Result};

// --- chunk type bits (BTRFS_BLOCK_GROUP_*) ---------------------------------
// Confirmed against the fixtures: plain.img's system chunk is 0x22 where
// dump-tree says SYSTEM|DUP, and mixed-4k.img has 0x5 for DATA|METADATA.
pub const BLOCK_GROUP_DATA: u64 = 0x1;
pub const BLOCK_GROUP_SYSTEM: u64 = 0x2;
pub const BLOCK_GROUP_METADATA: u64 = 0x4;
const BLOCK_GROUP_RAID0: u64 = 0x8;
const BLOCK_GROUP_RAID1: u64 = 0x10;
const BLOCK_GROUP_DUP: u64 = 0x20;
const BLOCK_GROUP_RAID10: u64 = 0x40;
const BLOCK_GROUP_RAID5: u64 = 0x80;
const BLOCK_GROUP_RAID6: u64 = 0x100;
const BLOCK_GROUP_RAID1C3: u64 = 0x200;
const BLOCK_GROUP_RAID1C4: u64 = 0x400;

/// Profiles where every stripe holds the same bytes, so a reader may use any
/// one of them and the mapping inside a chunk is linear.
const MIRRORED: u64 =
    BLOCK_GROUP_DUP | BLOCK_GROUP_RAID1 | BLOCK_GROUP_RAID1C3 | BLOCK_GROUP_RAID1C4;

/// Profiles that interleave, so a logical range is spread across stripes and
/// the linear mapping below would silently return the wrong bytes.
const STRIPED: u64 =
    BLOCK_GROUP_RAID0 | BLOCK_GROUP_RAID10 | BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6;

/// `key (17) + the fixed part of a chunk item (48)`.
const CHUNK_ITEM_HEAD: usize = 48;
const STRIPE_SIZE: usize = 32;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// One stripe of a chunk: a run of bytes on one device.
#[derive(Debug, Clone, Copy)]
pub struct Stripe {
    pub devid: u64,
    /// Byte offset on that device.
    pub offset: u64,
}

/// A contiguous range of the logical address space and where it lives.
#[derive(Debug, Clone)]
pub struct Chunk {
    pub logical: u64,
    pub length: u64,
    pub chunk_type: u64,
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    /// Parse a `CHUNK_ITEM`'s data. `logical` comes from the key's offset
    /// field, not from the item body — the body never repeats it.
    pub fn parse(logical: u64, data: &[u8]) -> Result<Self> {
        if data.len() < CHUNK_ITEM_HEAD {
            return Err(LuksError::CorruptFs("btrfs chunk item truncated"));
        }
        let length = u64le(data, 0);
        let chunk_type = u64le(data, 24);
        let num_stripes = u16le(data, 44) as usize;

        if num_stripes == 0 {
            return Err(LuksError::CorruptFs("btrfs chunk has no stripes"));
        }
        let needed = CHUNK_ITEM_HEAD + num_stripes * STRIPE_SIZE;
        if data.len() < needed {
            return Err(LuksError::CorruptFs("btrfs chunk stripe array truncated"));
        }
        if length == 0 {
            return Err(LuksError::CorruptFs("btrfs chunk has zero length"));
        }
        if logical.checked_add(length).is_none() {
            return Err(LuksError::CorruptFs("btrfs chunk wraps the address space"));
        }

        if chunk_type & STRIPED != 0 {
            // Not reachable on a single-device filesystem, which is all we
            // mount — but the check is here rather than relying on that,
            // because the consequence of getting it wrong is silently reading
            // one stripe's worth of an interleaved range as if it were
            // contiguous. That returns data, just not the file's.
            return Err(LuksError::UnsupportedFsFeature(
                "btrfs striped or parity chunk profile (RAID0/5/6/10)".into(),
            ));
        }

        let stripes = (0..num_stripes)
            .map(|i| {
                let at = CHUNK_ITEM_HEAD + i * STRIPE_SIZE;
                Stripe {
                    devid: u64le(data, at),
                    offset: u64le(data, at + 8),
                }
            })
            .collect();

        Ok(Chunk {
            logical,
            length,
            chunk_type,
            stripes,
        })
    }

    pub fn is_mirrored(&self) -> bool {
        self.chunk_type & MIRRORED != 0
    }

    pub fn stripe_len(data: &[u8]) -> u64 {
        u64le(data, 16)
    }

    pub fn sector_size(data: &[u8]) -> u32 {
        u32le(data, 40)
    }
}

/// Every chunk on the filesystem, sorted by logical address.
#[derive(Debug, Clone, Default)]
pub struct ChunkMap {
    chunks: Vec<Chunk>,
}

impl ChunkMap {
    /// Build the bootstrap map from the superblock's `sys_chunk_array`.
    ///
    /// The array is a bare sequence of `(key, chunk item)` pairs with no count
    /// and no padding — its length is the only terminator, so a parse that
    /// miscomputes one item's size runs off into the next one rather than
    /// failing.
    pub fn bootstrap(sb: &Superblock) -> Result<Self> {
        let a = &sb.sys_chunk_array;
        let mut map = ChunkMap::default();
        let mut at = 0usize;

        while at < a.len() {
            if at + super::tree::KEY_SIZE > a.len() {
                return Err(LuksError::CorruptFs("btrfs sys_chunk_array key truncated"));
            }
            let objectid = u64le(a, at);
            let item_type = a[at + 8];
            let logical = u64le(a, at + 9);
            at += super::tree::KEY_SIZE;

            if item_type != super::tree::CHUNK_ITEM_KEY
                || objectid != super::tree::FIRST_CHUNK_TREE_OBJECTID
            {
                return Err(LuksError::CorruptFs(
                    "btrfs sys_chunk_array holds something other than chunk items",
                ));
            }

            let chunk = Chunk::parse(logical, &a[at..])?;
            at += CHUNK_ITEM_HEAD + chunk.stripes.len() * STRIPE_SIZE;
            map.insert(chunk);
        }

        if map.chunks.is_empty() {
            return Err(LuksError::CorruptFs("btrfs sys_chunk_array is empty"));
        }
        Ok(map)
    }

    /// Add a chunk, keeping the list sorted and ignoring an exact duplicate.
    ///
    /// Duplicates are expected, not defensive: the system chunk appears both in
    /// `sys_chunk_array` and in the chunk tree, and the full map is built by
    /// adding the tree's items to the bootstrap map rather than by replacing it.
    pub fn insert(&mut self, chunk: Chunk) {
        match self
            .chunks
            .binary_search_by_key(&chunk.logical, |c| c.logical)
        {
            Ok(i) => self.chunks[i] = chunk,
            Err(i) => self.chunks.insert(i, chunk),
        }
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// Translate `logical`, returning the physical byte offset **and how many
    /// bytes from there stay contiguous**.
    ///
    /// The run length is not a nicety. Without it every read would have to be
    /// chopped at an arbitrary granularity and re-translated, which is exactly
    /// the mistake that made the ext4 reader take minutes to hash a 1 GiB file
    /// over USB — one device round trip per block instead of per run. A chunk
    /// is at least 8 MiB, so in practice this hands back the whole request.
    pub fn map(&self, logical: u64) -> Result<(u64, u64)> {
        let i = match self
            .chunks
            .binary_search_by_key(&logical, |c| c.logical)
        {
            Ok(i) => i,
            // The chunk starting at or before `logical`, if there is one.
            Err(0) => return Err(LuksError::CorruptFs("btrfs logical address below the first chunk")),
            Err(i) => i - 1,
        };
        let chunk = &self.chunks[i];

        let within = logical - chunk.logical;
        if within >= chunk.length {
            // The gap between two chunks is unallocated logical space. A
            // pointer into it means the tree is corrupt or we mapped something
            // wrong; it is never a hole to be read as zeros.
            return Err(LuksError::CorruptFs(
                "btrfs logical address falls in an unmapped gap",
            ));
        }

        // Single and mirrored profiles both map linearly: stripe 0 covers the
        // whole chunk, and any other stripe is a byte-identical copy of it.
        // Choosing stripe 0 unconditionally is therefore correct, though it
        // means a DUP filesystem never uses its second copy to recover from a
        // checksum failure. Worth doing one day; noted, not done.
        let stripe = &chunk.stripes[0];
        let physical = stripe
            .offset
            .checked_add(within)
            .ok_or(LuksError::CorruptFs("btrfs physical address overflows"))?;
        Ok((physical, chunk.length - within))
    }

    /// The device id every stripe must belong to on a single-device
    /// filesystem. A chunk naming any other device is one we cannot read.
    pub fn check_single_device(&self, devid: u64) -> Result<()> {
        for chunk in &self.chunks {
            if chunk.stripes.iter().any(|s| s.devid != devid) {
                return Err(LuksError::UnsupportedFsFeature(
                    "btrfs chunk refers to a device that is not this one".into(),
                ));
            }
        }
        Ok(())
    }
}
