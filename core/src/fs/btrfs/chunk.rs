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
use super::tree::{
    CHUNK_ITEM_KEY, CHUNK_TREE_OBJECTID, DEV_EXTENT_KEY, EXTENT_TREE_OBJECTID,
    FIRST_CHUNK_TREE_OBJECTID, Key,
};
use crate::error::{LuksError, Result};

// --- chunk type bits (BTRFS_BLOCK_GROUP_*) ---------------------------------
// Confirmed against the fixtures: plain.img's system chunk is 0x22 where
// dump-tree says SYSTEM|DUP, and mixed-4k.img has 0x5 for DATA|METADATA.
pub const BLOCK_GROUP_DATA: u64 = 0x1;
pub const BLOCK_GROUP_SYSTEM: u64 = 0x2;
pub const BLOCK_GROUP_METADATA: u64 = 0x4;
pub const BLOCK_GROUP_RAID0: u64 = 0x8;
pub const BLOCK_GROUP_RAID1: u64 = 0x10;
pub const BLOCK_GROUP_DUP: u64 = 0x20;
pub const BLOCK_GROUP_RAID10: u64 = 0x40;
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

/// Fixed part of a `CHUNK_ITEM` (48 bytes).
pub const CHUNK_ITEM_HEAD: usize = 48;
pub const STRIPE_SIZE: usize = 32;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stripe {
    pub devid: u64,
    /// Byte offset on that device.
    pub offset: u64,
    /// Device UUID (16 bytes).
    pub dev_uuid: [u8; 16],
}

impl Stripe {
    pub fn new(devid: u64, offset: u64, dev_uuid: [u8; 16]) -> Self {
        Stripe {
            devid,
            offset,
            dev_uuid,
        }
    }
}

/// A contiguous range of the logical address space and where it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub logical: u64,
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub chunk_type: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub sub_stripes: u16,
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
        let owner = u64le(data, 8);
        let stripe_len = u64le(data, 16);
        let chunk_type = u64le(data, 24);
        let io_align = u32le(data, 32);
        let io_width = u32le(data, 36);
        let sector_size = u32le(data, 40);
        let num_stripes = u16le(data, 44) as usize;
        let sub_stripes = u16le(data, 46);

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
                let mut dev_uuid = [0u8; 16];
                dev_uuid.copy_from_slice(&data[at + 16..at + 32]);
                Stripe {
                    devid: u64le(data, at),
                    offset: u64le(data, at + 8),
                    dev_uuid,
                }
            })
            .collect();

        Ok(Chunk {
            logical,
            length,
            owner,
            stripe_len,
            chunk_type,
            io_align,
            io_width,
            sector_size,
            sub_stripes,
            stripes,
        })
    }

    /// Construct a single-stripe DATA chunk with standard parameters.
    pub fn new_single(
        logical: u64,
        length: u64,
        chunk_type: u64,
        devid: u64,
        physical_offset: u64,
        dev_uuid: [u8; 16],
    ) -> Self {
        Chunk {
            logical,
            length,
            owner: EXTENT_TREE_OBJECTID,
            stripe_len: 65536,
            chunk_type,
            io_align: 65536,
            io_width: 65536,
            sector_size: 4096,
            sub_stripes: 1,
            stripes: vec![Stripe::new(devid, physical_offset, dev_uuid)],
        }
    }

    /// Emit the `(Key, Vec<u8>)` for this chunk item.
    ///
    /// Key is `Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, logical)`.
    /// Payload is 48 bytes header + 32 bytes per stripe.
    pub fn emit(&self) -> (Key, Vec<u8>) {
        let total_size = CHUNK_ITEM_HEAD + self.stripes.len() * STRIPE_SIZE;
        let mut buf = vec![0u8; total_size];
        buf[0..8].copy_from_slice(&self.length.to_le_bytes());
        buf[8..16].copy_from_slice(&self.owner.to_le_bytes());
        buf[16..24].copy_from_slice(&self.stripe_len.to_le_bytes());
        buf[24..32].copy_from_slice(&self.chunk_type.to_le_bytes());
        buf[32..36].copy_from_slice(&self.io_align.to_le_bytes());
        buf[36..40].copy_from_slice(&self.io_width.to_le_bytes());
        buf[40..44].copy_from_slice(&self.sector_size.to_le_bytes());
        buf[44..46].copy_from_slice(&(self.stripes.len() as u16).to_le_bytes());
        buf[46..48].copy_from_slice(&self.sub_stripes.to_le_bytes());

        for (i, stripe) in self.stripes.iter().enumerate() {
            let at = CHUNK_ITEM_HEAD + i * STRIPE_SIZE;
            buf[at..at + 8].copy_from_slice(&stripe.devid.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&stripe.offset.to_le_bytes());
            buf[at + 16..at + 32].copy_from_slice(&stripe.dev_uuid);
        }

        (
            Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, self.logical),
            buf,
        )
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

/// Fixed size of a `DEV_EXTENT` item payload (48 bytes).
pub const DEV_EXTENT_SIZE: usize = 48;

/// A device extent item (`DEV_EXTENT_KEY = 204`) in the DEV_TREE (root 4).
///
/// Maps a contiguous range of physical device bytes to a chunk in the chunk tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevExtent {
    /// Device id from the key's objectid.
    pub devid: u64,
    /// Physical byte offset on the device from the key's offset.
    pub physical_offset: u64,
    /// Chunk tree objectid (typically 3 = `CHUNK_TREE_OBJECTID`).
    pub chunk_tree: u64,
    /// Chunk objectid (typically 256 = `FIRST_CHUNK_TREE_OBJECTID`).
    pub chunk_objectid: u64,
    /// Chunk logical start address.
    pub chunk_offset: u64,
    /// Stripe length (bytes).
    pub length: u64,
    /// Chunk tree UUID (16 bytes, matching `super.chunk_tree_uuid` / fsid).
    pub chunk_tree_uuid: [u8; 16],
}

impl DevExtent {
    /// Parse a `DEV_EXTENT` item from its key and payload bytes.
    pub fn parse(key: &Key, data: &[u8]) -> Result<Self> {
        if key.item_type != DEV_EXTENT_KEY {
            return Err(LuksError::CorruptFs("not a btrfs dev extent key"));
        }
        if data.len() < DEV_EXTENT_SIZE {
            return Err(LuksError::CorruptFs("btrfs dev extent item truncated"));
        }
        let chunk_tree = u64le(data, 0x00);
        let chunk_objectid = u64le(data, 0x08);
        let chunk_offset = u64le(data, 0x10);
        let length = u64le(data, 0x18);
        let mut chunk_tree_uuid = [0u8; 16];
        chunk_tree_uuid.copy_from_slice(&data[0x20..0x30]);

        if length == 0 {
            return Err(LuksError::CorruptFs("btrfs dev extent has zero length"));
        }
        if key.offset.checked_add(length).is_none() {
            return Err(LuksError::CorruptFs(
                "btrfs dev extent wraps physical address space",
            ));
        }

        Ok(DevExtent {
            devid: key.objectid,
            physical_offset: key.offset,
            chunk_tree,
            chunk_objectid,
            chunk_offset,
            length,
            chunk_tree_uuid,
        })
    }

    /// Construct a new `DevExtent` for a standard chunk on a single device.
    pub fn new(
        devid: u64,
        physical_offset: u64,
        chunk_offset: u64,
        length: u64,
        chunk_tree_uuid: [u8; 16],
    ) -> Self {
        DevExtent {
            devid,
            physical_offset,
            chunk_tree: CHUNK_TREE_OBJECTID,
            chunk_objectid: FIRST_CHUNK_TREE_OBJECTID,
            chunk_offset,
            length,
            chunk_tree_uuid,
        }
    }

    /// Emit the `(Key, Vec<u8>)` for this device extent item.
    ///
    /// Key is `Key::new(devid, DEV_EXTENT_KEY, physical_offset)`.
    /// Payload is 48 bytes.
    pub fn emit(&self) -> (Key, Vec<u8>) {
        let mut buf = vec![0u8; DEV_EXTENT_SIZE];
        buf[0x00..0x08].copy_from_slice(&self.chunk_tree.to_le_bytes());
        buf[0x08..0x10].copy_from_slice(&self.chunk_objectid.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&self.chunk_offset.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&self.length.to_le_bytes());
        buf[0x20..0x30].copy_from_slice(&self.chunk_tree_uuid);

        (
            Key::new(self.devid, DEV_EXTENT_KEY, self.physical_offset),
            buf,
        )
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

    /// Translate `logical` into physical byte offsets for **every stripe** of
    /// its chunk.
    ///
    /// For single-profile chunks, this returns a single physical offset.
    /// For DUP-profile chunks, this returns two physical offsets (one per copy).
    pub fn map_all_stripes(&self, logical: u64) -> Result<Vec<u64>> {
        let i = match self
            .chunks
            .binary_search_by_key(&logical, |c| c.logical)
        {
            Ok(i) => i,
            Err(0) => return Err(LuksError::CorruptFs("btrfs logical address below the first chunk")),
            Err(i) => i - 1,
        };
        let chunk = &self.chunks[i];
        let within = logical - chunk.logical;
        if within >= chunk.length {
            return Err(LuksError::CorruptFs(
                "btrfs logical address falls in an unmapped gap",
            ));
        }

        let mut physicals = Vec::with_capacity(chunk.stripes.len());
        for stripe in &chunk.stripes {
            let phys = stripe
                .offset
                .checked_add(within)
                .ok_or(LuksError::CorruptFs("btrfs physical address overflows"))?;
            physicals.push(phys);
        }
        Ok(physicals)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_single_emit_and_parse_roundtrip() {
        let dev_uuid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        ];
        let chunk = Chunk::new_single(
            13_631_488,
            8_388_608,
            BLOCK_GROUP_DATA,
            1,
            13_631_488,
            dev_uuid,
        );

        let (key, bytes) = chunk.emit();
        assert_eq!(key.objectid, FIRST_CHUNK_TREE_OBJECTID);
        assert_eq!(key.item_type, CHUNK_ITEM_KEY);
        assert_eq!(key.offset, 13_631_488);
        assert_eq!(bytes.len(), 80); // 48 header + 32 stripe

        let parsed = Chunk::parse(key.offset, &bytes).expect("parse emitted chunk");
        assert_eq!(parsed, chunk);
    }

    #[test]
    fn test_chunk_dup_emit_and_parse_roundtrip() {
        let uuid0 = [0x01; 16];
        let uuid1 = [0x02; 16];
        let chunk = Chunk {
            logical: 30_408_704,
            length: 53_673_984,
            owner: EXTENT_TREE_OBJECTID,
            stripe_len: 65536,
            chunk_type: BLOCK_GROUP_METADATA | BLOCK_GROUP_DUP,
            io_align: 65536,
            io_width: 65536,
            sector_size: 4096,
            sub_stripes: 1,
            stripes: vec![
                Stripe::new(1, 38_797_312, uuid0),
                Stripe::new(1, 92_471_296, uuid1),
            ],
        };

        let (key, bytes) = chunk.emit();
        assert_eq!(key.objectid, FIRST_CHUNK_TREE_OBJECTID);
        assert_eq!(key.item_type, CHUNK_ITEM_KEY);
        assert_eq!(key.offset, 30_408_704);
        assert_eq!(bytes.len(), 112); // 48 header + 64 (2 stripes)

        let parsed = Chunk::parse(key.offset, &bytes).expect("parse emitted dup chunk");
        assert_eq!(parsed, chunk);
        assert!(parsed.is_mirrored());
    }

    #[test]
    fn test_dev_extent_emit_and_parse_roundtrip() {
        let chunk_tree_uuid = [
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
        ];
        let dev_extent = DevExtent::new(
            1,
            13_631_488,
            13_631_488,
            8_388_608,
            chunk_tree_uuid,
        );

        let (key, bytes) = dev_extent.emit();
        assert_eq!(key.objectid, 1);
        assert_eq!(key.item_type, DEV_EXTENT_KEY);
        assert_eq!(key.offset, 13_631_488);
        assert_eq!(bytes.len(), DEV_EXTENT_SIZE); // 48 bytes

        let parsed = DevExtent::parse(&key, &bytes).expect("parse emitted dev extent");
        assert_eq!(parsed, dev_extent);
    }

    #[test]
    fn test_chunk_parse_error_cases() {
        // Truncated header
        let truncated = vec![0u8; 40];
        assert!(Chunk::parse(1000, &truncated).is_err());

        // Zero stripes declared
        let mut zero_stripes = vec![0u8; 48];
        zero_stripes[0..8].copy_from_slice(&8388608u64.to_le_bytes()); // length
        assert!(Chunk::parse(1000, &zero_stripes).is_err());

        // Stripe array truncated
        let mut missing_stripe_bytes = vec![0u8; 60]; // needs 48 + 32 = 80
        missing_stripe_bytes[0..8].copy_from_slice(&8388608u64.to_le_bytes());
        missing_stripe_bytes[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes = 1
        assert!(Chunk::parse(1000, &missing_stripe_bytes).is_err());

        // Zero length
        let mut zero_len = vec![0u8; 80];
        zero_len[44..46].copy_from_slice(&1u16.to_le_bytes());
        assert!(Chunk::parse(1000, &zero_len).is_err());
    }

    #[test]
    fn test_dev_extent_parse_error_cases() {
        let key = Key::new(1, DEV_EXTENT_KEY, 13631488);
        let wrong_key = Key::new(1, CHUNK_ITEM_KEY, 13631488);

        // Wrong key item type
        let valid_data = vec![0u8; DEV_EXTENT_SIZE];
        assert!(DevExtent::parse(&wrong_key, &valid_data).is_err());

        // Truncated payload
        let truncated = vec![0u8; 32];
        assert!(DevExtent::parse(&key, &truncated).is_err());

        // Zero length
        let mut zero_len = vec![0u8; DEV_EXTENT_SIZE];
        zero_len[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());
        assert!(DevExtent::parse(&key, &zero_len).is_err());
    }
}
