//! ext4 `metadata_csum` — the crc32c on every metadata structure.
//!
//! Modern `mke2fs` turns this on by default, so a writer that ignores it
//! produces a filesystem `e2fsck` rejects on the first pass and the kernel
//! refuses to mount. Every counter this crate touches has a checksum over it,
//! which is a gift: a stale free-block count becomes a loud error instead of a
//! quiet divergence that only shows up as lost data months later.
//!
//! # The conventions
//!
//! The polynomial is Castagnoli, the same one btrfs uses, so
//! [`crate::fs::btrfs::crc32c`] already provides a hardware-accelerated
//! implementation. What differs — and what no amount of reading the polynomial
//! tells you — is the *seeding*, and ext4 uses several different rules:
//!
//! | structure | seed |
//! |---|---|
//! | superblock | `!0`, **not** the filesystem seed |
//! | group descriptor | fs seed, then the group number as LE32 |
//! | block/inode bitmap | fs seed |
//! | inode | fs seed, then inode number LE32, then `i_generation` LE32 |
//!
//! and the fs seed is itself either `s_checksum_seed` from the superblock, or,
//! when that feature is absent, `crc32c(!0, uuid)`.
//!
//! Getting any of these wrong produces a checksum that is stable, plausible,
//! and wrong — which is why every function here is graded against `mke2fs`'s
//! own output in `tests/ext4_csum.rs` rather than against itself.
//!
//! The kernel's `crc32c(crc, data, len)` is the raw accumulator with no
//! inversion at either end, which is exactly [`crc32c_seed`].

use crate::error::{LuksError, Result};
use crate::fs::btrfs::crc32c::crc32c_seed;
use crate::fs::ext4::Superblock;

/// Byte offset of `bg_checksum` within a group descriptor.
const BG_CHECKSUM_OFFSET: usize = 0x1E;
/// Byte offset of `s_checksum` within the superblock.
const SB_CHECKSUM_OFFSET: usize = 0x3FC;
/// Byte offsets of `i_checksum_lo` (in the base inode) and `i_checksum_hi`
/// (in the extra area, relative to the start of the inode).
const INODE_CSUM_LO_OFFSET: usize = 0x7C;
const INODE_CSUM_HI_OFFSET: usize = 0x82;

/// The per-filesystem checksum seed, and whether checksums apply at all.
#[derive(Debug, Clone, Copy)]
pub struct Seed {
    seed: u32,
    enabled: bool,
}

impl Seed {
    /// Derive the seed for reading. A filesystem without `metadata_csum` gets a
    /// disabled seed, and every `verify_*` below then trivially agrees.
    pub fn of(sb: &Superblock) -> Self {
        // `s_checksum_seed` exists so `tune2fs -U` can change the UUID without
        // rewriting every checksum on the disk. When it is absent the seed is
        // derived from the UUID instead, which is the case on a default
        // `mkfs.ext4` — both paths are exercised by the fixtures.
        let seed = sb
            .checksum_seed
            .unwrap_or_else(|| crc32c_seed(!0, &sb.uuid));
        Seed {
            seed,
            enabled: sb.has_metadata_csum(),
        }
    }

    /// Derive the seed for *writing*, refusing filesystems whose checksum
    /// scheme this crate cannot produce.
    ///
    /// The old `uninit_bg`/`gdt_csum` scheme puts a **crc16** on group
    /// descriptors, a different algorithm entirely. It would be a dozen lines
    /// to implement, and it is deliberately not implemented: there is no
    /// fixture in this repo that uses it, and shipping write code that has
    /// never been graded against a real filesystem is precisely how drives get
    /// corrupted. Reading such a filesystem still works.
    pub fn for_writing(sb: &Superblock) -> Result<Self> {
        if sb.has_gdt_csum_only() {
            return Err(LuksError::UnsupportedFsFeature(
                "gdt_csum group descriptors (crc16) — this filesystem can be \
                 read but not written"
                    .into(),
            ));
        }
        Ok(Self::of(sb))
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The superblock's own checksum: over everything before the field itself,
    /// seeded with `!0` rather than the filesystem seed — which it must be,
    /// since the seed may be derived from a UUID stored inside this very block.
    pub fn superblock(&self, sb_bytes: &[u8]) -> Option<u32> {
        if !self.enabled {
            return None;
        }
        Some(crc32c_seed(!0, &sb_bytes[..SB_CHECKSUM_OFFSET]))
    }

    /// A group descriptor's crc16, truncated from a crc32c.
    ///
    /// The checksum field is covered as two zero bytes rather than skipped, so
    /// the length of the input is the full descriptor either way.
    pub fn group_desc(&self, group: u64, desc: &[u8]) -> Option<u16> {
        if !self.enabled {
            return None;
        }
        let crc = crc32c_seed(self.seed, &(group as u32).to_le_bytes());
        let crc = crc32c_seed(crc, &desc[..BG_CHECKSUM_OFFSET]);
        let crc = crc32c_seed(crc, &[0u8, 0u8]);
        let crc = if desc.len() > BG_CHECKSUM_OFFSET + 2 {
            crc32c_seed(crc, &desc[BG_CHECKSUM_OFFSET + 2..])
        } else {
            crc
        };
        Some((crc & 0xFFFF) as u16)
    }

    /// A bitmap's checksum, stored split across a `_lo` and `_hi` field.
    ///
    /// The width matters: with 32-byte descriptors only the low 16 bits are
    /// stored, so a comparison must be truncated the same way or every check
    /// fails on a filesystem that is perfectly intact.
    pub fn bitmap(&self, bitmap: &[u8]) -> Option<u32> {
        if !self.enabled {
            return None;
        }
        Some(crc32c_seed(self.seed, bitmap))
    }

    /// An inode's checksum. `raw` is the whole on-disk inode, `inode_size`
    /// bytes long.
    ///
    /// `i_checksum_hi` lives in the extra area past byte 128 and only exists if
    /// `i_extra_isize` is large enough to reach it — an inode can legitimately
    /// have a 16-bit checksum on a filesystem with 256-byte inodes.
    pub fn inode(&self, ino: u64, raw: &[u8]) -> Option<u32> {
        if !self.enabled {
            return None;
        }
        let generation = u32::from_le_bytes([raw[100], raw[101], raw[102], raw[103]]);
        let crc = crc32c_seed(self.seed, &(ino as u32).to_le_bytes());
        let crc = crc32c_seed(crc, &generation.to_le_bytes());

        // The checksum fields must read as zero while being covered.
        let mut copy = raw.to_vec();
        copy[INODE_CSUM_LO_OFFSET..INODE_CSUM_LO_OFFSET + 2].fill(0);
        if self.inode_has_csum_hi(raw) {
            copy[INODE_CSUM_HI_OFFSET..INODE_CSUM_HI_OFFSET + 2].fill(0);
        }
        Some(crc32c_seed(crc, &copy))
    }

    /// Whether this inode's `i_extra_isize` reaches far enough to contain
    /// `i_checksum_hi`.
    pub fn inode_has_csum_hi(&self, raw: &[u8]) -> bool {
        if raw.len() < 130 {
            return false;
        }
        let extra_isize = u16::from_le_bytes([raw[128], raw[129]]) as usize;
        // i_checksum_hi sits at 0x82, which is 4 bytes into the extra area.
        128 + extra_isize >= INODE_CSUM_HI_OFFSET + 2
    }

    /// Read the checksum an inode currently claims, matching the width the
    /// `_hi` half's presence implies.
    pub fn stored_inode_csum(&self, raw: &[u8]) -> u32 {
        let lo = u16::from_le_bytes([raw[INODE_CSUM_LO_OFFSET], raw[INODE_CSUM_LO_OFFSET + 1]]);
        if self.inode_has_csum_hi(raw) {
            let hi = u16::from_le_bytes([raw[INODE_CSUM_HI_OFFSET], raw[INODE_CSUM_HI_OFFSET + 1]]);
            lo as u32 | ((hi as u32) << 16)
        } else {
            lo as u32
        }
    }
}
