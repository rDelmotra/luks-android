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
//! | directory block | fs seed, then the *directory's* inode number and generation, then the block up to its 12-byte tail |
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

/// Size of the fake trailing dirent that carries a directory block's
/// checksum: 4 bytes of zero where an inode number would go, `rec_len` 12, a
/// zero `name_len`, the `0xDE` type marker, then the 4-byte checksum.
pub const DIR_TAIL_SIZE: usize = 12;

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

    /// Derive the seed for *writing* — and, because every write operation in
    /// this crate calls it first, act as the **write gate**: the one place
    /// that refuses filesystems this writer does not fully understand.
    ///
    /// Each refusal below is a filesystem that *reads* fine and would be
    /// silently corrupted by a writer that assumes plain ext4:
    ///
    /// * `gdt_csum`-only: descriptors carry a crc16, a different algorithm.
    /// * `bigalloc`: bitmap bits and free counters are in *clusters*, so this
    ///   allocator's block numbers would be wrong by the cluster ratio — on
    ///   top of other files' data.
    /// * `inline_data`: directories can live inside `i_block`, where mapping
    ///   their "blocks" yields garbage that a writer would then write to.
    /// * missing `filetype`: the dirent byte this crate writes a type code
    ///   into is the high half of a 16-bit `name_len` there.
    /// * missing `extents`: the extent-mapped inodes this crate writes are
    ///   invalid on an indirect-block filesystem (ext2/ext3).
    /// * `quota`: hidden quota inodes must be updated in step with every
    ///   allocation, which this crate does not do.
    /// * a dirty or errored `s_state`: the metadata being patched cannot be
    ///   trusted as a base — it belongs to `e2fsck` (or to the kernel that
    ///   still has it mounted) first.
    ///
    /// Reading any of these still works; refusal is write-only.
    pub fn for_writing(sb: &Superblock) -> Result<Self> {
        let refuse = |what: &str| {
            Err(LuksError::UnsupportedFsFeature(format!(
                "{what} — this filesystem can be read but not written"
            )))
        };

        if sb.has_gdt_csum_only() {
            return refuse("gdt_csum group descriptors (crc16)");
        }
        if sb.feature_ro_compat & super::RO_COMPAT_BIGALLOC != 0 {
            return refuse("bigalloc (cluster-based allocation)");
        }
        if sb.feature_incompat & super::INCOMPAT_INLINE_DATA != 0 {
            return refuse("inline_data");
        }
        if sb.feature_incompat & super::INCOMPAT_FILETYPE == 0 {
            return refuse("a directory format without file types (no filetype feature)");
        }
        if sb.feature_incompat & super::INCOMPAT_EXTENTS == 0 {
            return refuse("an indirect-block filesystem (no extents feature; ext2/ext3)");
        }
        if sb.feature_ro_compat & super::RO_COMPAT_QUOTA != 0 {
            return refuse("quota tracking");
        }
        if sb.state & super::STATE_CLEANLY_UNMOUNTED == 0 {
            return refuse("a filesystem that was not cleanly unmounted");
        }
        if sb.state & super::STATE_ERRORS_SEEN != 0 {
            return refuse("a filesystem with recorded errors (run e2fsck)");
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

    /// A non-htree directory block's checksum, carried in a fake trailing
    /// dirent (`inode == 0`, `file_type == 0xDE`) rather than a header field —
    /// directory blocks have no field of their own to hold one.
    ///
    /// `block` is the **whole** block. The checksummed region stops at the
    /// *start* of the 12-byte tail — the tail's own `rec_len` and `0xDE`
    /// marker are **not** covered, only the real dirents before it. Covering
    /// four fewer bytes (up to the checksum field rather than up to the tail)
    /// is the obvious wrong guess and produces a stable, plausible mismatch.
    pub fn dir_block(&self, dir_ino: u64, dir_generation: u32, block: &[u8]) -> Option<u32> {
        if !self.enabled || block.len() < DIR_TAIL_SIZE {
            return None;
        }
        let crc = crc32c_seed(self.seed, &(dir_ino as u32).to_le_bytes());
        let crc = crc32c_seed(crc, &dir_generation.to_le_bytes());
        Some(crc32c_seed(crc, &block[..block.len() - DIR_TAIL_SIZE]))
    }
}
