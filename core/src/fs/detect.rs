//! Deciding which filesystem is on a volume before mounting it.
//!
//! This exists because mounting consumes the device. `Ext4::mount` and
//! `Btrfs::mount` both take ownership so the resulting handle is `'static` and
//! self-contained, which means "try one, and if it fails try the other" is not
//! available: the volume is gone with the first attempt. Re-opening it is worse
//! than it sounds — a `LuksVolume` is opened by deriving the master key, so a
//! second attempt would run Argon2 again, seconds of work and up to a gigabyte
//! of allocation, to answer a question two small reads can settle.
//!
//! So the decision is made first, by signature, and the volume is handed to
//! exactly one reader.
//!
//! # Detection Hardening (Phase 2)
//!
//! On plain (non-LUKS) volumes, the threat model changes fundamentally: arbitrary
//! attacker-controlled USB devices can reach detection without passing a LUKS keyslot
//! check. A naive 2-byte magic check at offset 1080 would produce false positives
//! on random data, swap, or LVM headers.
//!
//! ext4 detection therefore performs comprehensive superblock validation:
//! - Superblock magic `0xEF53` at offset 56 of the superblock (offset 1080 of device).
//! - Block size exponent `log_block_size <= 6` (`1024 << log_block_size` in `1024..=65536`).
//! - Non-zero `inodes_count` and `blocks_count`.
//! - Non-zero `blocks_per_group` and `inodes_per_group`.
//! - Device length consistency: total blocks * block size must not wildly exceed the device length.
//! - Inode size `>= 128` on revision >= 1.
//! - Superblock checksum validation: if `RO_COMPAT_METADATA_CSUM` is enabled, verify the
//!   CRC32c across `[..0x3FC]` with seed `!0`.
//!
//! Furthermore, common consumer filesystems that this driver does not support
//! (FAT32, exFAT, NTFS, XFS) are recognized explicitly so the UI can explain that
//! the format is unsupported rather than returning `UnknownFs`.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::crc32c::crc32c_seed;
use crate::fs::btrfs::Superblock as BtrfsSuperblock;

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_SIZE: usize = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

fn u16le(b: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([b[offset], b[offset + 1]])
}

fn u32le(b: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
}

/// Robust ext4 superblock validation (Phase 2).
///
/// Refuses a 2-byte collision by checking superblock geometry and, if present,
/// verifying the metadata checksum.
fn detect_ext4<D: ReadAt + ?Sized>(device: &D) -> bool {
    let mut buf = [0u8; EXT4_SUPERBLOCK_SIZE];
    if device.read_at(EXT4_SUPERBLOCK_OFFSET, &mut buf).is_err() {
        return false;
    }

    // 1. Magic at offset 56 (1080 from device start).
    if u16le(&buf, 56) != EXT4_MAGIC {
        return false;
    }

    // 2. Block size: log_block_size <= 6 (1024..=65536).
    let log_block_size = u32le(&buf, 24);
    if log_block_size > 6 {
        return false;
    }
    let block_size = 1024u64 << log_block_size;

    // 3. inodes_count > 0.
    let inodes_count = u32le(&buf, 0);
    if inodes_count == 0 {
        return false;
    }

    // 4. rev_level and blocks_count.
    let rev_level = u32le(&buf, 76);
    let blocks_lo = u32le(&buf, 4) as u64;
    let feature_incompat = if rev_level >= 1 {
        u32le(&buf, 96)
    } else {
        0
    };
    let blocks_hi = if feature_incompat & EXT4_INCOMPAT_64BIT != 0 {
        u32le(&buf, 0x150) as u64
    } else {
        0
    };
    let blocks_count = blocks_lo | (blocks_hi << 32);
    if blocks_count == 0 {
        return false;
    }

    // 5. blocks_per_group > 0 and inodes_per_group > 0.
    let blocks_per_group = u32le(&buf, 32);
    let inodes_per_group = u32le(&buf, 40);
    if blocks_per_group == 0 || inodes_per_group == 0 {
        return false;
    }

    // 6. If device length is known, ensure blocks_count * block_size <= dev_len * 2.
    if let Some(dev_len) = device.len() {
        if let Some(fs_bytes) = blocks_count.checked_mul(block_size) {
            if fs_bytes > dev_len.saturating_mul(2) {
                return false;
            }
        } else {
            return false;
        }
    }

    // 7. rev_level >= 1 checks.
    if rev_level >= 1 {
        let inode_size = u16le(&buf, 88);
        if inode_size < 128 {
            return false;
        }

        let feature_ro_compat = u32le(&buf, 100);
        if feature_ro_compat & EXT4_RO_COMPAT_METADATA_CSUM != 0 {
            let expected = u32le(&buf, 0x3FC);
            let calculated = crc32c_seed(!0, &buf[..0x3FC]);
            if calculated != expected {
                return false;
            }
        }
    }

    true
}

/// Inspect the initial sector for signatures of common recognized but unsupported filesystems.
fn detect_unsupported<D: ReadAt + ?Sized>(device: &D) -> Option<&'static str> {
    let mut buf = [0u8; 512];
    if device.read_at(0, &mut buf).is_err() {
        return None;
    }

    // XFS: b"XFSB" at offset 0
    if &buf[0..4] == b"XFSB" {
        return Some("XFS");
    }

    // NTFS: b"NTFS    " at offset 3
    if &buf[3..11] == b"NTFS    " {
        return Some("NTFS");
    }

    // exFAT: b"EXFAT   " at offset 3
    if &buf[3..11] == b"EXFAT   " {
        return Some("exFAT");
    }

    // FAT: boot sector signature [0x55, 0xAA] at offset 510, AND
    // (b"FAT12   " or b"FAT16   " at offset 0x36 or b"FAT32   " at offset 0x52)
    if buf[510] == 0x55
        && buf[511] == 0xAA
        && (&buf[0x36..0x3E] == b"FAT12   "
            || &buf[0x36..0x3E] == b"FAT16   "
            || &buf[0x52..0x5A] == b"FAT32   ")
    {
        return Some("FAT32");
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Ext4,
    Btrfs,
}

impl FsKind {
    pub fn name(self) -> &'static str {
        match self {
            FsKind::Ext4 => "ext4",
            FsKind::Btrfs => "btrfs",
        }
    }
}

#[derive(Debug, Clone)]
pub enum DetectedFs {
    Ext4,
    Btrfs(BtrfsSuperblock),
}

impl From<DetectedFs> for FsKind {
    fn from(detected: DetectedFs) -> Self {
        match detected {
            DetectedFs::Ext4 => FsKind::Ext4,
            DetectedFs::Btrfs(_) => FsKind::Btrfs,
        }
    }
}

/// Detect which filesystem is on this volume, returning the verified superblock
/// when Btrfs is present so mount does not repeat disk I/O and checksums (C-5).
pub fn detect_fs<D: ReadAt + ?Sized>(device: &D) -> Result<DetectedFs> {
    let btrfs = BtrfsSuperblock::find(device).ok();
    let ext4 = detect_ext4(device);

    match (btrfs, ext4) {
        (Some(sb), false) => Ok(DetectedFs::Btrfs(sb)),
        (None, true) => Ok(DetectedFs::Ext4),
        // Both signatures present. Formatting normally wipes the old one, so
        // this means either a partial reformat or a deliberately crafted
        // image. Picking one would be a coin flip over which data the user
        // sees.
        (Some(_), true) => Err(LuksError::AmbiguousFs),
        (None, false) => {
            if let Some(unsupported) = detect_unsupported(device) {
                Err(LuksError::UnsupportedFs(unsupported))
            } else {
                Err(LuksError::UnknownFs)
            }
        }
    }
}

/// Which filesystem is on this volume.
///
/// Errors rather than guessing when the answer is not clear, because both ways
/// of guessing are bad: reading a stale signature shows the user a filesystem
/// that was deleted, and reading the wrong one of two live ones shows them
/// somebody else's files.
pub fn detect<D: ReadAt + ?Sized>(device: &D) -> Result<FsKind> {
    detect_fs(device).map(FsKind::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::FileDevice;
    use std::path::PathBuf;

    /// Builds a valid minimal ext4 superblock in an image of `size` bytes.
    fn valid_fake_ext4(size: usize) -> Vec<u8> {
        let mut disk = vec![0u8; size];
        let sb = &mut disk[EXT4_SUPERBLOCK_OFFSET as usize..EXT4_SUPERBLOCK_OFFSET as usize + EXT4_SUPERBLOCK_SIZE];
        // inodes_count > 0
        sb[0..4].copy_from_slice(&100u32.to_le_bytes());
        // blocks_count > 0 (8 blocks of 1024 = 8192 bytes, fits within device len)
        sb[4..8].copy_from_slice(&8u32.to_le_bytes());
        // log_block_size = 0 (1024 bytes)
        sb[24..28].copy_from_slice(&0u32.to_le_bytes());
        // blocks_per_group > 0
        sb[32..36].copy_from_slice(&8u32.to_le_bytes());
        // inodes_per_group > 0
        sb[40..44].copy_from_slice(&100u32.to_le_bytes());
        // magic = 0xEF53 at offset 56
        sb[56..58].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        // rev_level = 1
        sb[76..80].copy_from_slice(&1u32.to_le_bytes());
        // inode_size = 256 (>= 128)
        sb[88..90].copy_from_slice(&256u16.to_le_bytes());
        // feature_ro_compat = 0 (no metadata_csum)
        sb[100..104].copy_from_slice(&0u32.to_le_bytes());
        disk
    }

    /// Builds a valid ext4 superblock with a verified metadata_csum.
    fn valid_ext4_with_csum(size: usize) -> Vec<u8> {
        let mut disk = valid_fake_ext4(size);
        let sb_start = EXT4_SUPERBLOCK_OFFSET as usize;
        // Enable metadata_csum
        disk[sb_start + 100..sb_start + 104]
            .copy_from_slice(&EXT4_RO_COMPAT_METADATA_CSUM.to_le_bytes());
        // Calculate CRC32c checksum over [..0x3FC] with seed !0
        let csum = crc32c_seed(!0, &disk[sb_start..sb_start + 0x3FC]);
        disk[sb_start + 0x3FC..sb_start + 0x400].copy_from_slice(&csum.to_le_bytes());
        disk
    }

    #[test]
    fn an_ext4_signature_is_recognised() {
        let disk = valid_fake_ext4(8192);
        assert_eq!(detect(&disk).unwrap(), FsKind::Ext4);
    }

    #[test]
    fn ext4_with_valid_metadata_csum_is_recognised() {
        let disk = valid_ext4_with_csum(8192);
        assert_eq!(detect(&disk).unwrap(), FsKind::Ext4);
    }

    #[test]
    fn ext4_with_corrupt_metadata_csum_is_rejected() {
        let mut disk = valid_ext4_with_csum(8192);
        let sb_start = EXT4_SUPERBLOCK_OFFSET as usize;
        // Corrupt a byte in the superblock
        disk[sb_start + 10] ^= 0xFF;
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn stray_ext4_magic_with_zeroes_is_rejected() {
        let mut disk = vec![0u8; 8192];
        let magic_offset = (EXT4_SUPERBLOCK_OFFSET + 56) as usize;
        disk[magic_offset..magic_offset + 2].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn stray_ext4_magic_with_random_bytes_is_rejected() {
        let mut disk = vec![0u8; 8192];
        for (i, b) in disk.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let magic_offset = (EXT4_SUPERBLOCK_OFFSET + 56) as usize;
        disk[magic_offset..magic_offset + 2].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn ext4_invalid_geometry_rejected() {
        let sb_start = EXT4_SUPERBLOCK_OFFSET as usize;

        // 1. log_block_size > 6
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 24..sb_start + 28].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 2. inodes_count == 0
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start..sb_start + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 3. blocks_count == 0
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 4..sb_start + 8].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 4. blocks_per_group == 0
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 32..sb_start + 36].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 5. inodes_per_group == 0
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 40..sb_start + 44].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 6. inode_size < 128 on revision >= 1
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 88..sb_start + 90].copy_from_slice(&64u16.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));

        // 7. blocks_count * block_size wildly exceeds device length
        let mut disk = valid_fake_ext4(8192);
        disk[sb_start + 4..sb_start + 8].copy_from_slice(&10_000u32.to_le_bytes());
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn an_empty_volume_is_neither() {
        let disk = vec![0u8; 8192];
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn random_data_returns_unknown_fs() {
        let mut disk = vec![0u8; 65536];
        for (i, b) in disk.iter_mut().enumerate() {
            *b = ((i * 101 + 37) % 256) as u8;
        }
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn lvm_pv_header_returns_unknown_fs() {
        let mut disk = vec![0u8; 4096];
        disk[512..520].copy_from_slice(b"LABELONE");
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn swap_header_returns_unknown_fs() {
        let mut disk = vec![0u8; 8192];
        disk[4086..4096].copy_from_slice(b"SWAPSPACE2");
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    #[test]
    fn fat32_boot_sector_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[0x52..0x5A].copy_from_slice(b"FAT32   ");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("FAT32")));
    }

    #[test]
    fn fat16_boot_sector_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[0x36..0x3E].copy_from_slice(b"FAT16   ");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("FAT32")));
    }

    #[test]
    fn fat12_boot_sector_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[0x36..0x3E].copy_from_slice(b"FAT12   ");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("FAT32")));
    }

    #[test]
    fn exfat_boot_sector_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[3..11].copy_from_slice(b"EXFAT   ");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("exFAT")));
    }

    #[test]
    fn ntfs_boot_sector_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[3..11].copy_from_slice(b"NTFS    ");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("NTFS")));
    }

    #[test]
    fn xfs_superblock_returns_unsupported_fs() {
        let mut disk = vec![0u8; 512];
        disk[0..4].copy_from_slice(b"XFSB");
        let err = detect(&disk).unwrap_err();
        assert!(matches!(err, LuksError::UnsupportedFs("XFS")));
    }

    #[test]
    fn real_ext4_fixtures_are_detected() {
        let ext4_fixtures = [
            "big-4k.img",
            "csum-uuid-4k.img",
            "dirtail-1k.img",
            "ext2-1k.img",
            "many-groups-1k.img",
            "small-1k.img",
        ];
        for fixture in ext4_fixtures {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("fixtures")
                .join("ext4")
                .join(fixture);
            let dev = FileDevice::open(&path).unwrap_or_else(|e| panic!("failed to open {fixture}: {e}"));
            let kind = detect(&dev).unwrap_or_else(|e| panic!("failed to detect {fixture}: {e}"));
            assert_eq!(kind, FsKind::Ext4, "expected ext4 for {fixture}");
        }
    }

    #[test]
    fn real_btrfs_fixtures_are_detected() {
        let btrfs_fixtures = [
            "plain.img",
            "compress.img",
            "mixed-4k.img",
            "nonmixed-4k.img",
            "sha256-4k.img",
        ];
        for fixture in btrfs_fixtures {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("fixtures")
                .join("btrfs")
                .join(fixture);
            let dev = FileDevice::open(&path).unwrap_or_else(|e| panic!("failed to open {fixture}: {e}"));
            let kind = detect(&dev).unwrap_or_else(|e| panic!("failed to detect {fixture}: {e}"));
            assert_eq!(kind, FsKind::Btrfs, "expected btrfs for {fixture}");
        }
    }

    /// The ext4 magic is two bytes, so it turns up by accident. Detection is
    /// hardened in Phase 2 so that geometry and checksum are validated, but the
    /// btrfs check must also not be confused by stray bytes.
    #[test]
    fn a_stray_two_byte_pattern_is_not_mistaken_for_btrfs() {
        let mut disk = vec![0u8; 0x2_0000];
        for (i, b) in disk.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        assert!(!matches!(detect(&disk), Ok(FsKind::Btrfs)));
    }
}
