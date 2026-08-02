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
//! **The two signatures are not equally strong.** btrfs is identified by an
//! 8-byte magic *and* a crc32c over the whole 4 KiB superblock that has to
//! match, which no accident produces. ext4's is a 2-byte magic, which will turn
//! up by chance in roughly one 64 KiB of arbitrary data. So btrfs is checked
//! first and ext4 is what remains — and when both are present the answer is an
//! error rather than a guess.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::Superblock as BtrfsSuperblock;

/// Where the ext4 superblock's magic sits: 1024 bytes in, 0x38 into the block.
const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;
const EXT4_MAGIC: u16 = 0xEF53;

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

/// Which filesystem is on this volume.
///
/// Errors rather than guessing when the answer is not clear, because both ways
/// of guessing are bad: reading a stale signature shows the user a filesystem
/// that was deleted, and reading the wrong one of two live ones shows them
/// somebody else's files.
pub fn detect<D: ReadAt + ?Sized>(device: &D) -> Result<FsKind> {
    // A full superblock parse, not a magic comparison: this verifies the
    // checksum and that the block claims the offset it was read from, so a
    // stale copy left in re-used space is rejected here rather than surviving
    // to confuse the mount.
    let btrfs = BtrfsSuperblock::find(device).is_ok();

    let mut magic = [0u8; 2];
    // A device too small to hold an ext4 superblock is simply not ext4; that
    // is not an error worth propagating over a missing filesystem.
    let ext4 = device.read_at(EXT4_MAGIC_OFFSET, &mut magic).is_ok()
        && u16::from_le_bytes(magic) == EXT4_MAGIC;

    match (btrfs, ext4) {
        (true, false) => Ok(FsKind::Btrfs),
        (false, true) => Ok(FsKind::Ext4),
        // Both signatures present. Formatting normally wipes the old one, so
        // this means either a partial reformat or a deliberately crafted
        // image. Picking one would be a coin flip over which data the user
        // sees.
        (true, true) => Err(LuksError::AmbiguousFs),
        (false, false) => Err(LuksError::UnknownFs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 KiB at 1024 with the ext4 magic in place — enough for detection,
    /// nowhere near enough to mount, which is the point of the split.
    fn fake_ext4() -> Vec<u8> {
        let mut disk = vec![0u8; 8192];
        disk[EXT4_MAGIC_OFFSET as usize..EXT4_MAGIC_OFFSET as usize + 2]
            .copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        disk
    }

    #[test]
    fn an_ext4_signature_is_recognised() {
        assert_eq!(detect(&fake_ext4()).unwrap(), FsKind::Ext4);
    }

    #[test]
    fn an_empty_volume_is_neither() {
        let disk = vec![0u8; 8192];
        assert!(matches!(detect(&disk), Err(LuksError::UnknownFs)));
    }

    /// The ext4 magic is two bytes, so it turns up by accident. Detection is
    /// allowed to be fooled by that — mounting is what rejects it — but the
    /// stronger btrfs check must not be.
    #[test]
    fn a_stray_two_byte_pattern_is_not_mistaken_for_btrfs() {
        let mut disk = vec![0u8; 0x2_0000];
        for (i, b) in disk.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        assert!(!matches!(detect(&disk), Ok(FsKind::Btrfs)));
    }
}
