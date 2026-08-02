//! Read-only btrfs reader.
//!
//! btrfs is not ext4 with different field names. The structural difference that
//! shapes this whole module is **indirection**: an ext4 inode names physical
//! block numbers, whereas every btrfs pointer is a *logical* address that has
//! to be translated through the chunk tree before it can be read. So the reader
//! is built bottom-up in that order:
//!
//! 1. [`superblock`] — geometry, feature gate, and the address of the chunk
//!    tree. Bootstrapped from a fixed offset, the only physical address on the
//!    whole filesystem.
//! 2. chunk tree — logical to physical. Itself reached through the superblock's
//!    embedded `sys_chunk_array`, which exists precisely to break the
//!    circularity of needing the chunk tree to find the chunk tree.
//! 3. root tree, then the fs trees — B-trees of `(key, item)` pairs.
//! 4. `EXTENT_DATA` items — file contents, inline or out of line, and
//!    optionally compressed.
//!
//! Only steps 1 and 2 exist so far.
//!
//! **Read-only means much of btrfs is simply not our problem.** The extent tree,
//! the free-space tree, the block-group tree and the back-references all exist
//! to make *allocation* work. A reader never consults them, which is why
//! several incompat flags that sound alarming are safe to accept.

pub mod crc32c;
pub mod superblock;

pub use superblock::{CsumType, Superblock};

use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// A mounted, read-only btrfs filesystem.
///
/// Owns its device, like [`crate::fs::Ext4`], so a JNI handle can hold the
/// whole stack. The blanket `impl ReadAt for &D` means `Btrfs::mount(&volume)`
/// still works.
pub struct Btrfs<D: ReadAt> {
    device: D,
    sb: Superblock,
}

impl<D: ReadAt> Btrfs<D> {
    /// Find the newest valid superblock and check that this reader can cope
    /// with the filesystem it describes.
    pub fn mount(device: D) -> Result<Self> {
        let sb = Self::read_superblock(&device)?;
        Ok(Btrfs { device, sb })
    }

    /// Pick the copy with the highest generation among those that verify.
    ///
    /// The kernel does the same, and it matters more here than the equivalent
    /// would on ext4: btrfs writes the mirrors in a fixed order, so a machine
    /// that lost power mid-commit can leave copy 0 newer than copy 1, or copy 1
    /// intact while copy 0 is torn. Taking the primary unconditionally would
    /// read a filesystem that is recoverable as one that is corrupt.
    fn read_superblock(device: &D) -> Result<Superblock> {
        let device_len = device.len();
        let mut best: Option<Superblock> = None;
        let mut first_error: Option<LuksError> = None;

        for offset in superblock::SUPER_OFFSETS {
            // A mirror only exists if the device is long enough for it. On a
            // 146 MiB fixture only the first two are present, and on anything
            // under 256 GiB the third never is.
            if let Some(len) = device_len {
                if offset + superblock::SUPER_SIZE as u64 > len {
                    continue;
                }
            }

            let mut buf = vec![0u8; superblock::SUPER_SIZE];
            if device.read_at(offset, &mut buf).is_err() {
                // Short device with an unknown length. Not an error in itself:
                // the copy simply is not there.
                continue;
            }

            match Superblock::parse(&buf, offset) {
                Ok(sb) => {
                    if best.as_ref().is_none_or(|b| sb.generation > b.generation) {
                        best = Some(sb);
                    }
                }
                Err(e) => {
                    // Report what the *primary* copy said. "bad checksum on the
                    // mirror at 64 MiB" is a confusing thing to show someone
                    // whose drive simply is not btrfs.
                    first_error.get_or_insert(e);
                }
            }
        }

        best.ok_or_else(|| {
            first_error.unwrap_or(LuksError::NotBtrfs([0; 8]))
        })
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    pub fn label(&self) -> &str {
        &self.sb.label
    }

    pub fn fsid(&self) -> [u8; 16] {
        self.sb.fsid
    }

    pub fn sector_size(&self) -> u32 {
        self.sb.sector_size
    }

    pub fn node_size(&self) -> u32 {
        self.sb.node_size
    }

    /// The underlying device, for layers that need to read past this one.
    pub fn device(&self) -> &D {
        &self.device
    }
}
