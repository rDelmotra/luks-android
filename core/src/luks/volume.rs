//! An unlocked LUKS volume, presented as plaintext bytes.
//!
//! Reads are translated into whole cipher blocks, decrypted, and sliced — the
//! caller never has to think in sectors.
//!
//! The tweak is the subtlety. For `aes-xts-plain64` the tweak for block *i* is
//! `iv_tweak + i`, counting from the start of the **segment**, not from the
//! partition or the disk. Using an absolute LBA here yields plausible-looking
//! garbage rather than an error, so it is worth being explicit.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::luks::header::{Luks2Header, SegmentSize};
use crate::luks::keyslot::{self, xts_decrypt};
use crate::secret::Secret;

pub struct LuksVolume<'a, D: ReadAt + ?Sized> {
    device: &'a D,
    /// Byte offset of the partition on the underlying device.
    partition_offset: u64,
    /// Byte offset of the ciphertext, relative to the partition.
    segment_offset: u64,
    /// Plaintext length, if the segment is not "dynamic".
    segment_len: Option<u64>,
    sector_size: usize,
    iv_tweak: u128,
    tweak_step: u128,
    master_key: Secret,
}

impl<'a, D: ReadAt + ?Sized> LuksVolume<'a, D> {
    /// Derive the master key and open the volume. This is the slow call.
    pub fn open(
        device: &'a D,
        partition_offset: u64,
        header: &Luks2Header,
        password: &[u8],
    ) -> Result<Self> {
        let master_key = keyslot::unlock(device, partition_offset, header, password)?;
        Self::with_master_key(device, partition_offset, header, master_key)
    }

    /// Open using an already-derived master key. Skips the KDF entirely, which
    /// is what makes it possible to test decryption against cryptsetup's
    /// `--dump-master-key` output without going through our own derivation.
    pub fn with_master_key(
        device: &'a D,
        partition_offset: u64,
        header: &Luks2Header,
        master_key: Secret,
    ) -> Result<Self> {
        let seg = header.primary_segment()?;

        if seg.encryption != "aes-xts-plain64" {
            return Err(LuksError::UnsupportedCipher(seg.encryption.clone()));
        }
        if !matches!(seg.sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(LuksError::BadSectorSize(seg.sector_size));
        }

        Ok(Self {
            device,
            partition_offset,
            segment_offset: seg.offset,
            segment_len: match seg.size {
                SegmentSize::Fixed(n) => Some(n),
                SegmentSize::Dynamic => None,
            },
            sector_size: seg.sector_size as usize,
            iv_tweak: seg.iv_tweak as u128,
            tweak_step: seg.tweak_step(),
            master_key,
        })
    }

    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Plaintext length, if the header pins it down.
    pub fn len(&self) -> Option<u64> {
        self.segment_len
    }

    pub fn is_empty(&self) -> Option<bool> {
        self.segment_len.map(|n| n == 0)
    }

    /// Read plaintext at `offset` bytes from the start of the decrypted volume.
    ///
    /// Handles arbitrary alignment by expanding to whole cipher blocks and
    /// slicing the result.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if let Some(len) = self.segment_len {
            if end > len {
                return Err(LuksError::OutOfBounds);
            }
        }

        let ss = self.sector_size as u64;
        let first_sector = offset / ss;
        let last_sector = end.div_ceil(ss);
        let span = ((last_sector - first_sector) * ss) as usize;

        let mut scratch = vec![0u8; span];
        let disk_offset = self
            .partition_offset
            .checked_add(self.segment_offset)
            .and_then(|o| o.checked_add(first_sector * ss))
            .ok_or(LuksError::OutOfBounds)?;
        self.device.read_at(disk_offset, &mut scratch)?;

        xts_decrypt(
            self.master_key.expose(),
            &mut scratch,
            self.sector_size,
            self.iv_tweak + first_sector as u128 * self.tweak_step,
            self.tweak_step,
        )?;

        let skip = (offset - first_sector * ss) as usize;
        buf.copy_from_slice(&scratch[skip..skip + buf.len()]);
        Ok(())
    }
}

/// Lets the filesystem layer read straight through the decryption layer.
impl<D: ReadAt + ?Sized> ReadAt for LuksVolume<'_, D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        LuksVolume::read_at(self, offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.segment_len
    }
}
