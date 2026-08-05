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
#[cfg(feature = "dangerous-write-support")]
use crate::luks::keyslot::xts_encrypt;
use crate::secret::Secret;

/// Owns its device rather than borrowing it.
///
/// `D` is usually a reference (`&Vec<u8>`, `&FileDevice`) thanks to the blanket
/// `impl ReadAt for &D`, so borrowing callers are unaffected. Owning matters for
/// the JNI bridge: `Ext4<LuksVolume<ScsiBlockDevice<UsbFsTransport>>>` is a
/// single `'static` value that can sit behind a raw handle. Were the layers
/// borrowing, that handle would be a self-referential struct — unrepresentable
/// in safe Rust.
pub struct LuksVolume<D: ReadAt> {
    device: D,
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

impl<D: ReadAt> LuksVolume<D> {
    /// Derive the master key and open the volume. This is the slow call.
    ///
    /// `partition_len` is how many bytes the container occupies on the device,
    /// or `None` when it runs to the end (a bare container, or a whole-disk
    /// LUKS). See [`LuksVolume::with_master_key`] for why it is asked for.
    pub fn open(
        device: D,
        partition_offset: u64,
        partition_len: Option<u64>,
        header: &Luks2Header,
        password: &[u8],
    ) -> Result<Self> {
        let master_key = keyslot::unlock(&device, partition_offset, header, password)?;
        Self::with_master_key(device, partition_offset, partition_len, header, master_key)
    }

    /// Open using an already-derived master key. Skips the KDF entirely, which
    /// is what makes it possible to test decryption against cryptsetup's
    /// `--dump-master-key` output without going through our own derivation.
    ///
    /// # Why `partition_len` is a parameter
    ///
    /// Nearly every container `cryptsetup` produces declares its segment size
    /// as `"dynamic"` — meaning "the rest of whatever I am in" — so the header
    /// alone does not say where the plaintext ends. Left unbounded, a write
    /// derived from a corrupt filesystem structure runs past the container and
    /// into whatever partition follows it, still encrypted with this volume's
    /// key and therefore pure destruction to its contents.
    ///
    /// The device's own length is not a substitute. It stops writes running
    /// off the end of the *disk*, which the layers below already do; the
    /// partition length is the only thing that stops them running off the end
    /// of the *container*. `partition::scan` reports it, so the caller that
    /// found the container always has it.
    ///
    /// `None` means "to the end of the device" and is the honest answer for a
    /// bare container. It is not a way to opt out: the bound simply comes from
    /// the device instead, which for a bare container is the same number.
    pub fn with_master_key(
        device: D,
        partition_offset: u64,
        partition_len: Option<u64>,
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

        // How much room the ciphertext actually has: the container's length
        // (or the device's, less where the container starts) minus the header
        // that precedes the segment. Whichever of the two is known and
        // smaller wins — a header claiming a fixed size larger than the space
        // it sits in is describing a filesystem that cannot fit.
        let room = partition_len
            .or_else(|| {
                device
                    .len()
                    .and_then(|d| d.checked_sub(partition_offset))
            })
            .and_then(|p| p.checked_sub(seg.offset));

        let segment_len = match (seg.size, room) {
            (SegmentSize::Fixed(n), Some(r)) => Some(n.min(r)),
            (SegmentSize::Fixed(n), None) => Some(n),
            (SegmentSize::Dynamic, r) => r,
        };

        Ok(Self {
            device,
            partition_offset,
            segment_offset: seg.offset,
            segment_len,
            sector_size: seg.sector_size as usize,
            iv_tweak: seg.iv_tweak as u128,
            tweak_step: seg.tweak_step(),
            master_key,
        })
    }

    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// The device underneath, for callers that need to keep talking to it
    /// (a JNI handle asking the SCSI layer for its capacity, say).
    pub fn device(&self) -> &D {
        &self.device
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

#[cfg(feature = "dangerous-write-support")]
impl<D: crate::device::WriteAt> LuksVolume<D> {
    /// Write plaintext at `offset` bytes from the start of the decrypted
    /// volume.
    ///
    /// # Why this reads before it writes
    ///
    /// XTS encrypts a whole cipher sector as a unit — the tweak covers the
    /// entire block, so there is no such thing as encrypting 100 bytes of one.
    /// A write that does not cover whole sectors therefore has to fetch them,
    /// decrypt, patch the plaintext, re-encrypt and put them back.
    ///
    /// That makes an unaligned write **destructive to bytes the caller never
    /// mentioned** if it is interrupted: the surrounding plaintext has been
    /// decrypted and is on its way back out. Callers that care — which means
    /// any filesystem writer — should align their requests to
    /// [`LuksVolume::sector_size`] so this path is never taken. The aligned
    /// case reads nothing at all.
    ///
    /// # Ordering
    ///
    /// This does not flush. Deciding *when* bytes must be durable is the
    /// filesystem's job, not the cipher's: metadata that reaches the medium
    /// before the data it points at describes blocks that were never written.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
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
        let skip = (offset - first_sector * ss) as usize;
        let aligned = skip == 0 && span == buf.len();

        let disk_offset = self
            .partition_offset
            .checked_add(self.segment_offset)
            .and_then(|o| o.checked_add(first_sector * ss))
            .ok_or(LuksError::OutOfBounds)?;

        let mut scratch = vec![0u8; span];
        if aligned {
            scratch.copy_from_slice(buf);
        } else {
            // Fetch the covering sectors and decrypt them, so the bytes
            // around the caller's range survive re-encryption unchanged.
            self.device.read_at(disk_offset, &mut scratch)?;
            xts_decrypt(
                self.master_key.expose(),
                &mut scratch,
                self.sector_size,
                self.iv_tweak + first_sector as u128 * self.tweak_step,
                self.tweak_step,
            )?;
            scratch[skip..skip + buf.len()].copy_from_slice(buf);
        }

        xts_encrypt(
            self.master_key.expose(),
            &mut scratch,
            self.sector_size,
            self.iv_tweak + first_sector as u128 * self.tweak_step,
            self.tweak_step,
        )?;
        self.device.write_at(disk_offset, &scratch)
    }

    /// Push everything written so far to the medium.
    pub fn flush(&self) -> Result<()> {
        self.device.flush()
    }
}

/// Lets the filesystem layer write straight through the encryption layer.
#[cfg(feature = "dangerous-write-support")]
impl<D: crate::device::WriteAt> crate::device::WriteAt for LuksVolume<D> {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        LuksVolume::write_at(self, offset, buf)
    }

    fn flush(&self) -> Result<()> {
        LuksVolume::flush(self)
    }
}

/// Lets the filesystem layer read straight through the decryption layer.
impl<D: ReadAt> ReadAt for LuksVolume<D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        LuksVolume::read_at(self, offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.segment_len
    }
}
