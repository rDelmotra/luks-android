//! Random-access byte source.
//!
//! Everything above this layer reads through `ReadAt`, so the LUKS and
//! filesystem code is identical whether the bytes come from a test image, a USB
//! device over SCSI (Phase 1), or a Windows physical drive later.

use crate::error::{LuksError, Result};

pub trait ReadAt {
    /// Fill `buf` with bytes starting at `offset`. Short reads are an error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Total readable length, if known. A USB block device knows it; a stream
    /// being fed to us might not.
    fn len(&self) -> Option<u64> {
        None
    }

    /// `None` when the length is unknown, rather than guessing.
    fn is_empty(&self) -> Option<bool> {
        self.len().map(|n| n == 0)
    }
}

impl ReadAt for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| LuksError::Truncated {
            needed: usize::MAX,
            got: self.len(),
        })?;
        let end = start
            .checked_add(buf.len())
            .ok_or(LuksError::Truncated {
                needed: usize::MAX,
                got: self.len(),
            })?;
        if end > self.len() {
            return Err(LuksError::Truncated {
                needed: end,
                got: self.len(),
            });
        }
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }

    fn len(&self) -> Option<u64> {
        Some(<[u8]>::len(self) as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.as_slice().read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        Some(Vec::len(self) as u64)
    }
}
