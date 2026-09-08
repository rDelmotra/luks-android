//! In-Memory Device implementation for fast, zero-I/O property testing.
//!
//! Provides [`MemoryDevice`], wrapping an `Arc<RwLock<Vec<u8>>>`. Implements
//! both [`ReadAt`] and [`WriteAt`] without touching disk, allowing thousands
//! of B-tree mutations per second during permutation and stress tests.
//!
//! Snapshot states can be exported to disk via [`MemoryDevice::dump_to_file`]
//! at milestone points to allow real Linux kernel verification (`verify-btrfs.sh`).

#![allow(dead_code)]

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use luks_core::device::ReadAt;
#[cfg(feature = "dangerous-write-support")]
use luks_core::device::WriteAt;
use luks_core::error::{LuksError, Result};

#[derive(Clone, Default, Debug)]
pub struct MemoryDevice {
    data: Arc<RwLock<Vec<u8>>>,
}

impl MemoryDevice {
    /// Create a new in-memory device filled with zeroes.
    pub fn new(size_bytes: usize) -> Self {
        Self {
            data: Arc::new(RwLock::new(vec![0u8; size_bytes])),
        }
    }

    /// Create a memory device initialized with the provided byte vector.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            data: Arc::new(RwLock::new(bytes)),
        }
    }

    /// Load a fixture directly into memory from `fixtures/<rel_path>`.
    pub fn from_fixture(rel_path: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("fixtures")
            .join(rel_path);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {:?}: {}", path, e));
        Self::from_bytes(bytes)
    }

    /// Dump the current in-memory contents to a disk file for kernel oracle checks.
    pub fn dump_to_file(&self, path: &Path) -> std::io::Result<()> {
        let guard = self.data.read().expect("lock poison");
        let mut file = File::create(path)?;
        file.write_all(&guard)?;
        file.sync_all()
    }

    /// Get a snapshot copy of the current in-memory buffer.
    pub fn snapshot(&self) -> Vec<u8> {
        self.data.read().expect("lock poison").clone()
    }

    /// Total byte length.
    pub fn len(&self) -> usize {
        self.data.read().expect("lock poison").len()
    }

    /// Whether the device is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReadAt for MemoryDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let guard = self.data.read().expect("lock poison");
        let start = usize::try_from(offset).map_err(|_| LuksError::Truncated {
            needed: usize::MAX,
            got: guard.len(),
        })?;
        let end = start
            .checked_add(buf.len())
            .ok_or(LuksError::Truncated {
                needed: usize::MAX,
                got: guard.len(),
            })?;

        if end > guard.len() {
            return Err(LuksError::Truncated {
                needed: end,
                got: guard.len(),
            });
        }

        buf.copy_from_slice(&guard[start..end]);
        Ok(())
    }

    fn len(&self) -> Option<u64> {
        let guard = self.data.read().expect("lock poison");
        Some(guard.len() as u64)
    }
}

#[cfg(feature = "dangerous-write-support")]
impl WriteAt for MemoryDevice {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut guard = self.data.write().expect("lock poison");
        let start = usize::try_from(offset).map_err(|_| LuksError::OutOfBounds)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(LuksError::OutOfBounds)?;

        // Auto-expand memory buffer if writing beyond current bounds
        if end > guard.len() {
            guard.resize(end, 0);
        }

        guard[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}
