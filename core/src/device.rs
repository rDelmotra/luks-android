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

/// Lets a reference stand in for the thing it points at.
///
/// This is what makes the owning layers above (`LuksVolume<D>`, `Ext4<D>`)
/// usable both ways. A test passes `&image` and gets `D = &Vec<u8>`, borrowing;
/// the JNI layer passes the device by value and gets a `'static` type with no
/// self-reference, which is the only shape that can live behind a raw handle
/// without `unsafe`.
impl<D: ReadAt + ?Sized> ReadAt for &D {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        (**self).len()
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

/// A file or block device on the host, read without loading it into memory.
///
/// This is how a desktop shell will read `/dev/sdX`, and how a multi-gigabyte
/// disk image is checked. Android never uses it — there the bytes arrive over
/// SCSI from [`crate::usb`].
///
/// Positional reads (`pread`) rather than seek-then-read, so `&self` is enough
/// and no interior mutability or locking is needed.
#[derive(Debug)]
pub struct FileDevice {
    file: std::fs::File,
    path: String,
    len: Option<u64>,
}

impl FileDevice {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let file = std::fs::File::open(path).map_err(|source| LuksError::Io {
            path: display.clone(),
            source,
        })?;
        // A regular file knows its length. A raw block device often reports 0
        // from `metadata()`, so treat 0 as "unknown" rather than "empty" — the
        // difference matters, because `len()` gates bounds checks upstream.
        let len = match file.metadata() {
            Ok(m) if m.len() > 0 => Some(m.len()),
            _ => None,
        };
        Ok(Self {
            file,
            path: display,
            len,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl ReadAt for FileDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file
                .read_exact_at(buf, offset)
                .map_err(|source| LuksError::Io {
                    path: self.path.clone(),
                    source,
                })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            let mut done = 0usize;
            while done < buf.len() {
                match self.file.seek_read(&mut buf[done..], offset + done as u64) {
                    // A short read of zero means EOF: the caller asked for more
                    // than exists, which is an error, not a partial success.
                    Ok(0) => {
                        return Err(LuksError::Io {
                            path: self.path.clone(),
                            source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                        })
                    }
                    Ok(n) => done += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(source) => {
                        return Err(LuksError::Io {
                            path: self.path.clone(),
                            source,
                        })
                    }
                }
            }
            Ok(())
        }
    }

    fn len(&self) -> Option<u64> {
        self.len
    }
}
