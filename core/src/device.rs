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

/// Alignment assumed for raw character devices.
///
/// The real requirement is the device's logical block size, which would need an
/// ioctl (`DKIOCGETBLOCKSIZE` on macOS, `BLKSSZGET` on Linux) and therefore
/// `unsafe` — which this crate forbids. 4096 is a safe over-estimate: it is a
/// multiple of every block size in use, so an aligned read stays aligned, and
/// over-reading by at most 4 KiB costs nothing next to the syscall.
const RAW_ALIGN: u64 = 4096;

/// A file or block device on the host, read without loading it into memory.
///
/// This is how a desktop shell will read `/dev/sdX`, and how a multi-gigabyte
/// disk image is checked. Android never uses it — there the bytes arrive over
/// SCSI from [`crate::usb`].
///
/// Positional reads (`pread`) rather than seek-then-read, so `&self` is enough
/// and no interior mutability or locking is needed.
///
/// # Raw character devices
///
/// On macOS a disk appears twice: `/dev/diskN` goes through the buffer cache,
/// `/dev/rdiskN` is the raw character device. Measured on the developer's SSD,
/// the raw node is **5.4x faster** for large sequential reads (722 vs 132
/// MiB/s), because the buffered node copies every byte through the page cache
/// for data that is read exactly once. But the raw node will only accept reads
/// whose offset *and* length are block-aligned — an unaligned `pread` returns
/// `EINVAL`, and the LUKS header parse does several. So a character device gets
/// its reads widened to [`RAW_ALIGN`] and sliced back down.
#[derive(Debug)]
pub struct FileDevice {
    file: std::fs::File,
    path: String,
    len: Option<u64>,
    /// 0 for a regular file or buffered block device: reads pass through
    /// untouched. Non-zero for a raw character device.
    align: u64,
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
        let meta = file.metadata().ok();
        let len = match &meta {
            Some(m) if m.len() > 0 => Some(m.len()),
            _ => None,
        };
        let align = match &meta {
            #[cfg(unix)]
            Some(m) => {
                use std::os::unix::fs::FileTypeExt;
                if m.file_type().is_char_device() {
                    RAW_ALIGN
                } else {
                    0
                }
            }
            #[cfg(not(unix))]
            Some(_) => 0,
            None => 0,
        };
        Ok(Self {
            file,
            path: display,
            len,
            align,
        })
    }

    /// Open with the alignment forced rather than inferred.
    ///
    /// Exists because the widening path is otherwise untestable: creating a
    /// character device needs root, and `/dev/zero` returns the same byte at
    /// every offset, so it cannot prove the bounce buffer is *sliced* at the
    /// right place — only that it did not crash. Pointed at an ordinary
    /// fixture, this exercises the real arithmetic against known content.
    ///
    /// `align` must be a power of two; 0 disables widening.
    pub fn open_with_alignment<P: AsRef<std::path::Path>>(path: P, align: u64) -> Result<Self> {
        let mut dev = Self::open(path)?;
        dev.align = align;
        Ok(dev)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether reads are being widened to satisfy a raw character device.
    ///
    /// Exposed so a diagnostic can say which node it is talking to; nothing in
    /// the read path branches on it from outside.
    pub fn is_raw(&self) -> bool {
        self.align != 0
    }

    /// One positional read, returning how much it actually got.
    ///
    /// Short reads are normal here rather than an error: widening to
    /// [`RAW_ALIGN`] can push the tail of a read past the end of the device,
    /// and the caller checks whether the bytes it actually wanted arrived.
    #[cfg(unix)]
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        use std::os::unix::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            match self.file.read_at(&mut buf[done..], offset + done as u64) {
                Ok(0) => break,
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
        Ok(done)
    }

    /// Read through a bounce buffer so the device only ever sees aligned
    /// offsets and lengths.
    #[cfg(unix)]
    fn read_widened(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let a = self.align;
        let start = offset / a * a;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?
            .div_ceil(a)
            * a;
        let skip = (offset - start) as usize;

        // Already aligned both ways: read straight into the caller's buffer.
        // This is the common case once past the header — btrfs nodes are 16
        // KiB on 16 KiB boundaries and the data path reads whole sectors — so
        // the bounce allocation is paid only by the handful of odd-sized
        // header reads.
        if skip == 0 && (buf.len() as u64).is_multiple_of(a) {
            let got = self.pread(offset, buf)?;
            return self.check(got, buf.len());
        }

        let mut scratch = vec![0u8; (end - start) as usize];
        let got = self.pread(start, &mut scratch)?;
        self.check(got, skip + buf.len())?;
        buf.copy_from_slice(&scratch[skip..skip + buf.len()]);
        Ok(())
    }

    /// A read that stopped before covering the bytes the caller asked for is
    /// EOF; one that merely stopped before the alignment padding is fine.
    fn check(&self, got: usize, needed: usize) -> Result<()> {
        if got < needed {
            return Err(LuksError::Io {
                path: self.path.clone(),
                source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            });
        }
        Ok(())
    }
}

impl ReadAt for FileDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        #[cfg(unix)]
        {
            if self.align == 0 {
                use std::os::unix::fs::FileExt;
                return self
                    .file
                    .read_exact_at(buf, offset)
                    .map_err(|source| LuksError::Io {
                        path: self.path.clone(),
                        source,
                    });
            }
            self.read_widened(offset, buf)
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
