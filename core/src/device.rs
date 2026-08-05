//! Random-access byte source.
//!
//! Everything above this layer reads through `ReadAt`, so the LUKS and
//! filesystem code is identical whether the bytes come from a test image, a USB
//! device over SCSI (Phase 1), or a Windows physical drive later.

use crate::error::{LuksError, Result};

/// A byte sink that can be written at an arbitrary offset.
///
/// **Only exists with the `dangerous-write-support` feature.** That is the
/// whole point: a default build cannot corrupt a drive because there is no
/// code path that writes one — not "we are careful", but "the instruction is
/// not in the binary". Keep it that way.
///
/// `: ReadAt` is a real requirement, not tidiness. Encryption works in whole
/// cipher sectors and filesystems in whole blocks, so writing anything smaller
/// or misaligned means read-modify-write: fetch the covering range, patch the
/// middle, put it back. A sink that cannot be read cannot be safely written.
#[cfg(feature = "dangerous-write-support")]
pub trait WriteAt: ReadAt {
    /// Write all of `buf` at `offset`. Short writes are an error.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Push everything to the medium.
    ///
    /// Separate from `write_at` because ordering is what makes a filesystem
    /// survivable: metadata that lands before the data it points at describes
    /// blocks that were never written. Callers are expected to flush at the
    /// points where an interruption must still leave something consistent.
    fn flush(&self) -> Result<()>;
}

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

/// The write-side mirror of the blanket `impl ReadAt for &D`, for the same
/// reason: callers pass `&device`, and without this every one of them would
/// have to hand over ownership just to write a byte.
#[cfg(feature = "dangerous-write-support")]
impl<D: WriteAt + ?Sized> WriteAt for &D {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        (**self).write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        (**self).flush()
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
    /// Whether the descriptor was opened for writing.
    ///
    /// Belt and braces. The kernel is the real enforcement — a descriptor from
    /// [`FileDevice::open`] is `O_RDONLY` and `pwrite` on it returns `EBADF`
    /// whatever this crate believes — but a flag lets the error say *why*
    /// instead of surfacing a bare errno, and it makes the intent visible at
    /// the call site rather than only in the file mode.
    writable: bool,
}

impl FileDevice {
    /// Open for reading. The descriptor is `O_RDONLY`, so the **kernel**
    /// refuses writes regardless of what this crate does — which is what makes
    /// pointing the reader at a real drive safe as a property rather than a
    /// promise. Use [`FileDevice::open_writable`] to opt out, deliberately.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Open for reading **and writing**.
    ///
    /// Gated behind `dangerous-write-support` so that a default build cannot
    /// call it at all. Everything about the read path's safety argument rests
    /// on `core` having no way to obtain a writable descriptor; this is that
    /// way, and it is compiled out unless asked for by name.
    #[cfg(feature = "dangerous-write-support")]
    pub fn open_writable<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    /// [`FileDevice::open_writable`], but refusing to open unless
    /// `confirmation` matches what the OS actually reports for `path`.
    ///
    /// This is the entry point every tool and every real-hardware write
    /// should use — see [`crate::device_guard`] for what it catches (a stale
    /// or renumbered device path) and what it deliberately does not (writing
    /// to a partition of the disk the OS itself is running from). Tests that
    /// only ever target scratch files they created themselves have no
    /// renumbering risk and can keep using the plain [`FileDevice::open_writable`].
    #[cfg(feature = "dangerous-write-support")]
    pub fn open_writable_confirmed<P: AsRef<std::path::Path>>(
        path: P,
        confirmation: &crate::device_guard::TargetConfirmation,
    ) -> Result<Self> {
        crate::device_guard::check(path.as_ref(), confirmation)?;
        Self::open_writable(path)
    }

    fn open_inner(path: &std::path::Path, writable: bool) -> Result<Self> {
        let display = path.display().to_string();
        let opened = if writable {
            std::fs::OpenOptions::new().read(true).write(true).open(path)
        } else {
            std::fs::File::open(path)
        };
        let file = opened.map_err(|source| LuksError::Io {
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
            writable,
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

    /// [`FileDevice::open_writable`] with the alignment forced, for the same
    /// reason as [`FileDevice::open_with_alignment`]: the read-modify-write
    /// path a raw device needs is otherwise untestable without root.
    #[cfg(feature = "dangerous-write-support")]
    pub fn open_writable_with_alignment<P: AsRef<std::path::Path>>(
        path: P,
        align: u64,
    ) -> Result<Self> {
        let mut dev = Self::open_writable(path)?;
        dev.align = align;
        Ok(dev)
    }

    /// [`FileDevice::open_writable_confirmed`] with the alignment forced —
    /// what a real raw device write needs, since a raw character device
    /// (`/dev/rdiskN` on macOS) requires the widened-read/read-modify-write
    /// path already used for reads.
    #[cfg(feature = "dangerous-write-support")]
    pub fn open_writable_confirmed_with_alignment<P: AsRef<std::path::Path>>(
        path: P,
        align: u64,
        confirmation: &crate::device_guard::TargetConfirmation,
    ) -> Result<Self> {
        crate::device_guard::check(path.as_ref(), confirmation)?;
        let mut dev = Self::open_writable(path)?;
        dev.align = align;
        Ok(dev)
    }

    pub fn is_writable(&self) -> bool {
        self.writable
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


    /// One positional write, looping until everything lands.
    #[cfg(all(unix, feature = "dangerous-write-support"))]
    fn pwrite_all(&self, offset: u64, buf: &[u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            match self.file.write_at(&buf[done..], offset + done as u64) {
                // Zero written with bytes remaining is not progress; looping
                // would spin forever, so treat it as the failure it is.
                Ok(0) => {
                    return Err(LuksError::Io {
                        path: self.path.clone(),
                        source: std::io::Error::from(std::io::ErrorKind::WriteZero),
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

    /// Read-modify-write, so a raw character device only ever sees aligned
    /// offsets and lengths.
    ///
    /// The read half is not optional and not an optimisation: the device will
    /// not accept a partial block, so the bytes surrounding the caller's range
    /// have to be fetched and written back unchanged. Which means **a failure
    /// between the read and the write can lose data the caller never touched**
    /// — the reason writes get their own feature gate, and the reason a
    /// filesystem writer should align its own requests rather than leaning on
    /// this.
    #[cfg(all(unix, feature = "dangerous-write-support"))]
    fn write_widened(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let a = self.align;
        let start = offset / a * a;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?
            .div_ceil(a)
            * a;
        let skip = (offset - start) as usize;

        // Already aligned: no surrounding bytes exist, so no read is needed
        // and the hazard above does not apply.
        if skip == 0 && (buf.len() as u64).is_multiple_of(a) {
            return self.pwrite_all(offset, buf);
        }

        let mut scratch = vec![0u8; (end - start) as usize];
        let got = self.pread(start, &mut scratch)?;
        // A short read means the tail runs past the end of the device. Writing
        // the zero padding back would extend or corrupt it, so refuse rather
        // than guess.
        self.check(got, scratch.len())?;
        scratch[skip..skip + buf.len()].copy_from_slice(buf);
        self.pwrite_all(start, &scratch)
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

#[cfg(feature = "dangerous-write-support")]
impl WriteAt for FileDevice {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if !self.writable {
            // The kernel would refuse this anyway (EBADF on an O_RDONLY
            // descriptor). Saying so here turns a bare errno into a sentence
            // that names the mistake.
            return Err(LuksError::Io {
                path: self.path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "device was opened read-only; use FileDevice::open_writable",
                ),
            });
        }
        if buf.is_empty() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            if self.align == 0 {
                return self.pwrite_all(offset, buf);
            }
            self.write_widened(offset, buf)
        }
        #[cfg(not(unix))]
        {
            let _ = offset;
            Err(LuksError::Io {
                path: self.path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "writing is implemented for unix only so far",
                ),
            })
        }
    }

    fn flush(&self) -> Result<()> {
        // `sync_data`, not `sync_all`: the file's contents must reach the
        // medium, but its mtime need not. On a block device they are the same
        // call; on a regular image file this skips a metadata round trip.
        self.file.sync_data().map_err(|source| LuksError::Io {
            path: self.path.clone(),
            source,
        })
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
