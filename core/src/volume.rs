//! Plain (non-LUKS) volume and source abstractions.
//!
//! Provides [`PlainVolume`], representing an unencrypted partition on an underlying device,
//! and [`VolumeSource`], abstracting over encrypted ([`LuksVolume`]) and unencrypted
//! volumes at open time.

use crate::device::ReadAt;
#[cfg(feature = "dangerous-write-support")]
use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::luks::LuksVolume;

/// An unencrypted partition volume on an underlying device.
///
/// Unlike LUKS containers which may have dynamic segment sizes, a plain volume's
/// length is always known and fixed from the partition table (Invariant 4).
pub struct PlainVolume<D: ReadAt> {
    device: D,
    partition_offset: u64,
    len: u64,
}

impl<D: ReadAt> PlainVolume<D> {
    /// Create a new `PlainVolume` after validating bounds.
    ///
    /// Refuses `len == 0`, overflow in `partition_offset + len`, and spans exceeding
    /// the underlying device length (if known) with [`LuksError::OutOfBounds`].
    pub fn new(device: D, partition_offset: u64, len: u64) -> Result<Self> {
        if len == 0 {
            return Err(LuksError::OutOfBounds);
        }
        let partition_end = partition_offset
            .checked_add(len)
            .ok_or(LuksError::OutOfBounds)?;
        if let Some(dev_len) = device.len() {
            if partition_end > dev_len {
                return Err(LuksError::OutOfBounds);
            }
        }
        Ok(Self {
            device,
            partition_offset,
            len,
        })
    }

    /// Offset of the partition in bytes from the start of the underlying device.
    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    /// Length of the partition in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the volume is empty (always `false` since `len > 0` is strictly enforced).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reference to the underlying device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Consume the volume and return the underlying device.
    pub fn into_device(self) -> D {
        self.device
    }

    /// Read bytes at `offset` relative to the partition start.
    ///
    /// Strictly checked against `self.len`. Slices into `self.device.read_at`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if end > self.len {
            return Err(LuksError::OutOfBounds);
        }
        if buf.is_empty() {
            return Ok(());
        }
        let dev_offset = self
            .partition_offset
            .checked_add(offset)
            .ok_or(LuksError::OutOfBounds)?;
        self.device.read_at(dev_offset, buf)
    }
}

#[cfg(feature = "dangerous-write-support")]
impl<D: WriteAt> PlainVolume<D> {
    /// Write bytes at `offset` relative to the partition start.
    ///
    /// Strictly checked against `self.len`. Slices into `self.device.write_at`.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if end > self.len {
            return Err(LuksError::OutOfBounds);
        }
        let dev_offset = self
            .partition_offset
            .checked_add(offset)
            .ok_or(LuksError::OutOfBounds)?;
        self.device.write_at(dev_offset, buf)
    }

    /// Push everything written so far to the medium.
    pub fn flush(&self) -> Result<()> {
        self.device.flush()
    }
}

impl<D: ReadAt> ReadAt for PlainVolume<D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        PlainVolume::read_at(self, offset, buf)
    }

    fn len(&self) -> Option<u64> {
        Some(self.len)
    }
}

#[cfg(feature = "dangerous-write-support")]
impl<D: WriteAt> WriteAt for PlainVolume<D> {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        PlainVolume::write_at(self, offset, buf)
    }

    fn flush(&self) -> Result<()> {
        PlainVolume::flush(self)
    }
}

impl<D: ReadAt> std::fmt::Debug for PlainVolume<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainVolume")
            .field("partition_offset", &self.partition_offset)
            .field("len", &self.len)
            .finish()
    }
}

/// Where a mounted filesystem's bytes come from. Decided once, at open time.
pub enum VolumeSource<D: ReadAt> {
    Luks(LuksVolume<D>),
    Plain(PlainVolume<D>),
}

impl<D: ReadAt> VolumeSource<D> {
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Luks(v) => v.read_at(offset, buf),
            Self::Plain(v) => v.read_at(offset, buf),
        }
    }

    pub fn len(&self) -> Option<u64> {
        match self {
            Self::Luks(v) => v.len(),
            Self::Plain(v) => Some(v.len()),
        }
    }

    pub fn is_empty(&self) -> Option<bool> {
        match self {
            Self::Luks(v) => v.is_empty(),
            Self::Plain(v) => Some(v.is_empty()),
        }
    }

    #[cfg(feature = "dangerous-write-support")]
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()>
    where
        D: WriteAt,
    {
        match self {
            Self::Luks(v) => v.write_at(offset, buf),
            Self::Plain(v) => v.write_at(offset, buf),
        }
    }

    #[cfg(feature = "dangerous-write-support")]
    pub fn flush(&self) -> Result<()>
    where
        D: WriteAt,
    {
        match self {
            Self::Luks(v) => v.flush(),
            Self::Plain(v) => v.flush(),
        }
    }
}

impl<D: ReadAt> ReadAt for VolumeSource<D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        VolumeSource::read_at(self, offset, buf)
    }

    fn len(&self) -> Option<u64> {
        VolumeSource::len(self)
    }
}

#[cfg(feature = "dangerous-write-support")]
impl<D: WriteAt> WriteAt for VolumeSource<D> {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        VolumeSource::write_at(self, offset, buf)
    }

    fn flush(&self) -> Result<()> {
        VolumeSource::flush(self)
    }
}

impl<D: ReadAt> From<LuksVolume<D>> for VolumeSource<D> {
    fn from(vol: LuksVolume<D>) -> Self {
        Self::Luks(vol)
    }
}

impl<D: ReadAt> From<PlainVolume<D>> for VolumeSource<D> {
    fn from(vol: PlainVolume<D>) -> Self {
        Self::Plain(vol)
    }
}

impl<D: ReadAt> std::fmt::Debug for VolumeSource<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Luks(_) => f.debug_tuple("Luks").finish(),
            Self::Plain(p) => f.debug_tuple("Plain").field(p).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::FileDevice;
    use crate::fs::MountedFs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SpyDevice {
        data: std::sync::RwLock<Vec<u8>>,
        read_calls: AtomicUsize,
        bytes_read: AtomicUsize,
        #[cfg(feature = "dangerous-write-support")]
        write_calls: AtomicUsize,
        #[cfg(feature = "dangerous-write-support")]
        bytes_written: AtomicUsize,
        #[cfg(feature = "dangerous-write-support")]
        flush_calls: AtomicUsize,
    }

    impl SpyDevice {
        fn new(size: usize) -> Self {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            Self {
                data: std::sync::RwLock::new(data),
                read_calls: AtomicUsize::new(0),
                bytes_read: AtomicUsize::new(0),
                #[cfg(feature = "dangerous-write-support")]
                write_calls: AtomicUsize::new(0),
                #[cfg(feature = "dangerous-write-support")]
                bytes_written: AtomicUsize::new(0),
                #[cfg(feature = "dangerous-write-support")]
                flush_calls: AtomicUsize::new(0),
            }
        }
    }

    impl ReadAt for SpyDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.read_calls.fetch_add(1, Ordering::SeqCst);
            self.bytes_read.fetch_add(buf.len(), Ordering::SeqCst);
            let guard = self.data.read().expect("lock poison");
            guard.read_at(offset, buf)
        }

        fn len(&self) -> Option<u64> {
            let guard = self.data.read().expect("lock poison");
            Some(guard.len() as u64)
        }
    }

    #[cfg(feature = "dangerous-write-support")]
    impl WriteAt for SpyDevice {
        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            if buf.is_empty() {
                return Ok(());
            }
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            self.bytes_written.fetch_add(buf.len(), Ordering::SeqCst);
            let mut guard = self.data.write().expect("lock poison");
            let start = usize::try_from(offset).map_err(|_| LuksError::OutOfBounds)?;
            let end = start.checked_add(buf.len()).ok_or(LuksError::OutOfBounds)?;
            if end > guard.len() {
                return Err(LuksError::OutOfBounds);
            }
            guard[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            self.flush_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct UnknownLenDevice(Vec<u8>);

    impl ReadAt for UnknownLenDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.0.read_at(offset, buf)
        }

        fn len(&self) -> Option<u64> {
            None
        }
    }

    #[test]
    fn new_rejects_zero_length_volume() {
        let dev = SpyDevice::new(1024);
        let err = PlainVolume::new(&dev, 0, 0).unwrap_err();
        assert!(matches!(err, LuksError::OutOfBounds));
    }

    #[test]
    fn new_rejects_offset_and_len_overflow() {
        let dev = SpyDevice::new(1024);
        let err = PlainVolume::new(&dev, u64::MAX - 5, 10).unwrap_err();
        assert!(matches!(err, LuksError::OutOfBounds));

        let unknown = UnknownLenDevice(vec![0u8; 100]);
        let err2 = PlainVolume::new(&unknown, u64::MAX, 1).unwrap_err();
        assert!(matches!(err2, LuksError::OutOfBounds));
    }

    #[test]
    fn new_rejects_span_exceeding_known_device_len() {
        let dev = SpyDevice::new(100);
        let err = PlainVolume::new(&dev, 50, 51).unwrap_err();
        assert!(matches!(err, LuksError::OutOfBounds));

        // Exactly fitting is permitted
        let ok = PlainVolume::new(&dev, 50, 50);
        assert!(ok.is_ok());

        // Unknown device length does not fail device length check
        let unknown = UnknownLenDevice(vec![0u8; 100]);
        let ok_unknown = PlainVolume::new(&unknown, 50, 500);
        assert!(ok_unknown.is_ok());
    }

    #[test]
    fn read_at_slices_into_device_and_respects_partition_offset() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");
        assert_eq!(vol.partition_offset(), 100);
        assert_eq!(vol.len(), 200);
        assert!(!vol.is_empty());
        assert_eq!(<PlainVolume<&SpyDevice> as ReadAt>::len(&vol), Some(200));

        let mut buf = [0u8; 15];
        vol.read_at(10, &mut buf).expect("read within volume");

        // Bytes read should match dev.data[110..125]
        assert_eq!(&buf[..], &dev.data.read().unwrap()[110..125]);
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 1);
        assert_eq!(dev.bytes_read.load(Ordering::SeqCst), 15);
    }

    #[test]
    fn read_crossing_boundary_returns_out_of_bounds_and_issues_zero_device_io() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");

        // Reset spy counters
        dev.read_calls.store(0, Ordering::SeqCst);
        dev.bytes_read.store(0, Ordering::SeqCst);

        let mut buf = [0u8; 10];

        // 1. Reading partially past the volume end (195 + 10 = 205 > 200)
        let err1 = vol.read_at(195, &mut buf).unwrap_err();
        assert!(matches!(err1, LuksError::OutOfBounds));
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_read.load(Ordering::SeqCst), 0);

        // 2. Reading exactly starting at the volume end (200 + 1 = 201 > 200)
        let mut single_byte = [0u8; 1];
        let err2 = vol.read_at(200, &mut single_byte).unwrap_err();
        assert!(matches!(err2, LuksError::OutOfBounds));
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_read.load(Ordering::SeqCst), 0);

        // 3. Offset overflow (u64::MAX + 1)
        let err3 = vol.read_at(u64::MAX, &mut single_byte).unwrap_err();
        assert!(matches!(err3, LuksError::OutOfBounds));
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_read.load(Ordering::SeqCst), 0);

        // 4. Zero-length read at the boundary (offset 200, 0 bytes) is valid
        assert!(vol.read_at(200, &mut []).is_ok());
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 0);

        // 5. Zero-length read beyond the boundary (offset 201, 0 bytes) is OutOfBounds
        let err4 = vol.read_at(201, &mut []).unwrap_err();
        assert!(matches!(err4, LuksError::OutOfBounds));
        assert_eq!(dev.read_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn byte_identical_plain_btrfs_fixture() {
        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("fixtures")
            .join("btrfs")
            .join("plain.img");

        let dev_direct = FileDevice::open(&fixture_path).expect("open fixture directly");
        let fs_direct = MountedFs::mount(dev_direct).expect("mount directly");

        let dev_plain = FileDevice::open(&fixture_path).expect("open fixture for plain volume");
        let img_len = dev_plain.len().expect("device len must be known");
        let plain_vol = PlainVolume::new(dev_plain, 0, img_len).expect("create plain volume");
        let source = VolumeSource::Plain(plain_vol);
        let fs_plain = MountedFs::mount(source).expect("mount via VolumeSource::Plain");

        // Verify filesystem-level properties match
        assert_eq!(fs_direct.kind(), fs_plain.kind());
        assert_eq!(fs_direct.label(), fs_plain.label());
        assert_eq!(fs_direct.uuid(), fs_plain.uuid());
        assert_eq!(fs_direct.block_size(), fs_plain.block_size());
        assert_eq!(fs_direct.size_bytes(), fs_plain.size_bytes());

        // Verify root directory listing matches
        let direct_entries = fs_direct.list_dir("/").expect("list direct root");
        let plain_entries = fs_plain.list_dir("/").expect("list plain root");
        assert_eq!(direct_entries.len(), plain_entries.len());

        for (d, p) in direct_entries.iter().zip(plain_entries.iter()) {
            assert_eq!(d.name, p.name);
            assert_eq!(d.file_type, p.file_type);
            assert_eq!(d.size, p.size);
            assert_eq!(d.mtime, p.mtime);
            assert_eq!(d.is_subvolume, p.is_subvolume);

            if d.file_type.is_file() {
                let path = format!("/{}", d.name);
                let content_direct = fs_direct.read_file(&path).expect("read direct file");
                let content_plain = fs_plain.read_file(&path).expect("read plain file");
                assert_eq!(
                    content_direct, content_plain,
                    "content mismatch for file {path}"
                );
            }
        }

        // Also test a known file and sub-directory in plain.img
        let hello_direct = fs_direct.read_file("/hello.txt").expect("read /hello.txt direct");
        let hello_plain = fs_plain.read_file("/hello.txt").expect("read /hello.txt plain");
        assert_eq!(hello_direct, hello_plain);

        let docs_direct = fs_direct.list_dir("/docs").expect("list /docs direct");
        let docs_plain = fs_plain.list_dir("/docs").expect("list /docs plain");
        assert_eq!(docs_direct.len(), docs_plain.len());
        for (d, p) in docs_direct.iter().zip(docs_plain.iter()) {
            assert_eq!(d.name, p.name);
            assert_eq!(d.size, p.size);
            if d.file_type.is_file() {
                let path = format!("/docs/{}", d.name);
                let content_direct = fs_direct.read_file(&path).expect("read docs direct file");
                let content_plain = fs_plain.read_file(&path).expect("read docs plain file");
                assert_eq!(content_direct, content_plain);
            }
        }
    }

    #[cfg(feature = "dangerous-write-support")]
    #[test]
    fn plain_volume_bounded_writes() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");

        // Write within partition bounds modifies device bytes at correct physical offset
        let payload = b"bounded write works";
        vol.write_at(20, payload).expect("write within volume");

        assert_eq!(dev.write_calls.load(Ordering::SeqCst), 1);
        assert_eq!(dev.bytes_written.load(Ordering::SeqCst), payload.len());

        let physical_start = 100 + 20;
        let physical_end = physical_start + payload.len();
        assert_eq!(
            &dev.data.read().unwrap()[physical_start..physical_end],
            payload
        );

        // Zero-length write within bounds / at boundary is a no-op that returns Ok(())
        vol.write_at(200, &[]).expect("zero-length write at boundary");
        assert_eq!(dev.write_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "dangerous-write-support")]
    #[test]
    fn plain_volume_boundary_guard() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");

        dev.write_calls.store(0, Ordering::SeqCst);
        dev.bytes_written.store(0, Ordering::SeqCst);

        // 1. Partially crossing boundary (195 + 10 = 205 > 200)
        let err1 = vol.write_at(195, &[0xAA; 10]).unwrap_err();
        assert!(matches!(err1, LuksError::OutOfBounds));
        assert_eq!(dev.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_written.load(Ordering::SeqCst), 0);

        // 2. Writing starting at boundary (200 + 1 = 201 > 200)
        let err2 = vol.write_at(200, &[0xBB]).unwrap_err();
        assert!(matches!(err2, LuksError::OutOfBounds));
        assert_eq!(dev.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_written.load(Ordering::SeqCst), 0);

        // 3. Offset overflow (u64::MAX)
        let err3 = vol.write_at(u64::MAX, &[0xCC]).unwrap_err();
        assert!(matches!(err3, LuksError::OutOfBounds));
        assert_eq!(dev.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(dev.bytes_written.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "dangerous-write-support")]
    #[test]
    fn plain_volume_flush_forwards_to_device() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");

        assert_eq!(dev.flush_calls.load(Ordering::SeqCst), 0);
        vol.flush().expect("inherent flush");
        assert_eq!(dev.flush_calls.load(Ordering::SeqCst), 1);

        WriteAt::flush(&vol).expect("trait flush");
        assert_eq!(dev.flush_calls.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "dangerous-write-support")]
    #[test]
    fn volume_source_plain_dispatches_writes_and_flush() {
        let dev = SpyDevice::new(500);
        let vol = PlainVolume::new(&dev, 100, 200).expect("create volume");
        let source = VolumeSource::Plain(vol);

        source.write_at(10, b"dispatched").expect("source write");
        assert_eq!(&dev.data.read().unwrap()[110..120], b"dispatched");

        source.flush().expect("source flush");
        assert_eq!(dev.flush_calls.load(Ordering::SeqCst), 1);

        WriteAt::write_at(&source, 30, b"trait_write").expect("source trait write");
        assert_eq!(&dev.data.read().unwrap()[130..141], b"trait_write");

        WriteAt::flush(&source).expect("source trait flush");
        assert_eq!(dev.flush_calls.load(Ordering::SeqCst), 2);
    }
}
