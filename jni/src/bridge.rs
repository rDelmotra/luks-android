//! Everything the JNI layer does, expressed without a single JNI type.
//!
//! `lib.rs` is deliberately thin — it converts Java values to Rust values, calls
//! in here, and converts back. That split exists so this half can be tested with
//! `cargo test` on the host: the tests below drive the same handles, the same
//! JSON and the same error codes the phone will, using a disk-image fixture in
//! place of a USB device.
//!
//! Two shapes matter here and are worth stating up front:
//!
//! * **Handles own their whole stack.** A `VolumeHandle` contains a
//!   [`MountedFs`] over `LuksVolume<SharedDevice>`, which is `'static` and
//!   self-contained. Both `Ext4` and `LuksVolume` were changed to own rather
//!   than borrow their device precisely so this type could exist without a
//!   self-referential struct.
//! * **The filesystem is chosen once, at unlock.** Mounting consumes the
//!   volume, so "try ext4, then btrfs" is not available — the volume is gone
//!   with the first attempt, and re-deriving it means running Argon2 again.
//!   [`luks_core::fs::detect`] settles it by signature first.
//! * **One lock at the bottom.** `SharedDevice` is the *only* handle to the
//!   transport, and it serialises every read. Two Java threads reading at once
//!   would otherwise interleave two SCSI command/data/status sequences on one
//!   bulk pipe and desynchronise the device.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use luks_core::device::ReadAt;
use luks_core::error::{LuksError, Result};
use luks_core::fs::FileType;
use luks_core::luks::{self, keyslot, LuksVolume};
use luks_core::partition::{self, PartitionTable, TableKind};
use luks_core::usb::ScsiBlockDevice;
use luks_usbfs::UsbFsTransport;

use serde_json::{json, Value};

/// Write-only volume operations live separately so the long-lived JNI bridge
/// stays navigable in read-only builds and while Pass 2b grows this boundary.
#[cfg(feature = "dangerous-write-support")]
mod writer;

// ---------------------------------------------------------------- error codes

/// Stable numeric error codes carried across JNI alongside the message.
///
/// Kotlin mirrors these in `LuksException.Code`. They exist so the UI can act
/// on `WRONG_PASSWORD` (offer a retry) without string-matching an error
/// message, which would break the moment a message is reworded.
///
/// Numbers are append-only: never renumber, never reuse.
pub mod code {
    pub const GENERIC: i32 = 1;
    pub const WRONG_PASSWORD: i32 = 2;
    pub const NOT_LUKS: i32 = 3;
    pub const UNSUPPORTED: i32 = 4;
    pub const CORRUPT: i32 = 5;
    pub const NOT_FOUND: i32 = 6;
    pub const TRANSPORT: i32 = 7;
    pub const NEEDS_FSCK: i32 = 8;
    pub const IO: i32 = 9;
    pub const BAD_HANDLE: i32 = 10;
    /// A Rust panic that `catch_unwind` intercepted. Always a bug in us.
    pub const PANIC: i32 = 11;
    /// The drive is out of space — or out of the space we can currently reach.
    pub const NO_SPACE: i32 = 12;
    /// A write target was not the device the caller said it was. Distinct
    /// from a permissions or I/O failure so the UI can say "wrong device"
    /// rather than a generic I/O message.
    pub const WRONG_TARGET: i32 = 13;
    /// A write target's size could not be probed at all. Split from
    /// `WRONG_TARGET` because the user's next step differs: 13 means "your
    /// byte count does not match this device", 14 means "this path cannot be
    /// checked — is it present and readable?".
    pub const UNVERIFIABLE_TARGET: i32 = 14;
    /// The name is already taken in that directory. Emphatically not
    /// `CORRUPT`, which is what this used to surface as: sending the same file
    /// twice is ordinary, and the UI's answer is "rename or replace", not
    /// "your filesystem is damaged".
    pub const ALREADY_EXISTS: i32 = 15;
    /// Another unlocked volume on this device holds the write claim. Split
    /// from `UNSUPPORTED`, which it used to share with "this volume is
    /// btrfs" — two refusals whose remedies have nothing in common, arriving
    /// at the UI as the same number.
    pub const WRITER_BUSY: i32 = 16;
    /// A single btrfs item was too large for a tree node. Split from
    /// `NO_SPACE`, which it used to share: on 2026-08-16 that made a 20 MB
    /// write on a drive with 676 MiB free tell the user their drive was full,
    /// and sent a day of investigation at the flash rather than at the leaf.
    /// The remedies are unrelated — 12 means "free something up", 17 means
    /// "this file's shape does not fit this filesystem's geometry".
    pub const ITEM_TOO_LARGE: i32 = 17;
    /// A previous write panicked, poisoning the volume mutex. Further writes
    /// on this volume handle are refused to protect disk state.
    pub const MUTEX_POISONED: i32 = 18;
    /// An operation was cancelled via cancellation token.
    pub const CANCELLED: i32 = 19;
}

pub fn error_code(e: &LuksError) -> i32 {
    use LuksError::*;
    match e {
        WrongPassword => code::WRONG_PASSWORD,
        BadMagic { .. } | NoPartitionTable => code::NOT_LUKS,
        UnsupportedVersion(_)
        | Luks1NotImplemented
        | UnsupportedChecksumAlg(_)
        | UnsupportedHash(_)
        | UnsupportedCipher(_)
        | UnsupportedDigest(_)
        | BadKeyLength(_)
        | BadSectorSize(_)
        | UnsupportedFsFeature(_)
        | NotExt4(_)
        | NotBtrfs(_)
        | UnknownFs
        | AmbiguousFs => code::UNSUPPORTED,
        FsNeedsRecovery => code::NEEDS_FSCK,
        FilesystemFull | NoFreeInodes => code::NO_SPACE,
        BtrfsItemTooLarge { .. } => code::ITEM_TOO_LARGE,
        AlreadyExists(_) => code::ALREADY_EXISTS,
        WriterBusy => code::WRITER_BUSY,
        WrongWriteTarget { .. } => code::WRONG_TARGET,
        UnverifiableWriteTarget { .. } => code::UNVERIFIABLE_TARGET,
        SessionPoisoned => code::MUTEX_POISONED,
        Cancelled => code::CANCELLED,
        NotFound(_) | NotADirectory(_) | IsADirectory(_) | BadInode(_) => code::NOT_FOUND,
        ScsiProtocol(_) | ScsiCommandFailed { .. } | UsbTransfer(_) => code::TRANSPORT,
        Io { .. } => code::IO,
        ChecksumMismatch
        | Truncated { .. }
        | ImplausibleHeaderSize(_)
        | JsonNotUtf8
        | JsonParse(_)
        | BadIntegerField { .. }
        | Missing(_)
        | BadExtentHeader(_)
        | BadExtentTree(_)
        | CorruptFs(_)
        | FsChecksumMismatch(_)
        | SymlinkLoop(_)
        | BadGpt(_)
        | OutOfBounds => code::CORRUPT,
        KdfFailed(_) => code::GENERIC,
    }
}

// -------------------------------------------------------------- shared device

/// The block device, shared between the device handle and any volume opened on
/// it, with every access serialised.
///
/// Cloning shares; it does not reopen. That is what lets a wrong password leave
/// the device handle usable for another attempt instead of forcing the app back
/// through USB permission.
///
/// # Why the trait object changes with the feature
///
/// With `dangerous-write-support` this holds a `dyn WriteAt`, not a
/// `dyn ReadAt`. Since `WriteAt: ReadAt`, every read path is unchanged and
/// keeps working through the same object. The alternative considered was a
/// second write-capable constructor beside this one, and rejected: a safety
/// property that holds only when the caller picks the right one of two doors
/// is decoration. Here a build either has the write path everywhere or does
/// not have it at all.
///
/// What this does **not** do is make "writable" a type-level fact.
/// `impl WriteAt for FileDevice` is unconditional and checks its own
/// `writable` flag at runtime, so a read-only `FileDevice` still satisfies the
/// bound and fails at the syscall instead of at compile time. The real gate on
/// writing a device is `FileDevice::open_writable` and its size confirmation;
/// this bound only decides whether the write path exists in the build.
#[derive(Clone)]
pub struct SharedDevice {
    inner: Arc<Mutex<dyn DeviceIo + Send>>,
    /// Whether some volume on this device has claimed the right to write.
    ///
    /// Shared by every clone, which is what makes it mean "this device"
    /// rather than "this handle". See [`VolumeHandle::write_file`] for why a
    /// device may have only one writer.
    writer: Arc<std::sync::atomic::AtomicBool>,
}

/// What a device must be able to do for this build: read only by default,
/// read *and* write when the write path is compiled in.
#[cfg(not(feature = "dangerous-write-support"))]
pub trait DeviceIo: ReadAt {}
#[cfg(not(feature = "dangerous-write-support"))]
impl<T: ReadAt + ?Sized> DeviceIo for T {}

#[cfg(feature = "dangerous-write-support")]
pub trait DeviceIo: luks_core::device::WriteAt {}
#[cfg(feature = "dangerous-write-support")]
impl<T: luks_core::device::WriteAt + ?Sized> DeviceIo for T {}

impl SharedDevice {
    pub fn new<D: DeviceIo + Send + 'static>(device: D) -> Self {
        SharedDevice {
            inner: Arc::new(Mutex::new(device)),
            writer: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A poisoned lock means some earlier call panicked mid-read. The device
    /// itself has no invariant we can corrupt — reads are stateless apart from
    /// the SCSI tag counter — so recovering the guard is better than turning
    /// every later call into a panic.
    // The `+ 'static` is not decoration: inside `Arc<Mutex<dyn ..>>` the elided
    // object lifetime defaults to 'static, but in a `MutexGuard<'_, dyn ..>`
    // return type it defaults to the guard's own lifetime. Spelling it out keeps
    // the two the same type.
    fn lock(&self) -> std::sync::MutexGuard<'_, dyn DeviceIo + Send + 'static> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ReadAt for SharedDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.lock().read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.lock().len()
    }
}

/// Writes go through the same single lock the reads do, for the same reason:
/// two Java threads interleaving on one bulk pipe desynchronise the device.
#[cfg(feature = "dangerous-write-support")]
impl luks_core::device::WriteAt for SharedDevice {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.lock().write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        self.lock().flush()
    }
}

// ------------------------------------------------------------------- handles

/// Every handle Java holds is a pointer to this one type, never to
/// `DeviceHandle` or `VolumeHandle` directly.
///
/// Handles are opaque `long`s on the Java side and nothing in the type system
/// stops `closeVolume(deviceHandle)`. The obvious defence — a magic field in
/// each struct, checked after casting — does not actually work: Rust reorders
/// fields in a `repr(Rust)` struct, so "read the magic through the wrong type"
/// is a read at an arbitrary offset of a possibly-smaller allocation. A first
/// version of this file did exactly that and the type-confusion test below
/// caught it.
///
/// With one concrete type, the cast is always correct and the variant tells us
/// what is inside. What remains unguardable is a fabricated or already-freed
/// pointer; no tagging scheme fixes that.
const MAGIC: u64 = 0x4C55_4B53_5F48_4E31; // "LUKS_HN1"

pub struct Handle {
    magic: u64,
    payload: Payload,
}

pub enum Payload {
    Device(DeviceHandle),
    Volume(VolumeHandle),
    #[cfg(feature = "dangerous-write-support")]
    Writer(WriterHandle),
}

#[derive(Clone)]
pub struct DeviceHandleRef(Arc<Handle>);

impl std::ops::Deref for DeviceHandleRef {
    type Target = DeviceHandle;
    fn deref(&self) -> &DeviceHandle {
        match &self.0.payload {
            Payload::Device(d) => d,
            _ => unreachable!("DeviceHandleRef invariant violated"),
        }
    }
}

#[derive(Clone)]
pub struct VolumeHandleRef(Arc<Handle>);

impl std::ops::Deref for VolumeHandleRef {
    type Target = VolumeHandle;
    fn deref(&self) -> &VolumeHandle {
        match &self.0.payload {
            Payload::Volume(v) => v,
            _ => unreachable!("VolumeHandleRef invariant violated"),
        }
    }
}

#[cfg(feature = "dangerous-write-support")]
#[derive(Clone)]
pub struct WriterHandleRef(Arc<Handle>);

#[cfg(feature = "dangerous-write-support")]
impl std::ops::Deref for WriterHandleRef {
    type Target = WriterHandle;
    fn deref(&self) -> &WriterHandle {
        match &self.0.payload {
            Payload::Writer(w) => w,
            _ => unreachable!("WriterHandleRef invariant violated"),
        }
    }
}

#[cfg(feature = "dangerous-write-support")]
pub enum FileWriterEnum {
    Ext4(luks_core::fs::ext4::file::FileWriter),
    Btrfs(luks_core::fs::btrfs::write::file::BtrfsFileWriter),
}

/// Opaque streaming state. It deliberately owns neither a device nor a volume.
#[cfg(feature = "dangerous-write-support")]
pub struct WriterHandle {
    pub volume_handle: i64,
    pub volume_id: u64,
    pub writer: Mutex<Option<FileWriterEnum>>,
}

pub struct DeviceHandle {
    pub dev: SharedDevice,
    pub block_size: u32,
    pub block_count: u64,
    pub vendor: String,
    pub product: String,
    pub table: PartitionTable,
    /// Where the usbfs transfer limit actually settled, once the kernel has had
    /// its say. `None` for a device that is not usbfs-backed (the tests).
    pub max_transfer: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

/// # Why the filesystem is behind a lock
///
/// Writing needs `&mut` — `write_new_file` mutates the in-memory superblock
/// counters and group descriptors before they reach the disk. Java holds an
/// opaque `long` and nothing stops it calling from two threads, so handing out
/// `&mut` from a shared handle would be undefined behaviour in the one crate
/// where `unsafe` is allowed at all.
///
/// A lock here rather than an `unsafe` accessor also buys a correctness
/// property the device-level lock cannot: `SharedDevice` serialises individual
/// reads and writes, but an allocation is *several* of them — read the bitmap,
/// set a bit, write it back — and a read interleaved mid-sequence sees ext4
/// state that never existed on disk. This makes each filesystem operation
/// whole.
static NEXT_VOLUME_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct VolumeHandle {
    pub id: u64,
    fs: Mutex<MountedFs>,
    pub partition_offset: u64,
    /// The device's writer flag, shared with every other volume on it.
    /// See [`VolumeHandle::write_file`].
    #[cfg_attr(
        not(feature = "dangerous-write-support"),
        allow(dead_code, reason = "only the write path claims it")
    )]
    device_writer: Arc<std::sync::atomic::AtomicBool>,
    /// Whether *this* volume is the one holding that flag, so dropping it
    /// releases the claim only if it made it.
    #[cfg_attr(
        not(feature = "dangerous-write-support"),
        allow(dead_code, reason = "only the write path claims it")
    )]
    holds_writer: std::sync::atomic::AtomicBool,
}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if self.holds_writer.load(Ordering::Acquire) {
            self.device_writer.store(false, Ordering::Release);
        }
    }
}

impl VolumeHandle {
    /// A poisoned lock on a read operation is recovered via `.into_inner()`
    /// because read operations do not mutate disk state or corrupt in-memory allocators.
    pub fn fs_for_reading(&self) -> std::sync::MutexGuard<'_, MountedFs> {
        self.fs.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A poisoned lock on a write operation fails immediately with `SessionPoisoned`
    /// (code 18 `MUTEX_POISONED`) to prevent mutating or flushing partially-broken state.
    pub fn fs_for_writing(&self) -> Result<std::sync::MutexGuard<'_, MountedFs>> {
        self.fs.lock().map_err(|_| LuksError::SessionPoisoned)
    }

    #[inline]
    pub fn fs(&self) -> std::sync::MutexGuard<'_, MountedFs> {
        self.fs_for_reading()
    }
}

/// The filesystem inside an unlocked volume.
///
/// The dispatch itself lives in `luks_core::fs::mounted`, so the host-side
/// examples and any future desktop build make the same decision the same way.
pub type MountedFs = luks_core::fs::MountedFs<LuksVolume<SharedDevice>>;
pub use luks_core::fs::OpenFile;

/// JSON shaping is a bridge concern, so it stays here rather than in core.
trait SubvolumesJson {
    fn subvolumes_json(&self) -> Vec<Value>;
}

impl SubvolumesJson for MountedFs {
    /// Subvolumes, for a filesystem that has them. Empty on ext4 rather than
    /// absent, so the JSON has one shape.
    fn subvolumes_json(&self) -> Vec<Value> {
        let MountedFs::Btrfs(fs) = self else {
            return Vec::new();
        };
        // A failure here must not take the whole volume-info call down with
        // it: the filesystem is mounted and browsable either way, and an
        // unreadable root tree will resurface the moment anything is listed.
        let Ok(subvols) = fs.subvolumes() else {
            return Vec::new();
        };
        subvols
            .iter()
            .map(|s| {
                json!({
                    "id": s.id,
                    "name": s.name,
                    "path": s.path,
                    "readOnly": s.is_read_only(),
                })
            })
            .collect()
    }
}

impl DeviceHandle {
    /// Build from anything readable. The USB path goes through
    /// [`open_usb_device`]; tests hand in an in-memory image.
    pub fn new<D: DeviceIo + Send + 'static>(
        device: D,
        block_size: u32,
        block_count: u64,
        vendor: String,
        product: String,
    ) -> Result<Self> {
        let dev = SharedDevice::new(device);
        let table = partition::scan(&dev, block_size)?;
        Ok(DeviceHandle {
            dev,
            block_size,
            block_count,
            vendor,
            product,
            table,
            max_transfer: None,
        })
    }

    /// Read raw sectors and time them — no decryption, no filesystem.
    ///
    /// This exists to settle an argument the full-stack number cannot. Reading a
    /// 1 GiB file through LUKS and ext4 gave the same ~21 MiB/s whether the
    /// transfer limit was 16 KiB or 128 KiB, which has two very different
    /// explanations: either the kernel quietly refused the larger size, or the
    /// link simply does not go faster and none of our layers are to blame.
    ///
    /// Reading raw blocks answers it directly. If this is also ~21 MiB/s, the
    /// transport is at its ceiling and the decrypt/filesystem layers cost
    /// nothing worth chasing. If it is markedly faster, the overhead is ours
    /// and there is a real bug above this line.
    pub fn benchmark_json(&self, bytes: u64, chunk_bytes: usize) -> Result<String> {
        let chunk = chunk_bytes.clamp(4096, 8 * 1024 * 1024);
        let capacity = self.block_count * self.block_size as u64;
        let total = bytes.min(capacity).max(chunk as u64);

        let mut buf = vec![0u8; chunk];
        let mut done = 0u64;
        let started = std::time::Instant::now();

        while done < total {
            let want = std::cmp::min(chunk as u64, total - done) as usize;
            self.dev.read_at(done, &mut buf[..want])?;
            done += want as u64;
        }

        let elapsed = started.elapsed();
        let secs = elapsed.as_secs_f64();

        Ok(json!({
            "bytes": done,
            "elapsedMs": elapsed.as_millis() as u64,
            "bytesPerSec": if secs > 0.0 { (done as f64 / secs) as u64 } else { 0 },
            "chunkBytes": chunk,
            // The number that says whether the self-tuning found headroom or
            // hit the historical 16 KiB wall.
            "maxTransfer": self
                .max_transfer
                .as_ref()
                .map(|c| c.load(std::sync::atomic::Ordering::Relaxed)),
        })
        .to_string())
    }

    /// Write raw sectors and time them — no encryption, no filesystem, no
    /// payload crossing the JNI boundary.
    ///
    /// The mirror of [`benchmark_json`](Self::benchmark_json), and it exists to
    /// end an argument three hypotheses have already lost. The phone reads at
    /// 31 MB/s and writes at 7.4 through the same Bulk-Only Transport, the same
    /// 128 KiB commands, the same three ioctls per command. Command size was
    /// ruled out by sweeping it — 128 KiB and 256 KiB give the same 7 MiB/s.
    /// Encryption was ruled out by measurement: AES-XTS runs at 1931 MiB/s on
    /// this phone, 0.4% of the time. The write path's seven payload memcpys
    /// were ruled out on the host, where the whole thing costs 0.10 s per
    /// 100 MB against the 13.5 s the phone spends.
    ///
    /// What is left is everything below this line and nothing above it. This
    /// isolates exactly that: one buffer allocated once, no LUKS, no ext4, no
    /// Java array. If it also reports ~7 MB/s the write path is innocent and
    /// the cost is the device, the bus or the kernel. If it reports ~22 — what
    /// the same drive does from a Mac at the same command size — the gap is
    /// ours after all, and lives somewhere this bypasses.
    ///
    /// # Where it writes
    ///
    /// Past the end of every partition, and never within the last mebibyte,
    /// where a GPT keeps its backup header. Computed from the partition table
    /// rather than hardcoded, so it cannot land on a filesystem if this is ever
    /// pointed at a different drive.
    #[cfg(feature = "dangerous-write-support")]
    pub fn benchmark_write_json(&self, bytes: u64, chunk_bytes: usize) -> Result<String> {
        use luks_core::device::WriteAt;

        let bs = self.block_size as u64;
        let chunk = (chunk_bytes.clamp(4096, 8 * 1024 * 1024) as u64 / bs * bs) as usize;
        let capacity = self.block_count * bs;

        // The first byte past every partition, block-aligned. A `max` over the
        // whole table rather than "the last entry": GPT entry order is not
        // required to match on-disk order.
        let past_partitions = self
            .table
            .partitions
            .iter()
            .map(|p| p.offset_bytes() + p.size_bytes())
            .max()
            .unwrap_or(0);
        let start = past_partitions.div_ceil(bs) * bs;
        const BACKUP_GPT_GUARD: u64 = 1024 * 1024;

        let room = capacity
            .saturating_sub(start)
            .saturating_sub(BACKUP_GPT_GUARD);
        if room < chunk as u64 {
            return Err(luks_core::error::LuksError::OutOfBounds);
        }
        let total = bytes.min(room).max(chunk as u64) / bs * bs;

        // Not zeros: a controller may special-case an all-zero block, and a
        // benchmark that measures a shortcut measures nothing.
        let buf: Vec<u8> = (0..chunk).map(|i| (i % 251) as u8).collect();

        let mut done = 0u64;
        let started = std::time::Instant::now();
        while done < total {
            let want = std::cmp::min(chunk as u64, total - done) as usize;
            self.dev.write_at(start + done, &buf[..want])?;
            done += want as u64;
        }
        let elapsed = started.elapsed();
        let secs = elapsed.as_secs_f64();

        Ok(json!({
            "bytes": done,
            "elapsedMs": elapsed.as_millis() as u64,
            "bytesPerSec": if secs > 0.0 { (done as f64 / secs) as u64 } else { 0 },
            "chunkBytes": chunk,
            "offsetBytes": start,
            "maxTransfer": self
                .max_transfer
                .as_ref()
                .map(|c| c.load(std::sync::atomic::Ordering::Relaxed)),
        })
        .to_string())
    }

    pub fn info_json(&self) -> String {
        let parts: Vec<Value> = self
            .table
            .partitions
            .iter()
            .map(|p| {
                json!({
                    "index": p.index,
                    "name": p.name,
                    "offsetBytes": p.offset_bytes(),
                    "sizeBytes": p.size_bytes(),
                    "isLuks": p.is_luks,
                    "luksVersion": p.luks_version,
                    "typeGuid": p.type_guid_string(),
                    "mbrType": p.mbr_type,
                })
            })
            .collect();

        json!({
            "vendor": self.vendor,
            "product": self.product,
            "blockSize": self.block_size,
            "blockCount": self.block_count,
            "sizeBytes": self.block_count * self.block_size as u64,
            "tableKind": match self.table.kind { TableKind::Gpt => "GPT", TableKind::Mbr => "MBR" },
            "partitions": parts,
        })
        .to_string()
    }

    /// Derive the master key and mount the filesystem inside.
    ///
    /// Slow — this is where Argon2 runs (seconds, and up to 1 GiB of allocation
    /// on a realistic drive). The caller must be off the UI thread and, on
    /// Android, inside a foreground service so the low-memory killer does not
    /// take the app during the allocation.
    pub fn unlock(&self, partition_offset: u64, password: &[u8]) -> Result<VolumeHandle> {
        // The container's length is what bounds every write inside it. The
        // caller passes only an offset — that is what the partition list it
        // was shown contains — so look the matching partition back up rather
        // than widening the JNI signature. A bare container has no table and
        // no bound tighter than the device, which is an honest `None`; the
        // extra scan is nothing beside the Argon2 run below.
        let partition_len = partition::scan(&self.dev, 512).ok().and_then(|t| {
            t.partitions
                .iter()
                .find(|p| p.offset_bytes() == partition_offset)
                .map(|p| p.size_bytes())
        });
        let header = luks::read_from(&self.dev, partition_offset)?;
        let volume = LuksVolume::open(
            self.dev.clone(),
            partition_offset,
            partition_len,
            &header,
            password,
        )?;
        let fs = MountedFs::mount(volume)?;
        let id = NEXT_VOLUME_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(VolumeHandle {
            id,
            fs: Mutex::new(fs),
            partition_offset,
            device_writer: Arc::clone(&self.dev.writer),
            holds_writer: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

/// Wrap a USB file descriptor owned by Java's `UsbDeviceConnection`.
///
/// # Safety
///
/// `fd` must be open for the whole life of the returned handle. It stays owned
/// by Java: this never closes it. Closing it on the Java side while a handle is
/// alive leaves us reading a descriptor number that the kernel may have handed
/// to something else.
pub unsafe fn open_usb_device(
    fd: i32,
    ep_in: u8,
    ep_out: u8,
    interface: u8,
    max_transfer: usize,
) -> Result<DeviceHandle> {
    let mut transport = UsbFsTransport::from_raw_fd(fd, ep_in, ep_out, interface);
    if max_transfer > 0 {
        transport = transport.with_max_transfer(max_transfer);
    }
    transport.claim_interface()?;

    // Grabbed before the transport is moved into the SCSI layer: after that the
    // concrete type is erased and the settled limit would be unobservable.
    let limit = transport.max_transfer_cell();

    let scsi = ScsiBlockDevice::open(transport)?;
    let capacity = scsi.capacity();
    let inquiry = scsi.inquiry()?;

    let mut handle = DeviceHandle::new(
        scsi,
        capacity.block_size,
        capacity.blocks,
        inquiry.vendor,
        inquiry.product,
    )?;
    handle.max_transfer = Some(limit);
    Ok(handle)
}

impl VolumeHandle {
    /// Existing fields keep their names and meanings; `fsType` and
    /// `subvolumes` are additions, so a Kotlin caller that does not know about
    /// them is unaffected.
    ///
    /// `label` is now null rather than `""` for an unlabelled volume — btrfs
    /// has no label at all until `mkfs` is given one, and reporting that as an
    /// empty string would make "unnamed" indistinguishable from "named with an
    /// empty string".
    pub fn info_json(&self) -> String {
        let fs = self.fs_for_reading();
        json!({
            "partitionOffset": self.partition_offset,
            "fsType": fs.kind().name(),
            "label": fs.label(),
            "uuid": format_uuid(&fs.uuid()),
            "blockSize": fs.block_size(),
            "sizeBytes": fs.size_bytes(),
            "subvolumes": fs.subvolumes_json(),
            // Absent from a read-only build rather than false: the UI should
            // find out what this library can do by asking it, not by assuming
            // its own build flavour matches.
            "canWrite": cfg!(feature = "dangerous-write-support"),
        })
        .to_string()
    }

    pub fn list_dir_json(&self, path: &str) -> Result<String> {
        let mut entries = self.fs_for_reading().list_dir(path)?;
        // "." and ".." are real dirents; the UI never wants them, and filtering
        // here keeps every future shell from re-deciding it.
        entries.retain(|e| e.name != "." && e.name != "..");
        entries.sort_by(|a, b| {
            b.file_type
                .is_dir()
                .cmp(&a.file_type.is_dir())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        let items: Vec<Value> = entries
            .iter()
            .map(|e| {
                // A size lookup per entry costs an inode read each. On a USB 2.0
                // link that is the difference between an instant listing and a
                // visible stall, so sizes are fetched lazily by `fileInfo`.
                json!({
                    "name": e.name,
                    "inode": e.inode,
                    "type": type_name(e.file_type),
                    // Always present, always false on ext4. On btrfs it also
                    // says that `inode` above is a tree id rather than an
                    // inode number.
                    "isSubvolume": e.is_subvolume,
                })
            })
            .collect();

        Ok(json!({ "path": path, "entries": items }).to_string())
    }

    pub fn list_directory_paged(&self, path: &str, offset: usize, limit: usize) -> Result<String> {
        let mut entries = self.fs_for_reading().list_dir(path)?;
        entries.retain(|e| e.name != "." && e.name != "..");
        entries.sort_by(|a, b| {
            b.file_type
                .is_dir()
                .cmp(&a.file_type.is_dir())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        let total_count = entries.len();
        let start = offset.min(total_count);
        let end = if limit == 0 {
            total_count
        } else {
            (start + limit).min(total_count)
        };
        let page_entries = &entries[start..end];
        let has_more = end < total_count;
        let next_offset = end;

        let items: Vec<Value> = page_entries
            .iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "inode": e.inode,
                    "type": type_name(e.file_type),
                    "isSubvolume": e.is_subvolume,
                })
            })
            .collect();

        Ok(json!({
            "path": path,
            "entries": items,
            "next_offset": next_offset,
            "has_more": has_more,
            "total_count": total_count,
        })
        .to_string())
    }

    pub fn file_info_json(&self, path: &str) -> Result<String> {
        let info = self.fs_for_reading().file_info(path)?;
        Ok(json!({
            "path": path,
            "size": info.size,
            "mode": info.mode,
            "uid": info.uid,
            "gid": info.gid,
            "links": info.links,
            "type": type_name(info.file_type),
            "atime": info.atime,
            "mtime": info.mtime,
            "ctime": info.ctime,
        })
        .to_string())
    }

    pub fn statfs_json(&self) -> Result<String> {
        let stat = self.fs_for_reading().statfs()?;
        Ok(json!({
            "totalBytes": stat.total_bytes,
            "freeBytes": stat.free_bytes,
            "availableBytes": stat.available_bytes,
            "totalInodes": stat.total_inodes,
            "freeInodes": stat.free_inodes,
            "blockSize": stat.block_size,
        })
        .to_string())
    }

    /// Whole-file read, refused above `max_bytes`.
    ///
    /// The cap is not paranoia: the result becomes a Java `byte[]`, and a
    /// gigabyte file would blow the app heap long before the read finished.
    /// Anything large goes through [`read_chunk`](Self::read_chunk) instead.
    pub fn read_file(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let fs = self.fs_for_reading();
        let info = fs.file_info(path)?;
        if info.size > max_bytes {
            return Err(LuksError::UnsupportedFsFeature(format!(
                "file is {} bytes, over the {} byte limit for a single read; \
                 use readChunk",
                info.size, max_bytes
            )));
        }
        let data = fs.read_file(path)?;
        if data.len() as u64 > max_bytes {
            return Err(LuksError::UnsupportedFsFeature(format!(
                "file is {} bytes, over the {} byte limit for a single read; \
                 use readChunk",
                data.len(), max_bytes
            )));
        }
        Ok(data)
    }

    /// Fill `buf` from `offset`, returning how many bytes were written.
    /// A short return means end of file.
    pub fn read_chunk(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file = self.fs_for_reading().open(path)?;
        if !file.file_type().is_file() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }
        self.fs_for_reading().read_open(&file, offset, buf)
    }

    /// Stream a file to an `io::Write` destination in chunks, checking for cancellation between chunks.
    pub fn read_file_stream<W: std::io::Write>(
        &self,
        path: &str,
        mut writer: W,
        chunk_bytes: usize,
        cancel_token: u64,
    ) -> Result<u64> {
        let file = self.fs_for_reading().open(path)?;
        let size = file.size();
        let chunk = if chunk_bytes == 0 {
            1024 * 1024
        } else {
            chunk_bytes.clamp(8, 8 * 1024 * 1024)
        };
        let mut buf = vec![0u8; chunk];
        let mut done = 0u64;

        while done < size {
            if cancel_token != 0 && is_cancelled(cancel_token) {
                return Err(LuksError::Cancelled);
            }
            let want = std::cmp::min(chunk as u64, size - done) as usize;
            let got = self.fs_for_reading().read_open(&file, done, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            writer.write_all(&buf[..got]).map_err(|e| LuksError::Io {
                path: path.to_string(),
                source: e,
            })?;
            done += got as u64;
        }

        if cancel_token != 0 && is_cancelled(cancel_token) {
            return Err(LuksError::Cancelled);
        }

        Ok(done)
    }

    /// Hash a file without ever holding it in memory, checking for cancellation between chunks.
    pub fn sha256_json_with_cancel(&self, path: &str, chunk_bytes: usize, cancel_token: u64) -> Result<String> {
        use sha2::{Digest, Sha256};

        let file = self.fs_for_reading().open(path)?;
        let size = file.size();
        // 0 means "pick something sensible". An explicit value is honoured down
        // to 8 bytes so the streaming loop can be tested against the small
        // fixture files; the upper clamp is what keeps a caller from asking for
        // a buffer the app heap cannot hold.
        let chunk = if chunk_bytes == 0 {
            1024 * 1024
        } else {
            chunk_bytes.clamp(8, 8 * 1024 * 1024)
        };

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; chunk];
        let mut done = 0u64;
        let started = std::time::Instant::now();

        while done < size {
            if cancel_token != 0 && is_cancelled(cancel_token) {
                return Err(LuksError::Cancelled);
            }
            let want = std::cmp::min(chunk as u64, size - done) as usize;
            // Re-locked each iteration rather than held across the whole hash: a
            // 1 GiB file is minutes of USB, and holding it would stall every
            // other call on the volume for that long.
            let got = self.fs_for_reading().read_open(&file, done, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            hasher.update(&buf[..got]);
            done += got as u64;
        }

        if cancel_token != 0 && is_cancelled(cancel_token) {
            return Err(LuksError::Cancelled);
        }

        let elapsed = started.elapsed();
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();

        Ok(json!({
            "path": path,
            "sha256": hex,
            "bytes": done,
            "elapsedMs": elapsed.as_millis() as u64,
            "bytesPerSec": if elapsed.as_secs_f64() > 0.0 {
                (done as f64 / elapsed.as_secs_f64()) as u64
            } else { 0 },
        })
        .to_string())
    }

    /// Hash a file without ever holding it in memory.
    ///
    /// This is the acceptance test for the whole stack: it is how the phone
    /// checks a 1 GiB file against `STICK-MANIFEST.txt` without a 1 GiB
    /// allocation, and the throughput it reports is the first real end-to-end
    /// number from USB through SCSI, LUKS and ext4.
    pub fn sha256_json(&self, path: &str, chunk_bytes: usize) -> Result<String> {
        self.sha256_json_with_cancel(path, chunk_bytes, 0)
    }
}

/// Time the CPU-side work in isolation, with no USB involved.
///
/// This exists because comparing the raw-read benchmark against the full-stack
/// SHA-256 number is not a fair comparison, and treating it as one led to a
/// wrong conclusion. Raw reads bytes and throws them away; the full-stack
/// figure also decrypts every sector, walks ext4, and hashes the result. Any of
/// those could account for the difference, and only measurement says which.
///
/// Both figures are per-core and in-memory, so they are upper bounds on what
/// the pipeline could sustain even with an infinitely fast drive.
pub fn self_test_json(mib: usize) -> String {
    use sha2::{Digest, Sha256};

    let bytes = mib.clamp(1, 256) * 1024 * 1024;
    let mut buf = vec![0u8; bytes];
    // A fixed non-zero pattern: an all-zero buffer would let neither cipher nor
    // hash take a shortcut, but it also would not resemble real ciphertext.
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i * 31 + 7) as u8;
    }
    let key = [0x42u8; 64]; // AES-256-XTS: two 32-byte keys

    let started = std::time::Instant::now();
    let xts = keyslot::xts_decrypt(&key, &mut buf, 512, 0, 1);
    let xts_secs = started.elapsed().as_secs_f64();

    let started = std::time::Instant::now();
    let digest = Sha256::digest(&buf);
    let sha_secs = started.elapsed().as_secs_f64();

    let rate = |secs: f64| -> u64 {
        if secs > 0.0 {
            (bytes as f64 / secs / (1024.0 * 1024.0)) as u64
        } else {
            0
        }
    };

    json!({
        "mib": mib,
        "xtsOk": xts.is_ok(),
        "xtsMiBs": rate(xts_secs),
        "sha256MiBs": rate(sha_secs),
        // Proves the hardware backend was compiled in. It is chosen at runtime
        // by cpufeatures, so this being true is necessary but not sufficient —
        // the measured rate is what actually settles it. Software AES-XTS runs
        // around 65 MiB/s; hardware runs in the thousands.
        "aesArmv8Compiled": cfg!(aes_armv8),
        "digestHead": format!("{:02x}{:02x}", digest[0], digest[1]),
    })
    .to_string()
}

fn type_name(t: FileType) -> &'static str {
    match t {
        FileType::Regular => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "symlink",
        FileType::CharDevice => "chardev",
        FileType::BlockDevice => "blockdev",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::Unknown => "unknown",
    }
}

/// ext4 stores its UUID as plain big-endian bytes, unlike a GPT type GUID.
fn format_uuid(u: &[u8; 16]) -> String {
    let h: String = u.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ------------------------------------------------------------ cancellation registry

static CANCEL_TOKENS: Mutex<Option<HashMap<u64, Arc<AtomicBool>>>> = Mutex::new(None);
static NEXT_CANCEL_TOKEN_ID: AtomicU64 = AtomicU64::new(1);

/// Register a new cancellation token and return its unique token ID.
pub fn register_cancel_token() -> u64 {
    let id = NEXT_CANCEL_TOKEN_ID.fetch_add(1, Ordering::Relaxed);
    let mut lock = CANCEL_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(id, Arc::new(AtomicBool::new(false)));
    id
}

/// Signal cancellation on the operation associated with `token_id`.
pub fn cancel_operation(token_id: u64) {
    if token_id == 0 {
        return;
    }
    let lock = CANCEL_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = lock.as_ref() {
        if let Some(flag) = map.get(&token_id) {
            flag.store(true, Ordering::Release);
        }
    }
}

/// Release / unregister the cancellation token.
pub fn unregister_cancel_token(token_id: u64) {
    if token_id == 0 {
        return;
    }
    let mut lock = CANCEL_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = lock.as_mut() {
        map.remove(&token_id);
    }
}

/// Query whether the operation associated with `token_id` has been cancelled.
pub fn is_cancelled(token_id: u64) -> bool {
    if token_id == 0 {
        return false;
    }
    let lock = CANCEL_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = lock.as_ref() {
        if let Some(flag) = map.get(&token_id) {
            return flag.load(Ordering::Acquire);
        }
    }
    false
}

// ------------------------------------------------------------ handle registry glue

static REGISTRY: Mutex<Option<HashMap<u64, Arc<Handle>>>> = Mutex::new(None);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Turn an owned payload into the opaque `long` Java holds.
pub fn into_raw(payload: Payload) -> i64 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let handle = Arc::new(Handle {
        magic: MAGIC,
        payload,
    });
    let mut lock = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(id, handle);
    id as i64
}

fn handle_ref(handle: i64) -> std::result::Result<Arc<Handle>, &'static str> {
    if handle <= 0 {
        return Err("not a luks handle (already closed?)");
    }
    let lock = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let map = lock.as_ref().ok_or("not a luks handle (already closed?)")?;
    let entry = map
        .get(&(handle as u64))
        .ok_or("not a luks handle (already closed?)")?;
    if entry.magic != MAGIC {
        return Err("not a luks handle (already closed?)");
    }
    Ok(Arc::clone(entry))
}

pub fn device_ref(handle: i64) -> std::result::Result<DeviceHandleRef, &'static str> {
    let h = handle_ref(handle)?;
    match &h.payload {
        Payload::Device(_) => Ok(DeviceHandleRef(h)),
        Payload::Volume(_) => Err("handle is a volume, not a device"),
        #[cfg(feature = "dangerous-write-support")]
        Payload::Writer(_) => Err("handle is a file writer, not a device"),
    }
}

pub fn volume_ref(handle: i64) -> std::result::Result<VolumeHandleRef, &'static str> {
    let h = handle_ref(handle)?;
    match &h.payload {
        Payload::Volume(_) => Ok(VolumeHandleRef(h)),
        Payload::Device(_) => Err("handle is a device, not a volume"),
        #[cfg(feature = "dangerous-write-support")]
        Payload::Writer(_) => Err("handle is a file writer, not a volume"),
    }
}

#[cfg(feature = "dangerous-write-support")]
pub fn writer_ref(handle: i64) -> std::result::Result<WriterHandleRef, &'static str> {
    let h = handle_ref(handle)?;
    match &h.payload {
        Payload::Writer(_) => Ok(WriterHandleRef(h)),
        _ => Err("handle is not a file writer"),
    }
}

#[derive(PartialEq, Eq)]
enum HandleKind {
    Device,
    Volume,
    #[cfg(feature = "dangerous-write-support")]
    Writer,
}

fn drop_handle(handle: i64, want: HandleKind) {
    if handle <= 0 {
        return;
    }
    let mut lock = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let Some(map) = lock.as_mut() else {
        return;
    };
    let id = handle as u64;
    let should_remove = if let Some(entry) = map.get(&id) {
        let kind = match &entry.payload {
            Payload::Device(_) => HandleKind::Device,
            Payload::Volume(_) => HandleKind::Volume,
            #[cfg(feature = "dangerous-write-support")]
            Payload::Writer(_) => HandleKind::Writer,
        };
        kind == want
    } else {
        false
    };
    if should_remove {
        map.remove(&id);
    }
}

pub fn drop_device(handle: i64) {
    drop_handle(handle, HandleKind::Device)
}

pub fn drop_volume(handle: i64) {
    drop_handle(handle, HandleKind::Volume)
}

#[cfg(feature = "dangerous-write-support")]
pub fn drop_writer(handle: i64) {
    drop_handle(handle, HandleKind::Writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-disk fixture: GPT with a decoy plain partition and a LUKS2
    /// partition, ext4 labelled DISKDATA inside, password "test". Built by real
    /// cryptsetup and mke2fs — see tools/README-fixtures.md.
    const PASSWORD: &[u8] = b"test";

    /// Read through a `FileDevice` rather than slurped into a `Vec<u8>`.
    ///
    /// A `Vec` cannot satisfy `DeviceIo` in a write-enabled build — `write_at`
    /// takes `&self`, and an in-memory buffer has no interior mutability to
    /// write through. That is not a limitation to work around: the device
    /// under a handle is a real device in every build, and the fixture should
    /// be one too.
    fn disk_image() -> luks_core::device::FileDevice {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/disks/gpt-luks.img"
        );
        luks_core::device::FileDevice::open(path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// The same stack with btrfs inside: GPT, one LUKS2 partition, password
    /// "test", a subvolume named `sub`. Read through `FileDevice` rather than
    /// slurped — btrfs's floor for a non-mixed filesystem makes this 128 MiB,
    /// and holding that in a test process to read a few files is wasteful.
    fn btrfs_device() -> luks_core::device::FileDevice {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/disks/gpt-luks-btrfs.img"
        );
        luks_core::device::FileDevice::open(path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn unlock_btrfs() -> VolumeHandle {
        let dev = btrfs_device();
        let blocks = dev.len().unwrap() / 512;
        let handle =
            DeviceHandle::new(dev, 512, blocks, "TEST".into(), "BTRFS".into()).expect("scan");
        let offset = handle
            .table
            .luks_partitions()
            .next()
            .expect("a LUKS partition")
            .offset_bytes();
        handle.unlock(offset, PASSWORD).expect("unlock")
    }

    fn open() -> DeviceHandle {
        let img = disk_image();
        let blocks = img.len().expect("fixture size") / 512;
        DeviceHandle::new(img, 512, blocks, "TEST".into(), "IMAGE".into()).expect("scan")
    }

    /// The fixture has two partitions and only the second is LUKS, so this also
    /// checks that the JSON does not simply flag everything.
    #[test]
    fn device_info_json_lists_the_luks_partition() {
        let dev = open();
        let v: Value = serde_json::from_str(&dev.info_json()).unwrap();
        assert_eq!(v["tableKind"], "GPT");
        assert_eq!(v["blockSize"], 512);

        let parts = v["partitions"].as_array().unwrap();
        assert_eq!(parts.len(), 2, "{v}");
        assert_eq!(parts[0]["name"], "plainpart");
        assert_eq!(parts[0]["isLuks"], false);
        assert_eq!(parts[1]["name"], "cryptdata");
        assert_eq!(parts[1]["isLuks"], true);
        assert_eq!(parts[1]["luksVersion"], 2);
        assert_eq!(parts[1]["offsetBytes"], 6144u64 * 512);
    }

    fn unlock_fixture() -> VolumeHandle {
        let dev = open();
        let offset = dev
            .table
            .luks_partitions()
            .next()
            .expect("a LUKS partition")
            .offset_bytes();
        dev.unlock(offset, PASSWORD).expect("unlock")
    }

    #[test]
    fn volume_info_json_reports_the_filesystem_label() {
        let vol = unlock_fixture();
        let v: Value = serde_json::from_str(&vol.info_json()).unwrap();
        assert_eq!(v["label"], "DISKDATA");
        assert_eq!(v["partitionOffset"], 6144u64 * 512);
    }

    #[test]
    fn unlock_then_list_the_root_directory() {
        let vol = unlock_fixture();
        let v: Value = serde_json::from_str(&vol.list_dir_json("/").unwrap()).unwrap();
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"proof.txt"), "{names:?}");
        assert!(names.contains(&"dir"), "{names:?}");
        assert!(
            !names.contains(&".") && !names.contains(&".."),
            "dot entries leaked into the listing: {names:?}"
        );
        // Directories sort ahead of files.
        assert_eq!(names[0], "dir", "{names:?}");
        // lost+found is a directory too, so the check above is not vacuous.
        assert!(names.contains(&"lost+found"), "{names:?}");
    }

    #[test]
    fn read_file_returns_the_bytes_on_the_drive() {
        let vol = unlock_fixture();
        assert_eq!(
            vol.read_file("/proof.txt", 1024).unwrap(),
            b"whole disk stack works\n"
        );
    }

    #[test]
    fn read_chunk_reads_from_the_middle_and_stops_at_eof() {
        let vol = unlock_fixture();
        let mut buf = [0u8; 64];
        let got = vol.read_chunk("/proof.txt", 6, &mut buf).unwrap();
        assert_eq!(&buf[..got], b"disk stack works\n");
    }

    #[test]
    fn a_wrong_password_is_reported_as_wrong_password() {
        let dev = open();
        let offset = dev.table.luks_partitions().next().unwrap().offset_bytes();
        // `.err()` rather than `unwrap_err()`: a VolumeHandle has no Debug, and
        // giving it one would mean deriving Debug down the whole stack.
        let err = dev
            .unlock(offset, b"definitely-not-it")
            .err()
            .expect("a wrong password must not unlock");
        assert_eq!(error_code(&err), code::WRONG_PASSWORD);
    }

    /// The reason `SharedDevice` exists: a failed unlock must not consume the
    /// device, or a typo would cost the user a full USB re-permission cycle.
    #[test]
    fn the_device_survives_a_failed_unlock() {
        let dev = open();
        let offset = dev.table.luks_partitions().next().unwrap().offset_bytes();
        assert!(dev.unlock(offset, b"wrong").is_err());
        assert!(
            dev.unlock(offset, PASSWORD).is_ok(),
            "second attempt failed"
        );
    }

    #[test]
    fn read_file_refuses_to_exceed_the_cap() {
        let vol = unlock_fixture();
        assert!(vol.read_file("/proof.txt", u64::MAX).is_ok());
        let exact_len = vol.read_file("/proof.txt", u64::MAX).unwrap().len() as u64;
        assert!(vol.read_file("/proof.txt", exact_len).is_ok());
        let err = vol.read_file("/proof.txt", exact_len - 1).unwrap_err();
        assert_eq!(error_code(&err), code::UNSUPPORTED);
        let err4 = vol.read_file("/proof.txt", 4).unwrap_err();
        assert_eq!(error_code(&err4), code::UNSUPPORTED);
    }

    /// `sha256_json` streams; `read_file` slurps. They must agree, or the
    /// chunked path — the only one usable for a real multi-gigabyte file — is
    /// silently wrong.
    #[test]
    fn streamed_sha256_matches_the_whole_file_read() {
        use sha2::{Digest, Sha256};
        let vol = unlock_fixture();
        let path = "/proof.txt";

        let whole = vol.read_file(path, u64::MAX).unwrap();
        let expected: String = Sha256::digest(&whole)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // The fixture's files are tens of bytes, so an 8-byte chunk is what
        // forces the loop to iterate. On the phone this is 1 MiB.
        for chunk in [8usize, 23, 1024, 0] {
            let v: Value = serde_json::from_str(&vol.sha256_json(path, chunk).unwrap()).unwrap();
            assert_eq!(v["sha256"], expected, "chunk={chunk}");
            assert_eq!(v["bytes"], whole.len() as u64, "chunk={chunk}");
        }
    }

    /// The Java-side mixup this guards against: handles are bare `long`s, so
    /// `closeVolume(deviceHandle)` compiles. An earlier version of this file
    /// put a magic field in each struct and cast the pointer to the guessed
    /// type — which this test failed, because `repr(Rust)` reorders fields and
    /// the "magic" being read was some other field entirely.
    #[test]
    fn handles_round_trip_and_reject_the_wrong_type() {
        let dev_handle = into_raw(Payload::Device(open()));
        let vol_handle = into_raw(Payload::Volume(unlock_fixture()));

        assert!(device_ref(dev_handle).is_ok());
        assert!(volume_ref(vol_handle).is_ok());
        assert!(device_ref(vol_handle).is_err());
        assert!(volume_ref(dev_handle).is_err());
        assert!(device_ref(0).is_err());

        // Closing with the wrong function must not free anything.
        drop_volume(dev_handle);
        assert!(device_ref(dev_handle).is_ok(), "wrong-type close freed it");
        drop_device(vol_handle);
        assert!(volume_ref(vol_handle).is_ok(), "wrong-type close freed it");

        drop_device(dev_handle);
        drop_volume(vol_handle);

        // Now closed: entry was removed from the registry, so a second close
        // is a no-op and a stale handle is refused rather than handed out.
        assert!(device_ref(dev_handle).is_err());
        drop_device(dev_handle);
    }

    // --- btrfs through the same bridge --------------------------------------

    /// The pass-4c claim in one test: the bridge picks the filesystem itself,
    /// and the JSON coming out is the same shape either way.
    #[test]
    fn unlocking_a_btrfs_volume_reports_it_as_btrfs() {
        let vol = unlock_btrfs();
        let v: Value = serde_json::from_str(&vol.info_json()).unwrap();
        assert_eq!(v["fsType"], "btrfs");
        assert_eq!(v["label"], "DISKBTRFS");
        // btrfs calls its allocation unit a sector; the field means the same
        // thing to a caller as ext4's block size.
        assert_eq!(v["blockSize"], 4096);

        let ext4 = unlock_fixture();
        let e: Value = serde_json::from_str(&ext4.info_json()).unwrap();
        assert_eq!(e["fsType"], "ext4");
        assert_eq!(e["label"], "DISKDATA");
        // Same keys, both filesystems — the point of the enum.
        let keys = |v: &Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&v), keys(&e));
    }

    #[test]
    fn lists_and_reads_a_btrfs_volume() {
        let vol = unlock_btrfs();
        let v: Value = serde_json::from_str(&vol.list_dir_json("/").unwrap()).unwrap();
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"proof.txt"), "{names:?}");
        assert!(names.contains(&"sub"), "{names:?}");
        // btrfs has no lost+found, so directories still sort first but the set
        // differs from ext4 — worth pinning so a future change to the sort is
        // visible.
        assert_eq!(names[0], "dir", "{names:?}");

        assert_eq!(
            vol.read_file("/proof.txt", 1024).unwrap(),
            b"whole disk stack works\n"
        );
        assert_eq!(
            vol.read_file("/dir/inner.txt", 1024).unwrap(),
            b"inside a directory\n"
        );
    }

    /// Reading across a subvolume boundary, through the bridge, on a real
    /// encrypted volume. Everything below this line was tested on bare images
    /// until now.
    #[test]
    fn reads_across_a_subvolume_boundary_through_the_bridge() {
        let vol = unlock_btrfs();
        assert_eq!(
            vol.read_file("/sub/nested.txt", 1024).unwrap(),
            b"inside a subvolume\n"
        );

        let v: Value = serde_json::from_str(&vol.info_json()).unwrap();
        let subvols = v["subvolumes"].as_array().unwrap();
        assert_eq!(subvols.len(), 1, "{v}");
        assert_eq!(subvols[0]["name"], "sub");
        assert_eq!(subvols[0]["path"], "/sub");
        assert_eq!(subvols[0]["readOnly"], false);

        // ext4 gets the same key with an empty list, not a missing key.
        let e: Value = serde_json::from_str(&unlock_fixture().info_json()).unwrap();
        assert_eq!(e["subvolumes"].as_array().unwrap().len(), 0);
    }

    /// The subvolume entry is flagged in a listing, because its `inode` field
    /// is a tree id and a caller cannot tell from the number.
    #[test]
    fn a_subvolume_is_flagged_in_a_listing() {
        let vol = unlock_btrfs();
        let v: Value = serde_json::from_str(&vol.list_dir_json("/").unwrap()).unwrap();
        let entries = v["entries"].as_array().unwrap();

        let sub = entries.iter().find(|e| e["name"] == "sub").unwrap();
        assert_eq!(sub["isSubvolume"], true);
        assert_eq!(sub["type"], "dir");

        let dir = entries.iter().find(|e| e["name"] == "dir").unwrap();
        assert_eq!(dir["isSubvolume"], false);

        // ext4 carries the field too, always false.
        let e: Value = serde_json::from_str(&unlock_fixture().list_dir_json("/").unwrap()).unwrap();
        assert!(e["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["isSubvolume"] == false));
    }

    /// Streaming reads must resolve the path once, not per chunk, and must
    /// agree with the whole-file read on both filesystems.
    #[test]
    fn streamed_sha256_matches_on_btrfs_too() {
        use sha2::{Digest, Sha256};
        let vol = unlock_btrfs();
        let whole = vol.read_file("/sub/nested.txt", u64::MAX).unwrap();
        let expected: String = Sha256::digest(&whole)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        for chunk in [8usize, 1024, 0] {
            let v: Value =
                serde_json::from_str(&vol.sha256_json("/sub/nested.txt", chunk).unwrap()).unwrap();
            assert_eq!(v["sha256"], expected, "chunk={chunk}");
            assert_eq!(v["bytes"], whole.len() as u64, "chunk={chunk}");
        }
    }

    #[test]
    fn error_codes_are_distinct_per_category() {
        assert_eq!(error_code(&LuksError::WrongPassword), code::WRONG_PASSWORD);
        assert_eq!(
            error_code(&LuksError::NotFound("x".into())),
            code::NOT_FOUND
        );
        assert_eq!(
            error_code(&LuksError::ScsiCommandFailed {
                opcode: 0x2A,
                sense: None
            }),
            code::TRANSPORT
        );
        assert_eq!(error_code(&LuksError::FsNeedsRecovery), code::NEEDS_FSCK);
        assert_eq!(
            error_code(&LuksError::BadMagic { found: [0; 6] }),
            code::NOT_LUKS
        );
        assert_eq!(error_code(&LuksError::SessionPoisoned), code::MUTEX_POISONED);
        assert_eq!(error_code(&LuksError::Cancelled), code::CANCELLED);
    }

    #[test]
    fn cancel_registry_lifecycle_and_cancellation() {
        let token = register_cancel_token();
        assert!(token > 0);
        assert!(!is_cancelled(token));

        cancel_operation(token);
        assert!(is_cancelled(token));

        unregister_cancel_token(token);
        assert!(!is_cancelled(token));
    }

    #[test]
    fn paged_directory_listing_returns_pagination_metadata() {
        let vol = unlock_fixture();
        // Root dir has at least proof.txt, dir, lost+found
        let v_all: Value = serde_json::from_str(&vol.list_directory_paged("/", 0, 0).unwrap()).unwrap();
        let total = v_all["total_count"].as_u64().unwrap() as usize;
        assert!(total >= 3);
        assert_eq!(v_all["entries"].as_array().unwrap().len(), total);
        assert_eq!(v_all["has_more"].as_bool().unwrap(), false);
        assert_eq!(v_all["next_offset"].as_u64().unwrap() as usize, total);

        // Page 1: limit 1
        let v_page1: Value = serde_json::from_str(&vol.list_directory_paged("/", 0, 1).unwrap()).unwrap();
        assert_eq!(v_page1["entries"].as_array().unwrap().len(), 1);
        assert_eq!(v_page1["total_count"].as_u64().unwrap() as usize, total);
        assert_eq!(v_page1["has_more"].as_bool().unwrap(), true);
        assert_eq!(v_page1["next_offset"].as_u64().unwrap(), 1);

        // Page 2: offset 1, limit 1
        let v_page2: Value = serde_json::from_str(&vol.list_directory_paged("/", 1, 1).unwrap()).unwrap();
        assert_eq!(v_page2["entries"].as_array().unwrap().len(), 1);
        assert_eq!(v_page2["total_count"].as_u64().unwrap() as usize, total);
        assert_eq!(v_page2["has_more"].as_bool().unwrap(), total > 2);
        assert_eq!(v_page2["next_offset"].as_u64().unwrap(), 2);

        // Verify entries do not overlap and match full listing
        let name_p1 = v_page1["entries"][0]["name"].as_str().unwrap();
        let name_p2 = v_page2["entries"][0]["name"].as_str().unwrap();
        assert_ne!(name_p1, name_p2);
        assert_eq!(name_p1, v_all["entries"][0]["name"].as_str().unwrap());
        assert_eq!(name_p2, v_all["entries"][1]["name"].as_str().unwrap());
    }

    #[test]
    fn streamed_sha256_and_read_stream_halt_when_cancelled() {
        let vol = unlock_fixture();
        let path = "/proof.txt";

        let token = register_cancel_token();
        cancel_operation(token);

        // sha256_json_with_cancel with cancelled token
        let err_sha = vol.sha256_json_with_cancel(path, 8, token).unwrap_err();
        assert_eq!(error_code(&err_sha), code::CANCELLED);

        // read_file_stream with cancelled token
        let mut buf = Vec::new();
        let err_stream = vol.read_file_stream(path, &mut buf, 8, token).unwrap_err();
        assert_eq!(error_code(&err_stream), code::CANCELLED);

        unregister_cancel_token(token);
    }
}
