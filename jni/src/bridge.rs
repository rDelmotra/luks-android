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

use std::sync::{Arc, Mutex};

use luks_core::device::ReadAt;
use luks_core::error::{LuksError, Result};
use luks_core::fs::FileType;
use luks_core::luks::{self, keyslot, LuksVolume};
use luks_core::partition::{self, PartitionTable, TableKind};
use luks_core::secret::Secret;
use luks_core::usb::ScsiBlockDevice;
use luks_usbfs::UsbFsTransport;

use serde_json::{json, Value};

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
    /// A write target was not the device the caller said it was, or its size
    /// could not be confirmed. Distinct from a permissions or I/O failure so
    /// the UI can say "wrong device" rather than a generic I/O message.
    pub const WRONG_TARGET: i32 = 13;
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
        WrongWriteTarget { .. } | UnverifiableWriteTarget { .. } => code::WRONG_TARGET,
        NotFound(_) | NotADirectory(_) | IsADirectory(_) | BadInode(_) => code::NOT_FOUND,
        ScsiProtocol(_) | ScsiCommandFailed | UsbTransfer(_) => code::TRANSPORT,
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
#[derive(Clone)]
pub struct SharedDevice(Arc<Mutex<dyn ReadAt + Send>>);

impl SharedDevice {
    pub fn new<D: ReadAt + Send + 'static>(device: D) -> Self {
        SharedDevice(Arc::new(Mutex::new(device)))
    }

    /// A poisoned lock means some earlier call panicked mid-read. The device
    /// itself has no invariant we can corrupt — reads are stateless apart from
    /// the SCSI tag counter — so recovering the guard is better than turning
    /// every later call into a panic.
    // The `+ 'static` is not decoration: inside `Arc<Mutex<dyn ..>>` the elided
    // object lifetime defaults to 'static, but in a `MutexGuard<'_, dyn ..>`
    // return type it defaults to the guard's own lifetime. Spelling it out keeps
    // the two the same type.
    fn lock(&self) -> std::sync::MutexGuard<'_, dyn ReadAt + Send + 'static> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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

#[repr(C)]
pub struct Handle {
    magic: u64,
    payload: Payload,
}

pub enum Payload {
    Device(DeviceHandle),
    Volume(VolumeHandle),
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

pub struct VolumeHandle {
    pub fs: MountedFs,
    pub partition_offset: u64,
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
    pub fn new<D: ReadAt + Send + 'static>(
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
        let header = luks::read_from(&self.dev, partition_offset)?;
        let volume = LuksVolume::open(self.dev.clone(), partition_offset, &header, password)?;
        let fs = MountedFs::mount(volume)?;
        Ok(VolumeHandle {
            fs,
            partition_offset,
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
        json!({
            "partitionOffset": self.partition_offset,
            "fsType": self.fs.kind().name(),
            "label": self.fs.label(),
            "uuid": format_uuid(&self.fs.uuid()),
            "blockSize": self.fs.block_size(),
            "sizeBytes": self.fs.size_bytes(),
            "subvolumes": self.fs.subvolumes_json(),
        })
        .to_string()
    }

    pub fn list_dir_json(&self, path: &str) -> Result<String> {
        let mut entries = self.fs.list_dir(path)?;
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

    pub fn file_info_json(&self, path: &str) -> Result<String> {
        let info = self.fs.file_info(path)?;
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

    /// Whole-file read, refused above `max_bytes`.
    ///
    /// The cap is not paranoia: the result becomes a Java `byte[]`, and a
    /// gigabyte file would blow the app heap long before the read finished.
    /// Anything large goes through [`read_chunk`](Self::read_chunk) instead.
    pub fn read_file(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let info = self.fs.file_info(path)?;
        if info.size > max_bytes {
            return Err(LuksError::UnsupportedFsFeature(format!(
                "file is {} bytes, over the {} byte limit for a single read; \
                 use readChunk",
                info.size, max_bytes
            )));
        }
        self.fs.read_file(path)
    }

    /// Fill `buf` from `offset`, returning how many bytes were written.
    /// A short return means end of file.
    pub fn read_chunk(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file = self.fs.open(path)?;
        if !file.file_type().is_file() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }
        self.fs.read_open(&file, offset, buf)
    }

    /// Hash a file without ever holding it in memory.
    ///
    /// This is the acceptance test for the whole stack: it is how the phone
    /// checks a 1 GiB file against `STICK-MANIFEST.txt` without a 1 GiB
    /// allocation, and the throughput it reports is the first real end-to-end
    /// number from USB through SCSI, LUKS and ext4.
    pub fn sha256_json(&self, path: &str, chunk_bytes: usize) -> Result<String> {
        use sha2::{Digest, Sha256};

        let file = self.fs.open(path)?;
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
            let want = std::cmp::min(chunk as u64, size - done) as usize;
            let got = self.fs.read_open(&file, done, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            hasher.update(&buf[..got]);
            done += got as u64;
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

// ------------------------------------------------------------ raw handle glue

/// Turn an owned payload into the opaque `long` Java holds.
pub fn into_raw(payload: Payload) -> i64 {
    Box::into_raw(Box::new(Handle {
        magic: MAGIC,
        payload,
    })) as i64
}

/// # Safety
/// `handle` must be a value previously returned by [`into_raw`] and not yet
/// freed. The magic check rejects zero and obvious garbage; it cannot detect a
/// freed pointer, because reading freed memory to check it is already the bug.
unsafe fn handle_ref<'a>(handle: i64) -> std::result::Result<&'a Handle, &'static str> {
    match (handle as *const Handle).as_ref() {
        None => Err("null handle"),
        Some(h) if h.magic != MAGIC => Err("not a luks handle (already closed?)"),
        Some(h) => Ok(h),
    }
}

/// # Safety
/// See [`handle_ref`].
pub unsafe fn device_ref<'a>(handle: i64) -> std::result::Result<&'a DeviceHandle, &'static str> {
    match &handle_ref(handle)?.payload {
        Payload::Device(d) => Ok(d),
        Payload::Volume(_) => Err("handle is a volume, not a device"),
    }
}

/// # Safety
/// See [`handle_ref`].
pub unsafe fn volume_ref<'a>(handle: i64) -> std::result::Result<&'a VolumeHandle, &'static str> {
    match &handle_ref(handle)?.payload {
        Payload::Volume(v) => Ok(v),
        Payload::Device(_) => Err("handle is a device, not a volume"),
    }
}

/// Free a handle, if it is one and it holds the expected kind.
///
/// The magic is cleared before the box is dropped so a double close is a no-op
/// rather than a second `Box::from_raw` — though that only holds while the
/// freed memory happens to be untouched, which is why Kotlin also nulls its
/// copy. Closing a device handle with `close_volume` does nothing, deliberately:
/// silently freeing the wrong thing would be worse than leaking.
///
/// # Safety
/// See [`handle_ref`].
unsafe fn drop_handle(handle: i64, want_volume: bool) {
    if handle == 0 {
        return;
    }
    let p = handle as *mut Handle;
    if (*p).magic != MAGIC {
        return;
    }
    let is_volume = matches!((*p).payload, Payload::Volume(_));
    if is_volume != want_volume {
        return;
    }
    (*p).magic = 0;
    drop(Box::from_raw(p));
}

/// # Safety
/// See [`handle_ref`].
pub unsafe fn drop_device(handle: i64) {
    drop_handle(handle, false)
}

/// # Safety
/// See [`handle_ref`]. Dropping a volume zeroes the master key it holds.
pub unsafe fn drop_volume(handle: i64) {
    drop_handle(handle, true)
}

/// Zeroising owner for a password copied out of a Java `byte[]`.
///
/// The Java side is expected to overwrite its own array in a `finally`; this
/// covers our copy of it. Both halves are needed — neither can zero the other's
/// memory.
pub fn password_secret(bytes: Vec<u8>) -> Secret {
    Secret::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-disk fixture: GPT with a decoy plain partition and a LUKS2
    /// partition, ext4 labelled DISKDATA inside, password "test". Built by real
    /// cryptsetup and mke2fs — see tools/README-fixtures.md.
    const PASSWORD: &[u8] = b"test";

    fn disk_image() -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/disks/gpt-luks.img");
        std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
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
        let handle = DeviceHandle::new(dev, 512, blocks, "TEST".into(), "BTRFS".into())
            .expect("scan");
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
        let blocks = img.len() as u64 / 512;
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
        assert!(dev.unlock(offset, PASSWORD).is_ok(), "second attempt failed");
    }

    #[test]
    fn read_file_refuses_to_exceed_the_cap() {
        let vol = unlock_fixture();
        assert!(vol.read_file("/proof.txt", u64::MAX).is_ok());
        let err = vol.read_file("/proof.txt", 4).unwrap_err();
        assert_eq!(error_code(&err), code::UNSUPPORTED);
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

        unsafe {
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

            // Now closed: the magic is cleared, so a second close is a no-op
            // and a stale reference is refused rather than handed out.
            assert!(device_ref(dev_handle).is_err());
            drop_device(dev_handle);
        }
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
        assert_eq!(error_code(&LuksError::NotFound("x".into())), code::NOT_FOUND);
        assert_eq!(error_code(&LuksError::ScsiCommandFailed), code::TRANSPORT);
        assert_eq!(error_code(&LuksError::FsNeedsRecovery), code::NEEDS_FSCK);
        assert_eq!(error_code(&LuksError::BadMagic { found: [0; 6] }), code::NOT_LUKS);
    }
}
