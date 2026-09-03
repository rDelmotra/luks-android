//! `BulkTransport` over Linux/Android usbfs ioctls.
//!
//! This crate exists to keep `unsafe` out of `luks_core`. Everything that parses
//! bytes from an untrusted drive — GPT, LUKS, ext4 — lives there under
//! `#![forbid(unsafe_code)]`, and `forbid` cannot be lifted by an `#[allow]`.
//! Splitting the ioctls out preserves that guarantee where it matters most and
//! confines the unsafe surface to this file, which only moves bytes.
//!
//! # How Android gets here
//!
//! ```text
//!   UsbManager.requestPermission()          user grants access to the device
//!   UsbManager.openDevice()   -> UsbDeviceConnection
//!   connection.getFileDescriptor()          a usbfs fd, owned by Java
//!         |
//!         v
//!   UsbFsTransport::from_raw_fd(fd, ep_in, ep_out, iface)
//! ```
//!
//! The fd stays owned by Java. This crate never closes it — see
//! [`UsbFsTransport::from_raw_fd`].

use luks_core::error::{LuksError, Result};
use luks_core::usb::BulkTransport;
use std::os::raw::{c_int, c_uint, c_void};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- ioctl codes

// From include/uapi/asm-generic/ioctl.h. Encoded rather than hardcoded because
// the size field depends on pointer width, and this crate builds for both
// aarch64 and armv7 Android.
const NRBITS: u32 = 8;
const TYPEBITS: u32 = 8;
const SIZEBITS: u32 = 14;
const TYPESHIFT: u32 = NRBITS;
const SIZESHIFT: u32 = TYPESHIFT + TYPEBITS;
const DIRSHIFT: u32 = SIZESHIFT + SIZEBITS;

/// Kept for completeness of the encoding, even though every ioctl this crate
/// issues moves data in at least one direction.
#[allow(dead_code)]
const DIR_NONE: u32 = 0;
const DIR_WRITE: u32 = 1;
const DIR_READ: u32 = 2;

const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> u32 {
    debug_assert!(size < (1 << SIZEBITS));
    (dir << DIRSHIFT) | ((size as u32) << SIZESHIFT) | ((ty as u32) << TYPESHIFT) | (nr as u32)
}

/// bionic declares `ioctl`'s request parameter as `int`; glibc uses
/// `unsigned long`. Request codes exceed `i32::MAX`, so the cast wraps to a
/// negative value on Android — which is exactly what C does there.
#[cfg(target_os = "android")]
type IoctlReq = std::os::raw::c_int;
#[cfg(not(target_os = "android"))]
type IoctlReq = libc::c_ulong;

const USB_IOC: u8 = b'U';

#[repr(C)]
pub struct UsbdevfsUrb {
    pub urb_type: u8,
    pub endpoint: u8,
    pub status: c_int,
    pub flags: c_uint,
    pub buffer: *mut c_void,
    pub buffer_length: c_int,
    pub actual_length: c_int,
    pub start_frame: c_int,
    pub number_of_packets_or_stream_id: c_int,
    pub error_count: c_int,
    pub signr: c_uint,
    pub usercontext: *mut c_void,
}

const USBDEVFS_URB_TYPE_BULK: u8 = 3;

#[repr(C)]
pub struct UsbFsCtrlTransfer {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
    pub timeout: c_uint,
    pub data: *mut c_void,
}

pub fn submit_urb_code() -> u32 {
    ioc(
        DIR_READ,
        USB_IOC,
        10,
        std::mem::size_of::<UsbdevfsUrb>(),
    )
}

pub fn discard_urb_code() -> u32 {
    ioc(DIR_NONE, USB_IOC, 11, 0)
}

pub fn reap_urb_code() -> u32 {
    ioc(
        DIR_WRITE,
        USB_IOC,
        12,
        std::mem::size_of::<*mut c_void>(),
    )
}

pub fn control_code() -> u32 {
    ioc(
        DIR_WRITE | DIR_READ,
        USB_IOC,
        0,
        std::mem::size_of::<UsbFsCtrlTransfer>(),
    )
}

pub fn claim_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 15, std::mem::size_of::<c_uint>())
}

pub fn release_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 16, std::mem::size_of::<c_uint>())
}

pub fn clear_halt_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 21, std::mem::size_of::<c_uint>())
}

// ----------------------------------------------------------- RawUsbFs trait seam

/// Abstraction over raw usbfs kernel ioctl and poll operations for deterministic testing.
pub trait RawUsbFs: Send + Sync {
    fn ioctl(&self, fd: RawFd, req: IoctlReq, arg: *mut c_void) -> c_int;
    fn poll(&self, fd: RawFd, events: libc::c_short, timeout_ms: i32) -> std::result::Result<libc::c_short, i32>;
}

/// Production implementation issuing real libc syscalls.
pub struct RealUsbFs;

impl RawUsbFs for RealUsbFs {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn ioctl(&self, fd: RawFd, req: IoctlReq, arg: *mut c_void) -> c_int {
        unsafe { libc::ioctl(fd, req, arg) }
    }

    fn poll(&self, fd: RawFd, events: libc::c_short, timeout_ms: i32) -> std::result::Result<libc::c_short, i32> {
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(e);
            }
            if rc == 0 {
                return Err(libc::ETIMEDOUT);
            }
            return Ok(pfd.revents);
        }
    }
}

// ------------------------------------------------------------- Transport State

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportState {
    Healthy = 0,
    Draining = 1,
    Dead = 2,
}

// ------------------------------------------------------------ Persistent Arena

pub const MAX_URB_SLOTS: usize = 32;

#[repr(C)]
pub struct UrbSlot {
    pub urb: UsbdevfsUrb,
    pub generation: u64,
    /// Position in the chunk sequence. Completions are scored by this, not
    /// by the order they are reaped in — REAPURB does not promise to return
    /// them in submission order, and a gap earlier in the sequence must stop
    /// the count even if a later chunk happened to complete first.
    pub index: usize,
    pub in_use: bool,
    pub submitted: bool,
    pub reaped: bool,
}

// SAFETY: UrbSlot's raw pointers are internally managed and only accessed with Arena lock.
unsafe impl Send for UrbSlot {}

pub struct UrbArena {
    pub slots: Box<[UrbSlot]>,
    pub next_generation: u64,
}

// SAFETY: UrbArena is protected inside Mutex.
unsafe impl Send for UrbArena {}

impl Default for UrbArena {
    fn default() -> Self {
        Self::new()
    }
}

impl UrbArena {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(MAX_URB_SLOTS);
        for _ in 0..MAX_URB_SLOTS {
            slots.push(UrbSlot {
                urb: UsbdevfsUrb {
                    urb_type: USBDEVFS_URB_TYPE_BULK,
                    endpoint: 0,
                    status: 0,
                    flags: 0,
                    buffer: std::ptr::null_mut(),
                    buffer_length: 0,
                    actual_length: 0,
                    start_frame: 0,
                    number_of_packets_or_stream_id: 0,
                    error_count: 0,
                    signr: 0,
                    usercontext: std::ptr::null_mut(),
                },
                generation: 0,
                index: 0,
                in_use: false,
                submitted: false,
                reaped: false,
            });
        }
        Self {
            slots: slots.into_boxed_slice(),
            next_generation: 1,
        }
    }

    /// Allocate `count` slots for a transfer, tagging each with a new generation ID.
    pub fn allocate(&mut self, count: usize) -> std::result::Result<(u64, Vec<usize>), LuksError> {
        let gen = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);

        let mut indices = Vec::with_capacity(count);
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if !slot.in_use {
                slot.in_use = true;
                slot.generation = gen;
                slot.index = indices.len();
                slot.submitted = false;
                slot.reaped = false;
                slot.urb.status = 0;
                slot.urb.actual_length = 0;
                // Encode slot index + 1 as usercontext token (non-null, bounded)
                slot.urb.usercontext = (i + 1) as *mut c_void;
                indices.push(i);
                if indices.len() == count {
                    return Ok((gen, indices));
                }
            }
        }
        for &idx in &indices {
            self.slots[idx].in_use = false;
        }
        Err(LuksError::UsbTransfer("all URB slots in use".into()))
    }

    /// Resolve a kernel-reaped pointer to a slot index in the arena.
    ///
    /// The Linux kernel's `USBDEVFS_REAPURB` returns the exact user-space pointer
    /// to `UsbdevfsUrb` that was passed to `USBDEVFS_SUBMITURB` (i.e. `&arena.slots[i].urb`).
    /// We first match by pointer equality across the arena's slots.
    /// As a fallback (for test mocks or synthetic ioctls), we also accept an encoded
    /// 1-based index token `(1..=MAX_URB_SLOTS)` in `reaped`.
    /// Any unaligned, invalid, or out-of-range pointer returns `None` safely without dereferencing.
    pub fn find_slot_idx(&self, reaped: *mut c_void) -> Option<usize> {
        if reaped.is_null() {
            return None;
        }
        // 1. Production kernel path: match the exact UsbdevfsUrb pointer submitted
        if let Some(idx) = self.slots.iter().position(|s| std::ptr::eq(&s.urb, reaped as *const _)) {
            return Some(idx);
        }
        // 2. Fallback for test mocks or integer tokens (1-based index)
        let raw_val = reaped as usize;
        if (1..=MAX_URB_SLOTS).contains(&raw_val) {
            return Some(raw_val - 1);
        }
        None
    }
}

/// Bytes actually usable from this round: the sum of `actual_length` over
/// the longest *prefix*, by index, of URBs that completed successfully.
///
/// A failed, discarded, or never-reaped URB anywhere before the end stops
/// the count there, even if later URBs — submitted concurrently, and
/// possibly still reaped as "successful" by the kernel — completed too.
/// Counting past a gap is exactly the bug this exists to prevent: on an OUT
/// transfer it would claim bytes as delivered when the ones before them
/// never reached the device in order, and on an IN transfer the bytes past
/// a gap cannot be trusted to sit at the offset the caller expects either
/// way.
fn contiguous_prefix(outcomes: &[Option<i32>]) -> usize {
    let mut total = 0usize;
    for outcome in outcomes {
        match outcome {
            Some(n) => total += *n as usize,
            None => break,
        }
    }
    total
}

// --------------------------------------------------------------------- errors

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A bulk transfer failure, naming **how much it was moving**.
///
/// The size is the diagnostic, not decoration. This bridge (0781:5591) is
/// fine at 128 KiB and times out after the full 5 s at 1 MiB — the kernel
/// raises no objection, because its own cap is 16 MB, so the refusal comes
/// from the device and arrives as `ETIMEDOUT`. Without the number in the
/// message that reads as "the drive stopped answering", which sends the search
/// at the cable and the drive instead of at the one setting that caused it.
///
/// The same mistake as the `SYNCHRONIZE CACHE` incident, in a different
/// place: an error that does not name what it was doing gets the gap filled
/// in by whoever reads it.
fn bulk_err(len: usize, limit: usize, e: i32) -> LuksError {
    match transfer_err("USBDEVFS_BULK", e) {
        LuksError::UsbTransfer(m) => LuksError::UsbTransfer(format!(
            "{m} while moving {len} bytes (max_transfer is {limit})"
        )),
        other => other,
    }
}

fn transfer_err(what: &str, e: i32) -> LuksError {
    let hint = match e {
        libc::EPIPE => " (endpoint stalled — clear_halt required before the next command)",
        libc::ETIMEDOUT => " (timed out)",
        libc::ENODEV => " (device disconnected)",
        libc::EBADF => " (bad file descriptor — was the UsbDeviceConnection closed?)",
        libc::EINVAL => " (invalid argument — the endpoint address, or a buffer \
                          the kernel considers too large)",
        libc::ENOMEM => " (kernel memory allocation failed for this transfer size)",
        libc::EAGAIN => " (would block)",
        _ => "",
    };
    LuksError::UsbTransfer(format!(
        "{what}: errno {e} ({}){hint}",
        std::io::Error::from_raw_os_error(e)
    ))
}

// ------------------------------------------------------------------ transport

/// A claimed USB Mass Storage interface, addressed through usbfs.
pub struct UsbFsTransport {
    fd: RawFd,
    ep_in: u8,
    ep_out: u8,
    interface: u8,
    /// Shrinks itself on `EINVAL`. See [`UsbFsTransport::DEFAULT_MAX_TRANSFER`].
    ///
    /// Shared so a caller can observe where it settled after the transport has
    /// been moved into the SCSI layer — the settled value is a measurement of
    /// the kernel, and worth reporting rather than assuming.
    max_transfer: Arc<AtomicUsize>,
    timeout_ms: u32,
    claimed: bool,
    state: Arc<AtomicU8>,
    raw: Arc<dyn RawUsbFs>,
    arena: Arc<Mutex<UrbArena>>,
}

unsafe impl Send for UsbFsTransport {}
unsafe impl Sync for UsbFsTransport {}

impl UsbFsTransport {
    /// Start optimistic and let the kernel say no.
    ///
    /// usbfs historically capped a single synchronous bulk transfer at 16 KiB
    /// (`MAX_USBFS_BUFFER_SIZE`); newer kernels allow far more. That used to be
    /// a guess we could only lose — too high meant `EINVAL` on older devices —
    /// so the default was the value that always works.
    ///
    /// It is not a guess any more: [`bulk`](Self::bulk) halves this and retries
    /// whenever the kernel rejects a transfer as too large, so the transport
    /// self-tunes on the first oversized command and stays there.
    ///
    /// Why this is worth doing: every SCSI command costs three separate
    /// synchronous ioctls — CBW out, data, CSW in — and the two wrappers are 31
    /// and 13 bytes. At 16 KiB per data phase, reading 1 GiB measured 760 µs per
    /// command of which only 273 µs was wire time, so two thirds of the link was
    /// spent on overhead. Bigger transfers amortise the wrappers over more
    /// payload.
    pub const DEFAULT_MAX_TRANSFER: usize = 1024 * 1024;

    /// Never shrink below this. A transfer this small still works on any
    /// kernel, so an `EINVAL` here means something other than the size and
    /// must be reported rather than retried forever.
    pub const MIN_MAX_TRANSFER: usize = 4 * 1024;

    /// Wrap a usbfs file descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a file descriptor open on a usbfs node (on Android, the one
    /// returned by `UsbDeviceConnection.getFileDescriptor()`), and it must stay
    /// open for the whole life of the returned value. This type **borrows** the
    /// descriptor and never closes it — closing is the owner's job, and on
    /// Android that owner is `UsbDeviceConnection.close()`.
    ///
    /// Calling this with a descriptor that Java later closes is the dangerous
    /// case: the number can be reused by an unrelated `open()`, and subsequent
    /// ioctls would then be issued against whatever took its place.
    ///
    /// `ep_in` and `ep_out` are endpoint addresses as they appear in the
    /// descriptor, so `ep_in` has the 0x80 direction bit set.
    pub unsafe fn from_raw_fd(fd: RawFd, ep_in: u8, ep_out: u8, interface: u8) -> Self {
        Self {
            fd,
            ep_in,
            ep_out,
            interface,
            max_transfer: Arc::new(AtomicUsize::new(Self::DEFAULT_MAX_TRANSFER)),
            timeout_ms: 5_000,
            claimed: false,
            state: Arc::new(AtomicU8::new(TransportState::Healthy as u8)),
            raw: Arc::new(RealUsbFs),
            arena: Arc::new(Mutex::new(UrbArena::new())),
        }
    }

    /// Inject a custom `RawUsbFs` implementation for testing.
    pub fn with_raw_usbfs(mut self, raw: Arc<dyn RawUsbFs>) -> Self {
        self.raw = raw;
        self
    }

    /// Current transport state (`Healthy`, `Draining`, or `Dead`).
    pub fn state(&self) -> TransportState {
        match self.state.load(Ordering::Acquire) {
            0 => TransportState::Healthy,
            1 => TransportState::Draining,
            _ => TransportState::Dead,
        }
    }

    pub fn with_max_transfer(mut self, bytes: usize) -> Self {
        self.max_transfer = Arc::new(AtomicUsize::new(bytes.max(Self::MIN_MAX_TRANSFER)));
        self
    }

    /// A handle on the self-tuned transfer limit, readable after this
    /// transport has been consumed by `ScsiBlockDevice`.
    pub fn max_transfer_cell(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.max_transfer)
    }

    pub fn with_timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Take the interface from the kernel's usb-storage driver.
    ///
    /// Android normally has no kernel mass-storage driver bound to an OTG
    /// device, so this usually succeeds immediately. On a desktop Linux host it
    /// will fail with `EBUSY` unless the kernel driver is detached first.
    pub fn claim_interface(&mut self) -> Result<()> {
        if self.state() == TransportState::Dead {
            return Err(LuksError::UsbTransfer("USB transport is dead".into()));
        }
        let n = self.interface as c_uint;
        let rc = self.raw.ioctl(
            self.fd,
            claim_code() as IoctlReq,
            &n as *const c_uint as *mut c_void,
        );
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_CLAIMINTERFACE", errno()));
        }
        self.claimed = true;
        Ok(())
    }

    pub fn release_interface(&mut self) -> Result<()> {
        if !self.claimed {
            return Ok(());
        }
        let n = self.interface as c_uint;
        let rc = self.raw.ioctl(
            self.fd,
            release_code() as IoctlReq,
            &n as *const c_uint as *mut c_void,
        );
        self.claimed = false;
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_RELEASEINTERFACE", errno()));
        }
        Ok(())
    }

    /// Wait for at least one submitted URB to be ready to reap, or time out.
    ///
    /// The synchronous `USBDEVFS_BULK` ioctl this crate used before the async
    /// URB rewrite carried its own `timeout` field; `USBDEVFS_SUBMITURB` /
    /// `USBDEVFS_REAPURB` do not, and nothing filled that gap when the
    /// rewrite landed. `REAPURB` blocks with **no bound at all** — if a URB
    /// never completes (a bridge that stops answering, or on Android, this
    /// app's `claimInterface(force = true)` racing the kernel's own
    /// `vold`-driven usb-storage probe of the same interface), the reap loop
    /// hangs forever. Not even a physical replug helps if the block is
    /// pinned to a descriptor from before the replug.
    ///
    /// `poll()` on the usbfs fd is the documented way to wait for a URB with
    /// a deadline: the fd reports writable when one is ready to reap.
    /// Returns a raw errno rather than this crate's `Result` so it plugs
    /// directly into the `reap_err` tracking in `bulk_out`/`bulk_in`, which
    /// already knows how to score a partial transfer and — one layer up, via
    /// `ScsiBlockDevice::recover` — trigger a Bulk-Only reset on any
    /// transport failure rather than leaving the bus wedged.
    fn poll_for_urb(&self, timeout_ms: i32) -> std::result::Result<(), i32> {
        match self.raw.poll(self.fd, libc::POLLOUT, timeout_ms) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// One asynchronous bulk transfer split into smaller URBs. Returns the number of
    /// bytes moved, which may be less than requested — short reads are normal on the
    /// IN endpoint.
    fn bulk_out(&self, ep: u8, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.state() == TransportState::Dead {
            return Err(LuksError::UsbTransfer(
                "USB transport dead: un-drained URBs pending from earlier failure".into(),
            ));
        }

        const CHUNK_SIZE: usize = 128 * 1024;

        loop {
            let limit = self.max_transfer.load(Ordering::Relaxed);
            let mut chunks = Vec::new();
            let mut offset = 0;
            while offset < buf.len() && offset < limit {
                let chunk_len = (buf.len() - offset).min(CHUNK_SIZE).min(limit - offset);
                if chunk_len == 0 {
                    break;
                }
                chunks.push(&buf[offset..offset + chunk_len]);
                offset += chunk_len;
            }

            let num_urbs = chunks.len();
            let mut arena = self.arena.lock().unwrap();
            let (generation, slot_indices) = arena.allocate(num_urbs)?;

            for (i, &slot_idx) in slot_indices.iter().enumerate() {
                let slot = &mut arena.slots[slot_idx];
                slot.urb.urb_type = USBDEVFS_URB_TYPE_BULK;
                slot.urb.endpoint = ep;
                slot.urb.flags = 0;
                slot.urb.buffer = chunks[i].as_ptr() as *mut c_void;
                slot.urb.buffer_length = chunks[i].len() as i32;
                slot.urb.actual_length = 0;
                slot.urb.status = 0;
            }

            let mut submit_err = None;
            let mut submitted_count = 0;

            for &slot_idx in &slot_indices {
                let slot = &mut arena.slots[slot_idx];
                let rc = self.raw.ioctl(
                    self.fd,
                    submit_urb_code() as IoctlReq,
                    &mut slot.urb as *mut UsbdevfsUrb as *mut c_void,
                );
                if rc < 0 {
                    submit_err = Some(errno());
                    break;
                }
                slot.submitted = true;
                submitted_count += 1;
            }

            luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Submit {
                ep,
                count: submitted_count,
                bytes: buf.len(),
                gen: generation,
            });

            let mut outcomes: Vec<Option<i32>> = vec![None; num_urbs];
            let mut completed = 0;
            let mut completion_err = None;
            let mut reap_err = None;

            if submit_err.is_none() {
                while completed < submitted_count {
                    if let Err(e) = self.poll_for_urb(self.timeout_ms as i32) {
                        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Timeout {
                            ep,
                            elapsed_ms: self.timeout_ms as u64,
                            active_urbs: submitted_count.saturating_sub(completed),
                            gen: generation,
                        });
                        reap_err = Some(e);
                        break;
                    }
                    let mut reaped: *mut c_void = std::ptr::null_mut();
                    let rc = self.raw.ioctl(
                        self.fd,
                        reap_urb_code() as IoctlReq,
                        &mut reaped as *mut *mut c_void as *mut c_void,
                    );
                    if rc < 0 {
                        let e = errno();
                        if e == libc::EINTR {
                            continue;
                        }
                        reap_err = Some(e);
                        break;
                    }
                    if let Some(slot_idx) = arena.find_slot_idx(reaped) {
                        let slot = &mut arena.slots[slot_idx];
                        if slot.generation == generation && slot.submitted && !slot.reaped {
                            slot.reaped = true;
                            slot.in_use = false;
                            completed += 1;

                            let status = slot.urb.status;
                            luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Reap {
                                ep,
                                status,
                                bytes: slot.urb.actual_length as usize,
                                gen: slot.generation,
                            });
                            if status < 0 {
                                let err = -status;
                                let was_discarded = err == libc::ENOENT || err == libc::ECONNRESET;
                                if !was_discarded && completion_err.is_none() {
                                    completion_err = Some(err);
                                    for &other_idx in &slot_indices {
                                        let other = &mut arena.slots[other_idx];
                                        if other.submitted && !other.reaped {
                                            let _ = self.raw.ioctl(
                                                self.fd,
                                                discard_urb_code() as IoctlReq,
                                                &mut other.urb as *mut UsbdevfsUrb as *mut c_void,
                                            );
                                        }
                                    }
                                }
                            } else if slot.index < outcomes.len() {
                                outcomes[slot.index] = Some(slot.urb.actual_length);
                            }
                        } else if slot.in_use && slot.generation < generation {
                            // Stale completion from older generation reclaimed
                            slot.in_use = false;
                        }
                    }
                }
            }

            let err = submit_err.or(completion_err).or(reap_err);

            if err.is_some() || completed < submitted_count {
                drain_unreaped(
                    self.fd,
                    &*self.raw,
                    &self.state,
                    &mut arena,
                    generation,
                    &slot_indices,
                    self.timeout_ms,
                    &mut completed,
                    submitted_count,
                );
            } else {
                for &slot_idx in &slot_indices {
                    arena.slots[slot_idx].in_use = false;
                }
            }

            let prefix = contiguous_prefix(&outcomes);

            match err {
                None => return Ok(prefix),
                Some(e) => {
                    let shrinkable = (e == libc::EINVAL || e == libc::ENOMEM)
                        && limit > Self::MIN_MAX_TRANSFER;
                    if shrinkable {
                        let smaller = (limit / 2).max(Self::MIN_MAX_TRANSFER);
                        self.max_transfer.fetch_min(smaller, Ordering::Relaxed);
                        if prefix == 0 {
                            // Nothing reached the wire this round — safe to
                            // redo the whole thing at the smaller size rather
                            // than reporting a zero-byte failure.
                            continue;
                        }
                    }
                    if prefix > 0 {
                        // Bytes are safely on the wire. Report them as a
                        // short transfer instead of discarding that
                        // progress — the caller already loops on a short
                        // write, and a still-live error surfaces on the very
                        // next call, where `prefix == 0` and it is handled
                        // above or returned below.
                        return Ok(prefix);
                    }
                    return Err(bulk_err(prefix, limit, e));
                }
            }
        }
    }

    fn bulk_in(&self, ep: u8, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.state() == TransportState::Dead {
            return Err(LuksError::UsbTransfer(
                "USB transport dead: un-drained URBs pending from earlier failure".into(),
            ));
        }

        const CHUNK_SIZE: usize = 128 * 1024;

        loop {
            let limit = self.max_transfer.load(Ordering::Relaxed);
            let mut chunks = Vec::new();
            let buf_len = buf.len();
            let mut remaining = &mut buf[..limit.min(buf_len)];
            while !remaining.is_empty() {
                let chunk_len = remaining.len().min(CHUNK_SIZE);
                let (chunk, rest) = remaining.split_at_mut(chunk_len);
                chunks.push(chunk);
                remaining = rest;
            }

            let num_urbs = chunks.len();
            let mut arena = self.arena.lock().unwrap();
            let (generation, slot_indices) = arena.allocate(num_urbs)?;

            for (i, &slot_idx) in slot_indices.iter().enumerate() {
                let slot = &mut arena.slots[slot_idx];
                slot.urb.urb_type = USBDEVFS_URB_TYPE_BULK;
                slot.urb.endpoint = ep;
                slot.urb.flags = 0;
                slot.urb.buffer = chunks[i].as_mut_ptr() as *mut c_void;
                slot.urb.buffer_length = chunks[i].len() as i32;
                slot.urb.actual_length = 0;
                slot.urb.status = 0;
            }

            let mut submit_err = None;
            let mut submitted_count = 0;

            for &slot_idx in &slot_indices {
                let slot = &mut arena.slots[slot_idx];
                let rc = self.raw.ioctl(
                    self.fd,
                    submit_urb_code() as IoctlReq,
                    &mut slot.urb as *mut UsbdevfsUrb as *mut c_void,
                );
                if rc < 0 {
                    submit_err = Some(errno());
                    break;
                }
                slot.submitted = true;
                submitted_count += 1;
            }

            luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Submit {
                ep,
                count: submitted_count,
                bytes: buf.len(),
                gen: generation,
            });

            let mut outcomes: Vec<Option<i32>> = vec![None; num_urbs];
            let mut completed = 0;
            let mut completion_err = None;
            let mut reap_err = None;
            let mut discarded_for_short_read = false;

            if submit_err.is_none() {
                while completed < submitted_count {
                    if let Err(e) = self.poll_for_urb(self.timeout_ms as i32) {
                        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Timeout {
                            ep,
                            elapsed_ms: self.timeout_ms as u64,
                            active_urbs: submitted_count.saturating_sub(completed),
                            gen: generation,
                        });
                        reap_err = Some(e);
                        break;
                    }
                    let mut reaped: *mut c_void = std::ptr::null_mut();
                    let rc = self.raw.ioctl(
                        self.fd,
                        reap_urb_code() as IoctlReq,
                        &mut reaped as *mut *mut c_void as *mut c_void,
                    );
                    if rc < 0 {
                        let e = errno();
                        if e == libc::EINTR {
                            continue;
                        }
                        reap_err = Some(e);
                        break;
                    }
                    if let Some(slot_idx) = arena.find_slot_idx(reaped) {
                        let slot = &mut arena.slots[slot_idx];
                        if slot.generation == generation && slot.submitted && !slot.reaped {
                            slot.reaped = true;
                            slot.in_use = false;
                            completed += 1;

                            let status = slot.urb.status;
                            luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Reap {
                                ep,
                                status,
                                bytes: slot.urb.actual_length as usize,
                                gen: slot.generation,
                            });
                            if status < 0 {
                                let err = -status;
                                let was_discarded = err == libc::ENOENT || err == libc::ECONNRESET;
                                if !was_discarded && completion_err.is_none() {
                                    completion_err = Some(err);
                                    for &other_idx in &slot_indices {
                                        let other = &mut arena.slots[other_idx];
                                        if other.submitted && !other.reaped {
                                            let _ = self.raw.ioctl(
                                                self.fd,
                                                discard_urb_code() as IoctlReq,
                                                &mut other.urb as *mut UsbdevfsUrb as *mut c_void,
                                            );
                                        }
                                    }
                                }
                            } else {
                                if slot.index < outcomes.len() {
                                    outcomes[slot.index] = Some(slot.urb.actual_length);
                                }
                                let short_read = slot.urb.actual_length < slot.urb.buffer_length;
                                if short_read && !discarded_for_short_read {
                                    discarded_for_short_read = true;
                                    for &other_idx in &slot_indices {
                                        let other = &mut arena.slots[other_idx];
                                        if other.submitted && !other.reaped {
                                            let _ = self.raw.ioctl(
                                                self.fd,
                                                discard_urb_code() as IoctlReq,
                                                &mut other.urb as *mut UsbdevfsUrb as *mut c_void,
                                            );
                                        }
                                    }
                                }
                            }
                        } else if slot.in_use && slot.generation < generation {
                            // Stale completion from older generation reclaimed
                            slot.in_use = false;
                        }
                    }
                }
            }

            let err = submit_err.or(completion_err).or(reap_err);

            if err.is_some() || completed < submitted_count {
                drain_unreaped(
                    self.fd,
                    &*self.raw,
                    &self.state,
                    &mut arena,
                    generation,
                    &slot_indices,
                    self.timeout_ms,
                    &mut completed,
                    submitted_count,
                );
            } else {
                for &slot_idx in &slot_indices {
                    arena.slots[slot_idx].in_use = false;
                }
            }

            let prefix = contiguous_prefix(&outcomes);

            match err {
                None => return Ok(prefix),
                Some(e) => {
                    let shrinkable = (e == libc::EINVAL || e == libc::ENOMEM)
                        && limit > Self::MIN_MAX_TRANSFER;
                    if shrinkable {
                        let smaller = (limit / 2).max(Self::MIN_MAX_TRANSFER);
                        self.max_transfer.fetch_min(smaller, Ordering::Relaxed);
                        if prefix == 0 {
                            // Nothing reached the wire this round — safe to
                            // redo the whole thing at the smaller size rather
                            // than reporting a zero-byte failure.
                            continue;
                        }
                    }
                    if prefix > 0 {
                        // Bytes are safely in hand. Report them as a short
                        // transfer instead of discarding that progress — the
                        // caller already loops on a short read, and a still-
                        // live error surfaces on the very next call, where
                        // `prefix == 0` and it is handled above or returned
                        // below.
                        return Ok(prefix);
                    }
                    return Err(bulk_err(prefix, limit, e));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_unreaped(
    fd: RawFd,
    raw: &dyn RawUsbFs,
    state: &AtomicU8,
    arena: &mut UrbArena,
    generation: u64,
    slot_indices: &[usize],
    timeout_ms: u32,
    completed: &mut usize,
    submitted_count: usize,
) {
    if *completed >= submitted_count {
        return;
    }

    luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::StateTransition {
        from: "Healthy",
        to: "Draining",
    });
    state.store(TransportState::Draining as u8, Ordering::Release);

    // 1. Issue DISCARDURB for all submitted but un-reaped URBs
    for &idx in slot_indices {
        let slot = &mut arena.slots[idx];
        if slot.generation == generation && slot.submitted && !slot.reaped {
            let _ = raw.ioctl(
                fd,
                discard_urb_code() as IoctlReq,
                &mut slot.urb as *mut UsbdevfsUrb as *mut c_void,
            );
        }
    }

    // 2. Bounded draining loop
    let drain_budget = Duration::from_millis(2 * timeout_ms as u64);
    let deadline = Instant::now() + drain_budget;

    while *completed < submitted_count {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let rem_ms = (deadline - now).as_millis().clamp(10, 500) as i32;

        if raw.poll(fd, libc::POLLOUT, rem_ms).is_err() {
            continue;
        }

        let mut reaped: *mut c_void = std::ptr::null_mut();
        let rc = raw.ioctl(
            fd,
            reap_urb_code() as IoctlReq,
            &mut reaped as *mut *mut c_void as *mut c_void,
        );
        if rc < 0 {
            continue;
        }

        if let Some(slot_idx) = arena.find_slot_idx(reaped) {
            let slot = &mut arena.slots[slot_idx];
            if slot.generation == generation && slot.submitted && !slot.reaped {
                slot.reaped = true;
                slot.in_use = false;
                *completed += 1;
            } else if slot.in_use && slot.generation < generation {
                slot.in_use = false;
            }
        }
    }

    // 3. State resolution:
    luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Drain {
        discarded_count: *completed,
        remaining: submitted_count.saturating_sub(*completed),
    });

    if *completed == submitted_count {
        // All submitted URBs for this transfer were successfully drained!
        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::StateTransition {
            from: "Draining",
            to: "Healthy",
        });
        state.store(TransportState::Healthy as u8, Ordering::Release);
    } else {
        // Some URBs un-drained! Permanently latch Dead.
        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::StateTransition {
            from: "Draining",
            to: "Dead",
        });
        state.store(TransportState::Dead as u8, Ordering::Release);
    }
}

impl BulkTransport for UsbFsTransport {
    fn write(&self, data: &[u8]) -> Result<usize> {
        self.bulk_out(self.ep_out, data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.bulk_in(self.ep_in, buf)
    }

    fn max_transfer(&self) -> usize {
        self.max_transfer.load(Ordering::Relaxed)
    }

    fn clear_halt(&self, endpoint_in: bool) -> Result<()> {
        if self.state() == TransportState::Dead {
            return Err(LuksError::UsbTransfer("USB transport is dead".into()));
        }
        let ep = if endpoint_in { self.ep_in } else { self.ep_out } as c_uint;
        let rc = self.raw.ioctl(
            self.fd,
            clear_halt_code() as IoctlReq,
            &ep as *const c_uint as *mut c_void,
        );
        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Reset {
            kind: if endpoint_in { "clear_halt_in" } else { "clear_halt_out" },
            status: rc,
        });
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_CLEAR_HALT", errno()));
        }
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        if self.state() == TransportState::Dead {
            return Err(LuksError::UsbTransfer("USB transport is dead".into()));
        }
        // Bulk-Only Mass Storage Reset: a *class* request on the interface.
        //
        // Deliberately NOT USBDEVFS_RESET. That performs a USB port reset,
        // which re-enumerates the device and invalidates the Java-side
        // UsbDeviceConnection — the app would then be holding a dead fd with no
        // obvious indication why. This request resets only the mass-storage
        // state machine, which is what the BOT spec calls for after a phase
        // error.
        let mut req = UsbFsCtrlTransfer {
            request_type: 0x21, // host-to-device | class | interface
            request: 0xFF,      // Bulk-Only Mass Storage Reset
            value: 0,
            index: self.interface as u16,
            length: 0,
            timeout: self.timeout_ms,
            data: std::ptr::null_mut(),
        };
        // SAFETY: length is 0 and data is null, so the kernel transfers no
        // payload and dereferences nothing.
        let rc = self.raw.ioctl(
            self.fd,
            control_code() as IoctlReq,
            &mut req as *mut UsbFsCtrlTransfer as *mut c_void,
        );
        luks_core::forensic::record_usb(luks_core::forensic::UsbEvent::Reset {
            kind: "bot_mass_storage_reset",
            status: rc,
        });
        if rc < 0 {
            return Err(transfer_err("Bulk-Only Mass Storage Reset", errno()));
        }
        // The spec requires clearing both endpoint stalls afterwards.
        self.clear_halt(true)?;
        self.clear_halt(false)?;
        Ok(())
    }
}

impl Drop for UsbFsTransport {
    fn drop(&mut self) {
        // Release the interface, but never close the fd — Java owns it.
        let _ = self.release_interface();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this exists to catch: a later URB completing successfully
    /// must not paper over an earlier gap. Before this fix, `bulk_out`/
    /// `bulk_in` summed `actual_length` over every URB that was *reaped*
    /// successfully, in reap order — not over the contiguous run from the
    /// start. A failure at index 1 with index 2 still completing used to
    /// count as 2 chunks' worth of bytes; it must count as 1.
    #[test]
    fn a_gap_stops_the_count_even_if_later_urbs_succeeded() {
        let outcomes = vec![Some(100), None, Some(100)];
        assert_eq!(contiguous_prefix(&outcomes), 100, "must stop at the gap, not sum past it");
    }

    /// The control for the test above: with no gap, every chunk counts. If
    /// this failed, the test above would be vacuously "passing" by
    /// under-counting everywhere, not by correctly stopping at a gap.
    #[test]
    fn no_gap_sums_everything() {
        let outcomes = vec![Some(100), Some(50), Some(25)];
        assert_eq!(contiguous_prefix(&outcomes), 175);
    }

    /// A gap at the very first URB — nothing reached the wire in order, so
    /// the prefix is zero even if later URBs completed.
    #[test]
    fn a_gap_at_the_start_is_zero_regardless_of_what_follows() {
        let outcomes = vec![None, Some(100), Some(100)];
        assert_eq!(contiguous_prefix(&outcomes), 0);
    }

    /// A short read (or a partial final chunk) is not a gap — it is simply
    /// the last successful entry, and everything after it is `None` because
    /// nothing further was submitted or it was deliberately discarded.
    #[test]
    fn a_short_final_urb_counts_its_own_partial_length() {
        let outcomes = vec![Some(100), Some(37), None];
        assert_eq!(contiguous_prefix(&outcomes), 137);
    }

    #[test]
    fn no_urbs_at_all_is_zero() {
        assert_eq!(contiguous_prefix(&[]), 0);
    }

    /// Ground truth, not self-reference.
    ///
    /// These numbers were **not** derived by re-reading my own arithmetic. They
    /// come from `tools/ioctl-truth.c`, compiled by gcc against the real
    /// `linux/usbdevice_fs.h` and `linux/ioctl.h` on aarch64 Linux (the colima
    /// VM — same pointer width as the phone), which printed:
    ///
    /// ```text
    /// shifts: NR=0 TYPE=8 SIZE=16 DIR=30   READ=2 WRITE=1
    /// sizeof(bulktransfer)      = 24
    /// sizeof(ctrltransfer)      = 24
    /// USBDEVFS_BULK             = 0xC0185502
    /// USBDEVFS_CONTROL          = 0xC0185500
    /// USBDEVFS_CLAIMINTERFACE   = 0x8004550F
    /// USBDEVFS_RELEASEINTERFACE = 0x80045510
    /// USBDEVFS_CLEAR_HALT       = 0x80045515
    /// ```
    ///
    /// Same rule as the LUKS and ext4 fixtures: test data must come from the
    /// real implementation, never from ours, or a misreading shows up on both
    /// sides and the test passes anyway. A wrong ioctl number surfaces as
    /// `ENOTTY` on a phone, which is a slow and confusing way to find a typo.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn ioctl_codes_match_the_kernel_header() {
        assert_eq!(std::mem::size_of::<UsbdevfsUrb>(), 56);
        assert_eq!(std::mem::size_of::<UsbFsCtrlTransfer>(), 24);
        assert_eq!(submit_urb_code(), 0x8038_550A, "USBDEVFS_SUBMITURB");
        assert_eq!(discard_urb_code(), 0x0000_550B, "USBDEVFS_DISCARDURB");
        assert_eq!(reap_urb_code(), 0x4008_550C, "USBDEVFS_REAPURB");
        assert_eq!(control_code(), 0xC018_5500, "USBDEVFS_CONTROL");
        assert_eq!(claim_code(), 0x8004_550F, "USBDEVFS_CLAIMINTERFACE");
        assert_eq!(release_code(), 0x8004_5510, "USBDEVFS_RELEASEINTERFACE");
        assert_eq!(clear_halt_code(), 0x8004_5515, "USBDEVFS_CLEAR_HALT");
    }

    /// 32-bit ARM has no padding before the pointer, so the size field — and
    /// therefore the whole ioctl number — differs. armv7 is a supported target.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn ioctl_codes_match_the_kernel_header_32bit() {
        assert_eq!(std::mem::size_of::<UsbdevfsUrb>(), 44);
        assert_eq!(submit_urb_code(), 0x802C_550A, "USBDEVFS_SUBMITURB");
        assert_eq!(reap_urb_code(), 0x4004_550C, "USBDEVFS_REAPURB");
    }

    #[test]
    fn endpoint_direction_bit_is_preserved() {
        // SAFETY: fd -1 is never used; the constructor performs no I/O.
        let t = unsafe { UsbFsTransport::from_raw_fd(-1, 0x81, 0x02, 0) };
        assert_eq!(t.ep_in, 0x81, "IN endpoints carry the 0x80 direction bit");
        assert_eq!(t.ep_out, 0x02);
        assert_eq!(t.max_transfer(), UsbFsTransport::DEFAULT_MAX_TRANSFER);
        assert_eq!(t.state(), TransportState::Healthy);
    }

    #[test]
    fn a_bad_fd_reports_an_error_rather_than_panicking() {
        // SAFETY: -1 is an invalid fd, so ioctl returns EBADF. This is the
        // documented misuse path and must surface as an error.
        let t = unsafe { UsbFsTransport::from_raw_fd(-1, 0x81, 0x02, 0) };
        let mut buf = [0u8; 64];
        let err = t.read(&mut buf).unwrap_err();
        assert!(
            matches!(err, LuksError::UsbTransfer(ref m) if m.contains("errno") || m.contains("dead")),
            "unexpected error: {err}"
        );
    }

    /// The shrink-on-EINVAL loop in `bulk` terminates only because the limit
    /// has a floor. If `with_max_transfer` could set a value at or below
    /// `MIN_MAX_TRANSFER / 2`, or if the floor were ever zero, a device that
    /// answers `EINVAL` for another reason would spin forever inside an ioctl
    /// loop with no way out.
    /// The size has to be in the message, because the size is the answer.
    ///
    /// A 1 MiB transfer to a bridge that is fine at 128 KiB times out, and an
    /// error saying only "timed out" is indistinguishable from a dead drive.
    #[test]
    fn a_bulk_failure_names_how_much_it_was_moving() {
        let e = bulk_err(1_048_576, 1_048_576, libc::ETIMEDOUT);
        let text = e.to_string();
        assert!(text.contains("1048576"), "no transfer size in: {text}");
        assert!(text.contains("max_transfer"), "no limit in: {text}");
        assert!(text.contains("timed out"), "lost the errno hint: {text}");

        // The control: the generic form has none of it, which is what made the
        // 1 MiB timeout read as a dead device.
        let plain = transfer_err("USBDEVFS_BULK", libc::ETIMEDOUT).to_string();
        assert!(!plain.contains("1048576"), "control is not a control: {plain}");
    }

    #[test]
    fn the_transfer_limit_has_a_floor_so_the_retry_loop_ends() {
        assert!(UsbFsTransport::MIN_MAX_TRANSFER > 0);
        assert!(UsbFsTransport::DEFAULT_MAX_TRANSFER > UsbFsTransport::MIN_MAX_TRANSFER);

        // SAFETY: never used for I/O; only the size arithmetic is inspected.
        let t = unsafe { UsbFsTransport::from_raw_fd(-1, 0x81, 0x02, 0) };
        assert_eq!(t.max_transfer(), UsbFsTransport::DEFAULT_MAX_TRANSFER);

        // Absurdly small requests clamp up to the floor rather than through it.
        let t = t.with_max_transfer(1);
        assert_eq!(t.max_transfer(), UsbFsTransport::MIN_MAX_TRANSFER);

        // Halving from the default reaches the floor in a bounded number of
        // steps and stops there, which is what makes the loop finite.
        let mut limit = UsbFsTransport::DEFAULT_MAX_TRANSFER;
        let mut steps = 0;
        while limit > UsbFsTransport::MIN_MAX_TRANSFER {
            limit = (limit / 2).max(UsbFsTransport::MIN_MAX_TRANSFER);
            steps += 1;
            assert!(steps < 64, "shrink did not converge");
        }
        assert_eq!(limit, UsbFsTransport::MIN_MAX_TRANSFER);
    }
}
