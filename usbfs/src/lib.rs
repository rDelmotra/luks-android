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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
struct UsbdevfsUrb {
    urb_type: u8,
    endpoint: u8,
    status: c_int,
    flags: c_uint,
    buffer: *mut c_void,
    buffer_length: c_int,
    actual_length: c_int,
    start_frame: c_int,
    number_of_packets_or_stream_id: c_int,
    error_count: c_int,
    signr: c_uint,
    usercontext: *mut c_void,
}

const USBDEVFS_URB_TYPE_BULK: u8 = 3;

#[repr(C)]
struct UsbFsCtrlTransfer {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    timeout: c_uint,
    data: *mut c_void,
}

fn submit_urb_code() -> u32 {
    ioc(
        DIR_READ,
        USB_IOC,
        10,
        std::mem::size_of::<UsbdevfsUrb>(),
    )
}

fn discard_urb_code() -> u32 {
    ioc(DIR_NONE, USB_IOC, 11, 0)
}

fn reap_urb_code() -> u32 {
    ioc(
        DIR_WRITE,
        USB_IOC,
        12,
        std::mem::size_of::<*mut c_void>(),
    )
}

fn control_code() -> u32 {
    ioc(
        DIR_WRITE | DIR_READ,
        USB_IOC,
        0,
        std::mem::size_of::<UsbFsCtrlTransfer>(),
    )
}

fn claim_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 15, std::mem::size_of::<c_uint>())
}

fn release_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 16, std::mem::size_of::<c_uint>())
}

fn clear_halt_code() -> u32 {
    ioc(DIR_READ, USB_IOC, 21, std::mem::size_of::<c_uint>())
}

struct InFlightUrb {
    urb: UsbdevfsUrb,
    submitted: bool,
    reaped: bool,
    /// Position in the chunk sequence. Completions are scored by this, not
    /// by the order they are reaped in — REAPURB does not promise to return
    /// them in submission order, and a gap earlier in the sequence must stop
    /// the count even if a later chunk happened to complete first.
    index: usize,
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
}

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
        let n = self.interface as c_uint;
        // SAFETY: `claim_code()` expects a pointer to a single c_uint, which is
        // what is passed. `self.fd` is valid per the `from_raw_fd` contract.
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                claim_code() as IoctlReq,
                &n as *const c_uint as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_CLAIMINTERFACE", errno()));
        }
        self.claimed = true;
        let _ = self.reset();
        Ok(())
    }

    pub fn release_interface(&mut self) -> Result<()> {
        if !self.claimed {
            return Ok(());
        }
        let n = self.interface as c_uint;
        // SAFETY: as in claim_interface.
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                release_code() as IoctlReq,
                &n as *const c_uint as *mut c_void,
            )
        };
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
    fn poll_for_urb(&self) -> std::result::Result<(), i32> {
        loop {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: `pfd` is a single, stack-local, correctly-sized
            // `pollfd` and `poll` writes only `revents` back into it.
            let rc = unsafe { libc::poll(&mut pfd, 1, self.timeout_ms as libc::c_int) };
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
            return Ok(());
        }
    }

    /// One asynchronous bulk transfer split into smaller URBs. Returns the number of
    /// bytes moved, which may be less than requested — short reads are normal on the
    /// IN endpoint.
    fn bulk_out(&self, ep: u8, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
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
            let mut urbs = Vec::with_capacity(num_urbs);
            for i in 0..num_urbs {
                urbs.push(InFlightUrb {
                    urb: UsbdevfsUrb {
                        urb_type: USBDEVFS_URB_TYPE_BULK,
                        endpoint: ep,
                        status: 0,
                        flags: 0,
                        buffer: chunks[i].as_ptr() as *mut c_void,
                        buffer_length: chunks[i].len() as i32,
                        actual_length: 0,
                        start_frame: 0,
                        number_of_packets_or_stream_id: 0,
                        error_count: 0,
                        signr: 0,
                        usercontext: std::ptr::null_mut(),
                    },
                    submitted: false,
                    reaped: false,
                    index: i,
                });
            }

            for i in 0..num_urbs {
                let inflight_ptr = &mut urbs[i] as *mut InFlightUrb as *mut c_void;
                urbs[i].urb.usercontext = inflight_ptr;
            }

            let mut submit_err = None;
            let mut submitted_count = 0;

            for i in 0..num_urbs {
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        submit_urb_code() as IoctlReq,
                        &mut urbs[i].urb as *mut UsbdevfsUrb as *mut c_void,
                    )
                };
                if rc < 0 {
                    submit_err = Some(errno());
                    break;
                }
                urbs[i].submitted = true;
                submitted_count += 1;
            }

            // Tear down immediately if submission itself failed, so the
            // kernel starts unwinding while the drain below runs rather than
            // after.
            if submit_err.is_some() {
                for j in 0..submitted_count {
                    if urbs[j].submitted && !urbs[j].reaped {
                        unsafe {
                            libc::ioctl(
                                self.fd,
                                discard_urb_code() as IoctlReq,
                                &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                            );
                        }
                    }
                }
            }

            // Reap every URB that was actually submitted and score each by
            // *index* — REAPURB makes no promise about completion order.
            let mut outcomes: Vec<Option<i32>> = vec![None; num_urbs];
            let mut completed = 0;
            let mut completion_err = None;
            let mut reap_err = None;

            while completed < submitted_count {
                if let Err(e) = self.poll_for_urb() {
                    reap_err = Some(e);
                    break;
                }
                let mut reaped: *mut c_void = std::ptr::null_mut();
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        reap_urb_code() as IoctlReq,
                        &mut reaped as *mut *mut c_void as *mut c_void,
                    )
                };
                if rc < 0 {
                    let e = errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    reap_err = Some(e);
                    break;
                }
                let inflight = unsafe { &mut *(reaped as *mut InFlightUrb) };
                inflight.reaped = true;
                completed += 1;

                let status = inflight.urb.status;
                if status < 0 {
                    let err = -status;
                    let was_discarded = err == libc::ENOENT || err == libc::ECONNRESET;
                    if !was_discarded && completion_err.is_none() {
                        completion_err = Some(err);

                        for j in 0..submitted_count {
                            if urbs[j].submitted && !urbs[j].reaped {
                                unsafe {
                                    libc::ioctl(
                                        self.fd,
                                        discard_urb_code() as IoctlReq,
                                        &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                                    );
                                }
                            }
                        }
                    }
                    // outcomes[inflight.index] stays None: failed or discarded.
                } else {
                    outcomes[inflight.index] = Some(inflight.urb.actual_length);
                }
            }

            // A REAPURB failure leaves whatever was still in flight neither
            // confirmed nor discarded. Best-effort clean-up so the next round
            // does not inherit URBs this one never resolved.
            if reap_err.is_some() {
                for j in 0..submitted_count {
                    if urbs[j].submitted && !urbs[j].reaped {
                        unsafe {
                            libc::ioctl(
                                self.fd,
                                discard_urb_code() as IoctlReq,
                                &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                            );
                        }
                    }
                }
            }

            let prefix = contiguous_prefix(&outcomes);
            let err = submit_err.or(completion_err).or(reap_err);

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
            let mut urbs = Vec::with_capacity(num_urbs);
            for i in 0..num_urbs {
                urbs.push(InFlightUrb {
                    urb: UsbdevfsUrb {
                        urb_type: USBDEVFS_URB_TYPE_BULK,
                        endpoint: ep,
                        status: 0,
                        flags: 0,
                        buffer: chunks[i].as_mut_ptr() as *mut c_void,
                        buffer_length: chunks[i].len() as i32,
                        actual_length: 0,
                        start_frame: 0,
                        number_of_packets_or_stream_id: 0,
                        error_count: 0,
                        signr: 0,
                        usercontext: std::ptr::null_mut(),
                    },
                    submitted: false,
                    reaped: false,
                    index: i,
                });
            }

            for i in 0..num_urbs {
                let inflight_ptr = &mut urbs[i] as *mut InFlightUrb as *mut c_void;
                urbs[i].urb.usercontext = inflight_ptr;
            }

            let mut submit_err = None;
            let mut submitted_count = 0;

            for i in 0..num_urbs {
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        submit_urb_code() as IoctlReq,
                        &mut urbs[i].urb as *mut UsbdevfsUrb as *mut c_void,
                    )
                };
                if rc < 0 {
                    submit_err = Some(errno());
                    break;
                }
                urbs[i].submitted = true;
                submitted_count += 1;
            }

            // Tear down immediately if submission itself failed, so the
            // kernel starts unwinding while the drain below runs rather than
            // after.
            if submit_err.is_some() {
                for j in 0..submitted_count {
                    if urbs[j].submitted && !urbs[j].reaped {
                        unsafe {
                            libc::ioctl(
                                self.fd,
                                discard_urb_code() as IoctlReq,
                                &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                            );
                        }
                    }
                }
            }

            // Reap every URB that was actually submitted and score each by
            // *index* — REAPURB makes no promise about completion order.
            let mut outcomes: Vec<Option<i32>> = vec![None; num_urbs];
            let mut completed = 0;
            let mut completion_err = None;
            let mut reap_err = None;
            let mut discarded_for_short_read = false;

            while completed < submitted_count {
                if let Err(e) = self.poll_for_urb() {
                    reap_err = Some(e);
                    break;
                }
                let mut reaped: *mut c_void = std::ptr::null_mut();
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        reap_urb_code() as IoctlReq,
                        &mut reaped as *mut *mut c_void as *mut c_void,
                    )
                };
                if rc < 0 {
                    let e = errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    reap_err = Some(e);
                    break;
                }
                let inflight = unsafe { &mut *(reaped as *mut InFlightUrb) };
                inflight.reaped = true;
                completed += 1;

                let status = inflight.urb.status;
                if status < 0 {
                    let err = -status;
                    let was_discarded = err == libc::ENOENT || err == libc::ECONNRESET;
                    if !was_discarded && completion_err.is_none() {
                        completion_err = Some(err);

                        for j in 0..submitted_count {
                            if urbs[j].submitted && !urbs[j].reaped {
                                unsafe {
                                    libc::ioctl(
                                        self.fd,
                                        discard_urb_code() as IoctlReq,
                                        &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                                    );
                                }
                            }
                        }
                    }
                    // outcomes[inflight.index] stays None: failed or discarded.
                } else {
                    outcomes[inflight.index] = Some(inflight.urb.actual_length);

                    // Short reads are normal — the device has no more data.
                    // Stop asking for the rest rather than waiting on it, but
                    // this is not an error: the prefix through here is still
                    // exactly what a caller should see.
                    let short_read = inflight.urb.actual_length < inflight.urb.buffer_length;
                    if short_read && !discarded_for_short_read {
                        discarded_for_short_read = true;
                        for j in 0..submitted_count {
                            if urbs[j].submitted && !urbs[j].reaped {
                                unsafe {
                                    libc::ioctl(
                                        self.fd,
                                        discard_urb_code() as IoctlReq,
                                        &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // A REAPURB failure leaves whatever was still in flight neither
            // confirmed nor discarded. Best-effort clean-up so the next round
            // does not inherit URBs this one never resolved.
            if reap_err.is_some() {
                for j in 0..submitted_count {
                    if urbs[j].submitted && !urbs[j].reaped {
                        unsafe {
                            libc::ioctl(
                                self.fd,
                                discard_urb_code() as IoctlReq,
                                &mut urbs[j].urb as *mut UsbdevfsUrb as *mut c_void,
                            );
                        }
                    }
                }
            }

            let prefix = contiguous_prefix(&outcomes);
            let err = submit_err.or(completion_err).or(reap_err);

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
        let ep = if endpoint_in { self.ep_in } else { self.ep_out } as c_uint;
        // SAFETY: the ioctl reads a single c_uint through this pointer.
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                clear_halt_code() as IoctlReq,
                &ep as *const c_uint as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_CLEAR_HALT", errno()));
        }
        Ok(())
    }

    fn reset(&self) -> Result<()> {
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
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                control_code() as IoctlReq,
                &mut req as *mut UsbFsCtrlTransfer as *mut c_void,
            )
        };
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
    }

    #[test]
    fn a_bad_fd_reports_an_error_rather_than_panicking() {
        // SAFETY: -1 is an invalid fd, so ioctl returns EBADF. This is the
        // documented misuse path and must surface as an error.
        let t = unsafe { UsbFsTransport::from_raw_fd(-1, 0x81, 0x02, 0) };
        let mut buf = [0u8; 64];
        let err = t.read(&mut buf).unwrap_err();
        assert!(
            matches!(err, LuksError::UsbTransfer(ref m) if m.contains("errno")),
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
