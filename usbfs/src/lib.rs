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
use std::os::raw::{c_uint, c_void};
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
struct UsbFsBulkTransfer {
    ep: c_uint,
    len: c_uint,
    timeout: c_uint,
    data: *mut c_void,
}

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

fn bulk_code() -> u32 {
    ioc(
        DIR_WRITE | DIR_READ,
        USB_IOC,
        2,
        std::mem::size_of::<UsbFsBulkTransfer>(),
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
    pub const DEFAULT_MAX_TRANSFER: usize = 128 * 1024;

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

    /// One synchronous bulk transfer. Returns the number of bytes moved, which
    /// may be less than requested — short reads are normal on the IN endpoint.
    fn bulk_out(&self, ep: u8, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let limit = self.max_transfer.load(Ordering::Relaxed);
            let len = buf.len().min(limit);

            let mut req = UsbFsBulkTransfer {
                ep: ep as c_uint,
                len: len as c_uint,
                timeout: self.timeout_ms,
                data: buf.as_ptr() as *mut c_void,
            };

            let rc = unsafe {
                libc::ioctl(
                    self.fd,
                    bulk_code() as IoctlReq,
                    &mut req as *mut UsbFsBulkTransfer as *mut c_void,
                )
            };
            if rc >= 0 {
                return Ok(rc as usize);
            }

            let e = errno();

            if e == libc::EINVAL && limit > Self::MIN_MAX_TRANSFER {
                let smaller = (limit / 2).max(Self::MIN_MAX_TRANSFER);
                self.max_transfer.fetch_min(smaller, Ordering::Relaxed);
                continue;
            }

            return Err(bulk_err(len, limit, e));
        }
    }

    fn bulk_in(&self, ep: u8, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let limit = self.max_transfer.load(Ordering::Relaxed);
            let len = buf.len().min(limit);

            let mut req = UsbFsBulkTransfer {
                ep: ep as c_uint,
                len: len as c_uint,
                timeout: self.timeout_ms,
                data: buf.as_mut_ptr() as *mut c_void,
            };

            let rc = unsafe {
                libc::ioctl(
                    self.fd,
                    bulk_code() as IoctlReq,
                    &mut req as *mut UsbFsBulkTransfer as *mut c_void,
                )
            };
            if rc >= 0 {
                return Ok(rc as usize);
            }

            let e = errno();

            if e == libc::EINVAL && limit > Self::MIN_MAX_TRANSFER {
                let smaller = (limit / 2).max(Self::MIN_MAX_TRANSFER);
                self.max_transfer.fetch_min(smaller, Ordering::Relaxed);
                continue;
            }

            return Err(bulk_err(len, limit, e));
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
        assert_eq!(std::mem::size_of::<UsbFsBulkTransfer>(), 24);
        assert_eq!(std::mem::size_of::<UsbFsCtrlTransfer>(), 24);
        assert_eq!(bulk_code(), 0xC018_5502, "USBDEVFS_BULK");
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
        assert_eq!(std::mem::size_of::<UsbFsBulkTransfer>(), 16);
        assert_eq!(bulk_code(), 0xC010_5502, "USBDEVFS_BULK");
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
