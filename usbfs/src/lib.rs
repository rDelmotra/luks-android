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

fn transfer_err(what: &str, e: i32) -> LuksError {
    let hint = match e {
        libc::EPIPE => " (endpoint stalled — clear_halt required before the next command)",
        libc::ETIMEDOUT => " (timed out)",
        libc::ENODEV => " (device disconnected)",
        libc::EBADF => " (bad file descriptor — was the UsbDeviceConnection closed?)",
        libc::EINVAL => " (invalid argument — check the endpoint address)",
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
    max_transfer: usize,
    timeout_ms: u32,
    claimed: bool,
}

impl UsbFsTransport {
    /// usbfs historically caps a single synchronous bulk transfer at 16 KiB
    /// (`MAX_USBFS_BUFFER_SIZE`). Newer kernels allow more, but guessing high
    /// turns into `EINVAL` on older Android devices, so the default is the
    /// value that always works. Raise it with [`with_max_transfer`] once
    /// measured. The SCSI layer splits reads to fit, so this costs throughput
    /// and never correctness.
    ///
    /// [`with_max_transfer`]: Self::with_max_transfer
    pub const DEFAULT_MAX_TRANSFER: usize = 16 * 1024;

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
            max_transfer: Self::DEFAULT_MAX_TRANSFER,
            timeout_ms: 5_000,
            claimed: false,
        }
    }

    pub fn with_max_transfer(mut self, bytes: usize) -> Self {
        self.max_transfer = bytes.max(512);
        self
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
    fn bulk(&self, ep: u8, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(self.max_transfer);

        let mut req = UsbFsBulkTransfer {
            ep: ep as c_uint,
            len: len as c_uint,
            timeout: self.timeout_ms,
            data: buf.as_mut_ptr() as *mut c_void,
        };

        // SAFETY: `req.data` points at `len` writable bytes owned by `buf`, and
        // `req.len` is exactly that count, so the kernel cannot write out of
        // bounds. The struct layout is `#[repr(C)]` and its size is what the
        // ioctl code was computed from.
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                bulk_code() as IoctlReq,
                &mut req as *mut UsbFsBulkTransfer as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(transfer_err("USBDEVFS_BULK", errno()));
        }
        Ok(rc as usize)
    }
}

impl BulkTransport for UsbFsTransport {
    fn write(&self, data: &[u8]) -> Result<usize> {
        // usbfs wants a `*mut` even for an OUT transfer. Rather than cast away
        // the shared reference — which would be UB to hand out as `&mut` — copy
        // into a local buffer. A CBW is 31 bytes, so this is free.
        let mut owned = data.to_vec();
        self.bulk(self.ep_out, &mut owned)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.bulk(self.ep_in, buf)
    }

    fn max_transfer(&self) -> usize {
        self.max_transfer
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
}
