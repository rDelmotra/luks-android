//! USB Mass Storage transport.
//!
//! ```text
//!   ScsiBlockDevice  (implements ReadAt — the rest of the stack plugs in here)
//!        |  SCSI Block Commands: INQUIRY, READ CAPACITY, READ(10)/(16)
//!        v
//!   Bulk-Only Transport:  CBW  ->  [data]  ->  CSW
//!        |
//!        v
//!   BulkTransport  (Android usbfs ioctls, or a mock in tests)
//! ```
//!
//! `BulkTransport` is the only platform-specific piece. Everything above it is
//! shared with the future Windows and macOS shells.

pub mod bot;
pub mod scsi;

pub use bot::{CommandBlockWrapper, CommandStatusWrapper, CswStatus, Direction};
pub use scsi::{Capacity, InquiryData, ScsiBlockDevice};

use crate::error::Result;

/// A pair of USB bulk endpoints.
///
/// On Android this wraps a file descriptor from `UsbDeviceConnection` and issues
/// `USBDEVFS_BULK` / `USBDEVFS_SUBMITURB` ioctls. Note that Kotlin's
/// `bulkTransfer()` is synchronous and cannot pipeline, so hitting useful
/// throughput requires the ioctl path from native code.
pub trait BulkTransport {
    /// Send on the bulk OUT endpoint. Returns bytes accepted.
    fn write(&self, data: &[u8]) -> Result<usize>;

    /// Receive on the bulk IN endpoint. Returns bytes read, which may be short.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Largest single transfer the platform will accept.
    ///
    /// usbfs has historically capped a single URB at 16 KiB, with larger limits
    /// on newer kernels. Reads are split to respect this, so a conservative
    /// value costs throughput but never correctness.
    fn max_transfer(&self) -> usize {
        128 * 1024
    }

    /// Clear a stalled endpoint. A failed SCSI command commonly stalls the IN
    /// endpoint, and the next command will not work until it is cleared.
    fn clear_halt(&self, _endpoint_in: bool) -> Result<()> {
        Ok(())
    }

    /// Bulk-Only Mass Storage Reset — the recovery of last resort.
    fn reset(&self) -> Result<()> {
        Ok(())
    }
}
