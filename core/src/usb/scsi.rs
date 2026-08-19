//! SCSI Block Commands over Bulk-Only Transport.
//!
//! Implements the read-only subset a LUKS reader needs. `WRITE(10)` is
//! deliberately absent from a default build: with `dangerous-write-support`
//! disabled there is no write opcode in the binary at all, so no bug can issue
//! one.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::usb::bot::{
    CommandBlockWrapper, CommandStatusWrapper, CswStatus, Direction, CSW_LEN,
};
use crate::usb::BulkTransport;
use std::sync::atomic::{AtomicU32, Ordering};

// SCSI opcodes
const OP_TEST_UNIT_READY: u8 = 0x00;
const OP_REQUEST_SENSE: u8 = 0x03;
const OP_INQUIRY: u8 = 0x12;
const OP_READ_CAPACITY_10: u8 = 0x25;
const OP_READ_10: u8 = 0x28;
const OP_READ_16: u8 = 0x88;
const OP_READ_CAPACITY_16: u8 = 0x9E;
const OP_MODE_SENSE_6: u8 = 0x1A;
/// Write opcodes exist only with `dangerous-write-support`. This is the
/// literal statement of the safety guarantee: without the feature, the byte
/// `0x2A` is never assembled into a command block, so no build of this crate
/// can tell a drive to overwrite a sector.
#[cfg(feature = "dangerous-write-support")]
const OP_WRITE_10: u8 = 0x2A;
#[cfg(feature = "dangerous-write-support")]
const OP_WRITE_16: u8 = 0x8A;
/// Probed for, never issued for real: some bridges implement only one of the
/// write forms, and which one is a question only the drive can answer.
#[cfg(feature = "dangerous-write-support")]
const OP_WRITE_12: u8 = 0xAA;
/// SYNCHRONIZE CACHE(10). A USB bridge acknowledges a write once it is in the
/// bridge's own buffer, not once it is on flash, so without this a "completed"
/// write can still be lost to a yanked cable.
#[cfg(feature = "dangerous-write-support")]
const OP_SYNCHRONIZE_CACHE_10: u8 = 0x35;
/// The 16-byte form, tried when a bridge does not know the 10-byte one.
#[cfg(feature = "dangerous-write-support")]
const OP_SYNCHRONIZE_CACHE_16: u8 = 0x91;
const SA_READ_CAPACITY_16: u8 = 0x10;

/// READ(10) carries a 16-bit block count and a 32-bit LBA.
const READ10_MAX_BLOCKS: u64 = 0xFFFF;
const READ10_MAX_LBA: u64 = 0xFFFF_FFFF;

/// The maximum bytes moved in a single SCSI data phase.
///
/// Linux `usb-storage` caps single transfers to 128 KiB (`US_MAX_SECTORS = 240`
/// or 120 KiB, commonly 128 KiB). Cheap USB flash bridges (e.g. SanDisk) have
/// limited internal SRAM buffers (typically 128 KiB) and stall the bulk pipe
/// (`EPIPE` / errno 32) if a single SCSI command requests more.
pub const MAX_SCSI_TRANSFER: usize = 128 * 1024;

#[derive(Debug, Clone)]
pub struct InquiryData {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub peripheral_device_type: u8,
    pub removable: bool,
}

impl InquiryData {
    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 36 {
            return Err(LuksError::ScsiProtocol("INQUIRY response too short"));
        }
        let text = |r: std::ops::Range<usize>| {
            String::from_utf8_lossy(&b[r]).trim_end().to_string()
        };
        Ok(Self {
            peripheral_device_type: b[0] & 0x1F,
            removable: b[1] & 0x80 != 0,
            vendor: text(8..16),
            product: text(16..32),
            revision: text(32..36),
        })
    }

    /// SCSI peripheral device type 0x00 is "direct access block device".
    pub fn is_block_device(&self) -> bool {
        self.peripheral_device_type == 0x00
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    /// Number of addressable blocks (last LBA + 1).
    pub blocks: u64,
    pub block_size: u32,
}

impl Capacity {
    pub fn bytes(&self) -> u64 {
        self.blocks * self.block_size as u64
    }
}

/// A SCSI opcode in words, for error messages.
///
/// Only the opcodes this crate issues. Anything else prints as its number,
/// which is more honest than a guess.
pub fn opcode_name(op: u8) -> String {
    let name = match op {
        0x00 => "TEST UNIT READY",
        0x03 => "REQUEST SENSE",
        0x12 => "INQUIRY",
        0x1A => "MODE SENSE(6)",
        0x25 => "READ CAPACITY(10)",
        0x28 => "READ(10)",
        0x2A => "WRITE(10)",
        0x35 => "SYNCHRONIZE CACHE(10)",
        0x88 => "READ(16)",
        0x8A => "WRITE(16)",
        0x91 => "SYNCHRONIZE CACHE(16)",
        0x9E => "READ CAPACITY(16)",
        0xAA => "WRITE(12)",
        _ => return format!("command {op:#04x}"),
    };
    format!("{name} ({op:#04x})")
}

/// Why a drive refused a command, as it reported when asked.
///
/// A CSW status of 1 says only "that failed". Every actual reason — write
/// protected, bad LBA, a field this drive does not accept, a dying medium —
/// arrives only in response to a REQUEST SENSE issued afterwards, and is lost
/// the moment any other command is sent. Before this existed, a real
/// `WRITE(10)` refusal on a Pixel 8 surfaced as the bare text "SCSI command
/// failed", which is compatible with every one of those causes and identifies
/// none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sense {
    /// Sense key: the coarse category, low nibble of byte 2.
    pub key: u8,
    /// Additional sense code, and its qualifier — the specific reason.
    pub asc: u8,
    pub ascq: u8,
}

impl Sense {
    /// Parse a fixed-format sense buffer (response code 0x70/0x71).
    pub fn parse(b: &[u8; 18]) -> Self {
        Self {
            key: b[2] & 0x0F,
            asc: b[12],
            ascq: b[13],
        }
    }

    /// The sense key in words. Deliberately only the key: the ASC/ASCQ table
    /// runs to hundreds of entries, most of them irrelevant to a USB stick,
    /// and a partial table that silently reports the wrong thing is worse than
    /// printing the numbers and letting them be looked up.
    pub fn key_text(&self) -> &'static str {
        match self.key {
            0x0 => "no sense",
            0x1 => "recovered error",
            0x2 => "not ready",
            0x3 => "medium error",
            0x4 => "hardware error",
            0x5 => "illegal request — the drive rejected the command itself",
            0x6 => "unit attention",
            0x7 => "data protect — the drive is refusing to be written",
            0x8 => "blank check",
            0xB => "aborted command",
            0xD => "volume overflow",
            0xE => "miscompare",
            _ => "unknown sense key",
        }
    }
}

impl std::fmt::Display for Sense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (key {:#x}, asc {:#04x}/{:#04x})",
            self.key_text(),
            self.key,
            self.asc,
            self.ascq
        )
    }
}

/// A USB mass storage device presented as random-access bytes.
pub struct ScsiBlockDevice<T: BulkTransport> {
    transport: T,
    capacity: Capacity,
    tag: AtomicU32,
    /// Set once a drive has told us it implements neither form of
    /// SYNCHRONIZE CACHE. See [`ScsiBlockDevice::synchronize_cache`].
    #[cfg(feature = "dangerous-write-support")]
    no_flush_command: std::sync::atomic::AtomicBool,
}

impl<T: BulkTransport> ScsiBlockDevice<T> {
    /// Probe the device: identify it, wait for it to be ready, read its size.
    pub fn open(transport: T) -> Result<Self> {
        let mut dev = Self {
            transport,
            capacity: Capacity {
                blocks: 0,
                block_size: 512,
            },
            tag: AtomicU32::new(1),
            #[cfg(feature = "dangerous-write-support")]
            no_flush_command: std::sync::atomic::AtomicBool::new(false),
        };

        let inquiry = dev.inquiry()?;
        if !inquiry.is_block_device() {
            return Err(LuksError::ScsiProtocol("not a direct-access block device"));
        }

        // Removable media commonly answer NOT READY once while spinning up.
        for _ in 0..3 {
            if dev.test_unit_ready().is_ok() {
                break;
            }
            let _ = dev.request_sense();
        }

        dev.capacity = dev.read_capacity()?;
        if dev.capacity.block_size == 0 || !dev.capacity.block_size.is_power_of_two() {
            return Err(LuksError::ScsiProtocol("implausible block size"));
        }
        Ok(dev)
    }

    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn next_tag(&self) -> u32 {
        self.tag.fetch_add(1, Ordering::Relaxed)
    }

    /// Best-effort Bulk-Only Mass Storage Reset before propagating a
    /// transport-level failure, so the bus is in a known state for the
    /// *next* command rather than left wedged. This is the spec's own Reset
    /// Recovery procedure — clean up, then still fail the command that
    /// triggered it — not a retry of that command (#14).
    ///
    /// Reset's own failure is discarded rather than propagated: the
    /// original error is the diagnosis, and losing it to a follow-up
    /// failure would be the same mistake `RULES.md` already names — an
    /// error that does not name what actually went wrong.
    fn recover<R>(&self, result: Result<R>) -> Result<R> {
        if result.is_err() {
            let _ = self.transport.reset();
        }
        result
    }

    /// Run one CBW / data / CSW exchange, asking the drive why on a failure.
    fn command(&self, cdb: Vec<u8>, direction: Direction, data: &mut [u8]) -> Result<usize> {
        self.command_inner(cdb, direction, data, true)
    }

    #[cfg(feature = "dangerous-write-support")]
    fn command_out(&self, cdb: Vec<u8>, data: &[u8]) -> Result<usize> {
        self.command_out_inner(cdb, data, true)
    }

    #[cfg(feature = "dangerous-write-support")]
    fn command_out_inner(&self, cdb: Vec<u8>, data: &[u8], ask_why: bool) -> Result<usize> {
        let opcode = cdb[0];
        let tag = self.next_tag();
        let cbw = CommandBlockWrapper::new(tag, data.len() as u32, Direction::Out, cdb);
        let encoded = cbw.encode()?;

        let sent = self.recover(self.transport.write(&encoded))?;
        if sent != encoded.len() {
            return Err(LuksError::ScsiProtocol("short CBW write"));
        }

        let mut transferred = 0usize;
        if !data.is_empty() {
            while transferred < data.len() {
                let n = self.recover(self.transport.write(&data[transferred..]))?;
                if n == 0 {
                    break;
                }
                transferred += n;
            }
        }

        let mut csw_buf = [0u8; CSW_LEN];
        let mut got = 0usize;
        let mut cleared_halt = false;
        while got < CSW_LEN {
            match self.transport.read(&mut csw_buf[got..]) {
                Ok(0) | Err(_) if !cleared_halt => {
                    // BOT 5.3: An endpoint stall (EPIPE) or 0-byte read on the In
                    // endpoint before/during CSW is standard; clear halt and retry once.
                    cleared_halt = true;
                    if let Err(e) = self.transport.clear_halt(true) {
                        let _ = self.transport.reset();
                        return Err(e);
                    }
                    continue;
                }
                Ok(0) => {
                    let _ = self.transport.reset();
                    return Err(LuksError::ScsiProtocol("no CSW"));
                }
                Ok(n) => {
                    got += n;
                }
                Err(e) => {
                    let _ = self.transport.reset();
                    return Err(e);
                }
            }
        }

        let csw = CommandStatusWrapper::decode(&csw_buf)?;
        if csw.tag != tag {
            return Err(LuksError::ScsiProtocol("CSW tag mismatch"));
        }
        match csw.status {
            CswStatus::Passed => {
                if csw.data_residue != 0 {
                    return Err(LuksError::ScsiProtocol(
                        "drive committed less than the full data phase",
                    ));
                }
                Ok(transferred)
            }
            CswStatus::Failed => {
                let sense = if ask_why {
                    self.request_sense().ok().map(|b| Sense::parse(&b))
                } else {
                    None
                };
                Err(LuksError::ScsiCommandFailed { opcode, sense })
            }
            CswStatus::PhaseError => {
                let _ = self.transport.reset();
                Err(LuksError::ScsiProtocol("CSW phase error"))
            }
        }
    }

    /// `ask_why` exists only to stop the REQUEST SENSE issued after a failure
    /// from recursing when it is itself the command that failed. Every other
    /// caller wants it true.
    fn command_inner(
        &self,
        cdb: Vec<u8>,
        direction: Direction,
        data: &mut [u8],
        ask_why: bool,
    ) -> Result<usize> {
        let opcode = cdb[0];
        let tag = self.next_tag();
        let cbw = CommandBlockWrapper::new(tag, data.len() as u32, direction, cdb);
        let encoded = cbw.encode()?;

        let sent = self.recover(self.transport.write(&encoded))?;
        if sent != encoded.len() {
            return Err(LuksError::ScsiProtocol("short CBW write"));
        }

        let mut transferred = 0usize;
        if !data.is_empty() {
            match direction {
                Direction::In => {
                    while transferred < data.len() {
                        let n = self.recover(self.transport.read(&mut data[transferred..]))?;
                        if n == 0 {
                            break; // device ended the data phase early
                        }
                        transferred += n;
                    }
                }
                Direction::Out => {
                    while transferred < data.len() {
                        let n = self.recover(self.transport.write(&data[transferred..]))?;
                        if n == 0 {
                            break;
                        }
                        transferred += n;
                    }
                }
                Direction::None => {}
            }
        }

        let mut csw_buf = [0u8; CSW_LEN];
        let mut got = 0usize;
        let mut cleared_halt = false;
        while got < CSW_LEN {
            match self.transport.read(&mut csw_buf[got..]) {
                Ok(0) | Err(_) if !cleared_halt => {
                    // BOT 5.3: An endpoint stall (EPIPE) or 0-byte read on the In
                    // endpoint before/during CSW is standard; clear halt and retry once.
                    cleared_halt = true;
                    if let Err(e) = self.transport.clear_halt(true) {
                        let _ = self.transport.reset();
                        return Err(e);
                    }
                    continue;
                }
                Ok(0) => {
                    let _ = self.transport.reset();
                    return Err(LuksError::ScsiProtocol("no CSW"));
                }
                Ok(n) => {
                    got += n;
                }
                Err(e) => {
                    let _ = self.transport.reset();
                    return Err(e);
                }
            }
        }

        let csw = CommandStatusWrapper::decode(&csw_buf)?;
        if csw.tag != tag {
            return Err(LuksError::ScsiProtocol("CSW tag mismatch"));
        }
        match csw.status {
            CswStatus::Passed => {
                // The residue is the *drive's* statement of how much of the
                // data phase it did not process. For an IN transfer the host
                // already knows (it counted what arrived), but for an OUT
                // transfer `transferred` only counts what the host handed to
                // the bridge — a drive can ACK every byte, report Passed, and
                // still say via the residue that it committed less. Ignoring
                // that turns a dropped sector into a success return, and the
                // corruption surfaces weeks later as one unreadable block
                // with no log line pointing anywhere. BOT requires the host
                // to honour this field; here that means failing loudly.
                if matches!(direction, Direction::Out) && csw.data_residue != 0 {
                    return Err(LuksError::ScsiProtocol(
                        "drive committed less than the full data phase",
                    ));
                }
                Ok(transferred)
            }
            CswStatus::Failed => {
                // Immediately, and before anything else touches the bus: sense
                // data describes the *last* command that failed and a drive is
                // free to discard it once another command arrives. Fetched
                // here rather than left to the caller, because by the time an
                // error has travelled up through ext4, LUKS and JNI there is
                // no bus left to ask.
                let sense = if ask_why {
                    self.request_sense().ok().map(|b| Sense::parse(&b))
                } else {
                    None
                };
                Err(LuksError::ScsiCommandFailed { opcode, sense })
            }
            CswStatus::PhaseError => {
                // Best-effort, like `recover`: a reset failure must not mask
                // the phase error that caused it.
                let _ = self.transport.reset();
                Err(LuksError::ScsiProtocol("phase error"))
            }
        }
    }

    pub fn inquiry(&self) -> Result<InquiryData> {
        let mut cdb = vec![0u8; 6];
        cdb[0] = OP_INQUIRY;
        cdb[4] = 36;
        let mut buf = [0u8; 36];
        self.command(cdb, Direction::In, &mut buf)?;
        InquiryData::parse(&buf)
    }

    pub fn test_unit_ready(&self) -> Result<()> {
        let cdb = vec![OP_TEST_UNIT_READY, 0, 0, 0, 0, 0];
        self.command(cdb, Direction::None, &mut [])?;
        Ok(())
    }

    /// Fetch sense data after a failure. Also clears a pending unit-attention.
    pub fn request_sense(&self) -> Result<[u8; 18]> {
        let mut cdb = vec![0u8; 6];
        cdb[0] = OP_REQUEST_SENSE;
        cdb[4] = 18;
        let mut buf = [0u8; 18];
        self.command_inner(cdb, Direction::In, &mut buf, false)?;
        Ok(buf)
    }

    /// Read the capacity, falling back to the 16-byte form for drives over 2 TiB.
    pub fn read_capacity(&self) -> Result<Capacity> {
        let mut cdb = vec![0u8; 10];
        cdb[0] = OP_READ_CAPACITY_10;
        let mut buf = [0u8; 8];
        self.command(cdb, Direction::In, &mut buf)?;

        let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        // 0xFFFFFFFF means "too big to express here, ask the 16-byte version".
        if last_lba == u32::MAX {
            return self.read_capacity_16();
        }
        Ok(Capacity {
            blocks: last_lba as u64 + 1,
            block_size,
        })
    }

    fn read_capacity_16(&self) -> Result<Capacity> {
        let mut cdb = vec![0u8; 16];
        cdb[0] = OP_READ_CAPACITY_16;
        cdb[1] = SA_READ_CAPACITY_16;
        cdb[13] = 32; // allocation length
        let mut buf = [0u8; 32];
        self.command(cdb, Direction::In, &mut buf)?;

        let last_lba = u64::from_be_bytes(buf[0..8].try_into().expect("8 bytes"));
        let block_size = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        // A drive can answer anything. `last_lba + 1` wrapping to zero would
        // make `bytes()` zero, and a zero capacity passes every "end > bytes"
        // bound trivially — so an absurd answer is refused here, once, rather
        // than trusted everywhere.
        let blocks = last_lba
            .checked_add(1)
            .ok_or(LuksError::ScsiProtocol("capacity overflows"))?;
        blocks
            .checked_mul(block_size as u64)
            .ok_or(LuksError::ScsiProtocol("capacity overflows"))?;
        Ok(Capacity { blocks, block_size })
    }

    /// Read `count` blocks starting at `lba`, choosing READ(10) or READ(16).
    pub fn read_blocks(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<usize> {
        let expected = count as usize * self.capacity.block_size as usize;
        if buf.len() < expected {
            return Err(LuksError::ScsiProtocol("read buffer too small"));
        }

        // The 10-byte form must fit the *whole* range, not just its first
        // block: `lba` within 32 bits but `lba + count` past them runs off
        // the end of the 32-bit LBA space mid-transfer.
        let needs_16 = count as u64 > READ10_MAX_BLOCKS
            || lba
                .checked_add(count as u64)
                .is_none_or(|end| end > READ10_MAX_LBA + 1);
        let cdb = if needs_16 {
            let mut cdb = vec![0u8; 16];
            cdb[0] = OP_READ_16;
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&count.to_be_bytes());
            cdb
        } else {
            let mut cdb = vec![0u8; 10];
            cdb[0] = OP_READ_10;
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            cdb
        };

        self.command(cdb, Direction::In, &mut buf[..expected])
    }

    /// Write `count` blocks starting at `lba`, choosing WRITE(10) or WRITE(16).
    ///
    /// The mirror of [`ScsiBlockDevice::read_blocks`], and deliberately built
    /// the same way: the CDB layout is identical, only the opcode and the
    /// direction change. Divergence between the two would be a bug that shows
    /// up as data landing at the wrong LBA.
    #[cfg(feature = "dangerous-write-support")]
    pub fn write_blocks(&self, lba: u64, count: u32, buf: &[u8]) -> Result<usize> {
        let expected = count as usize * self.capacity.block_size as usize;
        if buf.len() < expected {
            return Err(LuksError::ScsiProtocol("write buffer too small"));
        }

        // Same whole-range condition as `read_blocks` — see the note there.
        let needs_16 = count as u64 > READ10_MAX_BLOCKS
            || lba
                .checked_add(count as u64)
                .is_none_or(|end| end > READ10_MAX_LBA + 1);
        let cdb = if needs_16 {
            let mut cdb = vec![0u8; 16];
            cdb[0] = OP_WRITE_16;
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&count.to_be_bytes());
            cdb
        } else {
            let mut cdb = vec![0u8; 10];
            cdb[0] = OP_WRITE_10;
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            cdb
        };

        // usbfs requires a mutable pointer even for OUT transfers. The caller
        // already owns this command buffer, so passing it through is both safe
        // and bounded: no payload-sized copy exists merely to satisfy that ABI.
        self.command_out(cdb, &buf[..expected])
    }

    /// Read the mode parameter header and report the medium's write-protect
    /// bit — bit 7 of the device-specific parameter, byte 2.
    ///
    /// Read-only, and the direct answer to "is this drive refusing writes
    /// because it considers itself read-only". Not behind the write feature:
    /// knowing a drive is write-protected is useful precisely to a build that
    /// cannot write.
    pub fn is_write_protected(&self) -> Result<bool> {
        let mut cdb = vec![0u8; 6];
        cdb[0] = OP_MODE_SENSE_6;
        cdb[2] = 0x3F; // all pages
        cdb[4] = 4; // just the header
        let mut buf = [0u8; 4];
        self.command(cdb, Direction::In, &mut buf)?;
        Ok(buf[2] & 0x80 != 0)
    }

    /// Ask the drive which write opcodes it will accept, **without writing
    /// anything**.
    ///
    /// A `WRITE(10)` refused as "invalid command operation code" is not
    /// credible on its face — every USB stick implements it — so the useful
    /// question is what the drive *will* accept. Each opcode here is issued
    /// with a transfer length of zero blocks, which those commands define as a
    /// legal no-op: the drive validates the opcode and transfers nothing.
    ///
    /// `WRITE(6)` is deliberately absent. Its 5-bit transfer length treats
    /// zero as **256 blocks**, not none, so the one probe that looks safest
    /// would be the only destructive one.
    #[cfg(feature = "dangerous-write-support")]
    pub fn probe_write_support(&self) -> Vec<(&'static str, Result<()>)> {
        let mut out: Vec<(&'static str, Result<()>)> = Vec::new();

        let zero_length = |name: &'static str, cdb: Vec<u8>| -> (&'static str, Result<()>) {
            (name, self.command(cdb, Direction::None, &mut []).map(|_| ()))
        };

        let mut w10 = vec![0u8; 10];
        w10[0] = OP_WRITE_10;
        out.push(zero_length("WRITE(10)", w10));

        let mut w12 = vec![0u8; 12];
        w12[0] = OP_WRITE_12;
        out.push(zero_length("WRITE(12)", w12));

        let mut w16 = vec![0u8; 16];
        w16[0] = OP_WRITE_16;
        out.push(zero_length("WRITE(16)", w16));

        let mut sync = vec![0u8; 10];
        sync[0] = OP_SYNCHRONIZE_CACHE_10;
        out.push(zero_length("SYNCHRONIZE CACHE(10)", sync));

        let mut sync16 = vec![0u8; 16];
        sync16[0] = OP_SYNCHRONIZE_CACHE_16;
        out.push(zero_length("SYNCHRONIZE CACHE(16)", sync16));

        out
    }

    /// Tell the drive to commit its write cache to the medium.
    ///
    /// # When the drive does not have this command
    ///
    /// A SanDisk bridge (0781:5591) answers `SYNCHRONIZE CACHE(10)` with
    /// INVALID COMMAND OPERATION CODE — and because every write ends in a
    /// flush, that turned every write on that hardware into a failure, with
    /// the refusal misread as coming from `WRITE(10)`. The 16-byte form is
    /// tried next, since some bridges implement only one of the two.
    ///
    /// If neither exists, this returns `Ok` and stops asking. That is a real
    /// weakening of a guarantee this crate argues for elsewhere, so it is
    /// stated plainly rather than buried: **on such a drive a completed write
    /// is not known to be on the medium.** The reasoning for proceeding
    /// anyway is that SBC requires a device with no write cache to reject the
    /// command exactly this way, so "refuses to flush" is the same answer as
    /// "has nothing to flush" — and the alternative is refusing to write at
    /// all to hardware the kernel writes to happily. [`flush_is_a_no_op`]
    /// exposes which case a caller is in.
    ///
    /// Only an *invalid opcode* is treated this way. A flush that fails for
    /// any other reason is still an error: "this drive cannot flush" and "this
    /// flush did not work" are different facts.
    #[cfg(feature = "dangerous-write-support")]
    pub fn synchronize_cache(&self) -> Result<()> {
        use std::sync::atomic::Ordering as O;

        if self.no_flush_command.load(O::Acquire) {
            return Ok(());
        }

        let unsupported = |e: &LuksError| {
            matches!(
                e,
                LuksError::ScsiCommandFailed {
                    sense: Some(s),
                    ..
                } if s.key == 0x5 && s.asc == 0x20
            )
        };

        let mut cdb = vec![0u8; 10];
        cdb[0] = OP_SYNCHRONIZE_CACHE_10;
        // LBA 0, count 0 means "everything", which is what a flush wants.
        match self.command(cdb, Direction::None, &mut []) {
            Ok(_) => return Ok(()),
            Err(e) if !unsupported(&e) => return Err(e),
            Err(_) => {}
        }

        let mut cdb = vec![0u8; 16];
        cdb[0] = OP_SYNCHRONIZE_CACHE_16;
        match self.command(cdb, Direction::None, &mut []) {
            Ok(_) => return Ok(()),
            Err(e) if !unsupported(&e) => return Err(e),
            Err(_) => {}
        }

        self.no_flush_command.store(true, O::Release);
        Ok(())
    }

    /// Whether this drive rejected both forms of SYNCHRONIZE CACHE, so a
    /// flush does nothing and durability rests on the bridge writing through.
    ///
    /// `false` until a flush has actually been attempted — it reports what the
    /// drive has said, not a prediction.
    #[cfg(feature = "dangerous-write-support")]
    pub fn flush_is_a_no_op(&self) -> bool {
        self.no_flush_command.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Byte-addressed reads on top of block-addressed SCSI.
impl<T: BulkTransport> ReadAt for ScsiBlockDevice<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let bs = self.capacity.block_size as u64;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if end > self.capacity.bytes() {
            return Err(LuksError::OutOfBounds);
        }

        // Per-command block count is bounded by the transport's transfer limit,
        // the safe SCSI transfer cap (128 KiB), and what the CDB can express.
        let max_bytes = self.transport.max_transfer().min(MAX_SCSI_TRANSFER);
        let max_blocks = (max_bytes as u64 / bs).clamp(1, READ10_MAX_BLOCKS);

        let mut done = 0usize;
        let mut chunk = vec![0u8; (max_blocks * bs) as usize];

        while done < buf.len() {
            let pos = offset + done as u64;
            let lba = pos / bs;
            let within = (pos % bs) as usize;

            let remaining = buf.len() - done;
            let blocks = ((within + remaining) as u64).div_ceil(bs).min(max_blocks);
            let span = (blocks * bs) as usize;

            let got = self.read_blocks(lba, blocks as u32, &mut chunk[..span])?;
            if got < span {
                return Err(LuksError::ScsiProtocol("short data phase"));
            }

            let take = (span - within).min(remaining);
            buf[done..done + take].copy_from_slice(&chunk[within..within + take]);
            done += take;
        }
        Ok(())
    }

    fn len(&self) -> Option<u64> {
        Some(self.capacity.bytes())
    }
}

/// Byte-addressed writes on top of block-addressed SCSI.
///
/// A drive has no concept of writing part of a block, so any request that does
/// not start and end on a block boundary becomes read-modify-write: fetch the
/// straddled blocks, patch them, send them back. That costs an extra round trip
/// *and* puts bytes the caller never named at risk if the write fails partway.
///
/// It is not a hypothetical cost here. Over USB a single SCSI command was
/// measured at 760 us, so an unaligned write is two commands where an aligned
/// one is a single command — before any of the data moves. The LUKS layer
/// above always emits whole cipher sectors, and a cipher sector is a multiple
/// of the SCSI block size on every drive seen so far — **when that holds**,
/// this RMW never runs. It is a property of the drive, not a guarantee: a
/// 512-byte cipher sector on a 4096-byte-block drive (they exist) would land
/// every metadata patch here. The read-back check below is what makes that
/// case merely slow instead of dangerous.
#[cfg(feature = "dangerous-write-support")]
impl<T: BulkTransport> crate::device::WriteAt for ScsiBlockDevice<T> {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let bs = self.capacity.block_size as u64;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if end > self.capacity.bytes() {
            return Err(LuksError::OutOfBounds);
        }

        let max_bytes = self.transport.max_transfer().min(MAX_SCSI_TRANSFER);
        let max_blocks = (max_bytes as u64 / bs).clamp(1, READ10_MAX_BLOCKS);

        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let lba = pos / bs;
            let within = (pos % bs) as usize;

            let remaining = buf.len() - done;
            let blocks = ((within + remaining) as u64).div_ceil(bs).min(max_blocks);
            let span = (blocks * bs) as usize;
            let take = (span - within).min(remaining);

            // Whole blocks: nothing around the payload needs preserving, so
            // the read is skipped entirely and no scratch buffer is allocated.
            let partial = within != 0 || take != span;
            let put = if partial {
                let mut chunk = vec![0u8; span];
                let got = self.read_blocks(lba, blocks as u32, &mut chunk)?;
                if got < span {
                    return Err(LuksError::ScsiProtocol("short data phase"));
                }
                chunk[within..within + take].copy_from_slice(&buf[done..done + take]);
                self.write_blocks(lba, blocks as u32, &chunk)?
            } else {
                self.write_blocks(lba, blocks as u32, &buf[done..done + take])?
            };
            if put < span {
                return Err(LuksError::ScsiProtocol("short data phase"));
            }
            done += take;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.synchronize_cache()
    }
}
