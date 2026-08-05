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
/// Write opcodes exist only with `dangerous-write-support`. This is the
/// literal statement of the safety guarantee: without the feature, the byte
/// `0x2A` is never assembled into a command block, so no build of this crate
/// can tell a drive to overwrite a sector.
#[cfg(feature = "dangerous-write-support")]
const OP_WRITE_10: u8 = 0x2A;
#[cfg(feature = "dangerous-write-support")]
const OP_WRITE_16: u8 = 0x8A;
/// SYNCHRONIZE CACHE(10). A USB bridge acknowledges a write once it is in the
/// bridge's own buffer, not once it is on flash, so without this a "completed"
/// write can still be lost to a yanked cable.
#[cfg(feature = "dangerous-write-support")]
const OP_SYNCHRONIZE_CACHE_10: u8 = 0x35;
const SA_READ_CAPACITY_16: u8 = 0x10;

/// READ(10) carries a 16-bit block count and a 32-bit LBA.
const READ10_MAX_BLOCKS: u64 = 0xFFFF;
const READ10_MAX_LBA: u64 = 0xFFFF_FFFF;

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

/// A USB mass storage device presented as random-access bytes.
pub struct ScsiBlockDevice<T: BulkTransport> {
    transport: T,
    capacity: Capacity,
    tag: AtomicU32,
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

    /// Run one CBW / data / CSW exchange.
    fn command(&self, cdb: Vec<u8>, direction: Direction, data: &mut [u8]) -> Result<usize> {
        let tag = self.next_tag();
        let cbw = CommandBlockWrapper::new(tag, data.len() as u32, direction, cdb);
        let encoded = cbw.encode()?;

        let sent = self.transport.write(&encoded)?;
        if sent != encoded.len() {
            return Err(LuksError::ScsiProtocol("short CBW write"));
        }

        let mut transferred = 0usize;
        if !data.is_empty() {
            match direction {
                Direction::In => {
                    while transferred < data.len() {
                        let n = self.transport.read(&mut data[transferred..])?;
                        if n == 0 {
                            break; // device ended the data phase early
                        }
                        transferred += n;
                    }
                }
                Direction::Out => {
                    while transferred < data.len() {
                        let n = self.transport.write(&data[transferred..])?;
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
        while got < CSW_LEN {
            let n = self.transport.read(&mut csw_buf[got..])?;
            if n == 0 {
                // A stalled endpoint is the usual cause; clear it and retry once.
                self.transport.clear_halt(true)?;
                let n = self.transport.read(&mut csw_buf[got..])?;
                if n == 0 {
                    return Err(LuksError::ScsiProtocol("no CSW"));
                }
                got += n;
                continue;
            }
            got += n;
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
            CswStatus::Failed => Err(LuksError::ScsiCommandFailed),
            CswStatus::PhaseError => {
                self.transport.reset()?;
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
        self.command(cdb, Direction::In, &mut buf)?;
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

        // `command` takes `&mut [u8]` because an IN transfer fills it. An OUT
        // transfer only reads it, so a copy is needed to satisfy the signature.
        // Widening that signature would let a read path hand out a mutable
        // borrow it does not need; the copy is the cheaper mistake.
        let mut data = buf[..expected].to_vec();
        self.command(cdb, Direction::Out, &mut data)
    }

    /// Tell the drive to commit its write cache to the medium.
    #[cfg(feature = "dangerous-write-support")]
    pub fn synchronize_cache(&self) -> Result<()> {
        let mut cdb = vec![0u8; 10];
        cdb[0] = OP_SYNCHRONIZE_CACHE_10;
        // LBA 0, count 0 means "everything", which is what a flush wants.
        self.command(cdb, Direction::None, &mut [])?;
        Ok(())
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

        // Per-command block count is bounded by the transport's transfer limit
        // and by what the CDB can express.
        let max_blocks = (self.transport.max_transfer() as u64 / bs).clamp(1, READ10_MAX_BLOCKS);

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

        let max_blocks = (self.transport.max_transfer() as u64 / bs).clamp(1, READ10_MAX_BLOCKS);

        let mut done = 0usize;
        let mut chunk = vec![0u8; (max_blocks * bs) as usize];

        while done < buf.len() {
            let pos = offset + done as u64;
            let lba = pos / bs;
            let within = (pos % bs) as usize;

            let remaining = buf.len() - done;
            let blocks = ((within + remaining) as u64).div_ceil(bs).min(max_blocks);
            let span = (blocks * bs) as usize;
            let take = (span - within).min(remaining);

            // Whole blocks: nothing around the payload needs preserving, so
            // the read is skipped entirely.
            let partial = within != 0 || take != span;
            if partial {
                let got = self.read_blocks(lba, blocks as u32, &mut chunk[..span])?;
                if got < span {
                    return Err(LuksError::ScsiProtocol("short data phase"));
                }
            }

            chunk[within..within + take].copy_from_slice(&buf[done..done + take]);
            let put = self.write_blocks(lba, blocks as u32, &chunk[..span])?;
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
