//! A USB Mass Storage device emulator.
//!
//! Speaks Bulk-Only Transport over an in-memory disk image, so the SCSI layer,
//! partition parsing, LUKS unlock and filesystem read can all be exercised
//! without a phone or a physical drive. Only the Android usbfs ioctl layer sits
//! below this and remains untested until hardware bring-up.
//!
//! It also counts commands and bytes, which lets tests assert that reads are
//! actually being batched rather than issued one block at a time.

#![allow(dead_code)]

use luks_core::error::{LuksError, Result};
use luks_core::usb::bot::{CBW_LEN, CBW_SIGNATURE, CSW_LEN, CSW_SIGNATURE};
use luks_core::usb::BulkTransport;
use std::cell::RefCell;

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub commands: usize,
    pub read_commands: usize,
    pub bytes_read: usize,
    pub largest_read_blocks: u32,
}

enum Phase {
    Idle,
    /// Data to hand back, then the CSW.
    DataIn { data: Vec<u8>, pos: usize },
    Csw { pos: usize },
}

pub struct MockUsbDrive {
    image: Vec<u8>,
    block_size: u32,
    max_transfer: usize,
    phase: RefCell<Phase>,
    csw: RefCell<[u8; CSW_LEN]>,
    pub stats: RefCell<Stats>,
    /// Report capacity via the 0xFFFFFFFF escape, forcing READ CAPACITY(16).
    pub force_rc16: bool,
}

impl MockUsbDrive {
    pub fn new(image: Vec<u8>) -> Self {
        Self {
            image,
            block_size: 512,
            max_transfer: 128 * 1024,
            phase: RefCell::new(Phase::Idle),
            csw: RefCell::new([0u8; CSW_LEN]),
            stats: RefCell::new(Stats::default()),
            force_rc16: false,
        }
    }

    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
        self
    }

    pub fn with_max_transfer(mut self, max_transfer: usize) -> Self {
        self.max_transfer = max_transfer;
        self
    }

    pub fn blocks(&self) -> u64 {
        self.image.len() as u64 / self.block_size as u64
    }

    fn set_csw(&self, tag: u32, residue: u32, status: u8) {
        let mut csw = [0u8; CSW_LEN];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        csw[8..12].copy_from_slice(&residue.to_le_bytes());
        csw[12] = status;
        *self.csw.borrow_mut() = csw;
    }

    fn execute(&self, cdb: &[u8], tag: u32, expected_len: u32) -> Result<()> {
        self.stats.borrow_mut().commands += 1;

        let data: Vec<u8> = match cdb[0] {
            // INQUIRY
            0x12 => {
                let mut d = vec![0u8; 36];
                d[0] = 0x00; // direct-access block device
                d[1] = 0x80; // removable
                d[3] = 0x02;
                d[4] = 31;
                d[8..16].copy_from_slice(b"MOCKVEND");
                d[16..32].copy_from_slice(b"MOCK USB DISK   ");
                d[32..36].copy_from_slice(b"1.00");
                d
            }
            // TEST UNIT READY
            0x00 => Vec::new(),
            // REQUEST SENSE
            0x03 => {
                let mut d = vec![0u8; 18];
                d[0] = 0x70; // current error
                d[7] = 10;
                d
            }
            // READ CAPACITY(10)
            0x25 => {
                let last = self.blocks() - 1;
                let reported = if self.force_rc16 || last > u32::MAX as u64 {
                    u32::MAX
                } else {
                    last as u32
                };
                let mut d = vec![0u8; 8];
                d[0..4].copy_from_slice(&reported.to_be_bytes());
                d[4..8].copy_from_slice(&self.block_size.to_be_bytes());
                d
            }
            // READ CAPACITY(16)
            0x9E => {
                let mut d = vec![0u8; 32];
                d[0..8].copy_from_slice(&(self.blocks() - 1).to_be_bytes());
                d[8..12].copy_from_slice(&self.block_size.to_be_bytes());
                d
            }
            // READ(10) / READ(16)
            0x28 | 0x88 => {
                let (lba, count) = if cdb[0] == 0x28 {
                    (
                        u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]) as u64,
                        u16::from_be_bytes([cdb[7], cdb[8]]) as u32,
                    )
                } else {
                    (
                        u64::from_be_bytes(cdb[2..10].try_into().unwrap()),
                        u32::from_be_bytes([cdb[10], cdb[11], cdb[12], cdb[13]]),
                    )
                };

                let start = lba * self.block_size as u64;
                let len = count as u64 * self.block_size as u64;
                if start + len > self.image.len() as u64 {
                    // Out of range: fail the command the way a real drive would.
                    self.set_csw(tag, expected_len, 1);
                    *self.phase.borrow_mut() = Phase::Csw { pos: 0 };
                    return Ok(());
                }

                let mut s = self.stats.borrow_mut();
                s.read_commands += 1;
                s.bytes_read += len as usize;
                s.largest_read_blocks = s.largest_read_blocks.max(count);
                drop(s);

                self.image[start as usize..(start + len) as usize].to_vec()
            }
            _ => {
                self.set_csw(tag, expected_len, 1);
                *self.phase.borrow_mut() = Phase::Csw { pos: 0 };
                return Ok(());
            }
        };

        let residue = expected_len.saturating_sub(data.len() as u32);
        self.set_csw(tag, residue, 0);
        *self.phase.borrow_mut() = if data.is_empty() {
            Phase::Csw { pos: 0 }
        } else {
            Phase::DataIn { data, pos: 0 }
        };
        Ok(())
    }
}

impl BulkTransport for MockUsbDrive {
    fn write(&self, data: &[u8]) -> Result<usize> {
        if data.len() < CBW_LEN {
            return Err(LuksError::UsbTransfer("short CBW".into()));
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if signature != CBW_SIGNATURE {
            return Err(LuksError::UsbTransfer("bad CBW signature".into()));
        }
        let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let expected_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let cdb_len = data[14] as usize;
        let cdb = &data[15..15 + cdb_len.min(16)];

        self.execute(cdb, tag, expected_len)?;
        Ok(CBW_LEN)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut phase = self.phase.borrow_mut();
        match &mut *phase {
            Phase::Idle => Ok(0),
            Phase::DataIn { data, pos } => {
                // Serve at most max_transfer per call, as a real endpoint would.
                let n = (data.len() - *pos).min(buf.len()).min(self.max_transfer);
                buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                if *pos == data.len() {
                    *phase = Phase::Csw { pos: 0 };
                }
                Ok(n)
            }
            Phase::Csw { pos } => {
                let csw = *self.csw.borrow();
                let n = (CSW_LEN - *pos).min(buf.len());
                buf[..n].copy_from_slice(&csw[*pos..*pos + n]);
                *pos += n;
                if *pos == CSW_LEN {
                    *phase = Phase::Idle;
                }
                Ok(n)
            }
        }
    }

    fn max_transfer(&self) -> usize {
        self.max_transfer
    }
}

pub fn fixture(rel: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}
