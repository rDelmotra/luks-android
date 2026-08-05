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
    pub write_commands: usize,
    pub bytes_written: usize,
    pub largest_write_blocks: u32,
    pub sync_commands: usize,
}

enum Phase {
    Idle,
    /// Data to hand back, then the CSW.
    DataIn { data: Vec<u8>, pos: usize },
    /// Data the host still owes us, and where it lands when it arrives.
    ///
    /// Bulk-Only Transport has no framing inside the data phase: after the CBW
    /// the host simply writes bytes to the OUT endpoint, and only the byte
    /// count in the CBW says when the phase ends. So the mock has to remember
    /// what the pending command was, exactly as a real bridge does.
    /// `blocks` rides along so the write statistics can be counted when the
    /// data actually lands, not when the command merely promises it.
    DataOut {
        at: usize,
        want: usize,
        got: Vec<u8>,
        blocks: u32,
    },
    Csw { pos: usize },
}

pub struct MockUsbDrive {
    image: RefCell<Vec<u8>>,
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
            image: RefCell::new(image),
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
        self.image.borrow().len() as u64 / self.block_size as u64
    }

    fn set_csw(&self, tag: u32, residue: u32, status: u8) {
        let mut csw = [0u8; CSW_LEN];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        csw[8..12].copy_from_slice(&residue.to_le_bytes());
        csw[12] = status;
        *self.csw.borrow_mut() = csw;
    }

    /// `flags` is the CBW's `bmCBWFlags`: bit 7 set means the host expects an
    /// IN data phase. A real bridge phase-errors when the flag contradicts the
    /// command; a mock that ignored it (as this one did) would pass a WRITE
    /// issued with `Direction::In` — agreeable in exactly the direction that
    /// matters, given this mock is the only evidence the SCSI write path has
    /// until it meets real hardware.
    fn execute(&self, cdb: &[u8], tag: u32, expected_len: u32, flags: u8) -> Result<()> {
        self.stats.borrow_mut().commands += 1;

        let host_expects_in = flags & 0x80 != 0;
        let mut phase_error = |why: &str| {
            let _ = why; // named for the reader; the CSW carries only a status
            self.set_csw(tag, expected_len, 2); // 2 = phase error
            *self.phase.borrow_mut() = Phase::Csw { pos: 0 };
        };

        // Direction check: every command with a data phase declares its
        // direction in the opcode; the CBW flag must agree.
        let wants_in = matches!(cdb[0], 0x12 | 0x03 | 0x25 | 0x9E | 0x28 | 0x88);
        let wants_out = matches!(cdb[0], 0x2A | 0x8A);
        if expected_len > 0 && wants_in && !host_expects_in {
            phase_error("IN command sent with an OUT flag");
            return Ok(());
        }
        if wants_out && host_expects_in {
            phase_error("OUT command sent with an IN flag");
            return Ok(());
        }

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
                if start + len > self.image.borrow().len() as u64 {
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

                self.image.borrow()[start as usize..(start + len) as usize].to_vec()
            }
            // WRITE(10) / WRITE(16). The CDB layout is identical to READ, and
            // it is decoded by the same arithmetic on purpose: if the reader
            // and writer ever disagree about where an LBA lives, the tests
            // should fail rather than agree with the bug.
            0x2A | 0x8A => {
                let (lba, count) = if cdb[0] == 0x2A {
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
                if start + len > self.image.borrow().len() as u64 {
                    self.set_csw(tag, expected_len, 1);
                    *self.phase.borrow_mut() = Phase::Csw { pos: 0 };
                    return Ok(());
                }
                // The CBW's byte count and the CDB's block count are two
                // statements of the same length; a host that disagrees with
                // itself gets a phase error, as from a real bridge.
                if expected_len as u64 != len {
                    phase_error("CBW length disagrees with the WRITE CDB");
                    return Ok(());
                }

                // Statistics are counted when the data lands (see `write`),
                // not here — a command is not a write until its payload
                // arrives.
                *self.phase.borrow_mut() = Phase::DataOut {
                    at: start as usize,
                    want: len as usize,
                    got: Vec::with_capacity(len as usize),
                    blocks: count,
                };
                // The CSW is prepared now and sent once the data has arrived.
                self.set_csw(tag, 0, 0);
                return Ok(());
            }
            // SYNCHRONIZE CACHE(10): nothing is cached here, but the command
            // must succeed or a flush looks like a device error.
            0x35 => {
                self.stats.borrow_mut().sync_commands += 1;
                Vec::new()
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
        // Mid data-out phase: these bytes are payload, not a new command.
        {
            let mut phase = self.phase.borrow_mut();
            if let Phase::DataOut {
                at,
                want,
                got,
                blocks,
            } = &mut *phase
            {
                let n = data.len().min(*want - got.len()).min(self.max_transfer);
                got.extend_from_slice(&data[..n]);
                if got.len() == *want {
                    let (at, got, blocks) = (*at, std::mem::take(got), *blocks);
                    *phase = Phase::Csw { pos: 0 };
                    drop(phase);
                    self.image.borrow_mut()[at..at + got.len()].copy_from_slice(&got);
                    // Counted here, from the payload that actually arrived —
                    // a `bytes_written` assertion should prove a data phase
                    // happened, not that a command once made a promise.
                    let mut st = self.stats.borrow_mut();
                    st.write_commands += 1;
                    st.bytes_written += got.len();
                    st.largest_write_blocks = st.largest_write_blocks.max(blocks);
                }
                return Ok(n);
            }
        }
        if data.len() < CBW_LEN {
            return Err(LuksError::UsbTransfer("short CBW".into()));
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if signature != CBW_SIGNATURE {
            return Err(LuksError::UsbTransfer("bad CBW signature".into()));
        }
        let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let expected_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = data[12];
        let cdb_len = data[14] as usize;
        let cdb = &data[15..15 + cdb_len.min(16)];

        self.execute(cdb, tag, expected_len, flags)?;
        Ok(CBW_LEN)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut phase = self.phase.borrow_mut();
        match &mut *phase {
            Phase::Idle => Ok(0),
            // The host is reading while the drive is still waiting for the
            // data it promised to send. A real bridge stalls; returning zero
            // surfaces it as a hang in the test rather than as silent success.
            Phase::DataOut { .. } => Ok(0),
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
