//! USB Mass Storage Bulk-Only Transport (the "BBB" protocol).
//!
//! Every command is three phases:
//!
//! 1. **CBW** — a 31-byte Command Block Wrapper on the OUT endpoint
//! 2. **Data** — optional, in the direction the CBW declared
//! 3. **CSW** — a 13-byte Command Status Wrapper on the IN endpoint
//!
//! BOT has no command queuing: the host must see the CSW before sending the next
//! CBW. That serialisation, not the cipher, is what bounds sequential throughput.

use crate::error::{LuksError, Result};

pub const CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC"
pub const CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"
pub const CBW_LEN: usize = 31;
pub const CSW_LEN: usize = 13;
pub const MAX_CDB_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Device to host.
    In,
    /// Host to device.
    Out,
    /// No data phase.
    None,
}

impl Direction {
    fn flags(self) -> u8 {
        match self {
            Direction::In => 0x80,
            // A no-data command sets the OUT direction bit to zero.
            Direction::Out | Direction::None => 0x00,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandBlockWrapper {
    pub tag: u32,
    pub data_transfer_length: u32,
    pub direction: Direction,
    pub lun: u8,
    pub cdb: Vec<u8>,
}

impl CommandBlockWrapper {
    pub fn new(tag: u32, data_transfer_length: u32, direction: Direction, cdb: Vec<u8>) -> Self {
        Self {
            tag,
            data_transfer_length,
            direction,
            lun: 0,
            cdb,
        }
    }

    pub fn encode(&self) -> Result<[u8; CBW_LEN]> {
        if self.cdb.is_empty() || self.cdb.len() > MAX_CDB_LEN {
            return Err(LuksError::ScsiProtocol("CDB length out of range"));
        }
        let mut b = [0u8; CBW_LEN];
        b[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&self.tag.to_le_bytes());
        b[8..12].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        b[12] = self.direction.flags();
        b[13] = self.lun & 0x0F;
        b[14] = self.cdb.len() as u8;
        b[15..15 + self.cdb.len()].copy_from_slice(&self.cdb);
        Ok(b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CswStatus {
    Passed,
    Failed,
    /// The device and host disagree about the transfer; only a reset recovers.
    PhaseError,
}

#[derive(Debug, Clone, Copy)]
pub struct CommandStatusWrapper {
    pub tag: u32,
    /// Bytes the device did *not* transfer.
    pub data_residue: u32,
    pub status: CswStatus,
}

impl CommandStatusWrapper {
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < CSW_LEN {
            return Err(LuksError::ScsiProtocol("CSW too short"));
        }
        let signature = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if signature != CSW_SIGNATURE {
            return Err(LuksError::ScsiProtocol("bad CSW signature"));
        }
        let status = match b[12] {
            0 => CswStatus::Passed,
            1 => CswStatus::Failed,
            2 => CswStatus::PhaseError,
            _ => return Err(LuksError::ScsiProtocol("reserved CSW status")),
        };
        Ok(Self {
            tag: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            data_residue: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            status,
        })
    }
}
