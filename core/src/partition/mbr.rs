//! Master Boot Record partition table parsing.
//!
//! Only the four primary entries are read. Extended/logical partitions are rare
//! on removable drives and are not supported; an extended entry is reported as
//! itself rather than silently expanded.

use super::{u32le, Partition, PartitionTable, TableKind};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

const BOOT_SIGNATURE: u16 = 0xAA55;
const TABLE_OFFSET: usize = 446;
const ENTRY_SIZE: usize = 16;

/// A GPT disk carries one of these covering the whole disk, to stop MBR-only
/// tools from thinking the disk is blank.
pub const TYPE_PROTECTIVE_GPT: u8 = 0xEE;
pub const TYPE_EXTENDED_CHS: u8 = 0x05;
pub const TYPE_EXTENDED_LBA: u8 = 0x0F;
pub const TYPE_LINUX: u8 = 0x83;

pub fn parse<D: ReadAt + ?Sized>(device: &D, sector_size: u32) -> Result<PartitionTable> {
    let mut sector = [0u8; 512];
    device.read_at(0, &mut sector)?;

    let signature = u16::from_le_bytes([sector[510], sector[511]]);
    if signature != BOOT_SIGNATURE {
        return Err(LuksError::NoPartitionTable);
    }

    let mut partitions = Vec::new();
    for i in 0..4 {
        let e = &sector[TABLE_OFFSET + i * ENTRY_SIZE..][..ENTRY_SIZE];
        let part_type = e[4];
        let start_lba = u32le(e, 8) as u64;
        let sectors = u32le(e, 12) as u64;

        if part_type == 0 || sectors == 0 {
            continue;
        }
        // A protective MBR describes the GPT, not a real partition.
        if part_type == TYPE_PROTECTIVE_GPT {
            return Err(LuksError::BadGpt(
                "protective MBR present but GPT unreadable",
            ));
        }

        partitions.push(Partition {
            index: i as u32 + 1,
            start_lba,
            end_lba: start_lba + sectors - 1,
            sector_size,
            type_guid: None,
            mbr_type: Some(part_type),
            name: String::new(),
            is_luks: false,
            luks_version: None,
        });
    }

    if partitions.is_empty() {
        return Err(LuksError::NoPartitionTable);
    }
    Ok(PartitionTable {
        kind: TableKind::Mbr,
        partitions,
    })
}
