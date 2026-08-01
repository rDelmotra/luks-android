//! GUID Partition Table parsing.
//!
//! Both copies are validated by CRC32 and the backup at the end of the disk is
//! used when the primary fails — the same recovery posture as the LUKS header.

use super::{u32le, u64le, Partition, PartitionTable, TableKind};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

const SIGNATURE: &[u8; 8] = b"EFI PART";
const MIN_HEADER_SIZE: u32 = 92;
const MAX_ENTRIES: u32 = 4096;
const MAX_ENTRY_SIZE: u32 = 4096;

struct Header {
    header_size: u32,
    backup_lba: u64,
    entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    entries_crc: u32,
}

fn parse_header(raw: &[u8]) -> Result<Header> {
    if raw.len() < MIN_HEADER_SIZE as usize {
        return Err(LuksError::BadGpt("header too short"));
    }
    if &raw[0..8] != SIGNATURE {
        return Err(LuksError::BadGpt("bad signature"));
    }

    let header_size = u32le(raw, 12);
    if header_size < MIN_HEADER_SIZE || header_size as usize > raw.len() {
        return Err(LuksError::BadGpt("implausible header size"));
    }

    // The stored CRC covers header_size bytes with its own field zeroed.
    let stored_crc = u32le(raw, 16);
    let mut scratch = raw[..header_size as usize].to_vec();
    scratch[16..20].fill(0);
    if crc32fast::hash(&scratch) != stored_crc {
        return Err(LuksError::BadGpt("header CRC mismatch"));
    }

    let num_entries = u32le(raw, 80);
    let entry_size = u32le(raw, 84);
    if num_entries == 0 || num_entries > MAX_ENTRIES {
        return Err(LuksError::BadGpt("implausible entry count"));
    }
    if !(128..=MAX_ENTRY_SIZE).contains(&entry_size) || !entry_size.is_multiple_of(8) {
        return Err(LuksError::BadGpt("implausible entry size"));
    }

    Ok(Header {
        header_size,
        backup_lba: u64le(raw, 32),
        entry_lba: u64le(raw, 72),
        num_entries,
        entry_size,
        entries_crc: u32le(raw, 88),
    })
}

fn read_entries<D: ReadAt + ?Sized>(
    device: &D,
    header: &Header,
    sector_size: u32,
) -> Result<Vec<Partition>> {
    let total = (header.num_entries as usize)
        .checked_mul(header.entry_size as usize)
        .ok_or(LuksError::BadGpt("entry array too large"))?;

    let mut raw = vec![0u8; total];
    device.read_at(header.entry_lba * sector_size as u64, &mut raw)?;

    if crc32fast::hash(&raw) != header.entries_crc {
        return Err(LuksError::BadGpt("entry array CRC mismatch"));
    }

    let mut out = Vec::new();
    for i in 0..header.num_entries as usize {
        let e = &raw[i * header.entry_size as usize..][..header.entry_size as usize];

        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&e[0..16]);
        if type_guid == [0u8; 16] {
            continue; // unused slot
        }

        let start_lba = u64le(e, 32);
        let end_lba = u64le(e, 40);
        if end_lba < start_lba {
            return Err(LuksError::BadGpt("entry ends before it starts"));
        }

        // Name is 36 UTF-16LE code units, NUL-padded.
        let units: Vec<u16> = e[56..128]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();

        out.push(Partition {
            index: i as u32 + 1,
            start_lba,
            end_lba,
            sector_size,
            type_guid: Some(type_guid),
            mbr_type: None,
            name: String::from_utf16_lossy(&units),
            is_luks: false,
            luks_version: None,
        });
    }
    Ok(out)
}

/// Parse the GPT, falling back to the backup copy at the end of the disk.
pub fn parse<D: ReadAt + ?Sized>(device: &D, sector_size: u32) -> Result<PartitionTable> {
    let mut header_buf = vec![0u8; sector_size as usize];

    // Primary header lives at LBA 1.
    let primary = device
        .read_at(sector_size as u64, &mut header_buf)
        .ok()
        .and_then(|_| parse_header(&header_buf).ok());

    if let Some(h) = primary {
        if let Ok(parts) = read_entries(device, &h, sector_size) {
            return Ok(PartitionTable {
                kind: TableKind::Gpt,
                partitions: parts,
            });
        }
        // Header was sound but the entry array was not; try the backup it names.
        if let Ok(table) = parse_at(device, sector_size, h.backup_lba) {
            return Ok(table);
        }
    }

    // No usable primary. The backup sits in the last LBA, if we know the size.
    let last_lba = device
        .len()
        .map(|n| n / sector_size as u64 - 1)
        .ok_or(LuksError::BadGpt("no primary header and unknown device size"))?;
    parse_at(device, sector_size, last_lba)
}

fn parse_at<D: ReadAt + ?Sized>(
    device: &D,
    sector_size: u32,
    lba: u64,
) -> Result<PartitionTable> {
    let mut buf = vec![0u8; sector_size as usize];
    device.read_at(lba * sector_size as u64, &mut buf)?;
    let header = parse_header(&buf)?;
    let _ = header.header_size;
    let partitions = read_entries(device, &header, sector_size)?;
    Ok(PartitionTable {
        kind: TableKind::Gpt,
        partitions,
    })
}
