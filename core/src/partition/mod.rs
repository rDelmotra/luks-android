//! Partition table parsing and LUKS partition discovery.

pub mod gpt;
pub mod mbr;

use crate::device::ReadAt;
use crate::error::Result;
use crate::luks;

/// Well-known GPT partition type GUIDs, in mixed-endian on-disk byte order.
pub mod type_guid {
    /// `CA7D7CCB-63ED-4C53-861C-1742536059CC`
    pub const LUKS: [u8; 16] = [
        0xCB, 0x7C, 0x7D, 0xCA, 0xED, 0x63, 0x53, 0x4C, 0x86, 0x1C, 0x17, 0x42, 0x53, 0x60, 0x59,
        0xCC,
    ];
    /// `0FC63DAF-8483-4772-8E79-3D69D8477DE4` — what most installers actually
    /// use for a LUKS partition, so the type GUID alone is not enough.
    pub const LINUX_FS: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    /// `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`
    pub const EFI_SYSTEM: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    /// `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F`
    pub const LINUX_SWAP: [u8; 16] = [
        0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F,
        0x4F,
    ];
    /// `E6D6D379-F507-44C2-A23C-238F2A3DF928` — LVM, which sits between LUKS and
    /// the filesystem on standard Linux server and older installs.
    pub const LINUX_LVM: [u8; 16] = [
        0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9,
        0x28,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Gpt,
    Mbr,
}

#[derive(Debug, Clone)]
pub struct Partition {
    /// 1-based, matching how partitions are named (`/dev/sda1`).
    pub index: u32,
    pub start_lba: u64,
    /// Inclusive.
    pub end_lba: u64,
    pub sector_size: u32,
    /// GPT type GUID, absent on MBR.
    pub type_guid: Option<[u8; 16]>,
    /// MBR partition type byte, absent on GPT.
    pub mbr_type: Option<u8>,
    pub name: String,
    /// Set by probing for the LUKS magic, not by trusting the type GUID.
    pub is_luks: bool,
    pub luks_version: Option<u16>,
}

impl Partition {
    pub fn offset_bytes(&self) -> u64 {
        self.start_lba * self.sector_size as u64
    }

    pub fn size_bytes(&self) -> u64 {
        (self.end_lba + 1 - self.start_lba) * self.sector_size as u64
    }

    /// Human-readable GPT type GUID.
    pub fn type_guid_string(&self) -> Option<String> {
        self.type_guid.map(|g| format_guid(&g))
    }
}

#[derive(Debug, Clone)]
pub struct PartitionTable {
    pub kind: TableKind,
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    pub fn luks_partitions(&self) -> impl Iterator<Item = &Partition> {
        self.partitions.iter().filter(|p| p.is_luks)
    }
}

/// GPT GUIDs are stored with the first three fields little-endian and the rest
/// big-endian, so the on-disk bytes are not the printed order.
pub fn format_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[3], g[2], g[1], g[0],
        g[5], g[4],
        g[7], g[6],
        g[8], g[9],
        g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

/// Parse the partition table and probe each partition for a LUKS header.
///
/// GPT is tried first because a GPT disk carries a protective MBR that would
/// otherwise parse as a single junk partition. LUKS detection is by magic bytes
/// rather than type GUID, since installers commonly tag LUKS partitions as plain
/// Linux filesystems.
pub fn scan<D: ReadAt + ?Sized>(device: &D, sector_size: u32) -> Result<PartitionTable> {
    let mut table = match gpt::parse(device, sector_size) {
        Ok(t) => t,
        Err(_) => mbr::parse(device, sector_size)?,
    };

    for p in &mut table.partitions {
        if let Some(version) = probe_luks(device, p.offset_bytes()) {
            p.is_luks = true;
            p.luks_version = Some(version);
        }
    }
    Ok(table)
}

/// Look for the LUKS magic at the start of a partition.
fn probe_luks<D: ReadAt + ?Sized>(device: &D, offset: u64) -> Option<u16> {
    let mut head = [0u8; 8];
    device.read_at(offset, &mut head).ok()?;
    match luks::detect_version(&head).ok()? {
        luks::LuksVersion::V1 => Some(1),
        luks::LuksVersion::V2 => Some(2),
    }
}

pub(crate) fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub(crate) fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}
