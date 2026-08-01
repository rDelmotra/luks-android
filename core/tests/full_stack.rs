//! The complete chain, from a simulated USB drive to file bytes.
//!
//! ```text
//!   MockUsbDrive        <- emulates USB Mass Storage over Bulk-Only Transport
//!     -> ScsiBlockDevice    INQUIRY, READ CAPACITY, READ(10)
//!     -> partition::scan    GPT/MBR, LUKS detection by magic
//!     -> luks::read_from    header parse, checksum, dual-copy recovery
//!     -> LuksVolume::open   Argon2id -> AF-merge -> digest -> AES-XTS
//!     -> Ext4::mount        superblock, inodes, extents, dirents
//!     -> file contents
//! ```
//!
//! This is exactly what the Android app will do. The only piece not exercised
//! here is the usbfs ioctl implementation of `BulkTransport`.

mod common;

use common::{fixture, MockUsbDrive};
use luks_core::device::ReadAt;
use luks_core::fs::Ext4;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;

const PASSWORD: &[u8] = b"test";

fn walk(image: &str) {
    let dev = luks_core::usb::ScsiBlockDevice::open(MockUsbDrive::new(fixture(image)))
        .unwrap_or_else(|e| panic!("{image}: SCSI open: {e}"));

    let block_size = dev.capacity().block_size;
    let table = partition::scan(&dev, block_size).unwrap_or_else(|e| panic!("{image}: scan: {e}"));

    let luks_part = table
        .luks_partitions()
        .next()
        .unwrap_or_else(|| panic!("{image}: no LUKS partition found"));
    let offset = luks_part.offset_bytes();

    let header =
        luks::read_from(&dev, offset).unwrap_or_else(|e| panic!("{image}: header: {e}"));
    assert_eq!(header.primary_segment().unwrap().encryption, "aes-xts-plain64");

    let volume = LuksVolume::open(&dev, offset, &header, PASSWORD)
        .unwrap_or_else(|e| panic!("{image}: unlock: {e}"));

    let fs = Ext4::mount(&volume).unwrap_or_else(|e| panic!("{image}: mount: {e}"));
    assert_eq!(fs.volume_name(), "DISKDATA", "{image}");

    let names: Vec<String> = fs
        .list_dir("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"proof.txt".to_string()), "{image}: {names:?}");
    assert!(names.contains(&"dir".to_string()), "{image}: {names:?}");

    assert_eq!(
        fs.read_file("/proof.txt").unwrap(),
        b"whole disk stack works\n",
        "{image}"
    );
    assert_eq!(
        fs.read_file("/dir/inner.txt").unwrap(),
        b"inside a directory\n",
        "{image}"
    );
}

#[test]
fn gpt_disk_end_to_end() {
    walk("disks/gpt-luks.img");
}

#[test]
fn mbr_disk_end_to_end() {
    walk("disks/mbr-luks.img");
}

/// A tiny per-transfer cap is the pessimistic usbfs case. Correctness must not
/// depend on the transport being generous.
#[test]
fn works_with_a_16k_transfer_limit() {
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).with_max_transfer(16 * 1024);
    let dev = luks_core::usb::ScsiBlockDevice::open(drive).unwrap();

    let table = partition::scan(&dev, 512).unwrap();
    let offset = table.luks_partitions().next().unwrap().offset_bytes();
    let header = luks::read_from(&dev, offset).unwrap();
    let volume = LuksVolume::open(&dev, offset, &header, PASSWORD).unwrap();
    let fs = Ext4::mount(&volume).unwrap();

    assert_eq!(fs.read_file("/proof.txt").unwrap(), b"whole disk stack works\n");
}

/// Counts the SCSI commands a realistic browse costs. Not a performance
/// assertion — a baseline to compare against once the real transport lands,
/// and a guard against a regression that reads block-by-block.
#[test]
fn reports_scsi_command_count_for_a_browse() {
    let dev = luks_core::usb::ScsiBlockDevice::open(MockUsbDrive::new(fixture(
        "disks/gpt-luks.img",
    )))
    .unwrap();

    let table = partition::scan(&dev, 512).unwrap();
    let offset = table.luks_partitions().next().unwrap().offset_bytes();
    let header = luks::read_from(&dev, offset).unwrap();
    let volume = LuksVolume::open(&dev, offset, &header, PASSWORD).unwrap();
    let fs = Ext4::mount(&volume).unwrap();
    let _ = fs.list_dir("/").unwrap();
    let _ = fs.read_file("/proof.txt").unwrap();

    let stats = *dev.transport().stats.borrow();
    println!(
        "browse cost: {} SCSI commands, {} reads, {} bytes",
        stats.commands, stats.read_commands, stats.bytes_read
    );
    // Unlocking reads a 256 KiB keyslot area, so a few hundred commands is
    // expected. Thousands would mean something is reading a block at a time.
    assert!(
        stats.read_commands < 500,
        "far too many read commands: {}",
        stats.read_commands
    );
}

/// The LUKS partition does not start at offset 0 on a real disk. Using the
/// wrong base silently decrypts garbage, so pin the arithmetic down.
#[test]
fn partition_offset_is_applied_consistently() {
    let image = fixture("disks/gpt-luks.img");
    let dev = luks_core::usb::ScsiBlockDevice::open(MockUsbDrive::new(image.clone())).unwrap();
    let table = partition::scan(&dev, 512).unwrap();
    let part = table.luks_partitions().next().unwrap();

    assert_eq!(part.start_lba, 6144);
    assert_eq!(part.offset_bytes(), 6144 * 512);

    // The LUKS magic must sit exactly at the partition offset.
    let mut magic = [0u8; 6];
    dev.read_at(part.offset_bytes(), &mut magic).unwrap();
    assert_eq!(&magic, b"LUKS\xba\xbe");
}
