//! Writing through the SCSI transport.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test scsi_write
//! ```
//!
//! This is the last layer between Android and the drive's sectors. Above it
//! sits the LUKS encryptor (already graded against dm-crypt) and eventually a
//! filesystem writer; below it, on a phone, is usbfs.
//!
//! The mock drive in `common/` speaks Bulk-Only Transport over an in-memory
//! image and now accepts WRITE(10)/WRITE(16), so the whole path — CBW, data-out
//! phase, CSW — runs in `cargo test` with no hardware. What it cannot prove is
//! that a *real* USB bridge behaves the same way; that needs the phone and the
//! stick.
#![cfg(feature = "dangerous-write-support")]

mod common;

use common::MockUsbDrive;
use luks_core::device::{ReadAt, WriteAt};
use luks_core::usb::scsi::ScsiBlockDevice;

/// An image with position-dependent content, so a write landing at the wrong
/// LBA cannot coincidentally look correct.
fn image(blocks: usize) -> Vec<u8> {
    (0..blocks * 512).map(|i| (i * 31 + 7) as u8).collect()
}

fn device(blocks: usize) -> ScsiBlockDevice<MockUsbDrive> {
    ScsiBlockDevice::open(MockUsbDrive::new(image(blocks))).expect("open mock drive")
}

fn read(dev: &ScsiBlockDevice<MockUsbDrive>, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    dev.read_at(offset, &mut buf).expect("read back");
    buf
}

#[test]
fn a_block_aligned_write_lands_where_it_was_addressed() {
    let dev = device(64);
    let payload: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();

    dev.write_at(512 * 10, &payload).expect("write");
    assert_eq!(read(&dev, 512 * 10, 512), payload);

    // The blocks on either side are untouched. Checking the neighbours is the
    // point: an off-by-one in the LBA arithmetic writes the right bytes to the
    // wrong place, and reading back only what you wrote cannot see that.
    let fresh = image(64);
    assert_eq!(read(&dev, 512 * 9, 512), fresh[512 * 9..512 * 10]);
    assert_eq!(read(&dev, 512 * 11, 512), fresh[512 * 11..512 * 12]);
}

#[test]
fn an_aligned_write_costs_no_read() {
    // The read-modify-write path is a whole extra round trip, and over USB a
    // single SCSI command was measured at 760 us. Whole-block writes must skip
    // it — this asserts the optimisation exists rather than trusting the code
    // to have taken the branch.
    let drive = MockUsbDrive::new(image(64));
    let dev = ScsiBlockDevice::open(drive).expect("open");
    let before = dev.transport().stats.borrow().read_commands;

    dev.write_at(512 * 4, &[0xABu8; 2048]).expect("write");

    let reads = dev.transport().stats.borrow().read_commands - before;
    assert_eq!(
        reads, 0,
        "a 4-block write on a block boundary issued {reads} read commands; \
         it should need none"
    );
    assert_eq!(dev.transport().stats.borrow().write_commands, 1);
}

#[test]
fn a_partial_write_reads_first_and_spares_its_neighbours() {
    // A drive cannot write part of a block, so this must fetch the straddled
    // blocks, patch them and send them back. If the fetch is wrong, the damage
    // lands on bytes the caller never named.
    let dev = device(64);
    let fresh = image(64);
    let before = dev.transport().stats.borrow().read_commands;

    let at = 512 * 3 + 100;
    let payload = [0x5Cu8; 40];
    dev.write_at(at as u64, &payload).expect("write");

    assert!(
        dev.transport().stats.borrow().read_commands > before,
        "an unaligned write must read the straddled block first"
    );
    assert_eq!(read(&dev, at as u64, payload.len()), payload);
    assert_eq!(read(&dev, 512 * 3, 100), fresh[512 * 3..512 * 3 + 100]);
    assert_eq!(read(&dev, at as u64 + 40, 100), fresh[at + 40..at + 140]);
}

#[test]
fn a_write_spanning_more_than_one_command_is_reassembled() {
    // The transfer limit forces a large write to be split. Every split is a
    // chance to lose or duplicate a chunk at the seam, which shows up as a
    // block of correct-looking bytes in the wrong place.
    let drive = MockUsbDrive::new(image(512)).with_max_transfer(4096);
    let dev = ScsiBlockDevice::open(drive).expect("open");

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i * 17 + 3) as u8).collect();
    dev.write_at(512 * 8, &payload).expect("write");

    assert!(
        dev.transport().stats.borrow().write_commands > 1,
        "the transfer limit should have split this into several commands"
    );
    assert_eq!(read(&dev, 512 * 8, payload.len()), payload);
}

#[test]
fn writing_past_the_end_of_the_device_is_refused() {
    let dev = device(16);
    let end = 16 * 512;
    assert!(dev.write_at(end as u64, &[0u8; 512]).is_err());
    assert!(dev.write_at(end as u64 - 4, &[0u8; 512]).is_err());
}

#[test]
fn flush_issues_synchronize_cache() {
    // A USB bridge acknowledges a write once it is in the bridge's buffer, not
    // once it is on flash. Without SYNCHRONIZE CACHE a "completed" write can
    // still be lost to a yanked cable — which is the normal way a phone user
    // ends a transfer.
    let dev = device(16);
    dev.write_at(0, &[1u8; 512]).expect("write");
    assert_eq!(dev.transport().stats.borrow().sync_commands, 0);

    dev.flush().expect("flush");
    assert_eq!(
        dev.transport().stats.borrow().sync_commands,
        1,
        "flush must reach the drive, not just the host buffer"
    );
}

#[test]
fn the_write_path_reaches_a_luks_volume_through_scsi() {
    // The two layers together: plaintext in, ciphertext through SCSI, and the
    // filesystem inside still mounts. This is the shape of what the phone will
    // do, minus usbfs.
    use luks_core::fs::MountedFs;
    use luks_core::luks::{self, LuksVolume};
    use luks_core::partition;

    let disk = common::fixture("disks/gpt-luks.img");
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(disk)).expect("open");

    let table = partition::scan(&dev, 512).expect("gpt");
    let offset = table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();

    let header = luks::read_from(&dev, offset).expect("header");
    let volume = LuksVolume::open(&dev, offset, &header, b"test").expect("unlock");

    // Sector-aligned, so no read-modify-write anywhere in the stack.
    let ss = volume.sector_size() as u64;
    let at = ss * 200;
    let payload = vec![0x77u8; ss as usize];
    volume.write_at(at, &payload).expect("write through SCSI");
    volume.flush().expect("flush");

    let mut back = vec![0u8; ss as usize];
    volume.read_at(at, &mut back).expect("read back");
    assert_eq!(back, payload);

    let fs = MountedFs::mount(&volume).expect("the filesystem must still mount");
    assert_eq!(fs.kind().name(), "ext4");
    fs.list_dir("/").expect("root must still list");
}
