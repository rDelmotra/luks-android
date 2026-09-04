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

use common::{fixture, MockUsbDrive};
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
    let part = table
        .luks_partitions()
        .next()
        .expect("a LUKS partition");
    let offset = part.offset_bytes();
    let part_len = Some(part.size_bytes());

    let header = luks::read_from(&dev, offset).expect("header");
    let volume = LuksVolume::open(&dev, offset, part_len, &header, b"test").expect("unlock");

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

// --- why a drive said no ----------------------------------------------------

#[test]
fn a_refused_write_carries_the_drive_s_reason() {
    // The failure this reproduces happened on hardware: an Android test device refused
    // every WRITE(10) with CSW status 1 while reads kept working perfectly,
    // and the error reaching the UI was the bare text "SCSI command failed" —
    // equally consistent with a write-protected drive, a CDB the drive would
    // not accept, and failing media. The reason exists, but only in response
    // to a REQUEST SENSE issued before anything else touches the bus.
    //
    // 0x27/0x00 is WRITE PROTECTED, under sense key 7 (DATA PROTECT).
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).failing(0x2A, [0x7, 0x27, 0x00]);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let err = dev
        .write_at(0, &[0u8; 512])
        .expect_err("the mock refuses WRITE(10)");

    let luks_core::error::LuksError::ScsiCommandFailed {
        opcode,
        sense: Some(sense),
    } = err
    else {
        panic!("a refusal should carry sense data");
    };
    assert_eq!(opcode, 0x2A, "the error should name WRITE(10) as the command");
    assert_eq!(sense.key, 0x7, "sense key");
    assert_eq!((sense.asc, sense.ascq), (0x27, 0x00), "ASC/ASCQ");

    let text = luks_core::error::LuksError::ScsiCommandFailed {
        opcode,
        sense: Some(sense),
    }
    .to_string();
    assert!(
        text.contains("WRITE(10)") && text.contains("data protect"),
        "the message should say what happened, not just that it did: {text}"
    );
}

#[test]
fn reads_still_work_while_writes_are_refused() {
    // Exactly the shape of the hardware failure, and worth pinning: if a
    // refused write left the bus desynchronised, the next read would fail too
    // and the diagnosis would point at the wrong layer. On physical hardware a 26-byte
    // export succeeded after three refused writes.
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).failing(0x2A, [0x7, 0x27, 0x00]);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    assert!(dev.write_at(0, &[0u8; 512]).is_err());

    let mut buf = [0u8; 512];
    dev.read_at(0, &mut buf).expect("reads must survive a refusal");
    assert_eq!(&buf[510..], &[0x55, 0xAA], "the MBR signature should be there");
}

#[test]
fn asking_why_a_failure_happened_does_not_ask_why_that_failed() {
    // The obvious way to write the sense fetch recurses forever: a failure
    // triggers REQUEST SENSE, and if REQUEST SENSE is itself refused it
    // triggers another. A drive that refuses everything is unusual but a
    // wedged bridge is not, and a stack overflow is a poor way to report one.
    //
    // Reaching the assertion at all is the test; `None` says the fetch was
    // attempted and failed, which is worth distinguishing from a drive that
    // answered with no sense data.
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let dev = ScsiBlockDevice::open(drive).unwrap();
    // Refuse everything only *after* open(), which needs INQUIRY and friends.
    dev.transport().fail_opcodes.borrow_mut().extend(0u8..=0xFF);

    let err = dev.write_at(0, &[0u8; 512]).expect_err("everything is refused");
    assert!(
        matches!(
            err,
            luks_core::error::LuksError::ScsiCommandFailed { sense: None, .. }
        ),
        "expected a refusal with no obtainable reason, got: {err}"
    );
}

// --- a drive with no flush command ------------------------------------------

/// INVALID COMMAND OPERATION CODE: key 5, ASC 0x20/0x00.
const NO_SUCH_OPCODE: [u8; 3] = [0x5, 0x20, 0x00];

#[test]
fn a_flush_falls_back_to_the_16_byte_form() {
    // Some bridges implement one form and not the other, so a drive refusing
    // SYNCHRONIZE CACHE(10) is not a drive that cannot flush.
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).failing(0x35, NO_SUCH_OPCODE);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    dev.flush().expect("the 16-byte form should carry the flush");
    assert!(
        !dev.flush_is_a_no_op(),
        "a drive that answered the 16-byte form can still flush"
    );
}

#[test]
fn a_drive_with_neither_flush_command_does_not_fail_every_write() {
    // The hardware failure this comes from: a SanDisk bridge refuses
    // SYNCHRONIZE CACHE(10) as an unknown opcode, and because every write ends
    // in a flush, every write on that drive failed. The refusal was also read
    // as coming from WRITE(10), which sent the investigation to the CDB
    // encoder — hence the opcode now being carried in the error.
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"))
        .failing(0x35, NO_SUCH_OPCODE)
        .failing(0x91, NO_SUCH_OPCODE);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    dev.write_at(0, &[0u8; 512]).expect("the write itself is fine");
    dev.flush().expect("a drive with no flush command must not fail the write");
    assert!(
        dev.flush_is_a_no_op(),
        "the caller has to be able to find out that durability is not confirmed"
    );
}

#[test]
fn a_flush_that_fails_for_any_other_reason_is_still_an_error() {
    // "This drive cannot flush" and "this flush did not work" are different
    // facts, and only the first is safe to carry on from. 0x03/0x00 is a
    // peripheral device write fault under sense key 4, hardware error.
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).failing(0x35, [0x4, 0x03, 0x00]);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let err = dev.flush().expect_err("a real flush failure must surface");
    assert!(!dev.flush_is_a_no_op(), "one bad flush is not a missing command");
    assert!(
        err.to_string().contains("SYNCHRONIZE CACHE(10)"),
        "the error should name the command that failed: {err}"
    );
}

#[test]
fn max_scsi_transfer_caps_single_write_commands() {
    let drive = MockUsbDrive::new(image(4096)).with_max_transfer(1024 * 1024);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let payload = vec![0x5Au8; 1024 * 1024];
    dev.write_at(0, &payload).expect("write 1 MiB");

    let stats = *dev.transport().stats.borrow();
    // 1 MiB in 128 KiB commands = 8 commands
    assert!(
        stats.write_commands >= 8,
        "expected at least 8 write commands, got {}",
        stats.write_commands
    );
    assert_eq!(
        stats.largest_write_blocks, 256,
        "capped at 128 KiB / 512 = 256 blocks"
    );
}
