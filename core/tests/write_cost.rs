//! What a file write *costs* in SCSI commands, measured rather than reasoned
//! about.
//!
//! A 50 MB write on real hardware ran for more than five minutes before it was
//! killed, and the leaked-block range e2fsck reported afterwards showed nearly
//! every block had been allocated — so the time went into the allocation loop,
//! not the data transfer. That is a hypothesis until something counts, which is
//! what this file does.
//!
//! The number that matters is the **marginal** cost: commands per additional
//! block of file. Fixed setup (mount, unlock, the directory link) is charged
//! once no matter how big the file is, so two writes of different sizes and a
//! subtraction isolate the part that scales.
//!
//! These are deliberately *reported*, with only a loose ceiling asserted. A
//! tight assertion here would turn every legitimate change to the write path
//! into a failing test; the ceiling is set where "something has gone
//! quadratic" lives, not where today's number happens to sit.
#![cfg(feature = "dangerous-write-support")]

mod common;

use common::{fixture, MockUsbDrive};
use luks_core::fs::Ext4;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::usb::ScsiBlockDevice;

const PASSWORD: &[u8] = b"test";

/// Write one file of `bytes` through the whole stack and report what the
/// transport saw.
fn cost_of_writing(bytes: usize, name: &str) -> common::Stats {
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(fixture("disks/gpt-luks.img")))
        .expect("open the mock drive");

    let table = partition::scan(&dev, 512).expect("gpt");
    let part = table.luks_partitions().next().expect("a LUKS partition");
    let offset = part.offset_bytes();
    let part_len = Some(part.size_bytes());

    let header = luks::read_from(&dev, offset).expect("header");
    let volume = LuksVolume::open(&dev, offset, part_len, &header, PASSWORD).expect("unlock");
    let mut fs = Ext4::mount(&volume).expect("mount");

    // Counted from here: mount and unlock are fixed costs and would only
    // dilute the per-block number this exists to find.
    dev.transport().stats.borrow_mut().commands = 0;
    dev.transport().stats.borrow_mut().write_commands = 0;
    dev.transport().stats.borrow_mut().read_commands = 0;

    let data = vec![0x5Au8; bytes];
    fs.create_file(2, name, &data, luks_core::fs::FileType::Regular)
        .expect("write the file");

    let stats = *dev.transport().stats.borrow();
    stats
}

#[test]
fn a_file_write_costs_a_reported_number_of_scsi_commands() {
    // Both sizes are multiples of the 4 KiB block so neither pays a partial
    // final block the other does not.
    const BS: usize = 4096;
    let small_blocks = 16;
    let large_blocks = 48;

    let small = cost_of_writing(small_blocks * BS, "small.bin");
    let large = cost_of_writing(large_blocks * BS, "large.bin");

    let extra_blocks = large_blocks - small_blocks;
    let extra_commands = large.commands.saturating_sub(small.commands);
    let per_block = extra_commands as f64 / extra_blocks as f64;

    println!(
        "write cost: {} blocks = {} commands ({} reads, {} writes)",
        small_blocks, small.commands, small.read_commands, small.write_commands
    );
    println!(
        "write cost: {} blocks = {} commands ({} reads, {} writes)",
        large_blocks, large.commands, large.read_commands, large.write_commands
    );
    println!(
        "write cost: {extra_commands} commands for {extra_blocks} extra blocks \
         = {per_block:.1} SCSI commands per 4 KiB block"
    );

    // On this transport a command measured at 0.76-1.15 ms, and roughly 3x
    // that through the phone's USB host. At the 7.0 commands per block this
    // reported before batched allocation, a 50 MB file is 12,208 blocks and
    // ~85,000 round trips — minutes of pure latency before any data moves,
    // which is the hardware hang this exists to measure the cause of.
    println!(
        "write cost: extrapolated to 50 MB ({} blocks): {:.0} commands, \
         {:.1} s at 1 ms each",
        50_000_000 / BS,
        per_block * (50_000_000 / BS) as f64,
        per_block * (50_000_000 / BS) as f64 / 1000.0,
    );

    // The ceiling, not the target. Since allocation commits once per group
    // touched rather than once per block, the marginal block costs *nothing*
    // in metadata — only its share of a chunked data write. Measured at 0.03
    // (2026-08-08, `cargo test --features dangerous-write-support --test
    // write_cost`), down from 7.0.
    //
    // Half a command per block is therefore an enormous margin and still
    // catches the regression that matters: a commit that has crept back inside
    // the per-block loop cannot come in under it.
    assert!(
        per_block < 0.5,
        "a 4 KiB block should not cost {per_block:.1} SCSI commands — \
         the metadata commit is running per block again"
    );
}
