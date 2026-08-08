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

/// Where a *large* write's device commands actually go, now that the
/// per-block metadata commit is gone.
///
/// On hardware a 100 MB file moved at ~7 MiB/s — flat across sizes, so the
/// cost is per-byte. Which per-byte cost is the open question, and the first
/// thing to rule in or out is the shape of the traffic: if the stack issues
/// one command per `max_transfer` chunk, the count is small and the phone's
/// time is going somewhere else. If some layer below fragments the write into
/// sector-sized pieces, the count explodes and there is nothing else to look
/// for.
///
/// `max_transfer` is pinned to the 128 KiB the phone defaults to, so the
/// numbers here are comparable with the device rather than with the mock's own
/// generosity.
#[test]
fn a_large_write_is_issued_in_max_transfer_sized_commands() {
    const MAX_TRANSFER: usize = 128 * 1024;
    const SIZE: usize = 2 * 1024 * 1024;

    let dev = ScsiBlockDevice::open(
        MockUsbDrive::new(fixture("disks/gpt-luks.img")).with_max_transfer(MAX_TRANSFER),
    )
    .expect("open the mock drive");

    let table = partition::scan(&dev, 512).expect("gpt");
    let part = table.luks_partitions().next().expect("a LUKS partition");
    let header = luks::read_from(&dev, part.offset_bytes()).expect("header");
    let volume = LuksVolume::open(
        &dev,
        part.offset_bytes(),
        Some(part.size_bytes()),
        &header,
        PASSWORD,
    )
    .expect("unlock");
    let mut fs = Ext4::mount(&volume).expect("mount");

    dev.transport().stats.borrow_mut().commands = 0;
    dev.transport().stats.borrow_mut().write_commands = 0;
    dev.transport().stats.borrow_mut().read_commands = 0;
    dev.transport().stats.borrow_mut().bytes_written = 0;

    let data = vec![0x5Au8; SIZE];
    fs.create_file(2, "large.bin", &data, luks_core::fs::FileType::Regular)
        .expect("write the file");

    let stats = *dev.transport().stats.borrow();
    let per_write = stats.bytes_written as f64 / stats.write_commands.max(1) as f64;
    let ideal = SIZE / MAX_TRANSFER;

    println!(
        "large write: {} MiB in {} write commands ({} reads), {} bytes written",
        SIZE / (1024 * 1024),
        stats.write_commands,
        stats.read_commands,
        stats.bytes_written
    );
    println!(
        "large write: {per_write:.0} bytes per write command \
         (max_transfer is {MAX_TRANSFER}); {ideal} commands would be perfect"
    );
    // Extrapolated by scaling only the *data* commands. Metadata is a fixed
    // cost per file now, so multiplying the total would inflate it — the same
    // subtraction the per-block test above does, for the same reason.
    let metadata = (stats.write_commands as usize).saturating_sub(ideal);
    let at_100mb = 100_000_000 / MAX_TRANSFER + metadata;
    println!(
        "large write: {metadata} of those are metadata (fixed per file), so \
         100 MB is ~{at_100mb} write commands"
    );
    println!(
        "large write: hardware wrote 100 MB in ~13.6 s (~7 MiB/s, 2026-08-08), \
         which over ~{at_100mb} commands is {:.1} ms each",
        13_600.0 / at_100mb as f64
    );

    // Generous: the metadata writes are genuinely small and drag the mean
    // down, so this is nowhere near `max_transfer`. It bites only if some
    // layer starts issuing sector-sized commands, which is the failure this
    // exists to detect — that would put the mean near 4096 or below.
    assert!(
        per_write > 32_000.0,
        "a large write averaged only {per_write:.0} bytes per SCSI command — \
         something below the filesystem is fragmenting it"
    );
}

/// What the write path costs in **CPU alone**, with no real device under it.
///
/// The write path copies every payload byte seven times and allocates ~6x the
/// file (`file.rs` a whole run, `volume.rs` a whole ciphertext buffer, then two
/// `to_vec`s per SCSI command). That is obviously wasteful, and the tempting
/// conclusion is that it explains the hardware gap — the phone writes at
/// 7.4 MB/s where it reads at 31.
///
/// It is only an explanation if the copying is actually slow, and this is the
/// measurement that says. The mock drive is memory-backed, so what is left is
/// exactly the allocation, the memcpys and AES-XTS. If this reports hundreds of
/// MiB/s then the copies cost microseconds per command and cannot account for
/// the 12 ms per command the phone is losing — the cause is below this code,
/// and rewriting the buffer handling would be an optimisation, not a fix.
#[test]
fn the_write_path_costs_this_much_cpu_with_no_device_latency() {
    const SIZE: usize = 4 * 1024 * 1024;

    let dev = ScsiBlockDevice::open(MockUsbDrive::new(fixture("disks/gpt-luks.img")))
        .expect("open the mock drive");
    let table = partition::scan(&dev, 512).expect("gpt");
    let part = table.luks_partitions().next().expect("a LUKS partition");
    let header = luks::read_from(&dev, part.offset_bytes()).expect("header");
    let volume = LuksVolume::open(
        &dev,
        part.offset_bytes(),
        Some(part.size_bytes()),
        &header,
        PASSWORD,
    )
    .expect("unlock");
    let mut fs = Ext4::mount(&volume).expect("mount");

    let data = vec![0x5Au8; SIZE];
    let started = std::time::Instant::now();
    fs.create_file(2, "cpu.bin", &data, luks_core::fs::FileType::Regular)
        .expect("write the file");
    let elapsed = started.elapsed();

    let mibs = (SIZE as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    println!(
        "write cpu: {} MiB through the full stack in {:.1} ms = {mibs:.0} MiB/s \
         (no device latency: allocation + memcpy + AES-XTS only)",
        SIZE / (1024 * 1024),
        elapsed.as_secs_f64() * 1000.0,
    );
    println!(
        "write cpu: at this rate the copying alone would cost {:.2} s for 100 MB, \
         against the 13.5 s the phone took",
        95.4 / mibs
    );

    // Not a performance assertion — a floor far below anything plausible, so it
    // fails only if the write path has become pathologically slow rather than
    // merely wasteful.
    assert!(
        mibs > 20.0,
        "the write path manages only {mibs:.0} MiB/s of pure CPU"
    );
}
