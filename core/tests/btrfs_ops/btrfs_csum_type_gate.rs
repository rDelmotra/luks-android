//! Non-crc32c checksum volumes: readable, not writable.
//!
//! `CsumType::Sha256` is a type this driver parses and mounts
//! (`superblock.rs:72`) and that `mkfs.btrfs --csum sha256` really produces.
//! Before the gate added alongside this test, writing to one *succeeded* and
//! produced a filesystem the kernel rejects.
//!
//! Measured 2026-09-09 with the gate removed, on `fixtures/btrfs/sha256-4k.img`:
//! 40 files of 1,536,000 bytes written through `create_file_with_data` emitted
//! `total csum bytes: 60000` where 480,000 were required (40 x 375 sectors x 32
//! bytes/sector), and `btrfs check` reported `some csum missing` for every one
//! of inodes 257-296. `tools/verify-btrfs.sh` exited 1. The driver reported
//! success for all 40 writes.
//!
//! Root cause: `FileWriter::checksums` is `Vec<(u64, u32)>` — 4 bytes per
//! sector, too narrow for a 32-byte digest — and
//! `build_extent_csum_items_from_checksums` (`write/node.rs:701`), which
//! `Batch::commit` uses for every streamed file, hardcodes the width as 4 in
//! `max_csum_item_bytes(node_size, 4)`, `sectors_per_item = max_item / 4`, and
//! its `crc.to_le_bytes()` payload.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support --test btrfs_csum_type_gate
//! ```

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::fs;

use common::scratch::ScratchFixture;
use luks_core::device::{FileDevice, ReadAt};
use luks_core::error::LuksError;
use luks_core::fs::btrfs::superblock::CsumType;
use luks_core::fs::btrfs::Btrfs;

/// The fixture really is sha256, and mounting plus reading it still works.
///
/// This is the control for the refusal test below: if the fixture were crc32c,
/// or unmountable, that test would pass for the wrong reason.
#[test]
fn sha256_volume_mounts_and_reads() {
    let scratch = ScratchFixture::new("btrfs/sha256-4k.img", "sha256_reads");
    let len = fs::metadata(scratch.path()).expect("metadata").len();
    let dev = FileDevice::open(scratch.path()).expect("open read-only");
    let fs_drv = Btrfs::mount(dev).expect("mount sha256 volume read-only");

    assert!(
        len > 0,
        "fixture is empty — regenerate with tools/provision-fixtures.sh"
    );
    assert!(
        matches!(fs_drv.superblock().csum_type, CsumType::Sha256),
        "fixture must be sha256, got {:?} — this test proves nothing otherwise",
        fs_drv.superblock().csum_type
    );
    assert_eq!(
        fs_drv.superblock().csum_type.size(),
        32,
        "sha256 digests are 32 bytes"
    );

    // Reading is size-agnostic and must keep working: refusing writes must not
    // have cost us read support for these volumes.
    let entries = fs_drv.list_dir("/").expect("list root of sha256 volume");
    let _ = entries.len();
}

/// Every write entry point must refuse a sha256 volume by name.
///
/// `gate::check_writeable_fs` is the single choke point all eleven call sites
/// funnel through, so exercising the high-level APIs here covers them all.
#[test]
fn sha256_volume_refuses_every_write_path() {
    let scratch = ScratchFixture::new("btrfs/sha256-4k.img", "sha256_refuses_writes");
    let file_len = fs::metadata(scratch.path()).expect("metadata").len();

    // Capture the bytes before, so we can prove nothing was written.
    let mut before = vec![0u8; 1 << 20];
    {
        let probe = FileDevice::open(scratch.path()).expect("open for pre-image");
        probe.read_at(0, &mut before).expect("read pre-image");
    }

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs_drv = Btrfs::mount(dev).expect("mount sha256 volume");

    let data = vec![0xABu8; 8192];

    // (label, result) for each distinct high-level write entry point.
    let attempts: Vec<(&str, Result<(), LuksError>)> = vec![
        (
            "create_file_with_data",
            fs_drv.create_file_with_data("", "new.bin", &data).map(|_| ()),
        ),
        (
            "create_file",
            fs_drv.create_file("", "empty.bin"),
        ),
        (
            "create_directory",
            fs_drv.create_directory("", "newdir").map(|_| ()),
        ),
        (
            "begin_file",
            fs_drv.begin_file(data.len() as u64).map(|_| ()),
        ),
        (
            "begin_file_streaming",
            fs_drv.begin_file_streaming().map(|_| ()),
        ),
        (
            "set_mtime",
            fs_drv.set_mtime("/", 1_700_000_000, 0),
        ),
    ];

    assert!(
        !attempts.is_empty(),
        "no write entry points exercised — vacuous test"
    );

    for (label, result) in &attempts {
        match result {
            Err(LuksError::UnsupportedFsFeature(msg)) => {
                assert!(
                    msg.contains("checksums"),
                    "{label}: refused, but not for the checksum reason: {msg}"
                );
            }
            Err(other) => panic!(
                "{label}: expected UnsupportedFsFeature about checksums, got {other:?}"
            ),
            Ok(()) => panic!(
                "{label}: WROTE to a sha256 volume. This is the 2026-09-09 \
                 silent-corruption defect: the streaming csum builder emits \
                 4 bytes per sector for a 32-byte digest, so btrfs check \
                 reports 'some csum missing' on every inode."
            ),
        }
    }

    drop(fs_drv);

    // Refused means refused: the on-disk bytes must be untouched.
    let mut after = vec![0u8; 1 << 20];
    {
        let probe = FileDevice::open(scratch.path()).expect("open for post-image");
        probe.read_at(0, &mut after).expect("read post-image");
    }
    assert_eq!(
        before, after,
        "a refused write still modified the first MiB of the volume"
    );
}

/// Control: the same operations succeed on an otherwise-identical crc32c
/// volume. Without this, a bug that refused *all* writes would pass the test
/// above.
#[test]
fn crc32c_volume_still_accepts_writes() {
    let scratch = ScratchFixture::new("btrfs/nonmixed-4k.img", "crc32c_control");
    let file_len = fs::metadata(scratch.path()).expect("metadata").len();
    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs_drv = Btrfs::mount(dev).expect("mount crc32c volume");

    assert!(
        matches!(fs_drv.superblock().csum_type, CsumType::Crc32c),
        "control fixture must be crc32c"
    );

    let data = vec![0xCDu8; 8192];
    fs_drv
        .create_file_with_data("", "control.bin", &data)
        .expect("crc32c volume must still accept writes");
    fs_drv.commit_active_batch().expect("commit control write");

    let read_back = fs_drv.read_file("/control.bin").expect("read back");
    assert_eq!(read_back, data, "control write did not round-trip");
}
