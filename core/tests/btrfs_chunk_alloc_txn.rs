//! End-to-end Chunk Allocation Transaction & Oracle verification tests (Pass H.3).
//!
//! ```text
//! cargo test --features dangerous-write-support --test btrfs_chunk_alloc_txn
//! ```
//!
//! # The Oracle
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real kernel mount ro
//! 3. `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::chunk::{BLOCK_GROUP_DATA, BLOCK_GROUP_DUP, BLOCK_GROUP_METADATA, BLOCK_GROUP_SYSTEM};
use luks_core::fs::btrfs::write::chunk_alloc::next_logical;
use luks_core::fs::btrfs::write::gate::{
    check_chunk_allocation_profile, check_free_space_tree_no_bitmaps,
    check_sys_chunk_array_capacity,
};
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-chunk-alloc-{src_name}-{}-{}-{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_script(image_path: &PathBuf) -> bool {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !script.exists() {
        return false;
    }

    if !common::oracle::gate() {
        return true;
    }

    let output = Command::new(&script).arg(image_path).output();

    match output {
        Ok(out) => {
            if out.status.success() {
                println!("ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
                true
            } else {
                eprintln!(
                    "verify-btrfs.sh stdout:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                );
                eprintln!(
                    "verify-btrfs.sh stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("could not execute verify-btrfs.sh: {e}");
            false
        }
    }
}

#[test]
fn test_allocate_data_chunk_on_plain_img_and_verify() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;
    let initial_chunk_count = fs.chunk_map().len();
    let prev_next_logical = next_logical(fs.chunk_map());

    // Allocate a new DATA chunk (fits 12 MiB hole at physical 1 MiB..13 MiB)
    let new_logical = fs.allocate_data_chunk().expect("allocate data chunk");

    assert_eq!(new_logical, prev_next_logical);
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);
    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    // Verify chunk in chunk map
    let matching_chunk = fs
        .chunk_map()
        .chunks()
        .iter()
        .find(|c| c.logical == new_logical)
        .expect("new chunk must be in chunk map")
        .clone();
    assert_eq!(matching_chunk.chunk_type, BLOCK_GROUP_DATA);
    assert_eq!(matching_chunk.length, 12 * 1024 * 1024);
    assert_eq!(matching_chunk.stripes.len(), 1);
    assert_eq!(matching_chunk.stripes[0].devid, fs.superblock().dev_id);
    assert_eq!(matching_chunk.stripes[0].offset, 1024 * 1024);

    drop(fs);

    // Remount read-only and verify persistence
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
    assert_eq!(fs_ro.chunk_map().len(), initial_chunk_count + 1);
    let remount_chunk = fs_ro
        .chunk_map()
        .chunks()
        .iter()
        .find(|c| c.logical == new_logical)
        .expect("new chunk must persist after remount");
    assert_eq!(*remount_chunk, matching_chunk);
    drop(fs_ro);

    // Run Oracle verification on colima
    let verify_clean = run_verify_script(&temp_img);
    assert!(
        verify_clean,
        "tools/verify-btrfs.sh must pass clean on allocated chunk"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_allocate_data_chunk_device_exhaustion_refusal() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_chunk_count = fs.chunk_map().len();

    // Allocate chunk 1 (fills remaining 12 MiB on plain.img)
    let _log1 = fs.allocate_data_chunk().expect("allocate data chunk 1");
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);

    // Attempt allocate chunk 2 (device is now completely full)
    let res2 = fs.allocate_data_chunk();
    assert!(matches!(res2, Err(luks_core::error::LuksError::FilesystemFull)));

    drop(fs);

    // Run Oracle verification on colima
    let verify_clean = run_verify_script(&temp_img);
    assert!(
        verify_clean,
        "tools/verify-btrfs.sh must pass clean after allocation and refusal"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_allocate_data_chunk_across_all_fixtures() {
    let fixtures = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];
    for name in fixtures {
        let temp_img = copy_to_temp(name);
        let file_len = fs::metadata(&temp_img).unwrap().len();

        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        let initial_chunk_count = fs.chunk_map().len();
        let log = fs.allocate_data_chunk().unwrap_or_else(|e| panic!("{name}: allocate chunk failed: {e}"));

        assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);
        let chunk = fs.chunk_map().chunks().iter().find(|c| c.logical == log).unwrap();
        assert_eq!(chunk.chunk_type, BLOCK_GROUP_DATA);

        drop(fs);

        let verify_clean = run_verify_script(&temp_img);
        assert!(
            verify_clean,
            "{name}: tools/verify-btrfs.sh must pass clean after allocate_data_chunk"
        );

        let _ = fs::remove_file(&temp_img);
    }
}

#[test]
fn test_chunk_allocation_refusal_gates() {
    // 1. Profile refusal
    assert!(check_chunk_allocation_profile(BLOCK_GROUP_DATA).is_ok());
    assert!(check_chunk_allocation_profile(BLOCK_GROUP_METADATA).is_err());
    assert!(check_chunk_allocation_profile(BLOCK_GROUP_SYSTEM).is_err());
    assert!(check_chunk_allocation_profile(BLOCK_GROUP_DATA | BLOCK_GROUP_DUP).is_err());

    // 2. Free space tree bitmaps refusal
    let fixtures = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];
    for name in fixtures {
        let dev = FileDevice::open(fixture(name)).expect("open fixture");
        let fs = Btrfs::mount(dev).expect("mount fixture");
        assert!(check_free_space_tree_no_bitmaps(&fs).is_ok());
        assert!(check_sys_chunk_array_capacity(fs.superblock()).is_ok());
    }
}
