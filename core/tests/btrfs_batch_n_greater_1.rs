//! Phase 5 verification: N > 1 Batched Commits & FileMark Single-File Rollback.
//!
//! Tests:
//! 1. N=16 batched commits with vacuity control (commits_observed < files_written).
//! 2. Byte-for-byte readback against source for all batched files.
//! 3. Error injection at file k: single-file rollback of file k, automatic commit
//!    of files 1..k-1, and proof of no orphan extents via Linux kernel oracle.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-batch-n16-{src_name}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_btrfs(img_path: &Path) -> (bool, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");
    assert!(script.exists(), "verify-btrfs.sh must exist at {:?}", script);

    if !common::oracle::gate() {
        return (true, "skipped (ALLOW_NO_ORACLE)".to_string());
    }

    let output = Command::new("bash")
        .arg(&script)
        .arg(img_path)
        .output()
        .expect("run verify-btrfs.sh");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

#[test]
fn test_n_greater_1_batched_commits_with_vacuity_control() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let num_files = 32;
    let mut expected_shas = Vec::new();
    let initial_gen;
    let final_gen;

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");
        initial_gen = fs.superblock().generation;

        for i in 0..num_files {
            let filename = format!("batch_file_{:03}.dat", i);
            let payload = format!("Content payload for file index {} - {}", i, "A".repeat(1024 * ((i % 5) + 1))).into_bytes();

            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let expected_sha = format!("{:x}", hasher.finalize());
            expected_shas.push((filename.clone(), expected_sha, payload.clone()));

            let mut writer = fs.begin_file(payload.len() as u64).expect("begin_file");
            fs.write_chunk(&mut writer, &payload).expect("write_chunk");
            let ino = fs.finish_file(writer, "/", &filename).expect("finish_file");
            assert!(ino >= 256 + i as u64);
        }

        // Commit trailing batch
        fs.commit_active_batch().expect("commit active batch");
        final_gen = fs.superblock().generation;

        // Vacuity control: Generation bump must be strictly less than the number of files written
        let commits_observed = final_gen - initial_gen;
        assert!(
            commits_observed < num_files as u64,
            "vacuity control failed: commits_observed ({}) must be strictly less than files_written ({})",
            commits_observed,
            num_files
        );

        // At N=16 threshold, 32 files produce <= 3 commits (2 threshold commits + 1 trailing flush)
        assert!(
            commits_observed <= 3,
            "expected at most 3 commits for 32 files at N=16, observed: {}",
            commits_observed
        );
    }

    // Remount read-only and verify every file's bytes against source
    {
        let dev = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev).expect("mount ro");

        for (filename, expected_sha, expected_bytes) in &expected_shas {
            let readback = fs_ro.read_file(&format!("/{}", filename)).expect("read file");
            assert_eq!(&readback, expected_bytes, "byte mismatch for {}", filename);

            let mut hasher = Sha256::new();
            hasher.update(&readback);
            let actual_sha = format!("{:x}", hasher.finalize());
            assert_eq!(&actual_sha, expected_sha, "sha256 mismatch for {}", filename);
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{out}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_error_injection_at_file_k_rolls_back_single_file_and_commits_preceding() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let mut preceding_files = Vec::new();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Write 5 good files into batch
        for i in 0..5 {
            let filename = format!("good_file_{:02}.dat", i);
            let payload = vec![0x42 + (i as u8); 4096];
            let mut writer = fs.begin_file(payload.len() as u64).expect("begin");
            fs.write_chunk(&mut writer, &payload).expect("write");
            fs.finish_file(writer, "/", &filename).expect("finish");
            preceding_files.push((filename, payload));
        }

        // 2. Inject failure at file k=5 (duplicate name collision)
        let collision_name = "good_file_02.dat"; // Already exists in root!
        let collision_payload = vec![0xFF; 4096];
        let mut writer_k = fs.begin_file(collision_payload.len() as u64).expect("begin k");
        fs.write_chunk(&mut writer_k, &collision_payload).expect("write k");

        let err = fs.finish_file(writer_k, "/", collision_name);
        match err {
            Err(LuksError::AlreadyExists(_)) => {
                // Expected: duplicate rejected, file k rolled back, files 0..4 committed!
            }
            other => panic!("expected Err(AlreadyExists), got: {:?}", other),
        }
    }

    // Remount read-only and verify:
    // - Exactly files 0..4 exist and have correct content
    // - Colliding write did not corrupt file 2 or leave orphans
    {
        let dev = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev).expect("mount ro");

        for (filename, expected_bytes) in &preceding_files {
            let readback = fs_ro.read_file(&format!("/{}", filename)).expect("read good file");
            assert_eq!(&readback, expected_bytes, "content must match for {}", filename);
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed after rollback:\n{out}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_abandon_file_rolls_back_uncommitted_stream_and_commits_preceding() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let mut preceding_files = Vec::new();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Write 3 good files
        for i in 0..3 {
            let filename = format!("saved_file_{}.dat", i);
            let payload = vec![0x77 + (i as u8); 4096];
            let mut writer = fs.begin_file(payload.len() as u64).expect("begin");
            fs.write_chunk(&mut writer, &payload).expect("write");
            fs.finish_file(writer, "/", &filename).expect("finish");
            preceding_files.push((filename, payload));
        }

        // 2. Start a streaming file, write some chunks, then abandon
        let mut abandoned_writer = fs.begin_file_streaming().expect("begin streaming");
        fs.write_chunk(&mut abandoned_writer, &[0xDE, 0xAD, 0xBE, 0xEF]).expect("write partial");
        fs.abandon_file(abandoned_writer);
    }

    // Remount read-only and verify surviving files
    {
        let dev = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev).expect("mount ro");

        for (filename, expected_bytes) in &preceding_files {
            let readback = fs_ro.read_file(&format!("/{}", filename)).expect("read file");
            assert_eq!(&readback, expected_bytes);
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed after abandon:\n{out}");
    let _ = fs::remove_file(&img);
}
