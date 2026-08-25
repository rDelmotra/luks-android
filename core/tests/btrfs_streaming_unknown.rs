//! End-to-end btrfs unknown-size streaming writes oracle verification test (Pass J.7).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test btrfs_streaming_unknown
//! ```
//!
//! # The Oracle
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real Linux kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

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
        "btrfs-streaming-{src_name}-{}-{}-{}",
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
                println!(
                    "✅ ORACLE VERIFIED: verify-btrfs.sh passed for {}",
                    image_path.display()
                );
                true
            } else {
                eprintln!(
                    "❌ ORACLE FAILED (exit code {:?}):\nstdout:\n{}\nstderr:\n{}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("Failed to execute verify-btrfs.sh: {e}");
            false
        }
    }
}

#[test]
fn streaming_unknown_size_write_multimegabyte() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    // Generate 3.5 MB of deterministic pseudo-random test data with variable chunk sizes
    let total_size = 3 * 1024 * 1024 + 512 * 1024; // 3.5 MiB
    let mut payload = Vec::with_capacity(total_size);
    let mut seed: u32 = 0xDEADBEEF;
    for _ in 0..total_size {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        payload.push((seed >> 16) as u8);
    }

    let expected_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        format!("{:x}", hasher.finalize())
    };

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Begin streaming write without specifying total size
        let mut writer = fs.begin_file_streaming().expect("begin streaming writer");
        assert!(writer.is_streaming(), "writer should be in streaming mode");

        // Stream chunks of uneven sizes
        let chunk_sizes = [65536, 131072, 32768, 98304, 16384, 262144];
        let mut offset = 0;
        let mut i = 0;
        while offset < payload.len() {
            let chunk_size = chunk_sizes[i % chunk_sizes.len()];
            let end = (offset + chunk_size).min(payload.len());
            let slice = &payload[offset..end];
            fs.write_chunk(&mut writer, slice).expect("write chunk");
            offset = end;
            i += 1;
        }

        let ino = fs
            .finish_file(writer, "/", "streamed_large.bin")
            .expect("finish streamed file");
        assert!(ino >= 256);

        // Readback and verify
        let readback = fs
            .read_file("/streamed_large.bin")
            .expect("read streamed file");
        assert_eq!(readback.len(), total_size);
        assert_eq!(readback, payload);
        fs.commit_active_batch().expect("commit");
    }

    // Remount read-only and verify SHA256
    {
        let dev_ro = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");

        let readback = fs_ro
            .read_file("/streamed_large.bin")
            .expect("read streamed file ro");
        let mut hasher = Sha256::new();
        hasher.update(&readback);
        let actual_sha256 = format!("{:x}", hasher.finalize());
        assert_eq!(actual_sha256, expected_sha256);
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn streaming_unknown_size_zero_length_file() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        let writer = fs.begin_file_streaming().expect("begin streaming");
        let ino = fs
            .finish_file(writer, "/", "empty_streamed.bin")
            .expect("finish empty streamed file");
        assert!(ino >= 256);

        let readback = fs
            .read_file("/empty_streamed.bin")
            .expect("read empty file");
        assert!(readback.is_empty());
        fs.commit_active_batch().expect("commit");
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn streaming_unknown_size_on_mixed_4k_img() {
    let img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let data_len = 1024 * 1024; // 1 MiB
    let payload = vec![0x7A; data_len];

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        let mut writer = fs.begin_file_streaming().expect("begin streaming");
        let chunk_size = 4096 * 3; // 12 KB chunks
        for chunk in payload.chunks(chunk_size) {
            fs.write_chunk(&mut writer, chunk).expect("write chunk");
        }
        fs.finish_file(writer, "/", "streamed_4k.bin")
            .expect("finish file");

        let readback = fs.read_file("/streamed_4k.bin").expect("readback");
        assert_eq!(readback, payload);
        fs.commit_active_batch().expect("commit");
    }

    assert!(run_verify_script(&img), "oracle check passed for mixed-4k");
    let _ = fs::remove_file(&img);
}
