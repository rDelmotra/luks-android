//! End-to-end timestamp mutation and oracle verification test (Pass D).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_timestamp_write
//! ```
//!
//! # The Oracle
//!
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

/// See the note on the same counter in `btrfs_create_file.rs`: a timestamp
/// alone does not make this path unique, because this host's `SystemTime`
/// advances in 1 µs steps and `cargo` starts a binary's tests together.
static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-test-{src_name}-{}-{}-{}",
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
                println!("✅ ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
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
fn mutate_timestamp_on_plain_img_and_verify_with_kernel() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    // 1. Open writable device and mount
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // 2. Mutate timestamp on "hello.txt"
    let target_mtime_sec = 1_700_000_000u64;
    let target_mtime_nsec = 500_000_000u32;
    fs.set_mtime("hello.txt", target_mtime_sec, target_mtime_nsec)
        .expect("set_mtime hello.txt");

    // Verify in-memory mount state updated
    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    // Verify reader sees new timestamp
    let located = fs
        .resolve_no_follow(fs.fs_tree(), "hello.txt")
        .expect("resolve hello.txt");
    assert_eq!(located.inode.mtime, target_mtime_sec as i64);

    // Drop filesystem to flush/close
    drop(fs);

    // 3. Re-open read-only from disk to verify persistence across mounts
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");

    assert_eq!(fs_ro.superblock().generation, original_sb_gen + 1);
    let located_ro = fs_ro
        .resolve_no_follow(fs_ro.fs_tree(), "hello.txt")
        .expect("resolve hello.txt on remount");
    assert_eq!(located_ro.inode.mtime, target_mtime_sec as i64);

    // Verify directory listing and file contents are completely intact
    let entries = fs_ro
        .list_dir_by_inode(fs_ro.fs_tree().bytenr, fs_ro.fs_tree().root_dirid)
        .expect("list root dir");
    assert!(entries.iter().any(|e| e.name == "hello.txt"));
    assert!(entries.iter().any(|e| e.name == "docs"));

    drop(fs_ro);

    // 4. Grade with kernel oracle (btrfs check, mount, scrub)
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(oracle_clean, "kernel oracle verification failed on plain.img");
}

#[test]
fn mutate_timestamp_on_compress_img_and_verify_with_kernel() {
    let temp_img = copy_to_temp("compress.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;
    let target_mtime_sec = 1_720_000_000u64;
    let target_mtime_nsec = 123_456_789u32;

    fs.set_mtime("zstd.txt", target_mtime_sec, target_mtime_nsec)
        .expect("set_mtime zstd.txt");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);
    let located = fs
        .resolve_no_follow(fs.fs_tree(), "zstd.txt")
        .expect("resolve zstd.txt");
    assert_eq!(located.inode.mtime, target_mtime_sec as i64);

    drop(fs);

    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");
    assert_eq!(fs_ro.superblock().generation, original_sb_gen + 1);

    let located_ro = fs_ro
        .resolve_no_follow(fs_ro.fs_tree(), "zstd.txt")
        .expect("resolve zstd.txt on remount");
    assert_eq!(located_ro.inode.mtime, target_mtime_sec as i64);

    drop(fs_ro);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on compress.img"
    );
}

#[test]
fn mutate_timestamp_on_mixed_4k_img_and_verify_with_kernel() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;
    let target_mtime_sec = 1_730_000_000u64;
    let target_mtime_nsec = 987_654_321u32;

    fs.set_mtime("hello.txt", target_mtime_sec, target_mtime_nsec)
        .expect("set_mtime hello.txt");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);
    let located = fs
        .resolve_no_follow(fs.fs_tree(), "hello.txt")
        .expect("resolve hello.txt");
    assert_eq!(located.inode.mtime, target_mtime_sec as i64);

    drop(fs);

    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");
    assert_eq!(fs_ro.superblock().generation, original_sb_gen + 1);

    let located_ro = fs_ro
        .resolve_no_follow(fs_ro.fs_tree(), "hello.txt")
        .expect("resolve hello.txt on remount");
    assert_eq!(located_ro.inode.mtime, target_mtime_sec as i64);

    drop(fs_ro);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on mixed-4k.img"
    );
}
