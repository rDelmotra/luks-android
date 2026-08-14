//! End-to-end file creation and oracle verification test (Pass E).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_create_file
//! ```
//!
//! # The Oracle
//!
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::Btrfs;

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
    let dst = temp_dir.join(format!(
        "btrfs-create-{src_name}-{}-{}",
        std::process::id(),
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

    let output = Command::new(&script).arg(image_path).output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                eprintln!(
                    "verify-btrfs.sh stdout:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                );
                eprintln!(
                    "verify-btrfs.sh stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            out.status.success()
        }
        Err(e) => {
            eprintln!("could not execute verify-btrfs.sh: {e}");
            false
        }
    }
}

#[test]
fn create_file_in_root_directory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    // 1. Open writable device and mount
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // 2. Create a new empty file in root directory
    fs.create_file("/", "newfile.txt").expect("create newfile.txt in /");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    // Verify reader sees the new file
    let entries = fs.list_dir("/").expect("list root dir");
    assert!(entries.iter().any(|e| e.name == "newfile.txt"));
    assert!(entries.iter().any(|e| e.name == "hello.txt"));
    assert!(entries.iter().any(|e| e.name == "docs"));

    let info = fs.file_info("/newfile.txt").expect("file info newfile.txt");
    assert_eq!(info.size, 0);
    assert_eq!(info.links, 1);
    assert!(info.file_type.is_file());

    drop(fs);

    // 3. Re-open read-only from disk to verify persistence across mounts
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");

    assert_eq!(fs_ro.superblock().generation, original_sb_gen + 1);
    let entries_ro = fs_ro.list_dir("/").expect("list root dir on remount");
    assert!(entries_ro.iter().any(|e| e.name == "newfile.txt"));

    let info_ro = fs_ro
        .file_info("/newfile.txt")
        .expect("file info on remount");
    assert_eq!(info_ro.size, 0);
    assert_eq!(info_ro.links, 1);
    assert!(info_ro.file_type.is_file());

    drop(fs_ro);

    // 4. Grade with kernel oracle (btrfs check, mount, scrub)
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on plain.img root create"
    );
}

#[test]
fn create_file_in_subdirectory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Create a new empty file in subdirectory /docs
    fs.create_file("/docs", "note.txt")
        .expect("create note.txt in /docs");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    let entries = fs.list_dir("/docs").expect("list /docs");
    assert!(entries.iter().any(|e| e.name == "note.txt"));
    assert!(entries.iter().any(|e| e.name == "readme.md"));

    let info = fs.file_info("/docs/note.txt").expect("file info note.txt");
    assert_eq!(info.size, 0);
    assert_eq!(info.links, 1);

    drop(fs);

    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");
    let entries_ro = fs_ro.list_dir("/docs").expect("list /docs on remount");
    assert!(entries_ro.iter().any(|e| e.name == "note.txt"));

    drop(fs_ro);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on plain.img subdir create"
    );
}

#[test]
fn create_file_on_compress_img() {
    let temp_img = copy_to_temp("compress.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "extra.txt")
        .expect("create extra.txt in / on compress.img");

    let entries = fs.list_dir("/").expect("list / on compress.img");
    assert!(entries.iter().any(|e| e.name == "extra.txt"));
    assert!(entries.iter().any(|e| e.name == "zstd.txt"));

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on compress.img"
    );
}

#[test]
fn create_file_on_mixed_4k_img() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "mixed_new.txt")
        .expect("create mixed_new.txt on mixed-4k.img");

    let entries = fs.list_dir("/").expect("list / on mixed-4k.img");
    assert!(entries.iter().any(|e| e.name == "mixed_new.txt"));

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on mixed-4k.img"
    );
}

#[test]
fn duplicate_file_creation_is_refused() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Attempting to create an existing file must fail with AlreadyExists
    let res = fs.create_file("/", "hello.txt");
    match res {
        Err(LuksError::AlreadyExists(_)) => {}
        other => panic!("expected AlreadyExists error, got: {other:?}"),
    }

    // Superblock generation should be untouched
    assert_eq!(fs.superblock().generation, original_sb_gen);

    drop(fs);
    let _ = fs::remove_file(&temp_img);
}

#[test]
fn create_multiple_files_consecutively_and_verify() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Create 5 files consecutively
    for i in 0..5 {
        let name = format!("batch_file_{i}.txt");
        fs.create_file("/", &name).expect("create batch file");
    }

    assert_eq!(fs.superblock().generation, original_sb_gen + 5);

    let entries = fs.list_dir("/").expect("list root dir");
    for i in 0..5 {
        let name = format!("batch_file_{i}.txt");
        assert!(entries.iter().any(|e| e.name == name));
    }

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on multiple files creation"
    );
}
