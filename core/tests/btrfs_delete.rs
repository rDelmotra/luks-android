//! End-to-end Btrfs file deletion and oracle verification test (Phase 2).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_delete
//! ```
//!
//! # The Oracle
//!
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly` (verifying all extent items, backrefs, csums, and tree roots)
//! 2. Real kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all data sector checksums and DUP mirrors)
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

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-delete-{src_name}-{}-{}-{}",
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
    let up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !up {
        if std::env::var("REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false) {
            panic!("REQUIRE_ORACLE=1 is set but colima/oracle is not running!");
        }
        eprintln!("⚠️  ORACLE SKIPPED: colima is not running");
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
fn delete_empty_file_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Create an empty file
    fs.create_file("/", "empty_to_delete.txt").expect("create file");

    let entries = fs.list_dir("/").expect("list dir");
    assert!(entries.iter().any(|e| e.name == "empty_to_delete.txt"));

    // 2. Delete the empty file
    fs.delete_file("/empty_to_delete.txt").expect("delete file");

    // 3. Verify it is gone
    let entries_after = fs.list_dir("/").expect("list dir after delete");
    assert!(!entries_after.iter().any(|e| e.name == "empty_to_delete.txt"));
    assert!(matches!(fs.read_file("/empty_to_delete.txt"), Err(LuksError::NotFound(_))));

    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_file_with_data_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let test_data = b"Btrfs file deletion with extent freeing and checksum cleanup test!";
    fs.create_file_with_data("/", "data_to_delete.txt", test_data)
        .expect("create file with data");

    let read_back = fs.read_file("/data_to_delete.txt").expect("read file");
    assert_eq!(read_back, test_data);

    // Delete the file
    fs.delete_file("/data_to_delete.txt").expect("delete file");

    // Verify it is gone
    let entries = fs.list_dir("/").expect("list dir");
    assert!(!entries.iter().any(|e| e.name == "data_to_delete.txt"));
    assert!(matches!(fs.read_file("/data_to_delete.txt"), Err(LuksError::NotFound(_))));

    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_reclaims_space_and_allows_reallocation() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_used = fs.superblock().bytes_used;

    // Create 64 KiB file
    let large_data = vec![0x42u8; 64 * 1024];
    fs.create_file_with_data("/", "reclaim_test.bin", &large_data)
        .expect("create file");

    let used_after_create = fs.superblock().bytes_used;
    assert!(used_after_create > initial_used, "used space should have increased");

    // Delete the file
    fs.delete_file("/reclaim_test.bin").expect("delete file");

    let used_after_delete = fs.superblock().bytes_used;
    assert!(
        used_after_delete < used_after_create,
        "used space should have decreased after deletion: before={used_after_create}, after={used_after_delete}"
    );

    // Create a new file allocating reclaimed space
    let new_data = vec![0x77u8; 64 * 1024];
    fs.create_file_with_data("/", "reallocated.bin", &new_data)
        .expect("create new file in reclaimed space");

    let read_back = fs.read_file("/reallocated.bin").expect("read back");
    assert_eq!(read_back, new_data);

    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_multiple_files_sequentially() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file_with_data("/", "file1.txt", b"content 1").expect("create file1");
    fs.create_file_with_data("/", "file2.txt", b"content 2").expect("create file2");
    fs.create_file_with_data("/", "file3.txt", b"content 3").expect("create file3");

    // Delete file1 and file3, keep file2
    fs.delete_file("/file1.txt").expect("delete file1");
    fs.delete_file("/file3.txt").expect("delete file3");

    let entries = fs.list_dir("/").expect("list dir");
    assert!(!entries.iter().any(|e| e.name == "file1.txt"));
    assert!(entries.iter().any(|e| e.name == "file2.txt"));
    assert!(!entries.iter().any(|e| e.name == "file3.txt"));

    assert_eq!(fs.read_file("/file2.txt").expect("read file2"), b"content 2");

    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_file_across_fixtures() {
    for fixture_name in ["mixed-4k.img", "compress.img", "subvol.img"] {
        let temp_img = copy_to_temp(fixture_name);
        let file_len = fs::metadata(&temp_img).unwrap().len();

        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        let payload = format!("test delete on {fixture_name}").into_bytes();
        fs.create_file_with_data("/", "fixture_del.txt", &payload)
            .expect("create file");

        assert_eq!(fs.read_file("/fixture_del.txt").expect("read"), payload);

        fs.delete_file("/fixture_del.txt").expect("delete file");
        assert!(matches!(fs.read_file("/fixture_del.txt"), Err(LuksError::NotFound(_))));

        drop(fs);
        assert!(
            run_verify_script(&temp_img),
            "oracle check failed on {fixture_name}"
        );
    }
}

#[test]
fn delete_refusal_gates() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // Deleting root "/" should fail with IsADirectory
    assert!(matches!(fs.delete_file("/"), Err(LuksError::IsADirectory(_))));

    // Deleting non-existent file should fail with NotFound
    assert!(matches!(fs.delete_file("/nonexistent.txt"), Err(LuksError::NotFound(_))));
}
