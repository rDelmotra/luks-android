//! End-to-end data extent and checksum tree writing test (Pass F).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_data_write
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
        "btrfs-data-{src_name}-{}-{}-{}",
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
fn write_file_data_on_plain_img_and_verify() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Create a new empty file
    fs.create_file("/", "payload.txt").expect("create file");

    // 2. Write data to the file
    let test_data = b"Hello, Btrfs data writing with CSUM tree and ExtentTree backrefs!";
    fs.write_file("/payload.txt", test_data)
        .expect("write payload data");

    // Verify reader sees updated size and identical content
    let readback = fs.read_file("/payload.txt").expect("read file");
    assert_eq!(readback, test_data);

    let info = fs.file_info("/payload.txt").expect("file info");
    assert_eq!(info.size, test_data.len() as u64);

    drop(fs);

    // 3. Reopen read-only from disk to verify persistence across mounts
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");

    let readback_ro = fs_ro.read_file("/payload.txt").expect("read file on remount");
    assert_eq!(readback_ro, test_data);

    drop(fs_ro);

    // 4. Grade with Linux kernel oracle (btrfs check, mount, scrub)
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on plain.img data write"
    );
}

#[test]
fn write_multi_sector_data_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "multi_sector.dat").expect("create file");

    // 16 KiB of repeating pattern spanning 4 sectors
    let mut test_data = vec![0u8; 16384];
    for (i, b) in test_data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    fs.write_file("/multi_sector.dat", &test_data)
        .expect("write multi sector data");

    let readback = fs.read_file("/multi_sector.dat").expect("read multi sector");
    assert_eq!(readback, test_data);

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on multi-sector write"
    );
}

#[test]
fn write_file_data_on_compress_img() {
    let temp_img = copy_to_temp("compress.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "uncompressed_write.txt").expect("create file");
    let test_data = b"Testing data extent write on a filesystem with compress feature enabled.";
    fs.write_file("/uncompressed_write.txt", test_data)
        .expect("write data on compress.img");

    let readback = fs.read_file("/uncompressed_write.txt").expect("readback on compress.img");
    assert_eq!(readback, test_data);

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on compress.img"
    );
}

#[test]
fn write_file_data_on_mixed_4k_img() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "mixed_write.txt").expect("create file");
    let test_data = b"Testing data extent write on a mixed 4K data+metadata block group.";
    fs.write_file("/mixed_write.txt", test_data)
        .expect("write data on mixed-4k.img");

    let readback = fs.read_file("/mixed_write.txt").expect("readback on mixed-4k.img");
    assert_eq!(readback, test_data);

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on mixed-4k.img"
    );
}

#[test]
fn write_file_in_subdirectory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/docs", "guide.txt").expect("create file in /docs");
    let test_data = b"User guide for encrypted storage with Btrfs support.";
    fs.write_file("/docs/guide.txt", test_data)
        .expect("write data in /docs/guide.txt");

    let readback = fs.read_file("/docs/guide.txt").expect("readback from subdir");
    assert_eq!(readback, test_data);

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on subdir data write"
    );
}
