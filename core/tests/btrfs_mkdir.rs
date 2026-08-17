//! End-to-end btrfs directory creation (mkdir) and oracle verification test (Pass J.1).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test btrfs_mkdir
//! ```
//!
//! # The Oracle
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real Linux kernel mount
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

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-mkdir-{src_name}-{}-{}-{}",
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
fn mkdir_in_root_directory_on_plain_img() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        let ino = fs
            .create_directory("/", "test_folder")
            .expect("create directory in /");
        assert!(ino >= 256, "inode number must be >= 256");

        // Verify with reader API in same session
        let located = fs
            .resolve_no_follow(fs.fs_tree(), "/test_folder")
            .expect("resolve /test_folder");
        assert_eq!(located.inode.objectid, ino);
        assert!(located.inode.file_type().is_dir());
        assert_eq!(located.inode.mode, 0o040755);
        assert_eq!(located.inode.nlink, 1);
        assert_eq!(located.inode.size, 0);

        let entries = fs
            .list_dir_by_inode(fs.fs_tree().bytenr, fs.fs_tree().root_dirid)
            .expect("list root dir");
        assert!(entries.iter().any(|e| e.name == "test_folder" && e.file_type.is_dir()));
    }

    // Remount read-only and verify persistence
    {
        let dev_ro = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
        let located = fs_ro
            .resolve_no_follow(fs_ro.fs_tree(), "/test_folder")
            .expect("resolve ro");
        assert!(located.inode.file_type().is_dir());
        assert_eq!(located.inode.mode, 0o040755);
    }

    // Verify with Linux kernel oracle
    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn mkdir_nested_and_create_file_inside() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Step 1: Create parent directory
        let dir1_ino = fs
            .create_directory("/", "documents")
            .expect("mkdir /documents");
        assert!(dir1_ino >= 256);

        // Step 2: Create child directory inside /documents
        let dir2_ino = fs
            .create_directory("/documents", "personal")
            .expect("mkdir /documents/personal");
        assert!(dir2_ino >= 256);
        assert_ne!(dir1_ino, dir2_ino);

        // Step 3: Create a file with data inside /documents/personal
        let file_payload = b"Top secret content inside nested btrfs directories!";
        let file_ino = fs
            .create_file_with_data("/documents/personal", "secret.txt", file_payload)
            .expect("create file in /documents/personal");
        assert!(file_ino >= 256);

        // Readback file inside new directory
        let readback = fs
            .read_file("/documents/personal/secret.txt")
            .expect("read nested file");
        assert_eq!(readback, file_payload);
    }

    // Remount read-only and verify full path resolution and content
    {
        let dev_ro = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");

        let readback = fs_ro
            .read_file("/documents/personal/secret.txt")
            .expect("read nested file ro");
        assert_eq!(readback, b"Top secret content inside nested btrfs directories!");

        let entries = fs_ro
            .list_dir_by_inode(fs_ro.fs_tree().bytenr, fs_ro.fs_tree().root_dirid)
            .expect("list /");
        assert!(entries.iter().any(|e| e.name == "documents" && e.file_type.is_dir()));
    }

    // Oracle verification
    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn mkdir_duplicate_name_refused() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    // plain.img has existing file "hello.txt" in root
    let err = fs.create_directory("/", "hello.txt").unwrap_err();
    match err {
        LuksError::AlreadyExists(_) => {}
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }

    // Create a directory, then try to recreate it
    fs.create_directory("/", "my_dir").expect("first mkdir succeeds");
    let err2 = fs.create_directory("/", "my_dir").unwrap_err();
    match err2 {
        LuksError::AlreadyExists(_) => {}
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }

    drop(fs);
    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn mkdir_in_nonexistent_or_file_parent_refused() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    // Parent does not exist
    let err = fs.create_directory("/nonexistent", "sub").unwrap_err();
    match err {
        LuksError::NotFound(_) => {}
        other => panic!("expected NotFound, got: {other:?}"),
    }

    // Parent is a regular file
    let err2 = fs.create_directory("/hello.txt", "sub").unwrap_err();
    match err2 {
        LuksError::NotADirectory(_) => {}
        other => panic!("expected NotADirectory, got: {other:?}"),
    }

    drop(fs);
    let _ = fs::remove_file(&img);
}

#[test]
fn mkdir_on_mixed_4k_img() {
    let img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        let ino = fs.create_directory("/", "dir_4k").expect("mkdir on mixed-4k");
        assert!(ino >= 256);

        let file_payload = b"Hello from inside 4k mixed btrfs node!";
        fs.create_file_with_data("/dir_4k", "file_4k.txt", file_payload)
            .expect("create file inside 4k dir");
    }

    assert!(run_verify_script(&img), "oracle check passed for mixed-4k");
    let _ = fs::remove_file(&img);
}

#[test]
fn mkdir_on_compress_img() {
    let img = copy_to_temp("compress.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        let ino = fs.create_directory("/", "zstd_dir").expect("mkdir on compress");
        assert!(ino >= 256);

        let file_payload = b"Testing files inside new directories on compressed btrfs.";
        fs.create_file_with_data("/zstd_dir", "note.txt", file_payload)
            .expect("create file inside zstd_dir");
    }

    assert!(run_verify_script(&img), "oracle check passed for compress");
    let _ = fs::remove_file(&img);
}
