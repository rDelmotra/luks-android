//! End-to-end btrfs rename and cross-directory move oracle verification test (Pass J.4).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test btrfs_rename
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
        "btrfs-rename-{src_name}-{}-{}-{}",
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
fn rename_file_in_same_directory() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // hello.txt exists in root
        let orig_content = fs.read_file("/hello.txt").expect("read hello.txt");
        assert_eq!(orig_content, b"hello btrfs\n");

        fs.rename("/", "hello.txt", "/", "renamed.txt")
            .expect("rename hello.txt to renamed.txt");

        // Old path should not exist
        assert!(fs.read_file("/hello.txt").is_err());

        // New path should have exact content
        let new_content = fs.read_file("/renamed.txt").expect("read renamed.txt");
        assert_eq!(new_content, orig_content);
    }

    // Remount read-only and verify persistence
    {
        let dev_ro = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");

        assert!(fs_ro.read_file("/hello.txt").is_err());
        let new_content = fs_ro.read_file("/renamed.txt").expect("read renamed.txt ro");
        assert_eq!(new_content, b"hello btrfs\n");
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn rename_cross_directory_move() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Create a destination directory
        fs.create_directory("/", "target_dir").expect("mkdir target_dir");

        // 2. Move /hello.txt to /target_dir/moved_hello.txt
        fs.rename("/", "hello.txt", "/target_dir", "moved_hello.txt")
            .expect("move /hello.txt to /target_dir/moved_hello.txt");

        assert!(fs.read_file("/hello.txt").is_err());
        let moved = fs
            .read_file("/target_dir/moved_hello.txt")
            .expect("read moved file");
        assert_eq!(moved, b"hello btrfs\n");
    }

    // Remount and check
    {
        let dev_ro = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");

        assert!(fs_ro.read_file("/hello.txt").is_err());
        let moved = fs_ro
            .read_file("/target_dir/moved_hello.txt")
            .expect("read moved file ro");
        assert_eq!(moved, b"hello btrfs\n");
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn rename_overwrites_existing_file() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Create destination file with distinct content
        fs.create_file_with_data("/", "victim.txt", b"I will be overwritten")
            .expect("create victim.txt");

        // Rename hello.txt over victim.txt
        fs.rename("/", "hello.txt", "/", "victim.txt")
            .expect("rename hello.txt over victim.txt");

        assert!(fs.read_file("/hello.txt").is_err());
        let replaced_content = fs.read_file("/victim.txt").expect("read victim.txt");
        assert_eq!(replaced_content, b"hello btrfs\n");
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn rename_move_directory() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Create hierarchy: /src_dir/child.txt and /dst_dir
        fs.create_directory("/", "src_dir").expect("mkdir src_dir");
        fs.create_file_with_data("/src_dir", "child.txt", b"inside src_dir")
            .expect("create child.txt");
        fs.create_directory("/", "dst_dir").expect("mkdir dst_dir");

        // Move /src_dir into /dst_dir/nested_src
        fs.rename("/", "src_dir", "/dst_dir", "nested_src")
            .expect("move /src_dir to /dst_dir/nested_src");

        assert!(fs.resolve_no_follow(fs.fs_tree(), "/src_dir").is_err());
        let nested_content = fs
            .read_file("/dst_dir/nested_src/child.txt")
            .expect("read nested child");
        assert_eq!(nested_content, b"inside src_dir");
    }

    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn rename_cycle_refusal() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    // Create hierarchy /parent/child/grandchild
    fs.create_directory("/", "parent").expect("mkdir parent");
    fs.create_directory("/parent", "child").expect("mkdir child");
    fs.create_directory("/parent/child", "grandchild").expect("mkdir grandchild");

    // Moving /parent into /parent (itself) must be refused
    let err_self = fs.rename("/", "parent", "/parent", "sub").unwrap_err();
    match err_self {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("cannot move directory 'parent' into itself"));
        }
        other => panic!("expected UnsupportedFsFeature, got: {other:?}"),
    }

    // Moving /parent into /parent/child/grandchild (its descendant) must be refused
    let err_desc = fs.rename("/", "parent", "/parent/child/grandchild", "parent_in_grandchild").unwrap_err();
    match err_desc {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("cannot move directory 'parent' into its own descendant"));
        }
        other => panic!("expected UnsupportedFsFeature, got: {other:?}"),
    }

    drop(fs);
    assert!(run_verify_script(&img), "oracle check passed");
    let _ = fs::remove_file(&img);
}

#[test]
fn rename_on_mixed_4k_img() {
    let img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        fs.create_directory("/", "folder_4k").expect("mkdir folder_4k");
        fs.create_file_with_data("/folder_4k", "data.bin", &[0x42; 8192])
            .expect("create data.bin");

        fs.rename("/folder_4k", "data.bin", "/", "data_root.bin")
            .expect("move data.bin to root");

        let readback = fs.read_file("/data_root.bin").expect("read data_root.bin");
        assert_eq!(readback, vec![0x42; 8192]);
    }

    assert!(run_verify_script(&img), "oracle check passed for mixed-4k");
    let _ = fs::remove_file(&img);
}
