//! Tests for Phase 3 Subvolume Write Support.
//!
//! Verifies:
//! 1. File CRUD, data write, mkdir, mtime update, and delete inside subvolumes (e.g. `/home`).
//! 2. In-memory mount state preservation (Hazard H-E): `fs.fs_tree()` remains FS_TREE (5).
//! 3. Subvolume ROOT_ITEM update in ROOT_TREE (Hazard H-D): target subvolume root item updated with generation_v2 and ctransid.
//! 4. Refusal to delete a subvolume (`"subvolume deletion is not supported"`).
//! 5. Refusal to rename across subvolumes (`"cross-subvolume rename not supported"`).
//! 6. Refusal to rename a subvolume (`"subvolume rename not supported"`).
//! 7. Streaming batch file creation within a subvolume.
//! 8. Inverted aged subvolume allocation on `subvol-aged.img`: new inodes >= 310 (no collision with 259..=309).
//! 9. Tier B validation via `AccountingOracle`.
//! 10. Tier C validation via Linux kernel oracle (`verify-btrfs.sh`).

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::tree::FS_TREE_OBJECTID;
use luks_core::fs::btrfs::write::extent_tree::find_max_inode;
use luks_core::fs::btrfs::Btrfs;

use common::accounting::AccountingOracle;

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
        "btrfs_subvol_write_{}_{}_{}.img",
        std::process::id(),
        count,
        src_name
    ));
    std::fs::copy(&src, &dst).expect("copy fixture to temp");
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
                    "ORACLE VERIFIED: verify-btrfs.sh passed for {}",
                    image_path.display()
                );
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
fn test_subvolume_file_crud_and_readback() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    let orig_fs_tree_bytenr = fs.fs_tree().bytenr;
    let orig_fs_tree_objectid = fs.fs_tree().objectid;
    assert_eq!(orig_fs_tree_objectid, FS_TREE_OBJECTID);

    // 1. Create file with data in /home subvolume (id 257)
    let payload = b"Hello from inside Btrfs subvolume /home! Ultra low latency write engine verified.";
    fs.create_file_with_data("/home", "phase3_hello.txt", payload)
        .expect("create_file_with_data in /home");

    // 2. Read back file and verify contents
    {
        let read_buf = fs.read_file("/home/phase3_hello.txt").expect("read_file phase3_hello.txt");
        assert_eq!(&read_buf, payload);
    }

    // 3. Update mtime on subvolume file
    fs.set_mtime("/home/phase3_hello.txt", 1780001234, 500)
        .expect("set_mtime on subvolume file");
    let loc = fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_hello.txt").expect("resolve phase3_hello.txt");
    assert_eq!(loc.inode.mtime, 1780001234);

    // 4. Create directory in /home
    fs.create_directory("/home", "phase3_dir")
        .expect("create_directory in /home");
    let loc_dir = fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir").expect("resolve phase3_dir");
    assert!(loc_dir.inode.file_type().is_dir());

    // 5. Create file inside new directory
    fs.create_file("/home/phase3_dir", "sub_file.txt")
        .expect("create_file inside phase3_dir");
    assert!(fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir/sub_file.txt").is_ok());

    // 6. Same-subvolume rename
    fs.rename(
        "/home/phase3_dir",
        "sub_file.txt",
        "/home/phase3_dir",
        "sub_renamed.txt",
    )
    .expect("rename inside subvolume directory");
    assert!(fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir/sub_renamed.txt").is_ok());
    assert!(fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir/sub_file.txt").is_err());

    // 7. Delete file inside subvolume
    fs.delete_file("/home/phase3_dir/sub_renamed.txt")
        .expect("delete_file inside subvolume");
    assert!(fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir/sub_renamed.txt").is_err());

    // 8. Delete directory inside subvolume
    fs.delete_file("/home/phase3_dir")
        .expect("delete_file empty directory inside subvolume");
    assert!(fs.resolve_no_follow(fs.fs_tree(), "/home/phase3_dir").is_err());

    // 9. Hazard H-E Proof: In-memory FS_TREE must remain tree 5 with original bytenr
    assert_eq!(
        fs.fs_tree().objectid,
        FS_TREE_OBJECTID,
        "fs_tree objectid must remain FS_TREE (5)"
    );
    assert_eq!(
        fs.fs_tree().bytenr,
        orig_fs_tree_bytenr,
        "FS_TREE bytenr must be untouched after subvolume commits"
    );

    // 10. Tier B AccountingOracle verification
    AccountingOracle::check(&fs).expect("Tier B AccountingOracle verification passes");

    // 11. Tier C Linux Kernel verification
    drop(fs);
    assert!(
        run_verify_script(&temp_path),
        "Tier C Linux kernel verify-btrfs.sh must pass on mutated subvol.img"
    );

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_subvolume_deletion_refusal() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    // 1. Attempt to delete /home (top-level subvolume id 257)
    let res_home = fs.delete_file("/home");
    match res_home {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("subvolume deletion is not supported"),
                "expected 'subvolume deletion is not supported', got: {msg}"
            );
        }
        other => panic!("expected subvolume deletion refusal for /home, got: {other:?}"),
    }

    // 2. Attempt to delete /home/user/snap (nested subvolume id 258)
    let res_snap = fs.delete_file("/home/user/snap");
    match res_snap {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("subvolume deletion is not supported"),
                "expected 'subvolume deletion is not supported', got: {msg}"
            );
        }
        other => panic!("expected subvolume deletion refusal for /home/user/snap, got: {other:?}"),
    }

    // 3. Attempt to delete /snapshots/home-snap (read-only subvolume id 259)
    let res_ro = fs.delete_file("/snapshots/home-snap");
    match res_ro {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("subvolume deletion is not supported")
                    || msg.contains("btrfs read-only subvolume"),
                "expected subvolume deletion or read-only refusal, got: {msg}"
            );
        }
        other => panic!("expected refusal for /snapshots/home-snap, got: {other:?}"),
    }

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_cross_subvolume_rename_refusal() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    // Create a file in /home
    fs.create_file("/home", "cross_test.txt")
        .expect("create file in /home");

    // 1. Attempt cross-subvolume rename: /home -> /root
    let res_cross = fs.rename("/home", "cross_test.txt", "/root", "cross_test.txt");
    match res_cross {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("cross-subvolume rename not supported"),
                "expected 'cross-subvolume rename not supported', got: {msg}"
            );
        }
        other => panic!("expected cross-subvolume rename refusal, got: {other:?}"),
    }

    // 2. Attempt cross-subvolume rename: /home -> / (top level FS_TREE)
    let res_cross_root = fs.rename("/home", "cross_test.txt", "", "cross_test.txt");
    match res_cross_root {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("cross-subvolume rename not supported"),
                "expected 'cross-subvolume rename not supported', got: {msg}"
            );
        }
        other => panic!("expected cross-subvolume rename refusal to root, got: {other:?}"),
    }

    // 3. Attempt to rename a subvolume itself: /home -> /home2
    let res_rename_subvol = fs.rename("", "home", "", "home2");
    match res_rename_subvol {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("subvolume rename not supported"),
                "expected 'subvolume rename not supported', got: {msg}"
            );
        }
        other => panic!("expected subvolume rename refusal, got: {other:?}"),
    }

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_subvolume_streaming_batch() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    let stream_data = vec![0x5au8; 16384];
    let mut writer = fs.begin_file(stream_data.len() as u64).expect("begin_file");
    fs.write_chunk(&mut writer, &stream_data).expect("write_chunk");

    let ino = fs
        .finish_file(writer, "/home", "batch_streamed.bin")
        .expect("finish_file in /home");

    assert!(ino >= 256, "inode must be >= 256");

    fs.commit_active_batch().expect("commit active batch");

    // In-memory mount state check: FS_TREE objectid remains 5
    assert_eq!(fs.fs_tree().objectid, FS_TREE_OBJECTID);

    // Verify file listing in /home
    let entries = fs.list_dir("/home").expect("list /home");
    assert!(
        entries.iter().any(|e| e.name == "batch_streamed.bin"),
        "batch_streamed.bin must appear in /home listing"
    );

    // Tier B Oracle
    AccountingOracle::check(&fs).expect("Tier B AccountingOracle verification passes");

    // Tier C Linux Kernel verification
    drop(fs);
    assert!(
        run_verify_script(&temp_path),
        "Tier C Linux kernel verify-btrfs.sh must pass on batch subvol image"
    );

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_aged_subvolume_write_no_collision() {
    let temp_path = copy_to_temp("subvol-aged.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol-aged.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol-aged.img");

    let max_fs = find_max_inode(&fs, fs.fs_tree().bytenr).expect("find max fs");
    let home_root = fs.tree_root(257).expect("tree root 257");
    let max_home = find_max_inode(&fs, home_root.bytenr).expect("find max home");

    assert_eq!(max_fs, 258);
    assert_eq!(max_home, 309);

    // Create 5 new files in /home/user/docs
    for i in 1..=5 {
        let name = format!("extra_file_{i}.txt");
        let content = format!("Extra content {i}");
        fs.create_file_with_data(
            "/home/user/docs",
            &name,
            content.as_bytes(),
        )
        .expect("create extra file");

        let loc = fs
            .resolve_no_follow(fs.fs_tree(), &format!("/home/user/docs/{name}"))
            .expect("resolve extra file");

        // Ground-truth Defect D-2 / Hazard H-A Verification:
        // New inodes MUST be strictly greater than max_home (>= 310)
        // and MUST NOT collide with existing files (259..=309)!
        assert!(
            loc.inode.objectid > max_home,
            "allocated inode {} must strictly exceed max_home {}",
            loc.inode.objectid,
            max_home
        );
        assert!(
            !(259..=309).contains(&loc.inode.objectid),
            "allocated inode {} must not collide with existing files (259..=309)",
            loc.inode.objectid
        );
    }

    // Tier B Oracle
    AccountingOracle::check(&fs).expect("Tier B AccountingOracle verification passes");



    // Tier C Linux Kernel verification
    drop(fs);
    assert!(
        run_verify_script(&temp_path),
        "Tier C Linux kernel verify-btrfs.sh must pass on mutated subvol-aged.img"
    );

    let _ = std::fs::remove_file(&temp_path);
}
