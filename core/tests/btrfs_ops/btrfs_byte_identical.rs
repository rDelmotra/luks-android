//! Determinism and Byte-Identical Invariance Tests.
//!
//! Proves that:
//! 1. All transactions (create, data write, mkdir, rename, mtime, delete) executed with
//!    fixed timestamps against identical input images produce byte-identical
//!    on-disk images (verified via SHA-256 digests).
//! 2. The Phase 2 TargetTree refactoring produces valid filesystems verified by both
//!    TreeValidator (Tier A) and AccountingOracle (Tier B).

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::commit_transaction;
use luks_core::fs::btrfs::write::target::TargetTree;
use luks_core::fs::btrfs::write::Transaction;
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

use common::accounting::AccountingOracle;
use common::btree_validator::TreeValidator;

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
        "btrfs_byte_identical_{}_{}_{}.img",
        std::process::id(),
        count,
        src_name
    ));
    std::fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn sha256_of_file(path: &PathBuf) -> Vec<u8> {
    let mut file = File::open(path).expect("open file for hashing");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).expect("read chunk");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize().to_vec()
}

fn run_deterministic_workload(path: &PathBuf) {
    let len = std::fs::metadata(path).expect("stat").len();
    let dev = FileDevice::open_writable(path, len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount btrfs");

    // Fixed deterministic timestamps
    let t1_sec = 1_700_000_000u64;
    let t1_nsec = 123_456u32;

    // 1. Create an empty file
    let txn1 = Transaction::create_empty_file(&fs, "/", "det_file.txt", t1_sec, t1_nsec)
        .expect("create_empty_file");
    commit_transaction(&mut fs, txn1).expect("commit create_empty_file");

    // 2. Create directory
    let (txn2, dir_ino) = Transaction::create_directory(&fs, "/", "det_dir", t1_sec, t1_nsec)
        .expect("create_directory");
    commit_transaction(&mut fs, txn2).expect("commit create_directory");

    // 3. Rename file into directory
    let txn3 = Transaction::rename(
        &fs,
        "/",
        "det_file.txt",
        "/det_dir",
        "renamed_file.txt",
        t1_sec,
        t1_nsec,
    )
    .expect("rename");
    commit_transaction(&mut fs, txn3).expect("commit rename");

    // 4. Write data to the renamed file
    let payload = b"Deterministic payload for byte-identical verification. 1234567890.";
    let txn4 = Transaction::write_file_data(
        &fs,
        "/det_dir/renamed_file.txt",
        payload,
        t1_sec + 10,
        t1_nsec,
    )
    .expect("write_file_data");
    commit_transaction(&mut fs, txn4).expect("commit write_file_data");

    // 5. Update mtime on the directory
    let target = TargetTree::from_fs_tree(fs.fs_tree());
    let txn5 = Transaction::update_inode_mtime(&fs, target, dir_ino, t1_sec + 50, t1_nsec + 100)
        .expect("update_inode_mtime");
    commit_transaction(&mut fs, txn5).expect("commit update_inode_mtime");

    // 6. Delete a file in root directory (hello.txt is present in plain.img)
    let txn6 = Transaction::delete_file(&fs, "/hello.txt", t1_sec + 100, t1_nsec)
        .expect("delete_file");
    commit_transaction(&mut fs, txn6).expect("commit delete_file");
}

#[test]
fn test_deterministic_workload_produces_byte_identical_output() {
    let temp1 = copy_to_temp("plain.img");
    let temp2 = copy_to_temp("plain.img");

    // Initial copies must be identical
    let initial_hash1 = sha256_of_file(&temp1);
    let initial_hash2 = sha256_of_file(&temp2);
    assert_eq!(initial_hash1, initial_hash2, "initial fixtures must be identical");

    // Run identical operations on both independent temp files
    run_deterministic_workload(&temp1);
    run_deterministic_workload(&temp2);

    // Compute post-workload hashes
    let post_hash1 = sha256_of_file(&temp1);
    let post_hash2 = sha256_of_file(&temp2);

    // Core proof: output is 100% byte-identical!
    assert_ne!(initial_hash1, post_hash1, "filesystem must have mutated");
    assert_eq!(
        post_hash1, post_hash2,
        "identical deterministic workload MUST produce byte-identical images"
    );

    // Validate structural integrity of mutated image via TreeValidator (Tier A)
    let dev1 = FileDevice::open(&temp1).expect("open temp1");
    let fs1 = Btrfs::mount(dev1).expect("mount temp1");
    TreeValidator::validate_all(&fs1).expect("TreeValidator validate_all on temp1");

    // Validate structural integrity of mutated image via AccountingOracle (Tier B)
    AccountingOracle::check(&fs1).expect("AccountingOracle check on temp1");

    let _ = std::fs::remove_file(&temp1);
    let _ = std::fs::remove_file(&temp2);
}
