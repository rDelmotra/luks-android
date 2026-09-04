//! Phase 2 verification: Assert that Batch::open -> add_file -> commit
//! produces a valid, verified, and oracle-clean Btrfs transaction.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::batch::Batch;
use luks_core::fs::btrfs::write::commit::commit_transaction;
use luks_core::fs::btrfs::Btrfs;

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
        "btrfs-batch-{src_name}-{}-{}-{}",
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

fn run_verify_btrfs(img_path: &std::path::Path) -> (bool, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    assert!(script.exists(), "verify-btrfs.sh must exist at {:?}", script);

    if !common::oracle::gate() {
        return (true, "skipped (ALLOW_NO_ORACLE)".to_string());
    }

    let out = Command::new(&script)
        .arg(img_path)
        .output()
        .expect("exec verify-btrfs.sh");

    let text = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn test_batch_n1_refactor_creates_clean_oracle_verified_file() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // Write a file through Btrfs::finish_file (which internally calls Batch::open -> add_writer -> commit)
    let payload = b"Hello from Phase 2 Batch Engine! Byte-exact verification.".to_vec();
    let mut writer = fs.begin_file(payload.len() as u64).expect("begin_file");
    fs.write_chunk(&mut writer, &payload).expect("write_chunk");

    let ino = fs.finish_file(writer, "/", "batch_test.txt").expect("finish_file");
    assert!(ino >= 256);

    let (clean, output) = run_verify_btrfs(&img);
    assert!(clean, "verify-btrfs.sh must pass clean. Output:\n{output}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_batch_direct_invocation_matches_finish_file() {
    let img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let payload = vec![0xABu8; 16384];
    let mut writer = fs.begin_file(payload.len() as u64).expect("begin_file");
    fs.write_chunk(&mut writer, &payload).expect("write_chunk");

    let mut batch = Batch::open(&mut fs).expect("open");
    let ino = batch.add_writer(&mut fs, &writer, "/", "direct_batch.bin").expect("add_writer");
    assert!(ino >= 256);

    let txn = batch.commit(&mut fs).expect("commit");
    assert_eq!(txn.new_generation, fs.superblock().generation + 1);
    assert!(!txn.pending_blocks.is_empty());

    commit_transaction(&mut fs, txn).expect("commit_transaction");

    let (clean, output) = run_verify_btrfs(&img);
    assert!(clean, "verify-btrfs.sh must pass clean for direct batch. Output:\n{output}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_batch_transaction_byte_identical_on_fixture() {
    let img1 = copy_to_temp("plain.img");
    let img2 = copy_to_temp("plain.img");
    let file_len1 = fs::metadata(&img1).unwrap().len();
    let file_len2 = fs::metadata(&img2).unwrap().len();

    let dev1 = FileDevice::open_writable(&img1, file_len1).expect("open writable 1");
    let mut fs1 = Btrfs::mount(dev1).expect("mount writable btrfs 1");

    let dev2 = FileDevice::open_writable(&img2, file_len2).expect("open writable 2");
    let mut fs2 = Btrfs::mount(dev2).expect("mount writable btrfs 2");

    let payload = b"Deterministic payload for byte-identical transaction comparison test.".to_vec();

    let mut writer1 = fs1.begin_file(payload.len() as u64).expect("begin_file 1");
    fs1.write_chunk(&mut writer1, &payload).expect("write_chunk 1");

    let mut writer2 = fs2.begin_file(payload.len() as u64).expect("begin_file 2");
    fs2.write_chunk(&mut writer2, &payload).expect("write_chunk 2");

    let mut batch1 = Batch::open(&mut fs1).expect("open batch 1");
    let ino1 = batch1.add_writer_with_time(&mut fs1, &writer1, "/", "identical.txt", 1700000000, 0).expect("add_writer 1");

    let mut batch2 = Batch::open(&mut fs2).expect("open batch 2");
    let ino2 = batch2.add_writer_with_time(&mut fs2, &writer2, "/", "identical.txt", 1700000000, 0).expect("add_writer 2");

    assert_eq!(ino1, ino2);

    let txn1 = batch1.commit(&mut fs1).expect("commit 1");
    let txn2 = batch2.commit(&mut fs2).expect("commit 2");

    assert_eq!(txn1.new_generation, txn2.new_generation);
    assert_eq!(txn1.final_root_bytenr, txn2.final_root_bytenr);
    assert_eq!(txn1.final_root_level, txn2.final_root_level);
    assert_eq!(txn1.final_chunk_root, txn2.final_chunk_root);
    assert_eq!(txn1.final_bytes_used, txn2.final_bytes_used);
    assert_eq!(txn1.new_fs_tree.generation, txn2.new_fs_tree.generation);

    // Assert exact byte equality on all pending dirty tree blocks
    let mut pending_keys1: Vec<_> = txn1.pending_blocks.keys().copied().collect();
    let mut pending_keys2: Vec<_> = txn2.pending_blocks.keys().copied().collect();
    pending_keys1.sort();
    pending_keys2.sort();
    assert_eq!(pending_keys1, pending_keys2);

    for k in pending_keys1 {
        let block1 = txn1.pending_blocks.get(&k).unwrap();
        let block2 = txn2.pending_blocks.get(&k).unwrap();
        assert_eq!(block1, block2, "dirty block at bytenr {k} must be byte-identical");
    }

    commit_transaction(&mut fs1, txn1).expect("commit 1");
    commit_transaction(&mut fs2, txn2).expect("commit 2");

    let (clean1, out1) = run_verify_btrfs(&img1);
    assert!(clean1, "image 1 oracle clean. Output:\n{out1}");

    let (clean2, out2) = run_verify_btrfs(&img2);
    assert!(clean2, "image 2 oracle clean. Output:\n{out2}");

    let _ = fs::remove_file(&img1);
    let _ = fs::remove_file(&img2);
}
