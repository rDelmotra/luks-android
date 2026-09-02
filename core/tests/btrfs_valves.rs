//! Regression tests for Stage V: Fail-Closed Valves (Btrfs Write Safety).
//!
//! - Valve A: Refuse mid-stream chunk allocation during `write_chunk`. Return `FilesystemFull`
//!   instead of triggering `allocate_data_chunk_excluding`.
//! - Valve B: Refuse batch commit while writer open. `commit_active_batch()` returns `CorruptFs`
//!   if an open writer exists. Single-writer exclusion enforces `WriterBusy`.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::chunk::BLOCK_GROUP_DATA;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
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
        "btrfs-valves-{src_name}-{}-{}-{}",
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

fn free_data_bytes(fs: &Btrfs<FileDevice>) -> u64 {
    let extent_tree = ExtentTree::read(fs).expect("read extent tree");
    let allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())
        .expect("derive allocator");
    allocator
        .block_groups
        .iter()
        .filter(|bg| bg.block_group.flags & BLOCK_GROUP_DATA != 0)
        .map(|bg| bg.total_free_bytes)
        .sum()
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
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Valve A: Refuse mid-stream chunk allocation in write_chunk
// ---------------------------------------------------------------------------

#[test]
fn valve_a_streaming_write_exceeding_free_space_refuses_with_filesystem_full() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let initial_chunk_count = fs.chunk_map().len();
    let initial_data_free = free_data_bytes(&fs);

    // Prepare payload larger than existing free space
    let total_size = (initial_data_free + 2 * 1024 * 1024) as usize;
    let payload = vec![0xABu8; total_size];

    let mut writer = fs.begin_file_streaming().expect("begin streaming writer");

    // Streaming in 64 KiB chunks until space is exhausted
    let chunk_size = 64 * 1024;
    let mut offset = 0;
    let mut hit_filesystem_full = false;

    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        match fs.write_chunk(&mut writer, &payload[offset..end]) {
            Ok(()) => {
                offset = end;
            }
            Err(LuksError::FilesystemFull) => {
                hit_filesystem_full = true;
                break;
            }
            Err(e) => panic!("unexpected error from write_chunk: {e:?}"),
        }
    }

    // Valve A asserts:
    // 1. FilesystemFull was returned
    assert!(
        hit_filesystem_full,
        "write_chunk must return FilesystemFull when free space is exhausted"
    );
    // 2. Chunk count did NOT increase mid-stream
    assert_eq!(
        fs.chunk_map().len(),
        initial_chunk_count,
        "chunk count must not grow mid-stream in write_chunk"
    );

    // Clean up via abandon_file
    fs.abandon_file(writer).expect("abandon");
    drop(fs);

    assert!(run_verify_script(&img), "oracle check must pass clean");
    let _ = fs::remove_file(&img);
}

// ---------------------------------------------------------------------------
// Valve B: Refuse batch commit while writer is open; WriterBusy on second open
// ---------------------------------------------------------------------------

#[test]
fn valve_b_commit_active_batch_while_writer_open_returns_corrupt_fs() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let writer = fs.begin_file(1024).expect("begin file");

    // Attempting to commit active batch while writer is open MUST return CorruptFs
    let commit_err = fs.commit_active_batch().unwrap_err();
    match commit_err {
        LuksError::CorruptFs(msg) => {
            assert!(
                msg.contains("file writer is open"),
                "error message must mention open writer, got: {msg}"
            );
        }
        other => panic!("expected CorruptFs error, got: {other:?}"),
    }

    // Opening a second writer while one is open MUST return WriterBusy
    let second_writer_err = fs.begin_file(512).unwrap_err();
    match second_writer_err {
        LuksError::WriterBusy => (),
        other => panic!("expected WriterBusy error, got: {other:?}"),
    }

    let second_streaming_err = fs.begin_file_streaming().unwrap_err();
    match second_streaming_err {
        LuksError::WriterBusy => (),
        other => panic!("expected WriterBusy error, got: {other:?}"),
    }

    // After abandon_file, commit_active_batch succeeds
    fs.abandon_file(writer).expect("abandon");
    fs.commit_active_batch().expect("commit after abandon must succeed");

    // And opening a new writer succeeds
    let new_writer = fs.begin_file(512).expect("begin file after abandon");
    fs.abandon_file(new_writer).expect("abandon");

    drop(fs);
    assert!(run_verify_script(&img), "oracle check must pass clean");
    let _ = fs::remove_file(&img);
}

#[test]
fn valve_b_mutators_fail_while_writer_open() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let writer = fs.begin_file_streaming().expect("begin streaming");

    // All top-level mutating operations call commit_active_batch() at entry.
    // They must all fail with CorruptFs while writer is open.
    match fs.create_directory("/", "test_dir").unwrap_err() {
        LuksError::CorruptFs(_) => (),
        other => panic!("expected CorruptFs from create_directory, got {other:?}"),
    }

    match fs.create_file("/", "empty.txt").unwrap_err() {
        LuksError::CorruptFs(_) => (),
        other => panic!("expected CorruptFs from create_file, got {other:?}"),
    }

    match fs.rename("/", "hello.txt", "/", "renamed.txt").unwrap_err() {
        LuksError::CorruptFs(_) => (),
        other => panic!("expected CorruptFs from rename, got {other:?}"),
    }

    match fs.delete_file("/hello.txt").unwrap_err() {
        LuksError::CorruptFs(_) => (),
        other => panic!("expected CorruptFs from delete_file, got {other:?}"),
    }

    match fs.set_mtime("/hello.txt", 1000, 0).unwrap_err() {
        LuksError::CorruptFs(_) => (),
        other => panic!("expected CorruptFs from set_mtime, got {other:?}"),
    }

    // Finish file resets open_writer state
    let mut writer = writer;
    fs.write_chunk(&mut writer, b"valve b data").expect("write chunk");
    fs.finish_file(writer, "/", "valve_b.txt").expect("finish file");

    // Now mutators work cleanly
    fs.create_directory("/", "test_dir_after").expect("create_directory after finish");
    fs.commit_active_batch().expect("commit active batch");

    drop(fs);
    assert!(run_verify_script(&img), "oracle check must pass clean");
    let _ = fs::remove_file(&img);
}
