//! Stage B2 Verification Tests: Writer-Release Validation & Exact Ledger Freeing
//!
//! Asserts that:
//! 1. Attempting to abandon a writer with unreserved/foreign data runs fails closed with `CorruptFs`.
//! 2. Double-releasing a reservation fails closed with `CorruptFs`.
//! 3. Legitimate abandon and resume cycles maintain exact ledger integrity and pass kernel oracle verification.

#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::write::file::BtrfsFileWriter;
use luks_core::fs::btrfs::Btrfs;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(name: &str) -> PathBuf {
    let src = fixture_path(name);
    let tmp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = tmp_dir.join(format!(
        "stage_b2_{}_{}_{}_{}.img",
        name.trim_end_matches(".img"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_btrfs(img_path: &Path) -> (bool, String) {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    let output = Command::new("bash")
        .arg(&script_path)
        .arg(img_path)
        .output()
        .expect("failed to execute verify-btrfs.sh");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    (output.status.success(), combined)
}

#[test]
fn test_abandon_file_with_unregistered_runs_fails_closed() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let mut writer = fs.begin_file(16384).expect("begin_file");
    assert!(!writer.data_runs().is_empty());

    // Tamper with the writer to include an unregistered/forged logical bytenr
    writer.data_runs_mut()[0] = (999_999_999, 16384);

    let abandon_res = fs.abandon_file(writer);
    match abandon_res {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("reservation ledger"),
                "error message must cite reservation ledger: {msg}"
            );
        }
        other => panic!("expected CorruptFs on unregistered run abandon, got: {other:?}"),
    }

    let _ = fs::remove_file(&img);
}

#[test]
fn test_abandon_file_double_release_fails_closed() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let writer1 = fs.begin_file(16384).expect("begin_file 1");
    let runs = writer1.data_runs().to_vec();
    let alloc = writer1.allocator().clone();

    // Construct a forged duplicate writer with the exact same data runs
    let writer2 = BtrfsFileWriter::new_raw(
        16384,
        0,
        runs,
        Vec::new(),
        alloc,
        false,
        Vec::new(),
    );

    // First abandon cleanly releases the reservation
    fs.abandon_file(writer1).expect("first abandon must succeed");

    // Second abandon on the same batch session MUST fail closed with CorruptFs
    let second_res = fs.abandon_file(writer2);
    match second_res {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("reservation ledger"),
                "error message must cite reservation ledger: {msg}"
            );
        }
        other => panic!("expected CorruptFs on double release, got: {other:?}"),
    }

    let _ = fs::remove_file(&img);
}

#[test]
fn test_legitimate_abandon_and_resume_remains_clean() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Abandon a 64 KB writer
    let payload_abandon = vec![0xAAu8; 65536];
    let mut w1 = fs.begin_file(65536).expect("begin w1");
    fs.write_chunk(&mut w1, &payload_abandon).expect("write w1");
    fs.abandon_file(w1).expect("abandon w1");

    // 2. Open and commit a valid 64 KB file
    let payload_commit = vec![0xBBu8; 65536];
    let mut w2 = fs.begin_file(65536).expect("begin w2");
    fs.write_chunk(&mut w2, &payload_commit).expect("write w2");
    let ino = fs.finish_file(w2, "/", "clean_b2.bin").expect("finish w2");
    assert!(ino >= 256);

    fs.commit_active_batch().expect("commit");

    // 3. Verify content
    let readback = fs.read_file("/clean_b2.bin").expect("read_file");
    assert_eq!(readback, payload_commit);

    // 4. Kernel oracle verify
    let (clean, output) = run_verify_btrfs(&img);
    assert!(
        clean,
        "verify-btrfs.sh must pass clean after abandon and write. Output:\n{output}"
    );

    let _ = fs::remove_file(&img);
}
