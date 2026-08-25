//! Phase 4 verification: Negative control & double-allocation ledger guard test.
//!
//! Asserts that `Batch.handed_out` (backed by `IntervalSet`) records every allocation
//! and immediately catches and refuses any overlapping range before any disk write.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::write::batch::Batch;
use luks_core::fs::btrfs::write::interval_set::IntervalSet;
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
        "btrfs-batch-p4-{src_name}-{}-{}-{}",
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

fn run_verify_btrfs(img_path: &Path) -> (bool, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");
    assert!(script.exists(), "verify-btrfs.sh must exist at {:?}", script);

    if !common::oracle::gate() {
        return (true, "skipped (ALLOW_NO_ORACLE)".to_string());
    }

    let output = Command::new("bash")
        .arg(&script)
        .arg(img_path)
        .output()
        .expect("run verify-btrfs.sh");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

#[test]
fn test_interval_set_properties() {
    let mut set = IntervalSet::new();
    assert!(set.is_empty());
    assert_eq!(set.len(), 0);

    // Insert disjoint
    assert!(set.insert(1000, 100)); // [1000, 1100)
    assert!(set.insert(2000, 200)); // [2000, 2200)
    assert_eq!(set.len(), 2);
    assert_eq!(set.intervals(), &[(1000, 1100), (2000, 2200)]);

    // Check overlap detection
    assert!(set.overlaps(1050, 10)); // inside first
    assert!(set.overlaps(950, 100)); // overlapping left edge
    assert!(set.overlaps(1050, 100)); // overlapping right edge
    assert!(set.overlaps(500, 2000)); // enclosing first
    assert!(!set.overlaps(1200, 500)); // disjoint between 1st and 2nd

    // Attempt double allocations (must return false)
    assert!(!set.insert(1050, 10));
    assert!(!set.insert(950, 100));
    assert!(!set.insert(1050, 100));
    assert!(!set.insert(2000, 200));

    // Touching adjacent intervals merge automatically
    assert!(set.insert(1100, 900)); // [1100, 2000) touches both!
    assert_eq!(set.len(), 1);
    assert_eq!(set.intervals(), &[(1000, 2200)]);
}

#[test]
fn test_negative_control_reintroduce_b2_catches_double_allocation_before_disk_write() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let mut batch = Batch::open(&mut fs).expect("open batch");

    // 1. Direct allocation ledger recording test
    let test_bytenr = 50_000_000u64;
    let test_len = 16384u64;

    assert!(
        batch.record_allocation(test_bytenr, test_len).is_ok(),
        "first allocation must succeed"
    );

    // Negative control: Re-introducing exact duplicate allocation
    match batch.record_allocation(test_bytenr, test_len) {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("double allocation detected"),
                "error must cite double allocation, got: {}",
                msg
            );
        }
        other => panic!("expected Err(CorruptFs(double allocation)), got: {:?}", other),
    }

    // Negative control: Re-introducing partial overlap allocation
    match batch.record_allocation(test_bytenr + 4096, test_len) {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("double allocation detected"),
                "error must cite double allocation, got: {}",
                msg
            );
        }
        other => panic!("expected Err(CorruptFs(double allocation)), got: {:?}", other),
    }

    // Negative control: Re-introducing enclosing overlap allocation
    match batch.record_allocation(test_bytenr - 4096, test_len * 2) {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("double allocation detected"),
                "error must cite double allocation, got: {}",
                msg
            );
        }
        other => panic!("expected Err(CorruptFs(double allocation)), got: {:?}", other),
    }

    // 2. Test double allocation detection on add_file entry point
    // Passing a data run that collides with an already-handed-out range must immediately refuse
    let colliding_runs = [(test_bytenr, test_len)];
    let res = batch.add_file(
        &mut fs,
        false,
        test_len,
        test_len,
        &colliding_runs,
        &[],
        "/",
        "colliding.bin",
    );

    match res {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("double allocation detected"),
                "error must cite double allocation, got: {}",
                msg
            );
        }
        other => panic!("expected Err(CorruptFs(double allocation)), got: {:?}", other),
    }

    let _ = fs::remove_file(&img);
}

#[test]
fn test_batch_handed_out_ledger_guard_in_real_workload() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Write 5 files sequentially through the filesystem engine (exercising active_batch + handed_out)
        for i in 0..5 {
            let filename = format!("test_{i}.bin");
            let payload = vec![0x33 + (i as u8); 8192];
            let mut writer = fs.begin_file(payload.len() as u64).expect("begin");
            fs.write_chunk(&mut writer, &payload).expect("write");
            let ino = fs.finish_file(writer, "/", &filename).expect("finish file");
            assert!(ino >= 256 + i as u64);
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{out}");
    let _ = fs::remove_file(&img);
}
