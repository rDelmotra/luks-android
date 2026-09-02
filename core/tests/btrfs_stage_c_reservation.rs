//! Stage C verification: Open-Writer Reservation Ledger.
//!
//! Asserts that:
//! 1. `batch.allocator` is never eagerly mutated during `begin_file` or `write_chunk`.
//! 2. Open writer allocations are recorded solely in the reservation ledger (`Batch::handed_out`).
//! 3. Reservations are promoted to `batch.allocator` ONLY upon `finish_file`.
//! 4. `abandon_file` cleanly releases reservations from `handed_out` without touching `batch.allocator`.
//! 5. Commits following an abandoned file produce 100% exact match between `BLOCK_GROUP_ITEM.used`,
//!    `FREE_SPACE_TREE`, and `EXTENT_ITEM`s, verified by the kernel oracle.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
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
        "btrfs-stage-c-{src_name}-{}-{}-{}",
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
        .expect("failed to execute verify-btrfs.sh");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let full_output = format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);

    (output.status.success(), full_output)
}

#[test]
fn test_batch_allocator_remains_untouched_during_open_writer() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Write and commit one baseline file so an active batch is live
        let baseline_payload = vec![0x42u8; 8192];
        let mut w0 = fs.begin_file(baseline_payload.len() as u64).expect("begin w0");
        fs.write_chunk(&mut w0, &baseline_payload).expect("write w0");
        fs.finish_file(w0, "/", "baseline.bin").expect("finish w0");
        fs.commit_active_batch().expect("commit baseline");

        // Open a new batch session
        let dummy_writer = fs.begin_file(4096).expect("open batch via begin");
        fs.abandon_file(dummy_writer).expect("abandon dummy");

        // Capture batch allocator snapshot
        let active_batch = fs.active_batch().expect("batch must be active");
        let batch_alloc_snapshot = active_batch.allocator.clone();
        let batch_handed_out_before = active_batch.handed_out.clone();

        // 2. Open a new streaming writer and allocate multiple chunks
        let mut w1 = fs.begin_file_streaming().expect("begin streaming w1");
        let chunk1 = vec![0xAAu8; 65536];
        fs.write_chunk(&mut w1, &chunk1).expect("write chunk 1");
        let chunk2 = vec![0xBBu8; 65536];
        fs.write_chunk(&mut w1, &chunk2).expect("write chunk 2");

        // Verify batch allocator is 100% UNTOUCHED while w1 is open
        let active_batch_during = fs.active_batch().expect("batch still active");
        assert_eq!(
            active_batch_during.allocator, batch_alloc_snapshot,
            "batch.allocator must remain unchanged while writer is open!"
        );

        // Verify handed_out ledger has recorded w1's data runs
        assert!(
            active_batch_during.handed_out.len() >= batch_handed_out_before.len(),
            "handed_out ledger must hold open reservations"
        );
        for &(bytenr, len) in w1.data_runs() {
            assert!(
                active_batch_during.handed_out.overlaps(bytenr, len),
                "handed_out ledger must contain run [{}, +{})",
                bytenr,
                len
            );
        }

        // 3. Abandon w1
        fs.abandon_file(w1).expect("abandon w1");

        // Verify batch allocator is still identical to the baseline snapshot
        let active_batch_after = fs.active_batch().expect("batch still active");
        assert_eq!(
            active_batch_after.allocator, batch_alloc_snapshot,
            "batch.allocator must remain identical after abandon!"
        );

        // Commit active batch containing baseline.bin
        fs.commit_active_batch().expect("commit active batch");
    }

    // Oracle verify the resulting image
    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{}", out);

    let _ = fs::remove_file(&img);
}

#[test]
fn test_abandon_file_preserves_exact_block_group_accounting() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // Write file 1 (committed to batch)
        let p1 = vec![0x11u8; 16384];
        let mut w1 = fs.begin_file(p1.len() as u64).expect("begin w1");
        fs.write_chunk(&mut w1, &p1).expect("write w1");
        fs.finish_file(w1, "/", "f1.bin").expect("finish w1");

        // Write file 2 and abandon it
        let p2 = vec![0x22u8; 32768];
        let mut w2 = fs.begin_file(p2.len() as u64).expect("begin w2");
        fs.write_chunk(&mut w2, &p2).expect("write w2");
        fs.abandon_file(w2).expect("abandon w2");

        // Write file 3 (committed to batch)
        let p3 = vec![0x33u8; 16384];
        let mut w3 = fs.begin_file(p3.len() as u64).expect("begin w3");
        fs.write_chunk(&mut w3, &p3).expect("write w3");
        fs.finish_file(w3, "/", "f3.bin").expect("finish w3");

        fs.commit_active_batch().expect("commit batch");
    }

    // Inspect extent tree and block group used counters directly
    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open");
        let fs = Btrfs::mount(dev).expect("mount");
        let ext_tree = ExtentTree::read(&fs).expect("read extent tree");

        for bg in &ext_tree.block_groups {
            let bg_extents_used: u64 = ext_tree
                .extents
                .iter()
                .filter(|e| e.bytenr >= bg.start && e.bytenr < bg.start + bg.length)
                .map(|e| e.length)
                .sum();
            assert_eq!(
                bg.used, bg_extents_used,
                "block group [{}, +{}) used counter ({}) must match extent items sum ({})",
                bg.start, bg.length, bg.used, bg_extents_used
            );
        }
    }

    // Oracle verify
    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{}", out);

    let _ = fs::remove_file(&img);
}
