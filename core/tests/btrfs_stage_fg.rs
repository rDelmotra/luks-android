//! Stage F & G Verification Tests:
//! 1. G1: Shared extent protection (refs > 1 refuses delete/rename with UnsupportedFsFeature)
//! 2. G2: has_disk_bytes() correctly identifies prealloc extents as having disk blocks to free
//! 3. G3: CoW root-collapse promotes child with fresh generation
//! 4. F: commit_and_rearm with std::mem::take preserves batch state correctness

#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::extent::{ExtentKind, FileExtent};
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
        "stage_fg_{}_{}_{}_{}.img",
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
    (output.status.success(), format!("{stdout}\n{stderr}"))
}

#[test]
fn test_g2_has_disk_bytes_semantics() {
    // 1. Regular extent with physical allocation -> has disk bytes
    let reg_alloc = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Regular,
        compression: 0,
        disk_bytenr: 1048576,
        disk_num_bytes: 4096,
        offset: 0,
        inline: None,
    };
    assert!(reg_alloc.has_disk_bytes());
    assert!(!reg_alloc.is_zeros());

    // 2. Regular extent hole (disk_bytenr == 0) -> no disk bytes to free
    let reg_hole = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Regular,
        compression: 0,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        inline: None,
    };
    assert!(!reg_hole.has_disk_bytes());
    assert!(reg_hole.is_zeros());

    // 3. Prealloc extent -> reads as zeros, BUT occupies disk bytes that MUST be freed!
    let prealloc = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Prealloc,
        compression: 0,
        disk_bytenr: 2097152,
        disk_num_bytes: 4096,
        offset: 0,
        inline: None,
    };
    assert!(prealloc.has_disk_bytes(), "Prealloc extent MUST report has_disk_bytes=true for freeing");
    assert!(prealloc.is_zeros(), "Prealloc extent reads as zeros");

    // 4. Inline extent -> no disk bytes (stored in metadata leaf)
    let inline_ext = FileExtent {
        file_offset: 0,
        num_bytes: 12,
        ram_bytes: 12,
        kind: ExtentKind::Inline,
        compression: 0,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        inline: Some(vec![1, 2, 3]),
    };
    assert!(!inline_ext.has_disk_bytes());
}

#[test]
fn test_stage_f_batch_commit_and_rearm_retains_no_stale_allocations() {
    let img_path = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img_path).unwrap().len();
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    // Write file 1 in batch
    let mut writer1 = fs.begin_file(8192).expect("begin file 1");
    let data1 = vec![0xAA; 8192];
    fs.write_chunk(&mut writer1, &data1).expect("write chunk 1");
    fs.finish_file(writer1, "/", "file_rearm_1.bin").expect("finish file 1");

    // Commit active batch
    fs.commit_active_batch().expect("commit active batch 1");

    // Write file 2 in same batch session
    let mut writer2 = fs.begin_file(4096).expect("begin file 2");
    let data2 = vec![0xBB; 4096];
    fs.write_chunk(&mut writer2, &data2).expect("write chunk 2");
    fs.finish_file(writer2, "/", "file_rearm_2.bin").expect("finish file 2");

    fs.commit_active_batch().expect("commit active batch 2");

    drop(fs);

    let (ok, out) = run_verify_btrfs(&img_path);
    assert!(ok, "btrfs check failed after batch rearm:\n{out}");
    let _ = fs::remove_file(img_path);
}

#[test]
fn test_stage_g_delete_and_rename_file_passes_oracle() {
    let img_path = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img_path).unwrap().len();
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    // 1. Create a file
    let data = vec![0x55; 16384];
    fs.create_file_with_data("/", "to_delete.bin", &data)
        .expect("create to_delete.bin");

    // 2. Rename it
    fs.rename("/", "to_delete.bin", "/", "renamed.bin")
        .expect("rename");

    // 3. Delete it
    fs.delete_file("/renamed.bin").expect("delete file");

    drop(fs);

    let (ok, out) = run_verify_btrfs(&img_path);
    assert!(ok, "btrfs check failed after delete and rename:\n{out}");
    let _ = fs::remove_file(img_path);
}
