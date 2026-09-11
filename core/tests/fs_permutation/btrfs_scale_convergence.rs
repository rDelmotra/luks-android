//! Issue 45: Convergence round headroom and scale verification on 61 GB Btrfs medium.
//!
//! Tests Btrfs accounting and fixed-point convergence loop headroom (MAX_CONVERGENCE_ROUNDS = 30)
//! on a 61 GiB medium with multi-gigabyte block group address space.

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::accounting::AccountingOracle;
use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;

fn run_kernel_oracle_direct(image_path: &Path) -> (bool, String, String) {
    if !common::oracle::gate() {
        return (true, String::new(), String::new());
    }

    let name = format!("verify-scale-{}", std::process::id());
    let mnt = format!("/tmp/mnt-{}", name);
    let remote_path = image_path.display().to_string();

    let script = format!(
        r#"
set -euo pipefail
IMG="{remote_path}"
MNT="{mnt}"
cleanup() {{
    umount -l "$MNT" 2>/dev/null || true
    rm -rf "$MNT" 2>/dev/null || true
    for dev in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
        losetup -d "$dev" 2>/dev/null || true
    done
}}
cleanup
trap cleanup EXIT

echo "--- btrfs check --readonly ---"
btrfs check --readonly "$IMG"

mkdir -p "$MNT"
mount -o ro,loop "$IMG" "$MNT"
echo "--- mounted read-only, root contains ---"
ls -la "$MNT"
if [ -d "$MNT/benchmark" ]; then
    ls -la "$MNT/benchmark"
fi

echo "--- btrfs scrub start -Bdr ---"
SCRUB_OUT="$(btrfs scrub start -Bdr "$MNT" 2>&1)"
echo "$SCRUB_OUT"
if ! grep -q "Error summary:    no errors found" <<<"$SCRUB_OUT"; then
    echo "FAIL: scrub reported errors" >&2
    exit 1
fi
echo "VERDICT: clean — check passed, the kernel mounted it, scrub found nothing"
"#
    );

    let output = Command::new("colima")
        .args(["ssh", "--", "sudo", "bash", "-c", &script])
        .output();

    match output {
        Ok(out) => {
            let success = out.status.success();
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            if success {
                println!("ORACLE VERIFIED: kernel check/mount/scrub passed for {remote_path}");
            }
            (success, stdout, stderr)
        }
        Err(e) => (false, String::new(), format!("failed to invoke colima: {e}")),
    }
}

fn reset_61g_sparse_image(path: &Path) {
    let status = Command::new("truncate")
        .arg("-s")
        .arg("61G")
        .arg(path)
        .status()
        .expect("truncate sparse 61G");
    assert!(status.success(), "truncate failed");

    let remote_cmd = format!("mkfs.btrfs -f {}", path.display());
    let status = Command::new("colima")
        .args(["ssh", "--", "bash", "-c", &remote_cmd])
        .status()
        .expect("format 61G sparse image with colima mkfs.btrfs");
    assert!(status.success(), "colima mkfs.btrfs failed");
}

#[test]
fn test_scale_61g_medium_accounting_and_convergence_headroom() {
    let img_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("test_sparse_61g.img");

    reset_61g_sparse_image(&img_path);

    let file_len = fs::metadata(&img_path).unwrap().len();
    assert_eq!(
        file_len,
        61 * 1024 * 1024 * 1024,
        "image must be exact 61 GiB"
    );

    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable 61G image");
    let mut fs = Btrfs::mount(dev).expect("mount writable 61G btrfs");

    // Issue 45 is about the convergence loop's round count, so measure it.
    // Counting starts here, after mount, so only this test's own workload is
    // attributed to it.
    luks_core::forensic::reset_structural_counts();

    // 1. Initial assert_clean on fresh 61 GiB mkfs image
    let initial_report = AccountingOracle::assert_clean(&fs);
    println!("61 GiB initial report: {initial_report:#?}");
    assert_eq!(
        initial_report.superblock_bytes_used,
        initial_report.total_block_group_used
    );
    assert_eq!(
        initial_report.superblock_bytes_used,
        initial_report.total_referenced_bytes
    );

    // 2. Perform diverse operations on the 61 GiB filesystem:
    // Create hierarchy
    fs.create_directory("/", "benchmark").expect("mkdir benchmark");
    fs.create_directory("/benchmark", "sub").expect("mkdir sub");

    // Write small files
    for i in 0..50 {
        let name = format!("file_{i:04}.txt");
        let data = vec![((i * 19 + 7) & 0xFF) as u8; 1024];
        fs.create_file_with_data("/benchmark/sub", &name, &data)
            .expect("create file");
    }

    // Stream a 2 MiB file across chunks
    let mut writer = fs.begin_file(2 * 1024 * 1024).expect("begin_file");
    let chunk = vec![0xA5u8; 65536];
    for _ in 0..32 {
        fs.write_chunk(&mut writer, &chunk).expect("write_chunk");
    }
    fs.finish_file(writer, "/benchmark", "stream_2mb.bin")
        .expect("finish_file");

    // Commit active batch
    fs.commit_active_batch().expect("commit active batch");

    // Delete half the small files to trigger leaf deletions and extent prunings
    for i in 0..25 {
        let name = format!("/benchmark/sub/file_{i:04}.txt");
        fs.delete_file(&name).expect("delete_file");
    }

    fs.commit_active_batch().expect("commit deletes");

    // 3. In-process accounting oracle check with active allocator
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let allocator =
        FreeSpaceMap::from_extent_tree(&extent_tree).expect("allocator from extent tree");
    let post_report = AccountingOracle::check_with_allocator(&fs, &allocator)
        .expect("accounting check_with_allocator must pass on 61G medium");

    println!("61 GiB post-workload report: {post_report:#?}");
    assert_eq!(
        post_report.superblock_bytes_used,
        post_report.total_block_group_used
    );
    assert_eq!(
        post_report.superblock_bytes_used,
        post_report.total_referenced_bytes
    );

    // 3b. The headroom this test is named for.
    //
    // `MAX_CONVERGENCE_ROUNDS = 30` (`write/extent_tree.rs`) fails the whole
    // transaction closed when exceeded, so a workload that creeps toward it
    // aborts a transfer mid-flight. Phase 0 measured a max of 9 on 64 MiB
    // fixtures with a flat tail from 6 to 9, and traced that tail to deletion
    // cascades rather than to filesystem size — which is why the workload above
    // deletes 25 files before this check rather than only writing.
    //
    // Both bounds matter. The lower one is the vacuity control: a run that
    // never entered the convergence loop would satisfy any upper bound.
    let counts = luks_core::forensic::get_structural_counts();
    println!(
        "61 GiB convergence: {} invocations, max {} rounds (limit 30)",
        counts.converge_total_calls, counts.max_converge_rounds
    );
    assert!(
        counts.converge_total_calls > 0,
        "convergence loop never ran — this test proves nothing about headroom"
    );
    assert!(
        counts.max_converge_rounds > 0,
        "convergence rounds recorded as 0 across {} invocations — instrumentation is not wired",
        counts.converge_total_calls
    );
    assert!(
        counts.max_converge_rounds <= 12,
        "convergence reached {} rounds on a 61 GiB medium against a hard limit of 30. \
         Phase 0's worst case on 64 MiB fixtures was 9. Anything above 12 means the \
         round count scales with something this test's workload varies, and the limit \
         is closer than assumed — measure before raising this bound.",
        counts.max_converge_rounds
    );

    drop(fs);

    // 4. Kernel oracle check (btrfs check, mount, btrfs scrub)
    let (ok, out, err) = run_kernel_oracle_direct(&img_path);
    assert!(
        ok,
        "kernel oracle failed on 61 GiB medium: {err}\n{out}"
    );
}

fn reset_4tb_sparse_image_aged(path: &Path) {
    let status = Command::new("truncate")
        .arg("-s")
        .arg("4T")
        .arg(path)
        .status()
        .expect("truncate sparse 4T");
    assert!(status.success(), "truncate failed");

    let pid = std::process::id();
    let mnt = format!("/tmp/mnt-4tb-reset-{}", pid);
    let remote_path = path.display().to_string();

    let script = format!(
        r#"
set -euo pipefail
IMG="{remote_path}"
MNT="{mnt}"

cleanup() {{
    umount -l "$MNT" 2>/dev/null || true
    rm -rf "$MNT" 2>/dev/null || true
    for dev in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
        losetup -d "$dev" 2>/dev/null || true
    done
}}
cleanup
trap cleanup EXIT

mkfs.btrfs -q -f "$IMG"
mkdir -p "$MNT"
mount -o loop "$IMG" "$MNT"

python3 -c '
import os
for round in range(2):
    for i in range(600):
        fn = f"{mnt}/f_{{round:02d}}_{{i:04d}}.bin"
        with open(fn, "wb") as f:
            f.write(b"A" * 4096)
    os.sync()
    for i in range(0, 600, 2):
        fn = f"{mnt}/f_{{round:02d}}_{{i:04d}}.bin"
        os.remove(fn)
    os.sync()
'
umount "$MNT"
"#
    );

    let status = Command::new("colima")
        .args(["ssh", "--", "sudo", "bash", "-c", &script])
        .status()
        .expect("colima format/aging failed");
    assert!(status.success(), "colima format/aging script failed");
}

#[test]
fn test_scale_4tb_metadata_massive_convergence() {
    let img_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("test_sparse_4tb.img");

    reset_4tb_sparse_image_aged(&img_path);

    let file_len = fs::metadata(&img_path).unwrap().len();
    assert_eq!(
        file_len,
        4 * 1024 * 1024 * 1024 * 1024,
        "image must be exact 4 TiB"
    );

    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable 4T image");
    let mut fs = Btrfs::mount(dev).expect("mount writable 4T btrfs");

    luks_core::forensic::reset_structural_counts();

    // Perform diverse operations on the massive 4 TB filesystem
    fs.create_directory("/", "benchmark").expect("mkdir benchmark");
    fs.create_directory("/benchmark", "sub").expect("mkdir sub");

    // Write small files
    for i in 0..50 {
        let name = format!("file_{i:04}.txt");
        let data = vec![((i * 19 + 7) & 0xFF) as u8; 1024];
        fs.create_file_with_data("/benchmark/sub", &name, &data)
            .expect("create file");
    }

    // Stream a 2 MiB file across chunks
    let mut writer = fs.begin_file(2 * 1024 * 1024).expect("begin_file");
    let chunk = vec![0xA5u8; 65536];
    for _ in 0..32 {
        fs.write_chunk(&mut writer, &chunk).expect("write_chunk");
    }
    fs.finish_file(writer, "/benchmark", "stream_2mb.bin")
        .expect("finish_file");

    // Commit active batch
    fs.commit_active_batch().expect("commit active batch");

    // Delete half the small files to trigger leaf deletions and extent prunings
    for i in 0..25 {
        let name = format!("/benchmark/sub/file_{i:04}.txt");
        fs.delete_file(&name).expect("delete_file");
    }

    fs.commit_active_batch().expect("commit deletes");

    // 3. In-process accounting oracle check with active allocator
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let allocator =
        FreeSpaceMap::from_extent_tree(&extent_tree).expect("allocator from extent tree");
    let post_report = AccountingOracle::check_with_allocator(&fs, &allocator)
        .expect("accounting check_with_allocator must pass on 4T medium");

    println!("4 TiB post-workload report: {post_report:#?}");
    assert_eq!(
        post_report.superblock_bytes_used,
        post_report.total_block_group_used
    );
    assert_eq!(
        post_report.superblock_bytes_used,
        post_report.total_referenced_bytes
    );

    let counts = luks_core::forensic::get_structural_counts();
    println!(
        "4 TiB convergence: {} invocations, max {} rounds (limit 30)",
        counts.converge_total_calls, counts.max_converge_rounds
    );
    assert!(
        counts.converge_total_calls > 0,
        "convergence loop never ran"
    );
    assert!(
        counts.max_converge_rounds > 0,
        "convergence rounds recorded as 0"
    );
    assert!(
        counts.max_converge_rounds <= 12,
        "convergence reached {} rounds on a 4 TiB medium against a hard limit of 30.",
        counts.max_converge_rounds
    );

    drop(fs);

    let (ok, out, err) = run_kernel_oracle_direct(&img_path);
    assert!(
        ok,
        "kernel oracle failed on 4 TiB medium: {err}\n{out}"
    );
}

fn reset_4tb_sparse_image_fresh(path: &Path) {
    let status = Command::new("truncate")
        .arg("-s")
        .arg("4T")
        .arg(path)
        .status()
        .expect("truncate sparse 4T");
    assert!(status.success(), "truncate failed");

    let pid = std::process::id();
    let mnt = format!("/tmp/mnt-4tb-fresh-{}", pid);
    let remote_path = path.display().to_string();

    let script = format!(
        r#"
set -euo pipefail
IMG="{remote_path}"
MNT="{mnt}"

cleanup() {{
    umount -l "$MNT" 2>/dev/null || true
    rm -rf "$MNT" 2>/dev/null || true
    for dev in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
        losetup -d "$dev" 2>/dev/null || true
    done
}}
cleanup
trap cleanup EXIT

mkfs.btrfs -q -f "$IMG"
"#
    );

    let status = Command::new("colima")
        .args(["ssh", "--", "sudo", "bash", "-c", &script])
        .status()
        .expect("colima format failed");
    assert!(status.success(), "colima format script failed");
}

#[test]
fn test_scale_4tb_scalar_64bit_width() {
    let img_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("test_sparse_4tb_scalars.img");

    reset_4tb_sparse_image_fresh(&img_path);

    let file_len = fs::metadata(&img_path).unwrap().len();
    assert_eq!(
        file_len,
        4 * 1024 * 1024 * 1024 * 1024,
        "image must be exact 4 TiB"
    );

    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable 4T image");
    let mut fs = Btrfs::mount(dev).expect("mount writable 4T btrfs");

    // S2 item 3: 64-bit width on addresses and lengths.
    // alloc.rs:418 documents a real past instance — disk_num_bytes as u32 wrapped for
    // files >= 4 GiB. Write one file larger than 4 GiB and one at a bytenr above 2^32
    // on the sparse volume, then grade with the kernel.

    // 1. Write one file larger than 4 GiB: 4097 MiB = 4 * 1024 * 1024 * 1024 + 1024 * 1024
    let large_file_size: u64 = 4 * 1024 * 1024 * 1024 + 1024 * 1024;
    let mut writer = fs.begin_file(large_file_size).expect("begin_file > 4 GiB");
    let chunk = vec![0x5au8; 1024 * 1024]; // 1 MiB chunks
    for _ in 0..4097 {
        fs.write_chunk(&mut writer, &chunk).expect("write_chunk 1 MiB");
    }
    fs.finish_file(writer, "/", "large_over_4gb.bin")
        .expect("finish_file > 4 GiB");
    fs.commit_active_batch().expect("commit large file");

    // 2. Write one file at a bytenr above 2^32:
    // With 4097 MiB allocated across 1 GiB data chunks, chunk allocations have progressed
    // beyond 2^32 = 4,294,967,296. The next file allocation lands in Chunk 5 (> 5 GiB logical).
    let high_data = b"scalar 64-bit verification: bytenr strictly above 2^32";
    fs.create_file_with_data("/", "file_above_2_32.txt", high_data)
        .expect("create file above 2^32");
    fs.commit_active_batch().expect("commit file above 2^32");

    // Verify in-process accounting oracle across all block groups and trees
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let allocator = FreeSpaceMap::from_extent_tree(&extent_tree).expect("allocator from extent tree");
    let report = AccountingOracle::check_with_allocator(&fs, &allocator)
        .expect("accounting check_with_allocator must pass for 64-bit width test");

    println!("64-bit width post-workload report: {report:#?}");
    assert_eq!(report.superblock_bytes_used, report.total_block_group_used);
    assert_eq!(report.superblock_bytes_used, report.total_referenced_bytes);

    // Verify that at least one block group has bytenr >= 2^32 (4,294,967,296)
    let has_extent_above_4g = report
        .block_groups
        .iter()
        .any(|bg| bg.start >= (1u64 << 32) && bg.used > 0);
    assert!(
        has_extent_above_4g,
        "expected at least one block group with bytenr >= 2^32 to have allocations"
    );

    drop(fs);

    // Grade with the Linux kernel oracle
    let (ok, out, err) = run_kernel_oracle_direct(&img_path);
    assert!(
        ok,
        "kernel oracle failed on 64-bit scalar medium: {err}\n{out}"
    );
}

#[test]
fn test_scale_sys_chunk_array_threshold_refusal() {
    let img_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("test_sparse_4tb_chunk_array.img");

    reset_4tb_sparse_image_fresh(&img_path);

    let file_len = fs::metadata(&img_path).unwrap().len();
    assert_eq!(
        file_len,
        4 * 1024 * 1024 * 1024 * 1024,
        "image must be exact 4 TiB"
    );

    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable 4T image");
    let mut sb = luks_core::fs::btrfs::Superblock::find(&dev).expect("find superblock");

    // S2 item 2: BTRFS_SYSTEM_CHUNK_ARRAY_SIZE (gate.rs:38) — 2048 bytes caps the system chunk count.
    // Gated, but the gate has never been exercised at its threshold on a real filesystem.
    // Confirm it refuses cleanly rather than corrupting.
    
    // Find the SYSTEM chunk item in sys_chunk_array:
    // On fresh mkfs, sys_chunk_array has exactly 1 entry: the 129-byte SYSTEM chunk.
    let sys_chunk_item = sb.sys_chunk_array.clone();
    assert_eq!(sys_chunk_item.len(), 129);

    // Expand sys_chunk_array with valid system chunk items until remaining capacity
    // is insufficient (< 129 bytes remaining).
    // BTRFS_SYSTEM_CHUNK_ARRAY_SIZE = 2048. Threshold is > 2048 - 129 = 1919 bytes.
    let mut fake_logical = 0x2_0000_0000u64;
    while sb.sys_chunk_array.len() + 129 <= 2048 {
        let mut entry = sys_chunk_item.clone();
        entry[9..17].copy_from_slice(&fake_logical.to_le_bytes());
        sb.sys_chunk_array.extend_from_slice(&entry);
        fake_logical += 8 * 1024 * 1024;
    }
    assert!(
        sb.sys_chunk_array.len() > 2048 - 129,
        "sys_chunk_array must exceed capacity threshold (len {})",
        sb.sys_chunk_array.len()
    );

    // Mount the real filesystem with this superblock
    let mut fs = Btrfs::mount_with_superblock(dev, sb)
        .expect("mount real filesystem with threshold sys_chunk_array");

    // Exercise the gate at its threshold: attempt chunk allocation
    let res = fs.allocate_data_chunk();
    match res {
        Err(luks_core::error::LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("sys_chunk_array capacity exhausted"),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature for sys_chunk_array exhausted, got {other:?}"),
    }

    // Confirm filesystem is not corrupted: drop fs and grade untouched image with kernel
    drop(fs);

    let (ok, out, err) = run_kernel_oracle_direct(&img_path);
    assert!(
        ok,
        "kernel oracle failed after clean sys_chunk_array refusal: {err}\n{out}"
    );
}
