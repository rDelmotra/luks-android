//! Issue 45: Convergence round headroom and scale verification on 61 GB Btrfs medium.
//!
//! Tests Btrfs accounting and fixed-point convergence loop headroom (MAX_CONVERGENCE_ROUNDS = 30)
//! on a 61 GiB medium with multi-gigabyte block group address space.

#![cfg(feature = "dangerous-write-support")]

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

    let name = format!("verify-61g-{}", std::process::id());
    let mnt = format!("/tmp/mnt-{}", name);
    let remote_path = image_path.display().to_string();

    let script = format!(
        r#"
set -euo pipefail
IMG="{remote_path}"
MNT="{mnt}"
cleanup() {{
    umount "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}}
trap cleanup EXIT

echo "--- btrfs check --readonly ---"
btrfs check --readonly "$IMG"

mkdir -p "$MNT"
mount -o ro,loop "$IMG" "$MNT"
echo "--- mounted read-only, root contains ---"
ls -la "$MNT"
ls -la "$MNT/benchmark"

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
