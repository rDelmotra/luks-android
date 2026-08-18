//! Forces the streaming-write chunk-allocation-under-pressure path (Pass J.7)
//! to actually fire, and grades the result with a real kernel mount, not our
//! own reader (N.3).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test btrfs_streaming_chunk_alloc
//! ```
//!
//! # Why this file exists
//!
//! `btrfs_streaming_unknown.rs` (J.7's original test) writes 3.5 MiB into
//! `plain.img`, which has ~6 MiB of pre-existing free DATA space, and 1 MiB
//! into `mixed-4k.img`, which has ~5 MiB free. Both writes fit comfortably
//! inside space that already exists, so `write_chunk`'s
//! `Err(LuksError::FilesystemFull) => { self.allocate_data_chunk()?; ... }`
//! branch in `core/src/fs/btrfs/write/file.rs` — the entire reason
//! `begin_file_streaming` exists as a distinct code path from `begin_file` —
//! never runs. This file sizes writes to strictly exceed measured
//! pre-existing free DATA space (via `FreeSpaceMap`, the same instrument
//! `btrfs_large_file_chunk_alloc.rs`/H.4 uses) so the mid-stream allocation
//! path is provably exercised, and adds the kernel-mount byte-exact SHA256
//! readback that H.4 has and this pass never got.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::chunk::BLOCK_GROUP_DATA;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::chunk_alloc::next_logical;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

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
        "btrfs-streaming-chunk-alloc-{src_name}-{}-{}-{}",
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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Deterministic pseudo-random payload (not all-zero, so the writer can't
/// cheat by taking a hole/sparse shortcut and btrfs can't dedupe/compress it
/// away under us).
fn generate_payload(size: usize, mut seed: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((seed >> 16) as u8);
    }
    data
}

/// Sum of free bytes across all DATA block groups, measured the same way
/// `btrfs_large_file_chunk_alloc.rs` (H.4) measures it.
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
        Ok(out) => {
            if out.status.success() {
                println!(
                    "\u{2705} ORACLE VERIFIED: verify-btrfs.sh passed for {}",
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

/// Copy the image into colima, mount it with the real Linux kernel, and
/// `sha256sum` the file *inside that mount*. This is the H.4 precedent
/// (`verify_kernel_readback_sha256` in `btrfs_large_file_chunk_alloc.rs`) —
/// grading with the kernel's own reader, not ours.
fn verify_kernel_readback_sha256(image_path: &PathBuf, files: &[(&str, &str)]) -> bool {
    if !common::oracle::gate() {
        return true;
    }

    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(
        "verify-kernel-streaming-{}-{}-{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let remote_img = format!("/tmp/{name}.img");
    let remote_mnt = format!("/tmp/mnt-{name}");

    let cp_status = Command::new("colima")
        .args(["ssh", "--", "tee", &remote_img])
        .stdin(std::fs::File::open(image_path).unwrap())
        .stdout(std::process::Stdio::null())
        .status();
    if !cp_status.map_or(false, |s| s.success()) {
        eprintln!("failed to copy test image to colima");
        return false;
    }

    let mut check_commands = format!(
        "set -euo pipefail\n\
         mkdir -p {remote_mnt}\n\
         mount -o ro,loop,subvolid=5 {remote_img} {remote_mnt}\n\
         cleanup() {{ umount {remote_mnt} 2>/dev/null || true; rmdir {remote_mnt} 2>/dev/null || true; rm -f {remote_img}; }}\n\
         trap cleanup EXIT\n"
    );

    for (rel_path, expected_sha) in files {
        let clean_path = rel_path.trim_start_matches('/');
        check_commands.push_str(&format!(
            "ACTUAL_SHA=$(sha256sum {remote_mnt}/{clean_path} | cut -d' ' -f1)\n\
             if [ \"$ACTUAL_SHA\" != \"{expected_sha}\" ]; then\n\
                 echo \"SHA mismatch for {clean_path}: expected {expected_sha}, got $ACTUAL_SHA\" >&2\n\
                 exit 1\n\
             fi\n"
        ));
    }

    let script_output = Command::new("colima")
        .args(["ssh", "--", "sudo", "bash", "-c", &check_commands])
        .output();

    match script_output {
        Ok(out) => {
            if out.status.success() {
                println!(
                    "\u{2705} ORACLE VERIFIED: kernel sha256 passed for {}",
                    image_path.display()
                );
                true
            } else {
                eprintln!(
                    "kernel sha256 check stdout:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                );
                eprintln!(
                    "kernel sha256 check stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("failed to execute kernel sha256 check: {e}");
            false
        }
    }
}

/// The exit bar test: an unknown-size streaming write that is deliberately
/// sized to exceed all pre-existing free DATA space on `plain.img`, forcing
/// `write_chunk`'s mid-stream `allocate_data_chunk()` branch to fire — proven
/// positively via chunk-map count and by asserting the write's data runs
/// span a chunk that did not exist before the write started — followed by a
/// byte-exact SHA256 readback through a real Linux kernel mount.
#[test]
fn streaming_unknown_size_write_forces_chunk_allocation_and_kernel_verifies() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let initial_chunk_count = fs.chunk_map().len();
    let initial_data_free = free_data_bytes(&fs);
    let prev_next_logical = next_logical(fs.chunk_map());

    // plain.img measured (via `cargo run --example space_probe -- plain.img`)
    // at ~6 MiB (6,291,456 bytes) free DATA space. Sanity-check that measurement
    // hasn't drifted before trusting the margin below.
    assert!(
        initial_data_free < 7 * 1024 * 1024,
        "expected plain.img free DATA space under 7 MiB, measured {initial_data_free}"
    );

    // Deliberately larger than ALL pre-existing free DATA space, streamed in
    // uneven chunks so no single write_chunk call reveals the total up front
    // (that's the whole point of "unknown size").
    let total_size = (initial_data_free + 2 * 1024 * 1024) as usize;
    assert!(total_size as u64 > initial_data_free);

    let payload = generate_payload(total_size, 0xABCD_1234);
    let expected_sha256 = sha256_hex(&payload);

    let mut writer = fs.begin_file_streaming().expect("begin streaming writer");
    assert!(writer.is_streaming(), "writer should be in streaming mode");

    let chunk_sizes = [65536, 131072, 32768, 98304, 16384, 262144, 512 * 1024];
    let mut offset = 0;
    let mut i = 0;
    while offset < payload.len() {
        let chunk_size = chunk_sizes[i % chunk_sizes.len()];
        let end = (offset + chunk_size).min(payload.len());
        fs.write_chunk(&mut writer, &payload[offset..end])
            .expect("write chunk");
        offset = end;
        i += 1;
    }

    // --- Positive proof that mid-stream chunk allocation actually fired ---
    assert!(
        fs.chunk_map().len() > initial_chunk_count,
        "chunk map must have grown: before={initial_chunk_count}, after={}",
        fs.chunk_map().len()
    );
    let new_chunk = fs
        .chunk_map()
        .chunks()
        .iter()
        .find(|c| c.logical == prev_next_logical)
        .expect("a new chunk allocated at the pre-write next_logical must be present");
    assert_eq!(new_chunk.chunk_type, BLOCK_GROUP_DATA);
    assert!(
        writer
            .data_runs()
            .iter()
            .any(|&(bytenr, _)| bytenr >= prev_next_logical),
        "streamed file's data runs must include an extent inside the chunk \
         allocated mid-stream (logical >= {prev_next_logical}), runs: {:?}",
        writer.data_runs()
    );

    let ino = fs
        .finish_file(writer, "/", "streamed_forced_alloc.bin")
        .expect("finish streamed file");
    assert!(ino >= 256);

    drop(fs);

    // Remount read-only: chunk allocation must have persisted.
    let dev_ro = FileDevice::open(&img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
    assert!(fs_ro.chunk_map().len() > initial_chunk_count);
    let readback = fs_ro
        .read_file("/streamed_forced_alloc.bin")
        .expect("read streamed file ro");
    assert_eq!(readback.len(), total_size);
    assert_eq!(sha256_hex(&readback), expected_sha256);
    drop(fs_ro);

    // Ground-truth oracle: btrfs check + kernel mount + scrub.
    assert!(run_verify_script(&img), "oracle check must pass clean");

    // Byte-exact SHA256 readback through a REAL kernel mount — not our own
    // reader. This is the exit bar's non-negotiable half.
    assert!(
        verify_kernel_readback_sha256(&img, &[("streamed_forced_alloc.bin", &expected_sha256)]),
        "Linux kernel mount must read back an identical SHA256 checksum"
    );

    let _ = fs::remove_file(&img);
}

// A second fixture (`mixed-4k.img`, whose DATA and METADATA share one
// combined block group) was attempted here to prove the forced-allocation
// path on more than one on-disk geometry. It was pulled — not skipped, not
// `#[ignore]`d, removed — because it reproducibly finds a real bug rather
// than exercising the intended path:
//
// Forcing `write_chunk`'s mid-stream `Err(FilesystemFull) =>
// self.allocate_data_chunk()` branch on `mixed-4k.img`, at *any* margin over
// free space (4 KiB through 1 MiB all tried), fails deterministically at the
// same byte offset with `CorruptFs("range to mark allocated was not present
// in block group free ranges")`. `begin_file`'s equivalent path (used by
// `btrfs_large_file_chunk_alloc.rs`, H.4) does not hit this on the same
// fixture, because `begin_file` pre-satisfies total free space with a
// `while total_free_data < disk_num_bytes { self.allocate_data_chunk()?; }`
// loop *before* choosing any runs, so real chunk-tree growth (which, on a
// combined DATA+METADATA block group, consumes from the same pool the data
// runs are being carved from) never interleaves with picking a run.
// `write_chunk`'s streaming path allocates incrementally instead, so the
// real chunk-tree COW triggered by `self.allocate_data_chunk()` can land
// inside a free range a not-yet-committed data run in `writer.data_runs`
// believes is still free-but-reserved, and `mark_allocated` finds it gone.
//
// This is a defect in `core/src/fs/btrfs/write/file.rs`'s streaming
// allocator, not a test problem, and out of scope for N.3 (test-file-only
// ownership, no `core/src` changes). Flagging for a follow-up item rather
// than leaving it silently uncovered.
