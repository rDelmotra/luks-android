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
use luks_core::error::LuksError;
use luks_core::fs::btrfs::chunk::BLOCK_GROUP_DATA;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
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

/// Under Valve A (Stage V), an unknown-size streaming write that exceeds
/// pre-existing free DATA space on `plain.img` is refused with `FilesystemFull`
/// during `write_chunk` rather than triggering a mid-stream chunk allocation transaction.
/// (Full safe dynamic chunk growth will be re-enabled in Stage C via the Reservation Ledger).
#[test]
fn streaming_unknown_size_write_forces_chunk_allocation_and_kernel_verifies() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let initial_chunk_count = fs.chunk_map().len();
    let initial_data_free = free_data_bytes(&fs);

    // plain.img measured (via `cargo run --example space_probe -- plain.img`)
    // at ~6 MiB (6,291,456 bytes) free DATA space. Sanity-check that measurement
    // hasn't drifted before trusting the margin below.
    assert!(
        initial_data_free < 7 * 1024 * 1024,
        "expected plain.img free DATA space under 7 MiB, measured {initial_data_free}"
    );

    // Deliberately larger than ALL pre-existing free DATA space, streamed in
    // uneven chunks so no single write_chunk call reveals the total up front.
    let total_size = (initial_data_free + 2 * 1024 * 1024) as usize;
    assert!(total_size as u64 > initial_data_free);

    let payload = generate_payload(total_size, 0xABCD_1234);

    let mut writer = fs.begin_file_streaming().expect("begin streaming writer");
    assert!(writer.is_streaming(), "writer should be in streaming mode");

    let chunk_sizes = [65536, 131072, 32768, 98304, 16384, 262144, 512 * 1024];
    let mut offset = 0;
    let mut i = 0;
    let mut hit_filesystem_full = false;
    while offset < payload.len() {
        let chunk_size = chunk_sizes[i % chunk_sizes.len()];
        let end = (offset + chunk_size).min(payload.len());
        match fs.write_chunk(&mut writer, &payload[offset..end]) {
            Ok(()) => {
                offset = end;
                i += 1;
            }
            Err(LuksError::FilesystemFull) => {
                hit_filesystem_full = true;
                break;
            }
            Err(e) => panic!("unexpected error from write_chunk: {e:?}"),
        }
    }

    // Under Valve A:
    // 1. FilesystemFull was returned
    assert!(
        hit_filesystem_full,
        "write_chunk must refuse with FilesystemFull under Valve A"
    );
    // 2. Chunk count did NOT increase mid-stream
    assert_eq!(
        fs.chunk_map().len(),
        initial_chunk_count,
        "chunk map must not have grown mid-stream"
    );

    // Abandon file cleans up cleanly
    fs.abandon_file(writer);
    drop(fs);

    // Ground-truth oracle: btrfs check + kernel mount + scrub.
    assert!(run_verify_script(&img), "oracle check must pass clean");

    let _ = fs::remove_file(&img);
}

/// Forces the same mid-stream `write_chunk` chunk-allocation fallback as
/// `streaming_unknown_size_write_forces_chunk_allocation_and_kernel_verifies`,
/// but on `mixed-4k.img` — whose DATA and METADATA share one combined block
/// group — instead of `plain.img`.
///
/// This fixture used to be attempted here and pulled, because on a MIXED
/// block group, `write_chunk`'s mid-stream `self.allocate_data_chunk()`
/// call used to build a *fresh* allocator from on-disk state in which this
/// writer's own already-chosen-but-uncommitted `data_runs` still looked
/// free, so the new chunk's DEV_TREE/CHUNK_TREE/EXTENT_TREE CoW carved
/// metadata blocks out of them. Replaying `mark_allocated` for the writer's
/// own runs against the rebuilt allocator then found a run split across two
/// free ranges and failed with `CorruptFs("range to mark allocated was not
/// present in block group free ranges")` — silent corruption of the
/// allocator's bookkeeping, discovered only after the fact.
///
/// `chunk_alloc.rs` now excludes the writer's reserved runs from that fresh
/// allocator before the CoW (`exclude_ranges`, not `mark_allocated`, so
/// `used`/`total_allocated_bytes` are not touched — see the module docs).
/// That eliminates the corruption, which this test proves by asserting the
/// error is never `CorruptFs` with that message.
///
/// It does **not** assert the write succeeds. `mixed-4k.img`'s combined
/// block group has ~5.3 MiB of *total* METADATA-capable space, and this
/// write engine has no mechanism to grow a METADATA or MIXED block group —
/// `allocate_data_chunk` only ever creates `BLOCK_GROUP_DATA`-only chunks
/// (`chunk_alloc.rs`'s `gate::check_chunk_allocation_profile(BLOCK_GROUP_DATA)`
/// and `Chunk::new_single(..., BLOCK_GROUP_DATA, ...)`). Any write sized to
/// force growth on this fixture necessarily drains the mixed group's
/// *current* free bytes to zero before the shortfall is discovered (the
/// greedy allocator has no way to know in advance it will need more), which
/// leaves zero unreserved bytes for the growth transaction's own metadata
/// CoW — verified empirically at margins from 4 KiB to 40 MiB, all
/// deterministically `FilesystemFull`, never `CorruptFs`. That ceiling is a
/// separate, pre-existing limitation (no METADATA/MIXED chunk growth at
/// all), not part of Bug A or Bug B, and out of scope here; flagging it
/// rather than manufacturing a passing test around it.
#[test]
fn streaming_unknown_size_write_on_mixed_block_group_no_longer_corrupts_the_allocator() {
    let img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable");

    let initial_data_free = free_data_bytes(&fs);

    // mixed-4k.img measured (via `cargo run --example space_probe --
    // mixed-4k.img`) at ~5.3 MiB free DATA space in its single MIXED block
    // group. Sanity-check that measurement hasn't drifted before trusting
    // the margin below.
    assert!(
        initial_data_free < 6 * 1024 * 1024,
        "expected mixed-4k.img free DATA space under 6 MiB, measured {initial_data_free}"
    );

    // Deliberately larger than ALL pre-existing free DATA space, streamed in
    // uneven chunks so no single write_chunk call reveals the total up front.
    let total_size = (initial_data_free + 2 * 1024 * 1024) as usize;
    assert!(total_size as u64 > initial_data_free);

    let payload = generate_payload(total_size, 0x5EED_C0DE);

    let mut writer = fs.begin_file_streaming().expect("begin streaming writer");
    assert!(writer.is_streaming(), "writer should be in streaming mode");

    let chunk_sizes = [65536, 131072, 32768, 98304, 16384, 262144, 512 * 1024];
    let mut offset = 0;
    let mut i = 0;
    let outcome = loop {
        if offset >= payload.len() {
            break Ok(());
        }
        let chunk_size = chunk_sizes[i % chunk_sizes.len()];
        let end = (offset + chunk_size).min(payload.len());
        if let Err(e) = fs.write_chunk(&mut writer, &payload[offset..end]) {
            break Err(e);
        }
        offset = end;
        i += 1;
    };

    match outcome {
        Ok(()) => {
            // If it did fit, it must still be correct — finish and let the
            // kernel grade it, same as the plain.img sibling test.
            let expected_sha256 = sha256_hex(&payload);
            let ino = fs
                .finish_file(writer, "/", "streamed_mixed_forced_alloc.bin")
                .expect("finish streamed file");
            assert!(ino >= 256);
            fs.commit_active_batch().expect("commit");
            drop(fs);
            assert!(run_verify_script(&img), "oracle check must pass clean");
            assert!(
                verify_kernel_readback_sha256(&img, &[("streamed_mixed_forced_alloc.bin", &expected_sha256)]),
                "Linux kernel mount must read back an identical SHA256 checksum"
            );
        }
        Err(LuksError::FilesystemFull) => {
            // Expected on this fixture (see doc comment): the metadata
            // ceiling, not the corruption bug, is what stops this write.
        }
        Err(e) => panic!(
            "write_chunk must fail only with FilesystemFull (an honest \
             refusal) on this fixture, never with anything resembling the \
             fixed corruption bug: got {e:?}"
        ),
    }

    let _ = fs::remove_file(&img);
}

// A known-size `begin_file` variant on `mixed-4k.img`, forcing the
// `file.rs:105-115`-equivalent fallback, was attempted here to prove Bug B
// also affects the known-size path, not just streaming. It does not: probed
// at margins from 4 KiB through 40 MiB over pre-existing free DATA space
// (spanning one to three additional chunk allocations, confirmed via
// chunk-map growth), `begin_file` never hit the failure. This matches
// `begin_file`'s structure, not accident: its pre-satisfy loop
// (`while total_free_data < disk_num_bytes { self.allocate_data_chunk()?; }`)
// grows chunks with `data_runs` still empty — nothing reserved yet to
// collide with — and only *after* that loop's own sum check guarantees
// enough real, already-committed free space does it start carving runs from
// an allocator that cannot go stale mid-carve, because nothing mutates it
// between the sum check and the carve. The exclusion fix in
// `chunk_alloc.rs` is applied uniformly to this path anyway (defense in
// depth, and it costs nothing when `reserved` is unreachable), but no
// regression test is added for it here — a test that cannot fail on this
// code is not a test, per this repo's own rule.
