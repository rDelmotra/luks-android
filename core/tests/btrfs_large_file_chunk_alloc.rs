//! End-to-end Large File Dynamic Chunk Allocation & Linux Kernel Mount Tests (Pass H.4).
//!
//! ```text
//! cargo test --features dangerous-write-support --test btrfs_large_file_chunk_alloc
//! ```
//!
//! # Verification & The Oracle
//! 1. `begin_file` / `create_file_with_data` dynamically allocates a `DATA|single` chunk
//!    when file size exceeds pre-existing free data space.
//! 2. `read_file` from the writer returns byte-exact data matching the source.
//! 3. Ground truth `tools/verify-btrfs.sh`:
//!    - `btrfs check --readonly`
//!    - Real Linux kernel mount
//!    - `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
//! 4. Real Linux kernel mount reads back the written files and verifies byte-for-byte SHA256 match.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::chunk::BLOCK_GROUP_DATA;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::chunk_alloc::next_logical;
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
        "btrfs-large-file-{src_name}-{}-{}-{}",
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
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn generate_deterministic_pattern(size: usize, seed: u64) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut state = seed;
    for chunk in data.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }
    data
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
                println!("ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
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

/// Mount image inside Colima and verify that the Linux kernel reads back the exact SHA256 checksums.
fn verify_kernel_readback_sha256(image_path: &PathBuf, files: &[(&str, &str)]) -> bool {
    if !common::oracle::gate() {
        return true;
    }

    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(
        "verify-kernel-{}-{}-{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let remote_img = format!("/tmp/{name}.img");
    let remote_mnt = format!("/tmp/mnt-{name}");

    // Copy image to Colima
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
                println!("ORACLE VERIFIED: kernel sha256 passed for {}", image_path.display());
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

#[test]
fn test_streaming_large_file_triggers_chunk_allocation_and_oracle_clean() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_chunk_count = fs.chunk_map().len();
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let initial_allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())
        .expect("derive allocator");

    // Calculate initial free data space
    let initial_data_free: u64 = initial_allocator
        .block_groups
        .iter()
        .filter(|bg| bg.block_group.flags & BLOCK_GROUP_DATA != 0)
        .map(|bg| bg.total_free_bytes)
        .sum();

    // Verify initial data free space is around ~8 MiB (8,364,032 bytes on plain.img)
    assert!(
        initial_data_free < 9 * 1024 * 1024,
        "initial free data space must be < 9 MiB, got {initial_data_free}"
    );

    // Target file size: 15 MiB (15,728,640 bytes) — strictly larger than all pre-existing free data space!
    let target_file_size = 15 * 1024 * 1024usize;
    assert!(target_file_size as u64 > initial_data_free);

    let pattern = generate_deterministic_pattern(target_file_size, 0xCAFE_BABE_DEAD_BEEF);
    let expected_sha256 = sha256_hex(&pattern);

    let prev_next_logical = next_logical(fs.chunk_map());

    // 1. Begin file: dynamically creates and commits a new DATA chunk to satisfy 15 MiB
    let mut writer = fs.begin_file(target_file_size as u64).expect("begin_file");

    // Verify a new chunk was allocated and registered
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);
    let new_chunk = fs
        .chunk_map()
        .chunks()
        .iter()
        .find(|c| c.logical == prev_next_logical)
        .expect("new chunk must be present in chunk map");
    assert_eq!(new_chunk.chunk_type, BLOCK_GROUP_DATA);
    assert_eq!(new_chunk.length, 12 * 1024 * 1024);

    // Verify writer has allocated data runs spanning across both chunks
    assert!(
        writer.data_runs().len() >= 2,
        "15 MiB allocation must span at least 2 data extents across both chunks"
    );
    let total_allocated_runs: u64 = writer.data_runs().iter().map(|(_, len)| *len).sum();
    assert_eq!(total_allocated_runs, target_file_size as u64);

    // 2. Stream data in varied chunk sizes (64 KiB, 256 KiB, 512 KiB)
    let chunk_sizes = [65536, 262144, 524288, 131072];
    let mut offset = 0usize;
    let mut step = 0;
    while offset < pattern.len() {
        let chunk_size = chunk_sizes[step % chunk_sizes.len()];
        let take = (pattern.len() - offset).min(chunk_size);
        fs.write_chunk(&mut writer, &pattern[offset..offset + take])
            .expect("write_chunk");
        offset += take;
        step += 1;
    }
    assert_eq!(writer.written_bytes(), target_file_size as u64);

    // 3. Finish file
    let ino = fs
        .finish_file(writer, "/", "large_streaming.bin")
        .expect("finish_file");
    assert!(ino >= 256);

    // 4. Verify reader returns byte-exact content matching source
    let readback = fs.read_file("/large_streaming.bin").expect("read_file");
    assert_eq!(readback.len(), target_file_size);
    assert_eq!(sha256_hex(&readback), expected_sha256);

    fs.commit_active_batch().expect("commit");
    drop(fs);

    // 5. Remount read-only and verify persistence
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
    assert_eq!(fs_ro.chunk_map().len(), initial_chunk_count + 1);
    let readback_ro = fs_ro.read_file("/large_streaming.bin").expect("read_file ro");
    assert_eq!(sha256_hex(&readback_ro), expected_sha256);
    drop(fs_ro);

    // 6. Oracle verification via tools/verify-btrfs.sh on Colima
    let oracle_clean = run_verify_script(&temp_img);
    assert!(
        oracle_clean,
        "tools/verify-btrfs.sh oracle must pass clean after 15 MiB streaming write"
    );

    // 7. Verify byte-exact readback from real Linux kernel mount in VM
    let kernel_ok = verify_kernel_readback_sha256(
        &temp_img,
        &[("large_streaming.bin", &expected_sha256)],
    );
    assert!(
        kernel_ok,
        "Linux kernel mount must read back identical SHA256 checksum"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_atomic_create_file_with_data_large_file_triggers_chunk_allocation() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_chunk_count = fs.chunk_map().len();

    // Target file size: 14 MiB (14,680,064 bytes)
    let target_file_size = 14 * 1024 * 1024usize;
    let payload = generate_deterministic_pattern(target_file_size, 0x1234_5678_9ABC_DEF0);
    let expected_sha256 = sha256_hex(&payload);

    // 1. Call create_file_with_data
    let ino = fs
        .create_file_with_data("/", "large_atomic.bin", &payload)
        .expect("create_file_with_data");
    assert!(ino >= 256);

    // Verify chunk count increased
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);

    // Verify readback
    let readback = fs.read_file("/large_atomic.bin").expect("read_file");
    assert_eq!(sha256_hex(&readback), expected_sha256);

    drop(fs);

    // Remount read-only
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
    let readback_ro = fs_ro.read_file("/large_atomic.bin").expect("read_file ro");
    assert_eq!(sha256_hex(&readback_ro), expected_sha256);
    drop(fs_ro);

    // Oracle check
    let oracle_clean = run_verify_script(&temp_img);
    assert!(
        oracle_clean,
        "tools/verify-btrfs.sh oracle must pass clean after 14 MiB create_file_with_data"
    );

    // Linux kernel readback check
    let kernel_ok = verify_kernel_readback_sha256(
        &temp_img,
        &[("large_atomic.bin", &expected_sha256)],
    );
    assert!(
        kernel_ok,
        "Linux kernel mount must read back identical SHA256 checksum for atomic file"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_multiple_files_crossing_chunk_boundary() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_chunk_count = fs.chunk_map().len();

    // File 1: 5 MiB (fits inside chunk 1)
    let f1_data = generate_deterministic_pattern(5 * 1024 * 1024, 0x1111_2222_3333_4444);
    let f1_sha = sha256_hex(&f1_data);
    fs.create_file_with_data("/", "file1_5mb.bin", &f1_data)
        .expect("create file 1");
    assert_eq!(fs.chunk_map().len(), initial_chunk_count);

    // File 2: 7 MiB (exceeds chunk 1 remaining ~3.36 MiB, triggers chunk allocation, spans into chunk 2)
    let f2_data = generate_deterministic_pattern(7 * 1024 * 1024, 0x5555_6666_7777_8888);
    let f2_sha = sha256_hex(&f2_data);
    fs.create_file_with_data("/", "file2_7mb.bin", &f2_data)
        .expect("create file 2");
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);

    // File 3: 4 MiB (fits entirely into newly allocated chunk 2)
    let f3_data = generate_deterministic_pattern(4 * 1024 * 1024, 0x9999_AAAA_BBBB_CCCC);
    let f3_sha = sha256_hex(&f3_data);
    fs.create_file_with_data("/", "file3_4mb.bin", &f3_data)
        .expect("create file 3");
    assert_eq!(fs.chunk_map().len(), initial_chunk_count + 1);

    // Verify all 3 files
    assert_eq!(sha256_hex(&fs.read_file("/file1_5mb.bin").unwrap()), f1_sha);
    assert_eq!(sha256_hex(&fs.read_file("/file2_7mb.bin").unwrap()), f2_sha);
    assert_eq!(sha256_hex(&fs.read_file("/file3_4mb.bin").unwrap()), f3_sha);

    drop(fs);

    // Oracle verification
    let oracle_clean = run_verify_script(&temp_img);
    assert!(
        oracle_clean,
        "tools/verify-btrfs.sh oracle must pass clean across multi-file chunk crossing"
    );

    // Linux kernel readback
    let kernel_ok = verify_kernel_readback_sha256(
        &temp_img,
        &[
            ("file1_5mb.bin", &f1_sha),
            ("file2_7mb.bin", &f2_sha),
            ("file3_4mb.bin", &f3_sha),
        ],
    );
    assert!(
        kernel_ok,
        "Linux kernel mount must read back all 3 files matching SHA256 exactly"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_file_larger_than_total_device_capacity_is_safely_refused() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // plain.img is 64 MiB. Requesting 100 MiB must fail with FilesystemFull
    let res = fs.begin_file(100 * 1024 * 1024);
    assert!(matches!(res, Err(LuksError::FilesystemFull)));

    drop(fs);

    // Verify oracle still passes clean
    let oracle_clean = run_verify_script(&temp_img);
    assert!(
        oracle_clean,
        "filesystem must remain 100% clean after refused oversized file allocation"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_large_file_chunk_alloc_across_all_fixtures() {
    let fixtures = ["compress.img", "mixed-4k.img", "subvol.img"];
    for name in fixtures {
        let temp_img = copy_to_temp(name);
        let file_len = fs::metadata(&temp_img).unwrap().len();

        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        let initial_chunk_count = fs.chunk_map().len();
        let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
        let initial_allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())
            .expect("derive allocator");

        let initial_data_free: u64 = initial_allocator
            .block_groups
            .iter()
            .filter(|bg| bg.block_group.flags & BLOCK_GROUP_DATA != 0)
            .map(|bg| bg.total_free_bytes)
            .sum();

        // Write a file size that requires allocating a new chunk (initial_data_free + 2 MiB)
        let target_size = (initial_data_free + 2 * 1024 * 1024) as usize;
        let pattern = generate_deterministic_pattern(target_size, 0xA1B2_C3D4_E5F6_0718);
        let expected_sha = sha256_hex(&pattern);

        let mut writer = fs.begin_file(target_size as u64).unwrap_or_else(|e| {
            panic!("{name}: begin_file failed: {e}");
        });

        // Verify chunk allocation was triggered
        assert_eq!(
            fs.chunk_map().len(),
            initial_chunk_count + 1,
            "{name}: chunk map should have grown"
        );

        fs.write_chunk(&mut writer, &pattern).unwrap_or_else(|e| {
            panic!("{name}: write_chunk failed: {e}");
        });

        let ino = fs
            .finish_file(writer, "/", "fixture_large.bin")
            .unwrap_or_else(|e| {
                panic!("{name}: finish_file failed: {e}");
            });
        assert!(ino >= 256);

        // Verify readback
        let readback = fs.read_file("/fixture_large.bin").unwrap();
        assert_eq!(sha256_hex(&readback), expected_sha);

        fs.commit_active_batch().expect("commit");
        drop(fs);

        // Oracle
        let oracle_clean = run_verify_script(&temp_img);
        assert!(
            oracle_clean,
            "{name}: tools/verify-btrfs.sh oracle failed"
        );

        // Kernel sha256
        let kernel_ok = verify_kernel_readback_sha256(
            &temp_img,
            &[("fixture_large.bin", &expected_sha)],
        );
        assert!(
            kernel_ok,
            "{name}: kernel readback sha256 mismatch"
        );

        let _ = fs::remove_file(&temp_img);
    }
}
