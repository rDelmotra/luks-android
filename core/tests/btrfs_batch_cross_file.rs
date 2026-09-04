//! Phase 3 verification: Assert that active_batch carries state across files,
//! preserves allocator and counters, and creates oracle-clean filesystems.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

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
        "btrfs-batch-p3-{src_name}-{}-{}-{}",
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
fn test_cross_file_batch_sequential_writes() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    let num_files = 15;
    let mut expected_shas = Vec::new();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        for i in 0..num_files {
            let filename = format!("file_{:03}.dat", i);
            let payload = format!("Payload content for file index {} - {}", i, "x".repeat(500 * (i + 1))).into_bytes();
            
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let expected_sha = format!("{:x}", hasher.finalize());
            expected_shas.push((filename.clone(), expected_sha));

            let mut writer = fs.begin_file(payload.len() as u64).expect("begin_file");
            fs.write_chunk(&mut writer, &payload).expect("write_chunk");
            let ino = fs.finish_file(writer, "/", &filename).expect("finish_file");
            assert!(ino >= 256 + i as u64);
        }

        // Commit trailing active batch before in-session readbacks
        fs.commit_active_batch().expect("commit active batch");

        // Readback within same mount session
        for (name, expected_sha) in &expected_shas {
            let readback = fs.read_file(&format!("/{}", name)).expect("read_file");
            let mut hasher = Sha256::new();
            hasher.update(&readback);
            let actual_sha = format!("{:x}", hasher.finalize());
            assert_eq!(&actual_sha, expected_sha, "readback mismatch for {}", name);
        }
    }

    // Remount read-only to verify cold state
    {
        let dev = FileDevice::open(&img).expect("open ro");
        let fs_ro = Btrfs::mount(dev).expect("mount ro");
        for (name, expected_sha) in &expected_shas {
            let readback = fs_ro.read_file(&format!("/{}", name)).expect("read_file ro");
            let mut hasher = Sha256::new();
            hasher.update(&readback);
            let actual_sha = format!("{:x}", hasher.finalize());
            assert_eq!(&actual_sha, expected_sha, "cold readback mismatch for {}", name);
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{out}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_cross_file_batch_interleaved_with_dir_and_delete() {
    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Write file 1 into root
        let mut w1 = fs.begin_file(100).expect("begin 1");
        fs.write_chunk(&mut w1, &[0xAA; 100]).expect("write 1");
        fs.finish_file(w1, "/", "file1.bin").expect("finish 1");

        // 2. Create subfolder (should commit active batch and reset)
        fs.create_directory("/", "subfolder").expect("mkdir");

        // 3. Write file 2 into subfolder
        let mut w2 = fs.begin_file(200).expect("begin 2");
        fs.write_chunk(&mut w2, &[0xBB; 200]).expect("write 2");
        fs.finish_file(w2, "/subfolder", "file2.bin").expect("finish 2");

        // 4. Write file 3 into subfolder (should use cached batch for subfolder)
        let mut w3 = fs.begin_file(300).expect("begin 3");
        fs.write_chunk(&mut w3, &[0xCC; 300]).expect("write 3");
        fs.finish_file(w3, "/subfolder", "file3.bin").expect("finish 3");

        // 5. Delete file 1 from root
        fs.delete_file("/file1.bin").expect("delete file1");

        // 6. Write file 4 into root
        let mut w4 = fs.begin_file(400).expect("begin 4");
        fs.write_chunk(&mut w4, &[0xDD; 400]).expect("write 4");
        fs.finish_file(w4, "/", "file4.bin").expect("finish 4");

        // Commit active batch before verifying readbacks
        fs.commit_active_batch().expect("commit active batch");

        // 7. Verify surviving files read back correctly
        let r2 = fs.read_file("/subfolder/file2.bin").expect("read f2");
        assert_eq!(r2, vec![0xBB; 200]);
        let r3 = fs.read_file("/subfolder/file3.bin").expect("read f3");
        assert_eq!(r3, vec![0xCC; 300]);
        let r4 = fs.read_file("/file4.bin").expect("read f4");
        assert_eq!(r4, vec![0xDD; 400]);

        // 8. Verify deleted file returns NotFound
        assert!(
            fs.read_file("/file1.bin").is_err(),
            "/file1.bin must not exist after deletion"
        );
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{out}");
    let _ = fs::remove_file(&img);
}

#[test]
fn test_cross_file_batch_allocator_stays_in_sync_with_disk() {
    use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
    use luks_core::fs::btrfs::write::extent_tree::ExtentTree;

    let img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img).unwrap().len();

    {
        let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        for i in 0..10 {
            let filename = format!("sync_file_{:02}.dat", i);
            let payload = vec![0x55 + (i as u8); 4096 * (i + 1)];
            let mut writer = fs.begin_file(payload.len() as u64).expect("begin");
            fs.write_chunk(&mut writer, &payload).expect("write");
            fs.finish_file(writer, "/", &filename).expect("finish");
        }

        // Compare in-memory cached allocator from active_batch with fresh on-disk ExtentTree
        let temp_writer = fs.begin_file(0).expect("begin zero");
        let in_memory_allocator = temp_writer.allocator().clone();
        fs.abandon_file(temp_writer).expect("abandon");

        fs.commit_active_batch().expect("commit");
        let disk_extent_tree = ExtentTree::read(&mut fs).expect("read extent tree from disk");
        let disk_allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
            &disk_extent_tree,
            fs.chunk_map(),
        )
        .expect("build allocator from disk");

        // Verify block group count and flags match exactly
        assert_eq!(
            in_memory_allocator.block_groups.len(),
            disk_allocator.block_groups.len(),
            "block group count must match"
        );
        for (in_mem_bg, disk_bg) in in_memory_allocator
            .block_groups
            .iter()
            .zip(disk_allocator.block_groups.iter())
        {
            assert_eq!(
                in_mem_bg.block_group.flags, disk_bg.block_group.flags,
                "flags must match"
            );
            // In-memory allocator tracked all allocated ranges safely
            assert!(
                in_mem_bg.total_free_bytes <= disk_bg.total_free_bytes,
                "in-memory free bytes ({}) must not exceed disk free bytes ({}) (pinned CoW space)",
                in_mem_bg.total_free_bytes,
                disk_bg.total_free_bytes,
            );
        }
    }

    let (ok, out) = run_verify_btrfs(&img);
    assert!(ok, "oracle verification failed:\n{out}");
    let _ = fs::remove_file(&img);
}
