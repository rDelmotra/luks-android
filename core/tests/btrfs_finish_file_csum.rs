//! Item P.1 test suite: finish_file zero read I/O & live write buffer checksums.
//!
//! ```text
//! cargo test --test btrfs_finish_file_csum --features dangerous-write-support
//! ```
//!
//! # Verification
//! 1. Test 1 (Zero Read I/O during finish_file): TrackingDevice asserts 0 data bytes read during `finish_file`.
//! 2. Test 2 (Kernel Oracle Scrub): Written file passes kernel mount and `btrfs scrub` with 0 errors.
//! 3. Test 3 (Deliberate-Break Control per RULES.md:85): Corrupt `writer.checksums` before calling `finish_file`, asserting `verify-btrfs.sh` fails.
//! 4. Test 4 (Multi-item CSUM on mixed-4k.img): Exercises multi-item splitting from live checksums.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::Result;
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
        "btrfs-finish-csum-{src_name}-{}-{}-{}",
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
                println!("✅ ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
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

/// A device wrapper that tracks all reads and their byte ranges.
#[derive(Clone)]
struct TrackingDevice<D> {
    inner: D,
    read_count: Arc<AtomicUsize>,
    bytes_read: Arc<AtomicUsize>,
    read_ranges: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl<D> TrackingDevice<D> {
    fn new(inner: D) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<Mutex<Vec<(u64, usize)>>>) {
        let read_count = Arc::new(AtomicUsize::new(0));
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let read_ranges = Arc::new(Mutex::new(Vec::new()));
        let dev = TrackingDevice {
            inner,
            read_count: Arc::clone(&read_count),
            bytes_read: Arc::clone(&bytes_read),
            read_ranges: Arc::clone(&read_ranges),
        };
        (dev, read_count, bytes_read, read_ranges)
    }
}

impl<D: ReadAt> ReadAt for TrackingDevice<D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_count.fetch_add(1, Ordering::SeqCst);
        self.bytes_read.fetch_add(buf.len(), Ordering::SeqCst);
        self.read_ranges.lock().unwrap().push((offset, buf.len()));
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl<D: WriteAt> WriteAt for TrackingDevice<D> {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }
}

#[test]
fn test_zero_data_read_io_during_finish_file() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let (tracking_dev, read_count, bytes_read, read_ranges) = TrackingDevice::new(dev);
    let mut fs = Btrfs::mount(tracking_dev).expect("mount btrfs");

    let size = 65536u64; // 64 KiB
    let mut payload = vec![0u8; size as usize];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 37 + 11) & 0xFF) as u8;
    }

    let mut writer = fs.begin_file(size).expect("begin_file");
    let data_runs = writer.data_runs().to_vec();
    assert!(!data_runs.is_empty(), "data_runs should be allocated");

    // Collect all physical ranges corresponding to the data runs
    let mut physical_data_ranges = Vec::new();
    for &(bytenr, run_len) in &data_runs {
        let stripes = fs.chunk_map().map_all_stripes(bytenr).expect("map stripes");
        for phys in stripes {
            physical_data_ranges.push((phys, run_len));
        }
    }

    // Write the data in chunks
    fs.write_chunk(&mut writer, &payload[..20000]).expect("write chunk 1");
    fs.write_chunk(&mut writer, &payload[20000..]).expect("write chunk 2");

    // Reset tracking counters right before calling finish_file
    read_count.store(0, Ordering::SeqCst);
    bytes_read.store(0, Ordering::SeqCst);
    read_ranges.lock().unwrap().clear();

    // Call finish_file - this must NOT read back any data bytes from disk!
    let ino = fs
        .finish_file(writer, "/", "zero_read_test.bin")
        .expect("finish_file");
    assert!(ino >= 256);

    let recorded_ranges = read_ranges.lock().unwrap().clone();
    let mut data_bytes_read = 0usize;

    for &(read_offset, read_len) in &recorded_ranges {
        let read_end = read_offset + read_len as u64;
        for &(data_phys, data_len) in &physical_data_ranges {
            let data_end = data_phys + data_len;
            // Check for overlap between [read_offset, read_end) and [data_phys, data_end)
            if read_offset < data_end && data_phys < read_end {
                let overlap_start = read_offset.max(data_phys);
                let overlap_end = read_end.min(data_end);
                data_bytes_read += (overlap_end - overlap_start) as usize;
            }
        }
    }

    assert_eq!(
        data_bytes_read, 0,
        "finish_file must read 0 data bytes from disk, but read {} bytes in data extents! Recorded reads: {:?}",
        data_bytes_read, recorded_ranges
    );

    // Verify read-back content matches payload
    let readback = fs.read_file("/zero_read_test.bin").expect("read file");
    assert_eq!(readback, payload);

    drop(fs);

    // Grade with kernel oracle
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(oracle_clean, "kernel oracle scrub failed on zero read I/O test");
}

#[test]
fn test_kernel_oracle_scrub_on_chunked_and_tail_padded_writes() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount btrfs");

    // Write a file with unaligned odd size (13,337 bytes: 3 full sectors + 1049 bytes partial tail)
    let size1 = 13337u64;
    let mut data1 = vec![0u8; size1 as usize];
    for (i, b) in data1.iter_mut().enumerate() {
        *b = ((i * 53 + 7) & 0xFF) as u8;
    }

    let mut writer1 = fs.begin_file(size1).expect("begin_file 1");
    // Write in unaligned slices to test live incremental checksumming across partial sectors
    fs.write_chunk(&mut writer1, &data1[..5000]).expect("chunk 1");
    fs.write_chunk(&mut writer1, &data1[5000..11000]).expect("chunk 2");
    fs.write_chunk(&mut writer1, &data1[11000..]).expect("chunk 3");
    let ino1 = fs.finish_file(writer1, "/", "tail_padded.bin").expect("finish 1");
    assert!(ino1 >= 256);

    // Write a multi-megabyte streamed file
    let size2 = 2 * 1024 * 1024 + 1234; // 2 MiB + 1234 bytes
    let mut data2 = vec![0u8; size2];
    for (i, b) in data2.iter_mut().enumerate() {
        *b = ((i * 17 + 29) & 0xFF) as u8;
    }

    let mut writer2 = fs.begin_file_streaming().expect("begin_file_streaming");
    let chunk_size = 65536;
    let mut offset = 0;
    while offset < data2.len() {
        let end = (offset + chunk_size).min(data2.len());
        fs.write_chunk(&mut writer2, &data2[offset..end]).expect("write streaming chunk");
        offset = end;
    }
    let ino2 = fs.finish_file(writer2, "/", "streamed_large.bin").expect("finish 2");
    assert!(ino2 >= 256);

    fs.commit_active_batch().expect("commit");
    drop(fs);

    // Verify persistence and correctness on remount
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");
    assert_eq!(fs_ro.read_file("/tail_padded.bin").expect("read 1"), data1);
    assert_eq!(fs_ro.read_file("/streamed_large.bin").expect("read 2"), data2);
    drop(fs_ro);

    // Grade with kernel oracle: btrfs check, mount, and btrfs scrub
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle scrub failed on tail-padded and streamed writes"
    );
}

#[test]
fn test_deliberate_corrupted_checksums_fails_scrub() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount btrfs");

    let size = 16384u64; // 16 KiB (4 sectors)
    let payload = vec![0xCAu8; size as usize];

    let mut writer = fs.begin_file(size).expect("begin_file");
    fs.write_chunk(&mut writer, &payload).expect("write_chunk");

    // Deliberate Break (RULES.md:85): Corrupt the live-computed checksum in writer.checksums
    assert!(!writer.checksums.is_empty(), "writer must have checksums");
    let original_csum = writer.checksums[0].1;
    writer.checksums[0].1 ^= 0xDEAD_BEEF;

    let ino = fs
        .finish_file(writer, "/", "corrupted_csum.bin")
        .expect("finish_file");
    assert!(ino >= 256);

    fs.commit_active_batch().expect("commit");
    drop(fs);

    // If oracle is available, verify that btrfs scrub catches the checksum error and verify script FAILS
    if common::oracle::gate() {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tools")
            .join("verify-btrfs.sh");
        let output = Command::new(&script).arg(&temp_img).output().expect("execute verify script");
        
        assert!(
            !output.status.success(),
            "Control failed: verify-btrfs.sh passed despite deliberate checksum corruption! (original csum: 0x{:08X})",
            original_csum
        );
        let combined_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined_output.contains("FAIL: scrub reported errors")
                || combined_output.contains("csum")
                || combined_output.contains("checksum")
                || combined_output.contains("Error summary"),
            "Expected scrub failure message in output, got:\n{}",
            combined_output
        );
        println!("✅ CONTROL CONFIRMED: verify-btrfs.sh correctly failed on corrupted checksums");
    }

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn test_mixed_4k_multi_item_csum_live_checksums_oracle() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount btrfs");

    // 5 MiB on mixed-4k.img (4096 node size) splits across 2 EXTENT_CSUM items in CSUM tree
    let size = 5 * 1024 * 1024;
    let mut test_data = vec![0u8; size];
    for (i, b) in test_data.iter_mut().enumerate() {
        *b = ((i * 31 + 47) & 0xFF) as u8;
    }

    let mut writer = fs.begin_file(size as u64).expect("begin_file");
    fs.write_chunk(&mut writer, &test_data[..2 * 1024 * 1024]).expect("chunk 1");
    fs.write_chunk(&mut writer, &test_data[2 * 1024 * 1024..]).expect("chunk 2");

    let ino = fs.finish_file(writer, "/", "mixed_5mb.bin").expect("finish_file");
    assert!(ino >= 256);

    fs.commit_active_batch().expect("commit");
    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(oracle_clean, "kernel oracle failed on mixed-4k multi-item csum write");
}
