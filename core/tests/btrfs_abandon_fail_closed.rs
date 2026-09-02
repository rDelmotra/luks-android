//! Stage A3 Integration Tests: Btrfs fail-closed behavior on abandon_file
//! and finish_file error rollback.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::Btrfs;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(src_name: &str, tag: &str) -> PathBuf {
    let src = fixture(src_name);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = std::env::temp_dir().join(format!(
        "btrfs-abandon-fail-closed-{src_name}-{tag}-{}-{}",
        std::process::id(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_btrfs(img_path: &Path) -> bool {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");
    assert!(script.exists(), "verify-btrfs.sh must exist at {:?}", script);

    if !common::oracle::gate() {
        return true;
    }

    let output = Command::new("bash")
        .arg(&script)
        .arg(img_path)
        .output()
        .expect("run verify-btrfs.sh");
    output.status.success()
}

struct FailNextWrite {
    inner: FileDevice,
    fail_writes: Arc<AtomicBool>,
}

impl FailNextWrite {
    fn new(inner: FileDevice) -> (Self, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                fail_writes: Arc::clone(&flag),
            },
            flag,
        )
    }
}

impl ReadAt for FailNextWrite {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl WriteAt for FailNextWrite {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(LuksError::UsbTransfer("simulated transport failure on write".to_string()));
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(LuksError::UsbTransfer("simulated transport failure on flush".to_string()));
        }
        self.inner.flush()
    }
}

#[test]
fn abandon_file_transport_failure_during_commit_discards_batch_and_returns_error() {
    let img = copy_to_temp("plain.img", "abandon-err");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let (faulty, fail_flag) = FailNextWrite::new(dev);
    let mut fs = Btrfs::mount(faulty).expect("mount writable");

    // 1. Write a file into batch (uncommitted)
    let payload = b"uncommitted good file content";
    let mut writer1 = fs.begin_file(payload.len() as u64).expect("begin 1");
    fs.write_chunk(&mut writer1, payload).expect("write 1");
    fs.finish_file(writer1, "/", "saved.dat").expect("finish 1");

    // 2. Open a second writer
    let mut writer2 = fs.begin_file_streaming().expect("begin 2");
    fs.write_chunk(&mut writer2, b"partial bytes").expect("write 2");

    // 3. Inject transport failure right before abandon_file commits preceding files
    fail_flag.store(true, Ordering::SeqCst);

    let err = fs.abandon_file(writer2).unwrap_err();
    match err {
        LuksError::UsbTransfer(msg) => {
            assert!(msg.contains("simulated transport failure"));
        }
        other => panic!("expected UsbTransfer error, got: {:?}", other),
    }

    // Active batch was discarded on commit failure, so has_open_writer is false and
    // no active batch remains.
    fail_flag.store(false, Ordering::SeqCst);
    assert!(!fs.discard_active_batch(), "batch should already have been discarded");

    let _ = fs::remove_file(&img);
}

#[test]
fn finish_file_rollback_transport_failure_discards_batch_and_returns_error() {
    let img = copy_to_temp("plain.img", "finish-rollback-err");
    let file_len = fs::metadata(&img).unwrap().len();

    let dev = FileDevice::open_writable(&img, file_len).expect("open writable");
    let (faulty, fail_flag) = FailNextWrite::new(dev);
    let mut fs = Btrfs::mount(faulty).expect("mount writable");

    // 1. Write a file into batch
    let payload = b"first good file";
    let mut writer1 = fs.begin_file(payload.len() as u64).expect("begin 1");
    fs.write_chunk(&mut writer1, payload).expect("write 1");
    fs.finish_file(writer1, "/", "file1.dat").expect("finish 1");

    // 2. Start a second file that collides
    let mut writer2 = fs.begin_file(payload.len() as u64).expect("begin 2");
    fs.write_chunk(&mut writer2, payload).expect("write 2");

    // 3. Enable write failure so the commit of file1 during file2's collision rollback fails
    fail_flag.store(true, Ordering::SeqCst);

    let err = fs.finish_file(writer2, "/", "file1.dat").unwrap_err();
    match err {
        LuksError::UsbTransfer(msg) => {
            assert!(msg.contains("simulated transport failure"));
        }
        other => panic!("expected UsbTransfer error, got: {:?}", other),
    }

    // Active batch was discarded on commit failure
    fail_flag.store(false, Ordering::SeqCst);
    assert!(!fs.discard_active_batch(), "batch should already have been discarded");

    let _ = fs::remove_file(&img);
}
