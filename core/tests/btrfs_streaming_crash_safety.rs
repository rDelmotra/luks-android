//! Crash-consistency test for the STREAMING (unknown-size) write path:
//! `begin_file_streaming()` -> repeated `write_chunk()` -> `finish_file()`.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_streaming_crash_safety
//! ```
//!
//! # Why this is a different claim than `btrfs_crash_safety.rs`
//!
//! `btrfs_crash_safety.rs` proves `commit_transaction`'s write ordering is
//! crash-safe for `create_file_with_data`, a one-shot path: every byte is
//! buffered in memory, then one transaction writes new data blocks, new
//! metadata blocks, flushes, writes superblock mirrors, flushes again. Its
//! entire 17-`write_at` boundary map is derived against that exact sequence.
//!
//! The streaming path is structurally different. `write_chunk`
//! (`core/src/fs/btrfs/write/file.rs:153`) issues `device_mut().write_at()`
//! calls directly, immediately, as bytes arrive — *before* any transaction
//! exists and long before `finish_file` is ever called. Those data blocks are
//! allocated from free space but never linked into any tree until
//! `finish_file` (`file.rs:330`) does the metadata CoW and calls
//! `commit_transaction`. So a streaming write has two structurally distinct
//! places an interruption can land:
//!
//! 1. **Mid-stream**, inside the `write_chunk` loop, before `finish_file` is
//!    ever called. The data blocks written so far are real bytes on disk,
//!    allocated from what the *old* superblock still considers free — but
//!    nothing points to them. The claim: this is unreferenced garbage, exactly
//!    like `btrfs_crash_safety.rs`'s N=1 case, and the old filesystem is
//!    completely untouched.
//! 2. **Inside `finish_file`'s commit**, which — because streaming's data was
//!    already written directly by `write_chunk` — has an empty
//!    `txn.pending_data`. `commit_transaction`'s data-block step (`commit.rs`
//!    line ~28-33) is therefore a no-op for this path, and the only writes
//!    left in the commit are the metadata blocks (CoW’d directory entries,
//!    inode items, extent-data items, checksum-tree items) and the superblock
//!    mirrors. This is the same "metadata, flush, superblock, flush" shape
//!    `btrfs_crash_safety.rs` exercises, but with a different (measured, not
//!    assumed) block count, because streaming's metadata footprint differs
//!    from the one-shot path's.
//!
//! Both are exercised here, against a write-count boundary map derived fresh
//! for the exact streaming sequence this file uses — never against the
//! one-shot path's 17-write boundaries, which do not apply.
//!
//! # The oracle
//!
//! Ground truth is `tools/verify-btrfs.sh` (`btrfs check --readonly`, a real
//! kernel mount, `btrfs scrub`), gated by `common::oracle::gate()` exactly the
//! way every other write-support test gates it.
//!
//! # On duplication
//!
//! `FailAfterNWrites`, `run_verify_script`, the pre-existing-file assertions,
//! and the scrub-summary parser below are deliberately duplicated from
//! `btrfs_crash_safety.rs` rather than factored into a shared module — this
//! task is scoped to adding streaming coverage as a sibling file, not to
//! restructuring the existing, already-proven one-shot crash-safety suite.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::Btrfs;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Fixture plumbing — same convention as btrfs_crash_safety.rs.
// ---------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn copy_to_temp(src_name: &str, tag: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-streaming-crash-{src_name}-{tag}-{}-{}-{}",
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

fn run_verify_script(image_path: &Path) -> bool {
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

// ---------------------------------------------------------------------
// FailAfterNWrites — identical shim to btrfs_crash_safety.rs. See that
// file's copy for the full rationale; duplicated here rather than shared,
// per this file's module doc comment.
// ---------------------------------------------------------------------

struct FailAfterNWrites {
    inner: FileDevice,
    budget: AtomicUsize,
    attempted: AtomicUsize,
}

impl FailAfterNWrites {
    fn new(inner: FileDevice, budget: usize) -> Self {
        Self {
            inner,
            budget: AtomicUsize::new(budget),
            attempted: AtomicUsize::new(0),
        }
    }

    fn simulated_failure() -> LuksError {
        LuksError::Io {
            path: "simulated-power-loss".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "device vanished mid-streaming-write (simulated by FailAfterNWrites)",
            ),
        }
    }
}

impl ReadAt for FailAfterNWrites {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl WriteAt for FailAfterNWrites {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.attempted.fetch_add(1, Ordering::SeqCst);
        let prev = self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |b| {
                if b == 0 {
                    None
                } else {
                    Some(b - 1)
                }
            });
        if prev.is_err() {
            return Err(Self::simulated_failure());
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        if self.budget.load(Ordering::SeqCst) == 0 {
            return Err(Self::simulated_failure());
        }
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------
// The streaming sequence under test: fixed payload, fixed chunk plan.
//
// 262_144 bytes (256 KiB), split into 6 `write_chunk` calls whose sizes sum
// to exactly the payload length so the plan is a single clean pass with no
// wraparound. Every chunk size is a multiple of the 4096-byte sector size
// (65536, 32768, 16384, 98304, 8192, 40960 — each divisible by 4096), so
// nothing here depends on `write_chunk`'s unaligned-tail handling; that path
// already has dedicated non-crash coverage in `btrfs_streaming_unknown.rs`.
// 256 KiB is comfortably inside `plain.img`'s ~6 MiB of free DATA space
// (measured in `btrfs_streaming_chunk_alloc.rs`), so no mid-stream chunk
// allocation fires here either — this file's job is the write-ordering
// claim, not the allocator.
// ---------------------------------------------------------------------

const STREAM_FILE_NAME: &str = "streamcrash.bin";
const STREAM_CHUNK_SIZES: &[usize] = &[65536, 32768, 16384, 98304, 8192, 40960];
const STREAM_TOTAL_SIZE: usize = 262_144;

fn streaming_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(STREAM_TOTAL_SIZE);
    let mut seed: u32 = 0xC0FFEE42;
    for _ in 0..STREAM_TOTAL_SIZE {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        payload.push((seed >> 16) as u8);
    }
    payload
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------
// Write-count probe.
//
// Runs the exact streaming sequence above against a fresh device with an
// unlimited write budget, and reports two numbers:
//   - `after_chunks`: total `write_at` calls attempted once every
//     `write_chunk` call has returned (i.e. immediately before `finish_file`
//     is called at all).
//   - `after_finish`: total `write_at` calls attempted once `finish_file`
//     (and therefore `commit_transaction`) has fully completed.
//
// `after_finish - after_chunks` is entirely `commit_transaction`'s work for
// this path: metadata blocks, then 2 superblock mirrors (`plain.img` is 146
// MiB, so only the first two of the three `SUPER_OFFSETS` entries are within
// the image — see `btrfs_crash_safety.rs`'s own comment on this). Because
// streaming writes its data directly in `write_chunk`, `txn.pending_data` is
// empty by the time `commit_transaction` runs, so — unlike the one-shot
// path — there is no separate "data blocks" step inside the commit itself.
fn probe_streaming_write_counts(fixture_name: &str) -> (usize, usize) {
    let temp_img = copy_to_temp(fixture_name, "probe");
    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let counting = FailAfterNWrites::new(dev, usize::MAX);
    let mut fs_ = Btrfs::mount(counting).expect("mount writable btrfs");

    let payload = streaming_payload();
    let mut writer = fs_.begin_file_streaming().expect("begin streaming writer");
    let mut offset = 0;
    let mut i = 0;
    while offset < payload.len() {
        let chunk_size = STREAM_CHUNK_SIZES[i % STREAM_CHUNK_SIZES.len()];
        let end = (offset + chunk_size).min(payload.len());
        fs_.write_chunk(&mut writer, &payload[offset..end])
            .expect("uninterrupted write_chunk must succeed");
        offset = end;
        i += 1;
    }
    let after_chunks = fs_.device().attempted.load(Ordering::SeqCst);

    fs_.finish_file(writer, "/", STREAM_FILE_NAME)
        .expect("uninterrupted finish_file must succeed");
    fs_.commit_active_batch()
        .expect("uninterrupted commit must succeed");
    let after_finish = fs_.device().attempted.load(Ordering::SeqCst);

    drop(fs_);
    let _ = fs::remove_file(&temp_img);
    (after_chunks, after_finish)
}

// ---------------------------------------------------------------------
// Core harness.
// ---------------------------------------------------------------------

struct InterruptedStreamingRun {
    image_path: PathBuf,
    /// `true` only if every `write_chunk` call *and* `finish_file` returned
    /// `Ok`.
    commit_ok: bool,
    /// Did the interruption land inside the `write_chunk` loop, i.e. before
    /// `finish_file` was even called? Distinguishes "mid-stream, no
    /// transaction ever existed" from "inside finish_file's commit" for
    /// assertions that care.
    failed_mid_stream: bool,
}

/// Copy `fixture_name` to a scratch image, mount it writable behind a
/// [`FailAfterNWrites`] with the given `budget`, and run the fixed streaming
/// sequence (`STREAM_CHUNK_SIZES` over `streaming_payload()`) against it. The
/// scratch image is left in place for the caller to inspect; cleanup is the
/// caller's job.
fn run_interrupted_streaming(fixture_name: &str, budget: usize, tag: &str) -> InterruptedStreamingRun {
    let temp_img = copy_to_temp(fixture_name, tag);
    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let wrapped = FailAfterNWrites::new(dev, budget);
    let mut fs_ = Btrfs::mount(wrapped).expect("mount writable btrfs");

    let payload = streaming_payload();
    let mut writer = fs_
        .begin_file_streaming()
        .expect("begin_file_streaming issues no write_at calls, must always succeed");

    let mut offset = 0;
    let mut i = 0;
    let mut mid_stream_err: Option<LuksError> = None;
    while offset < payload.len() {
        let chunk_size = STREAM_CHUNK_SIZES[i % STREAM_CHUNK_SIZES.len()];
        let end = (offset + chunk_size).min(payload.len());
        match fs_.write_chunk(&mut writer, &payload[offset..end]) {
            Ok(()) => {
                offset = end;
                i += 1;
            }
            Err(e) => {
                mid_stream_err = Some(e);
                break;
            }
        }
    }

    let (commit_ok, failed_mid_stream) = if let Some(e) = mid_stream_err {
        match e {
            LuksError::Io { .. } => {}
            other => panic!(
                "expected simulated I/O failure mid-stream at budget={budget}, got {other:?}"
            ),
        }
        // Simulated crash: the writer is simply dropped, exactly as an
        // interrupted process would never reach `finish_file`.
        (false, true)
    } else {
        match fs_.finish_file(writer, "/", STREAM_FILE_NAME) {
            Ok(_) => match fs_.commit_active_batch() {
                Ok(_) => (true, false),
                Err(e) => {
                    match e {
                        LuksError::Io { .. } => {}
                        other => panic!(
                            "expected simulated I/O failure in commit at budget={budget}, got {other:?}"
                        ),
                    }
                    (false, false)
                }
            },
            Err(e) => {
                match e {
                    LuksError::Io { .. } => {}
                    other => panic!(
                        "expected simulated I/O failure in finish_file at budget={budget}, got {other:?}"
                    ),
                }
                (false, false)
            }
        }
    };

    drop(fs_);

    InterruptedStreamingRun {
        image_path: temp_img,
        commit_ok,
        failed_mid_stream,
    }
}

/// In-process half of the pre-existing-file check — same shape as
/// `btrfs_crash_safety.rs::assert_preexisting_readable`.
fn assert_preexisting_readable(image_path: &Path) {
    let dev_ro = FileDevice::open(image_path).expect("open ro after interruption");
    let fs_ro = Btrfs::mount(dev_ro).expect("filesystem must still mount after interruption");

    let entries = fs_ro.list_dir("/").expect("list root dir after interruption");
    assert!(
        entries.iter().any(|e| e.name == "hello.txt"),
        "pre-existing hello.txt vanished from root directory after interrupted streaming write"
    );
    assert!(
        entries.iter().any(|e| e.name == "docs"),
        "pre-existing docs/ vanished from root directory after interrupted streaming write"
    );

    let hello = fs_ro
        .read_file("/hello.txt")
        .expect("pre-existing hello.txt must still be readable after interrupted streaming write");
    assert!(
        !hello.is_empty(),
        "pre-existing hello.txt read back empty after interrupted streaming write"
    );

    drop(fs_ro);
}

/// Assertions common to every interrupted image *except* the torn-superblock
/// boundary — see `btrfs_crash_safety.rs::assert_preexisting_intact` for why
/// the torn-superblock case needs a looser (but still strict) oracle check.
fn assert_preexisting_intact(image_path: &Path) {
    assert_preexisting_readable(image_path);

    let oracle_clean = run_verify_script(image_path);
    assert!(
        oracle_clean,
        "kernel oracle reported an unclean filesystem for {}",
        image_path.display()
    );
}

/// The torn-superblock-mirror oracle check — identical strictness to
/// `btrfs_crash_safety.rs::assert_torn_superblock_mount_valid`: `btrfs check
/// --readonly` must be clean, the kernel must actually mount the image and
/// see the pre-existing files, and `btrfs scrub`'s only acceptable non-clean
/// outcome is a *corrected*, superblock-only mismatch (nothing uncorrectable,
/// nothing named besides "super").
fn assert_torn_superblock_mount_valid(image_path: &Path) {
    assert_preexisting_readable(image_path);

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");
    assert!(script.exists(), "verify-btrfs.sh missing");

    if !common::oracle::gate() {
        return;
    }

    let output = Command::new(&script)
        .arg(image_path)
        .output()
        .expect("run verify-btrfs.sh");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("no error found"),
        "btrfs check --readonly reported structural errors on a torn-superblock \
         image (this must always be clean, torn superblock or not):\n{stdout}"
    );

    assert!(
        stdout.contains("mounted read-only, root contains"),
        "verify-btrfs.sh's mount step did not run:\n{stdout}"
    );
    assert!(
        stdout.contains("hello.txt"),
        "kernel mount does not show pre-existing hello.txt:\n{stdout}"
    );

    let scrub_summary = parse_scrub_summary(&stdout);
    let scrub_clean = scrub_summary.as_ref().is_some_and(ScrubSummary::is_clean);
    let scrub_super_only_corrected = scrub_summary
        .as_ref()
        .is_some_and(ScrubSummary::is_superblock_only_corrected);
    assert!(
        scrub_clean || scrub_super_only_corrected,
        "scrub reported something other than a clean run or a corrected, \
         superblock-only mismatch — this indicates real data or metadata \
         corruption, not just a torn superblock mirror:\nparsed: {scrub_summary:?}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Parsed form of `btrfs scrub`'s "Error summary" block — identical parser to
/// `btrfs_crash_safety.rs`'s, duplicated per this file's module doc comment.
#[derive(Debug, Default, PartialEq, Eq)]
struct ScrubSummary {
    error_counts: std::collections::BTreeMap<String, u64>,
    uncorrectable: u64,
}

impl ScrubSummary {
    fn is_clean(&self) -> bool {
        self.error_counts.is_empty() && self.uncorrectable == 0
    }

    /// The *only* error type scrub named was the superblock ("super"), and
    /// nothing was left uncorrectable. Deliberately strict: a summary naming
    /// "super" alongside anything else (e.g. "verify", "csum") is rejected —
    /// see `btrfs_crash_safety.rs`'s `scrub_summary_parsing` tests for the
    /// control that proves this the hard way.
    fn is_superblock_only_corrected(&self) -> bool {
        self.uncorrectable == 0
            && self.error_counts.len() == 1
            && self.error_counts.contains_key("super")
    }
}

fn parse_scrub_summary(stdout: &str) -> Option<ScrubSummary> {
    let summary_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("Error summary:"))?;
    let after = summary_line
        .trim_start()
        .strip_prefix("Error summary:")?
        .trim();

    if after == "no errors found" {
        return Some(ScrubSummary::default());
    }

    let mut error_counts = std::collections::BTreeMap::new();
    for tok in after.split_whitespace() {
        let (name, count) = tok.split_once('=')?;
        error_counts.insert(name.to_string(), count.parse().ok()?);
    }

    let uncorrectable = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("Uncorrectable:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    Some(ScrubSummary {
        error_counts,
        uncorrectable,
    })
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

/// Sanity check on the write counts this whole file's boundaries are chosen
/// against. If the streaming writer's block layout ever changes for this
/// exact payload/chunk plan on `plain.img`, this fails first and obviously,
/// instead of the boundary tests below silently testing the wrong thing.
#[test]
fn probe_streaming_write_counts_are_stable() {
    let (after_chunks, after_finish) = probe_streaming_write_counts("plain.img");
    assert_eq!(
        after_chunks, 6,
        "write_at calls attempted across the 6 write_chunk() calls changed from 6 to \
         {after_chunks} — every N value in this file's other tests was chosen against \
         the old count and needs to be re-derived"
    );
    assert_eq!(
        after_finish, 24,
        "total write_at calls (write_chunk phase + finish_file's commit_transaction) \
         changed from 22 to {after_finish} — every N value in this file's other tests \
         was chosen against the old count and needs to be re-derived"
    );
}

/// N=0: the device fails before a single byte is written. Must be a pure
/// no-op — not even `begin_file_streaming` touches the device via `write_at`.
#[test]
fn interrupted_at_write_0_is_a_pure_noop() {
    let run = run_interrupted_streaming("plain.img", 0, "n0");
    assert!(!run.commit_ok, "commit must report failure when budget=0");
    assert!(run.failed_mid_stream, "budget=0 must fail inside write_chunk, not finish_file");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == STREAM_FILE_NAME),
        "new file must not exist when nothing was written"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// Mid-stream: interrupted partway through the `write_chunk` loop, well
/// before `finish_file` is ever called (budget is half of `after_chunks`,
/// derived fresh from the probe rather than hardcoded). The data blocks
/// written so far are real, allocated bytes with nothing pointing to them —
/// exactly the "unreferenced garbage" case `btrfs_crash_safety.rs` proves for
/// its single N=1 data write, but here spanning several already-flushed
/// `write_chunk` calls. The old filesystem must be completely untouched and
/// the new file must not exist (streaming has no fallback size to fall back
/// on — a partial stream is simply abandoned).
#[test]
fn interrupted_mid_stream_data_writes_leaves_old_fs_untouched() {
    let (after_chunks, _) = probe_streaming_write_counts("plain.img");
    let budget = after_chunks / 2;
    assert!(
        budget > 0 && budget < after_chunks,
        "mid-stream budget {budget} must be strictly between 0 and after_chunks \
         ({after_chunks}) for this to actually land mid-stream"
    );

    let run = run_interrupted_streaming("plain.img", budget, "midstream");
    assert!(!run.commit_ok, "commit must report failure when budget={budget}");
    assert!(
        run.failed_mid_stream,
        "budget={budget} (< after_chunks={after_chunks}) must fail inside the \
         write_chunk loop, before finish_file is ever called"
    );

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == STREAM_FILE_NAME),
        "new file must not exist when the stream was interrupted mid-write_chunk"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// The transition boundary: every `write_chunk` call succeeds in full
/// (budget == `after_chunks`), so the very first `write_at` inside
/// `finish_file`'s `commit_transaction` (the first metadata block) is the one
/// that gets denied. All the streamed data blocks are durably on disk, but
/// `finish_file` never got far enough to link any of it into a tree, so it
/// must be exactly as invisible as the mid-stream case.
#[test]
fn interrupted_at_transition_into_finish_file_commit() {
    let (after_chunks, _) = probe_streaming_write_counts("plain.img");

    let run = run_interrupted_streaming("plain.img", after_chunks, "transition");
    assert!(
        !run.commit_ok,
        "commit must report failure when budget={after_chunks} (exactly after_chunks)"
    );
    assert!(
        !run.failed_mid_stream,
        "budget={after_chunks} must let every write_chunk call succeed and fail \
         inside finish_file's commit instead"
    );

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == STREAM_FILE_NAME),
        "new file must not exist when finish_file's commit failed on its first write"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// Between the metadata writes and the superblock writes: every data block
/// (already written during streaming) and every new metadata block from
/// `finish_file`'s CoW is fully written and flushed (barrier 1 succeeds —
/// the budget is not exhausted at that point), but the first superblock
/// mirror write is denied. The old superblock's generation was never bumped,
/// so the entire, fully-written new tree is still just unreferenced garbage —
/// same shape as `btrfs_crash_safety.rs`'s N=15 case, re-derived for this
/// path's own (different) metadata footprint.
#[test]
fn interrupted_between_metadata_and_superblock_writes() {
    let (_, after_finish) = probe_streaming_write_counts("plain.img");
    let budget = after_finish - 2; // both superblock mirror writes still to come

    let run = run_interrupted_streaming("plain.img", budget, "premeta");
    assert!(!run.commit_ok, "commit must report failure when budget={budget}");
    assert!(!run.failed_mid_stream, "this boundary must land inside finish_file's commit");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == STREAM_FILE_NAME),
        "new file must not exist when interrupted before any superblock mirror write"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// Mid-superblock-mirror (the torn-superblock case): superblock mirror 0 is
/// written with the bumped generation; mirror 1 is not and still holds the
/// old generation. `Superblock::find` picks the highest-generation *valid*
/// mirror, so mount should pick mirror 0 and come up with the new,
/// fully-streamed file present — a torn mirror pair, but self-consistent,
/// because everything mirror 0 points to was already fully and durably
/// written before barrier 1 succeeded. Same shape as `btrfs_crash_safety.rs`'s
/// N=16 case, re-derived for this path's write count.
#[test]
fn interrupted_mid_superblock_mirror_picks_valid_generation() {
    let (_, after_finish) = probe_streaming_write_counts("plain.img");
    let budget = after_finish - 1; // mirror 0 written, mirror 1 denied

    let run = run_interrupted_streaming("plain.img", budget, "torn");
    assert!(!run.commit_ok, "commit must report failure when budget={budget}");
    assert!(!run.failed_mid_stream, "this boundary must land inside finish_file's commit");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let gen = fs_ro.superblock().generation;
    let entries = fs_ro.list_dir("/").unwrap();
    let new_file_present = entries.iter().any(|e| e.name == STREAM_FILE_NAME);
    println!("torn superblock: mounted at generation {gen}, new file present = {new_file_present}");
    assert!(
        new_file_present,
        "expected mount to pick the rewritten, higher-generation superblock mirror \
         (mirror 0) and see the new streamed file; instead it did not"
    );
    drop(fs_ro);

    assert_torn_superblock_mount_valid(&run.image_path);
    cleanup(&run.image_path);
}

/// Positive control: an uninterrupted streaming write (budget far above the
/// measured write count) succeeds, reads back byte-identical to the payload,
/// and the oracle is clean. Run through the identical `FailAfterNWrites`
/// harness as every other test here — if this one somehow failed, that would
/// say more about the harness than the filesystem.
#[test]
fn uninterrupted_streaming_commit_succeeds_and_is_oracle_clean() {
    let run = run_interrupted_streaming("plain.img", usize::MAX, "control");
    assert!(run.commit_ok, "uninterrupted streaming commit must succeed");
    assert!(!run.failed_mid_stream);

    let payload = streaming_payload();
    let expected_sha = sha256_hex(&payload);

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(entries.iter().any(|e| e.name == STREAM_FILE_NAME));
    let readback = fs_ro
        .read_file(&format!("/{STREAM_FILE_NAME}"))
        .expect("read streamed file");
    assert_eq!(readback.len(), payload.len());
    assert_eq!(sha256_hex(&readback), expected_sha, "readback must be byte-identical to the streamed payload");
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}
