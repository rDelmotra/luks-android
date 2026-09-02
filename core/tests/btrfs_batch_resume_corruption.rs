//! Regression test for the 2026-09-01 field corruption: a **transient** device
//! write failure that the import loop swallows, after which the batch keeps
//! going and a later commit publishes a `BLOCK_GROUP_ITEM.used` that the
//! extent tree does not back.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support --test btrfs_batch_resume_corruption
//! ```
//!
//! # Why the existing crash-safety suite cannot express this
//!
//! `btrfs_crash_safety.rs` and `btrfs_streaming_crash_safety.rs` both drive
//! `FailAfterNWrites`, whose budget is **monotonic**: once it hits zero every
//! subsequent `write_at` *and* `flush` fails forever
//! (`btrfs_streaming_crash_safety.rs:188-211`). Every test built on it stops at
//! the interruption and then inspects the image. That is the right model for
//! power loss, and it proves what those files claim.
//!
//! It is the wrong model for what actually happened in the field. The reported
//! failure was `ETIMEDOUT` (errno 110) on a 1 MiB bulk transfer — the drive
//! stopped answering, the transfer was abandoned, and then the drive answered
//! again. The bug does not live at the interruption. It lives in what the
//! writer does *after* one, which a device that never heals cannot reach.
//!
//! # The mechanism under test
//!
//! `Batch::commit_and_rearm` (`write/batch.rs:628-631`) `mem::take`s
//! `pending_blocks`, `blocks_to_add`, `blocks_to_remove` and
//! `data_extents_to_add` **before** the fallible `converge_and_finalize` on the
//! next line. On `Err` none of it is restored, so the EXTENT_ITEMs that would
//! record this batch's allocations are gone — while `self.allocator` keeps
//! every `block_group.used` bump it made at allocation time
//! (`write/alloc.rs:297,409,466,529`).
//!
//! `finish_file`'s error arm (`write/file.rs:363-366`) then discards both the
//! convergence error and the device error (`if let Ok(txn) = … { let _ = … }`)
//! and puts the batch back for reuse, mirroring `TreeImporter.kt:92,227`'s
//! `catch (ignored: Throwable) {}`. A later commit succeeds and writes
//! `BLOCK_GROUP_ITEM.used` straight from that allocator
//! (`write/extent_tree.rs:996-1027`).
//!
//! # The assertion
//!
//! Exactly the condition the driver itself refuses to mount on:
//! `FreeSpaceMap::from_extent_tree` (`write/alloc.rs:92-97`) compares the sum
//! of a block group's extent items against its `used` field and returns
//! `CorruptFs("extent tree allocations do not match block group used
//! counter")`. That is the error the drive reported. This test reads the two
//! numbers directly rather than going through that constructor, so a failure
//! reports *which* group and *by how much* instead of a bare string.
//!
//! Self-graded on purpose: the detector here **is** the error observed in the
//! field, so reproducing it needs no kernel. Confirming a *fix* does — that is
//! `tools/verify-btrfs.sh` via `common::oracle::gate()`, and it is a separate
//! claim this file does not make.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;

// ---------------------------------------------------------------------
// Fixture plumbing — same convention as the rest of the btrfs write suite:
// never mutate a shared fixture, always work on a uniquely named copy.
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
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = std::env::temp_dir().join(format!(
        "btrfs-batch-resume-{src_name}-{tag}-{}-{}",
        std::process::id(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

// ---------------------------------------------------------------------
// FailInWindow: fails every device operation whose write index falls in
// `[from, until)`, then **heals** and serves everything after it normally.
//
// The healing is the entire point, and the one thing `FailAfterNWrites`
// cannot do. A window of width 1 is the minimal faithful model of the
// reported `ETIMEDOUT`: one transfer refused, nothing on the wire
// (`usbfs/src/lib.rs:576` reports `prefix == 0`), drive fine afterwards.
// ---------------------------------------------------------------------

/// Counters live behind an `Arc` so the caller can still read them after the
/// device has been moved into `Btrfs` — no raw pointer into a value that
/// `Btrfs`'s drop is about to free.
#[derive(Default)]
struct Counters {
    attempted: AtomicUsize,
    refused: AtomicUsize,
    reads_attempted: AtomicUsize,
    reads_refused: AtomicUsize,
}

/// Which direction the simulated outage refuses.
///
/// Both are needed, and they are not interchangeable. A drive that has stopped
/// answering refuses reads too — and the difference decides *which* function
/// fails. `converge_and_finalize`, the fallible call `commit_and_rearm`
/// (`write/batch.rs:633`) makes after it has already `mem::take`n the batch's
/// pending state, does no device writes at all: it CoWs in memory and **reads**
/// existing tree blocks. A write-only fault therefore can never make it fail,
/// and can never reach the un-restored `mem::take`. Only a read fault can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Writes,
    Reads,
}

struct FailInWindow {
    inner: FileDevice,
    counters: Arc<Counters>,
    direction: Direction,
    from: usize,
    until: usize,
}

impl FailInWindow {
    fn new(
        inner: FileDevice,
        direction: Direction,
        from: usize,
        until: usize,
    ) -> (Self, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        (
            Self {
                inner,
                counters: Arc::clone(&counters),
                direction,
                from,
                until,
            },
            counters,
        )
    }

    fn simulated_timeout() -> LuksError {
        LuksError::Io {
            path: "simulated-etimedout".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "bulk transfer timed out, nothing on the wire (simulated by FailInWindow)",
            ),
        }
    }

    fn in_window(&self, idx: usize) -> bool {
        idx >= self.from && idx < self.until
    }
}

impl ReadAt for FailInWindow {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let idx = self.counters.reads_attempted.fetch_add(1, Ordering::SeqCst);
        if self.direction == Direction::Reads && self.in_window(idx) {
            self.counters.reads_refused.fetch_add(1, Ordering::SeqCst);
            return Err(Self::simulated_timeout());
        }
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl WriteAt for FailInWindow {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let idx = self.counters.attempted.fetch_add(1, Ordering::SeqCst);
        if self.direction == Direction::Writes && self.in_window(idx) {
            self.counters.refused.fetch_add(1, Ordering::SeqCst);
            return Err(Self::simulated_timeout());
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        // A drive that is refusing writes refuses SYNCHRONIZE CACHE too — and
        // `synchronize_cache` (`usb/scsi.rs:888`) only swallows an *invalid
        // opcode* sense, so a timed-out flush is a hard error, not a no-op.
        if self.direction == Direction::Writes
            && self.in_window(self.counters.attempted.load(Ordering::SeqCst))
        {
            self.counters.refused.fetch_add(1, Ordering::SeqCst);
            return Err(Self::simulated_timeout());
        }
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------
// The import loop. Deliberately shaped like `TreeImporter.kt`, swallows and
// all — a repro that handled errors correctly would not be a repro.
// ---------------------------------------------------------------------

/// Must exceed `Batch::should_commit`'s 16-file threshold
/// (`write/batch.rs:152`) **more than once**. The bug needs three things in
/// sequence: a `commit_and_rearm` that fails, more files accepted afterwards,
/// and a later commit that succeeds and publishes the counter. A run that
/// commits only once — which is every existing batch test, and was this file's
/// first draft at 8 files — cannot produce it.
///
/// 40 files gives mid-loop commits after file 16 and file 32, plus the final
/// `commit_active_batch`.
const NUM_FILES: usize = 40;
const CHUNK: usize = 16_384;

/// Payload for file `i`: distinct content, four different sizes so commits do
/// not all land at one stride. Capped so 40 files stay well inside
/// `plain.img`'s free DATA space (~6 MiB, measured in
/// `btrfs_streaming_chunk_alloc.rs`) — a `FilesystemFull` would be a different
/// test.
fn payload_for(i: usize) -> Vec<u8> {
    let len = 24_576 + (i % 4) * 8_192;
    (0..len).map(|b| (b as u8) ^ (i as u8).wrapping_mul(31)).collect()
}

struct ImportOutcome {
    writes_attempted: usize,
    writes_refused: usize,
    reads_attempted: usize,
    reads_refused: usize,
    files_reported_written: usize,
    /// `false` when the outage landed before the filesystem was even mounted.
    /// Not a result — nothing was exercised — so callers must skip it rather
    /// than count it as a pass.
    mounted: bool,
}

impl ImportOutcome {
    fn refused(&self) -> usize {
        self.writes_refused + self.reads_refused
    }
}

/// Drive `NUM_FILES` streaming writes through `fs`, swallowing every error the
/// way `TreeImporter` does. Returns what the device saw.
fn run_import(img: &Path, direction: Direction, from: usize, until: usize) -> ImportOutcome {
    let file_len = fs::metadata(img).expect("stat image").len();
    let dev = FileDevice::open_writable(img, file_len).expect("open writable");
    let (faulty, counters) = FailInWindow::new(dev, direction, from, until);

    let mut btrfs = match Btrfs::mount(faulty) {
        Ok(f) => f,
        // A read fault inside `Btrfs::mount` itself: the outage started before
        // the import did. Nothing under test ran.
        Err(_) => {
            return ImportOutcome {
                writes_attempted: counters.attempted.load(Ordering::SeqCst),
                writes_refused: counters.refused.load(Ordering::SeqCst),
                reads_attempted: counters.reads_attempted.load(Ordering::SeqCst),
                reads_refused: counters.reads_refused.load(Ordering::SeqCst),
                files_reported_written: 0,
                mounted: false,
            }
        }
    };

    let mut files_reported_written = 0usize;

    for i in 0..NUM_FILES {
        let name = format!("resume_{i:02}.dat");
        let payload = payload_for(i);

        let mut writer = match btrfs.begin_file_streaming() {
            Ok(w) => w,
            // TreeImporter.kt:113 — logged, skipped, loop continues.
            Err(_) => continue,
        };

        let mut torn = false;
        for chunk in payload.chunks(CHUNK) {
            if btrfs.write_chunk(&mut writer, chunk).is_err() {
                torn = true;
                break;
            }
        }

        if torn {
            let _ = btrfs.abandon_file(writer);
            continue;
        }

        // `write/file.rs:363-366` — the swallow under test. TreeImporter's
        // per-file catch does the same thing one layer up.
        if btrfs.finish_file(writer, "/", &name).is_ok() {
            files_reported_written += 1;
        }
    }

    // TreeImporter.kt:227 — `try { volume.commitActiveBatch() } catch (ignored: Throwable) {}`
    let _ = btrfs.commit_active_batch();

    drop(btrfs);

    ImportOutcome {
        writes_attempted: counters.attempted.load(Ordering::SeqCst),
        writes_refused: counters.refused.load(Ordering::SeqCst),
        reads_attempted: counters.reads_attempted.load(Ordering::SeqCst),
        reads_refused: counters.reads_refused.load(Ordering::SeqCst),
        files_reported_written,
        mounted: true,
    }
}

/// A run with no fault injected at all.
fn run_clean(img: &Path) -> ImportOutcome {
    run_import(img, Direction::Writes, usize::MAX, usize::MAX)
}

// ---------------------------------------------------------------------
// The check: `BLOCK_GROUP_ITEM.used` against the extent items that back it.
// This is `write/alloc.rs:92-97`'s comparison, reported per group.
// ---------------------------------------------------------------------

#[derive(Debug)]
struct Mismatch {
    bg_start: u64,
    used: u64,
    summed: u64,
}

#[derive(Debug)]
enum PostState {
    /// The image no longer mounts at all — a strictly worse outcome than a
    /// counter mismatch, and never acceptable.
    Unmountable(String),
    /// Mounted, and these groups disagree with their extent items.
    Mounted(Vec<Mismatch>),
}

fn inspect(img: &Path) -> PostState {
    let dev = match FileDevice::open(img) {
        Ok(d) => d,
        Err(e) => return PostState::Unmountable(format!("open: {e:?}")),
    };
    let btrfs = match Btrfs::mount(dev) {
        Ok(f) => f,
        Err(e) => return PostState::Unmountable(format!("mount: {e:?}")),
    };
    let et = match ExtentTree::read(&btrfs) {
        Ok(t) => t,
        Err(e) => return PostState::Unmountable(format!("extent tree read: {e:?}")),
    };

    let mut out = Vec::new();
    for bg in &et.block_groups {
        let end = bg.start + bg.length;
        let summed: u64 = et
            .extents
            .iter()
            .filter(|e| e.bytenr >= bg.start && e.bytenr < end)
            .map(|e| e.length)
            .sum();
        if summed != bg.used {
            out.push(Mismatch {
                bg_start: bg.start,
                used: bg.used,
                summed,
            });
        }
    }
    PostState::Mounted(out)
}

fn cleanup(p: &Path) {
    let _ = fs::remove_file(p);
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------


/// Vacuity control. Without this, a green scan below would be indistinguishable
/// from "the import loop never ran".
///
/// Establishes what every scan depends on: the loop actually writes, it
/// actually reads, it reports every file written, and with no fault injected
/// the resulting image has `used == sum(extents)` in every block group.
#[test]
fn control_clean_import_leaves_used_matching_the_extent_items() {
    let img = copy_to_temp("plain.img", "control");

    let outcome = run_clean(&img);

    assert!(outcome.mounted, "control must mount");
    assert!(
        outcome.writes_attempted > 0,
        "control import issued zero write_at calls — the loop did not run"
    );
    assert!(
        outcome.reads_attempted > 0,
        "control import issued zero read_at calls — the read scan would be vacuous"
    );
    assert_eq!(
        outcome.refused(),
        0,
        "control must refuse nothing; refused {}",
        outcome.refused()
    );
    assert_eq!(
        outcome.files_reported_written, NUM_FILES,
        "control import must report all {NUM_FILES} files written, got {}",
        outcome.files_reported_written
    );

    match inspect(&img) {
        PostState::Unmountable(why) => {
            cleanup(&img);
            panic!("clean import produced an unmountable image: {why}");
        }
        PostState::Mounted(m) => {
            assert!(
                m.is_empty(),
                "clean import already disagrees with its own extent tree \
                 (a bug in the control, not the scan): {m:?}"
            );
        }
    }

    cleanup(&img);
}

/// Publishes the operation counts the scans iterate over, so a change in the
/// import path shows up as a failure here rather than as silently shrunken
/// coverage.
#[test]
fn probe_reports_stable_operation_counts() {
    let img = copy_to_temp("plain.img", "probe");
    let outcome = run_clean(&img);
    cleanup(&img);

    assert!(
        outcome.writes_attempted >= 16,
        "expected a non-trivial write count from {NUM_FILES} streamed files, got {}",
        outcome.writes_attempted
    );
    eprintln!(
        "clean import: {} write_at, {} read_at, {} files",
        outcome.writes_attempted, outcome.reads_attempted, outcome.files_reported_written
    );
}

/// Shared scan driver: refuse exactly one operation, let the device heal, let
/// the import carry on, then ask whether the filesystem still agrees with
/// itself.
///
/// Returns `(damaged, injected)`. `injected` counts only runs where the fault
/// actually fired *and* the filesystem mounted — a run that took a shorter path
/// and never reached index `idx` tested nothing and must not be counted as a
/// pass.
fn scan(direction: Direction, total: usize, tag: &str) -> (Vec<(usize, PostState)>, usize) {
    let mut damaged = Vec::new();
    let mut injected = 0usize;

    for idx in 0..total {
        let img = copy_to_temp("plain.img", &format!("{tag}-{idx}"));
        let outcome = run_import(&img, direction, idx, idx + 1);

        if !outcome.mounted || outcome.refused() == 0 {
            cleanup(&img);
            continue;
        }
        injected += 1;

        match inspect(&img) {
            PostState::Mounted(m) if m.is_empty() => {}
            other => damaged.push((idx, other)),
        }
        cleanup(&img);
    }

    (damaged, injected)
}

fn assert_scan_clean(direction: Direction, damaged: Vec<(usize, PostState)>, injected: usize) {
    assert!(
        injected > 0,
        "{direction:?} scan was vacuous: no run actually refused an operation"
    );
    assert!(
        damaged.is_empty(),
        "{} of {injected} injected single-operation {direction:?} failures left the \
         filesystem inconsistent with itself.\n\
         Each entry is (operation index refused, resulting state). A `used` larger \
         than the summed extents is the exact condition `FreeSpaceMap::from_extent_tree` \
         (core/src/fs/btrfs/write/alloc.rs:92) refuses to mount on — the error the \
         drive reported.\n{damaged:#?}",
        damaged.len()
    );
}

/// A transient failure may legitimately cost the file being written. It may not
/// cost the consistency of the filesystem, and it may never leave a `used`
/// counter the extent tree cannot account for.
#[test]
fn a_healed_write_failure_never_leaves_used_disagreeing_with_the_extent_tree() {
    let probe = copy_to_temp("plain.img", "wscan-probe");
    let total = run_clean(&probe).writes_attempted;
    cleanup(&probe);
    assert!(total > 0, "nothing to scan: clean import issued no writes");

    let (damaged, injected) = scan(Direction::Writes, total, "wscan");
    eprintln!("write scan: {injected} of {total} indices injected, {} damaged", damaged.len());
    assert_scan_clean(Direction::Writes, damaged, injected);
}

/// The read direction, which is the one that can actually reach the suspected
/// mechanism.
///
/// `commit_and_rearm` (`write/batch.rs:628-633`) `mem::take`s `pending_blocks`,
/// `blocks_to_add`, `blocks_to_remove` and `data_extents_to_add` before calling
/// `converge_and_finalize`, and restores none of it on `Err`. But
/// `converge_and_finalize` issues **no device writes** — it CoWs in memory and
/// reads existing tree blocks — so no write fault can make it fail. Only a read
/// fault can, which is why the write scan above is not sufficient evidence and
/// this test exists alongside it rather than instead of it.
#[test]
fn a_healed_read_failure_never_leaves_used_disagreeing_with_the_extent_tree() {
    let probe = copy_to_temp("plain.img", "rscan-probe");
    let total = run_clean(&probe).reads_attempted;
    cleanup(&probe);
    assert!(total > 0, "nothing to scan: clean import issued no reads");

    let (damaged, injected) = scan(Direction::Reads, total, "rscan");
    eprintln!("read scan: {injected} of {total} indices injected, {} damaged", damaged.len());
    assert_scan_clean(Direction::Reads, damaged, injected);
}
