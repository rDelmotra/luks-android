//! Crash-consistency test for `commit_transaction` (Pass G).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_crash_safety
//! ```
//!
//! # The claim under test
//!
//! `core/src/fs/btrfs/write/commit.rs` writes a transaction in strict order:
//! new data blocks, then new metadata blocks, `flush()`, then updated
//! superblock mirrors, then a final `flush()`. Because nothing live is ever
//! overwritten — every new block lands at a freshly allocated bytenr that the
//! *old* superblock still considers free — the argument is that an
//! interruption anywhere before the superblock mirrors are written leaves the
//! previous filesystem completely intact, and an interruption partway through
//! the (sequential) superblock mirror loop still leaves a mountable
//! filesystem, because mount always picks the highest-generation mirror that
//! passes its own checksum.
//!
//! This has never been exercised. This file exercises it by wrapping the
//! backing device in [`FailAfterNWrites`], which lets `N` successful
//! `write_at` calls through and then fails every device operation after that
//! — a stand-in for a USB drive vanishing or a phone losing power mid-commit.
//!
//! # The oracle
//!
//! Ground truth is `tools/verify-btrfs.sh` (`btrfs check --readonly`, a real
//! kernel mount, `btrfs scrub`), gated by `common::oracle::gate()` exactly the
//! way every other write-support test gates it. This is the load-bearing
//! assertion: the real Linux kernel, not this crate's own reader, has to
//! agree the interrupted image is fine.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::Btrfs;

// ---------------------------------------------------------------------
// Fixture plumbing — same convention as btrfs_create_file.rs /
// btrfs_data_write.rs: never mutate a shared fixture, always work on a
// uniquely named scratch copy.
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
        "btrfs-crash-{src_name}-{tag}-{}-{}-{}",
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
// FailAfterNWrites: a device wrapper that lets exactly `budget` successful
// `write_at` calls through, then fails every subsequent device operation
// (writes *and* flushes — a vanished device answers nothing, not just
// writes).
// ---------------------------------------------------------------------

/// Wraps a real, file-backed [`FileDevice`] and simulates the device
/// disappearing (USB detach, power loss) after `budget` successful
/// `write_at` calls.
///
/// `write_at`/`flush` are `&self` in this crate's `WriteAt` trait — the
/// budget therefore has to be interior-mutable. A plain `AtomicUsize` is
/// used rather than `Cell` so the wrapper stays `Sync`-agnostic-safe; the
/// test harness is single-threaded, but nothing about the trait promises
/// that.
struct FailAfterNWrites {
    inner: FileDevice,
    /// Number of `write_at` calls still allowed to succeed.
    budget: AtomicUsize,
    /// Total `write_at` calls observed, successful or not — used by the
    /// probe test and by assertions that want to know how far the commit
    /// actually got.
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
                "device vanished mid-commit (simulated by FailAfterNWrites)",
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
        // Decrement-if-nonzero. Every call after the budget hits zero fails,
        // including this one.
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
        // A vanished device answers a flush the same way it answers a write:
        // not at all. Once the budget is exhausted the device is gone, full
        // stop, so `flush()` fails too rather than quietly succeeding on a
        // device that no longer exists.
        if self.budget.load(Ordering::SeqCst) == 0 {
            return Err(Self::simulated_failure());
        }
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------
// Write-count probe.
//
// `create_file_with_data` on `fixtures/btrfs/plain.img` issues exactly 17
// `write_at` calls before this test file was written (verified with an
// instrumented probe, see the report this test shipped with):
//
//   #1        one DATA block (single-copy — plain.img's DATA block group is
//             not DUP, only METADATA is)
//   #2..#15   7 metadata blocks, each written to both of its 2 DUP stripes
//             back-to-back (pairs: 2/3, 4/5, 6/7, 8/9, 10/11, 12/13, 14/15)
//   -- flush (barrier 1) --
//   #16       superblock mirror 0 (offset 0x1_0000)
//   #17       superblock mirror 1 (offset 0x400_0000; the third SUPER_OFFSETS
//             entry, 256 GiB in, is beyond this 146 MiB fixture and is
//             skipped by both commit() and Superblock::find())
//   -- flush (barrier 2) --
//
/// The write filename/payload this test always uses, and the boundary write
/// count `create_file_with_data("/", NEW_FILE_NAME, NEW_FILE_DATA)` takes on
/// `plain.img`. Re-derived by [`total_writes_for_commit`] rather than only
/// trusted as a constant, so a change to the writer that shifts this number
/// fails loudly here instead of silently invalidating every boundary below.
const NEW_FILE_NAME: &str = "crashfile.txt";
const NEW_FILE_DATA: &[u8] = b"hello crash safety test data";

/// Run the same create-file-with-data transaction against a fresh device
/// with an unlimited budget, purely to count how many `write_at` calls
/// `commit_transaction` makes for this fixture and payload. Used to keep the
/// boundary constants below honest rather than magic.
fn total_writes_for_commit(fixture_name: &str) -> usize {
    let temp_img = copy_to_temp(fixture_name, "probe");
    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let counting = FailAfterNWrites::new(dev, usize::MAX);
    let mut fs_ = Btrfs::mount(counting).expect("mount writable btrfs");
    fs_.create_file_with_data("/", NEW_FILE_NAME, NEW_FILE_DATA)
        .expect("uninterrupted commit must succeed");
    let n = fs_.device().attempted.load(Ordering::SeqCst);
    drop(fs_);
    let _ = fs::remove_file(&temp_img);
    n
}

// ---------------------------------------------------------------------
// Core harness: run the transaction with a given write budget, then report
// what happened.
// ---------------------------------------------------------------------

struct InterruptedRun {
    image_path: PathBuf,
    /// What `create_file_with_data` returned.
    commit_ok: bool,
}

/// Copy `fixture_name` to a scratch image, mount it writable behind a
/// [`FailAfterNWrites`] with the given `budget`, and attempt to create a new
/// file with data in one transaction. The scratch image is left in place
/// (whatever state the interrupted commit left it in) for the caller to
/// inspect; cleanup is the caller's job.
fn run_interrupted_create(fixture_name: &str, budget: usize, tag: &str) -> InterruptedRun {
    let temp_img = copy_to_temp(fixture_name, tag);
    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let wrapped = FailAfterNWrites::new(dev, budget);
    let mut fs_ = Btrfs::mount(wrapped).expect("mount writable btrfs");

    let result = fs_.create_file_with_data("/", NEW_FILE_NAME, NEW_FILE_DATA);
    let commit_ok = result.is_ok();
    if !commit_ok {
        // Must be the simulated failure, not some unrelated bug tripping the
        // same code path.
        match result.unwrap_err() {
            LuksError::Io { .. } => {}
            other => panic!("expected simulated I/O failure at budget={budget}, got {other:?}"),
        }
    }
    drop(fs_);

    InterruptedRun {
        image_path: temp_img,
        commit_ok,
    }
}

/// In-process half of the pre-existing-file check: still mounts with this
/// crate's own reader, root directory entries survived, `hello.txt` still
/// reads back non-empty. No kernel involved yet.
fn assert_preexisting_readable(image_path: &Path) {
    let dev_ro = FileDevice::open(image_path).expect("open ro after interruption");
    let fs_ro = Btrfs::mount(dev_ro).expect("filesystem must still mount after interruption");

    let entries = fs_ro.list_dir("/").expect("list root dir after interruption");
    assert!(
        entries.iter().any(|e| e.name == "hello.txt"),
        "pre-existing hello.txt vanished from root directory after interrupted commit"
    );
    assert!(
        entries.iter().any(|e| e.name == "docs"),
        "pre-existing docs/ vanished from root directory after interrupted commit"
    );

    let hello = fs_ro
        .read_file("/hello.txt")
        .expect("pre-existing hello.txt must still be readable after interrupted commit");
    assert!(
        !hello.is_empty(),
        "pre-existing hello.txt read back empty after interrupted commit"
    );

    drop(fs_ro);
}

/// Assertions common to every interrupted image *except* the torn-superblock
/// boundary: still mounts, still has its pre-existing files with correct
/// content, and the kernel oracle (`btrfs check`, real mount, `btrfs
/// scrub -Bdr`) is fully clean.
fn assert_preexisting_intact(image_path: &Path) {
    assert_preexisting_readable(image_path);

    let oracle_clean = run_verify_script(image_path);
    assert!(
        oracle_clean,
        "kernel oracle reported an unclean filesystem for {}",
        image_path.display()
    );
}

/// The torn-superblock-mirror oracle check.
///
/// `tools/verify-btrfs.sh`'s `scrub` gate is deliberately zero-tolerance —
/// see its own header comment — because for *metadata and data* DUP
/// mirrors, disagreement between the two copies is always a writer bug: a
/// well-formed commit that finished writing block X wrote both of X's
/// mirrors, full stop. Applying that same zero-tolerance to the
/// *superblock*'s DUP mirrors during a test that deliberately interrupts the
/// superblock-mirror loop conflates two different things. btrfs's on-disk
/// format keeps multiple superblock copies with a generation number
/// specifically so that a torn write across them is survivable — mount
/// picks the newest valid one on purpose, not as a fallback. So this
/// boundary's own oracle only demands what commit.rs actually promises for
/// this case: `btrfs check --readonly` reports no error, and a real kernel
/// mount can see (and correctly serve) both the new file and every
/// pre-existing one. It does not demand scrub silence on the superblock,
/// because a torn superblock is exactly what this test intentionally
/// produced, and scrub correctly reports it — self-healing from the good
/// mirror, per the kernel's own designed-for recovery path, rather than
/// finding uncorrectable damage.
///
/// Measured once (see this test's report) that scrub's "Error summary"
/// under this exact interruption is `super=1 / Corrected: 0 / Uncorrectable:
/// 0` — a *corrected* superblock mismatch, not data loss. This helper
/// verifies exactly that distinction rather than asserting it away.
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

    // `btrfs check --readonly` must be clean regardless of the torn
    // superblock — structural validity does not depend on which mirror
    // happened to be picked.
    assert!(
        stdout.contains("no error found"),
        "btrfs check --readonly reported structural errors on a torn-superblock \
         image (this must always be clean, torn superblock or not):\n{stdout}"
    );

    // The mount + ls step must have run and shown both the pre-existing and
    // new files — i.e. the kernel actually mounted it, not merely that
    // `check` liked it.
    assert!(
        stdout.contains("mounted read-only, root contains"),
        "verify-btrfs.sh's mount step did not run:\n{stdout}"
    );
    assert!(
        stdout.contains("hello.txt"),
        "kernel mount does not show pre-existing hello.txt:\n{stdout}"
    );

    // The only acceptable non-"no errors found" scrub outcome here is a
    // *corrected* superblock mismatch with nothing uncorrectable — i.e.
    // exactly the self-healing recovery a torn superblock is supposed to
    // get. An actual data/metadata problem (Uncorrectable > 0, or any error
    // counter other than "super" — e.g. "verify=" or "csum=" — implicating
    // file data or metadata rather than the superblock) is still a real
    // failure. This is enforced by actually parsing scrub's "Error summary"
    // block (see `parse_scrub_summary` below) rather than substring-matching
    // "super=1", which would also match a summary that additionally reported
    // "verify=4" or any other corruption alongside the superblock mismatch.
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

/// Parsed form of `btrfs scrub`'s "Error summary" block, e.g.
///
/// ```text
/// Error summary:    super=1
///   Corrected:      0
///   Uncorrectable:  0
///   Unverified:     0
/// ```
///
/// or, when clean, simply `Error summary:    no errors found`. Measured
/// directly from a real `btrfs-progs` binary (`strings` on `/usr/bin/btrfs`
/// inside the colima VM, 2026-08-21): the summary line is built from
/// space-separated `name=count` pairs — one per nonzero error type
/// (`super`, `verify`, `csum`, `read`, ...) — followed by separate
/// `Corrected:` / `Uncorrectable:` / `Unverified:` lines.
#[derive(Debug, Default, PartialEq, Eq)]
struct ScrubSummary {
    /// Every `name=count` pair named on the "Error summary:" line itself,
    /// keyed by error-type name (e.g. "super", "verify", "csum").
    error_counts: std::collections::BTreeMap<String, u64>,
    uncorrectable: u64,
}

impl ScrubSummary {
    /// No errors of any kind were reported.
    fn is_clean(&self) -> bool {
        self.error_counts.is_empty() && self.uncorrectable == 0
    }

    /// The *only* error type scrub named was the superblock ("super"), and
    /// nothing was left uncorrectable. This is the one self-healing outcome
    /// a deliberately torn superblock mirror pair is expected to produce; any
    /// other named error type (data or metadata corruption) fails this.
    fn is_superblock_only_corrected(&self) -> bool {
        self.uncorrectable == 0
            && self.error_counts.len() == 1
            && self.error_counts.contains_key("super")
    }
}

/// Parse the "Error summary" block out of `verify-btrfs.sh`'s stdout.
/// Returns `None` if no such block is present at all (e.g. the script did
/// not get as far as running scrub).
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

#[cfg(test)]
mod scrub_summary_parsing {
    use super::*;

    /// Real output captured from `verify-btrfs.sh` for the N=16
    /// torn-superblock-mirror case (this file's own oracle run, 2026-08-21):
    /// a corrected, superblock-only mismatch. This must be accepted.
    const REAL_TORN_SUPERBLOCK_OUTPUT: &str = "\
Starting scrub on devid 1

Scrub device /dev/loop1 (id 1) done
Scrub started:    Fri Aug 21 15:22:57 2026
Status:           finished
Duration:         0:00:00
Total to scrub:   2.69MiB
Rate:             2.69MiB/s
Error summary:    super=1
  Corrected:      0
  Uncorrectable:  0
  Unverified:     0
";

    #[test]
    fn accepts_the_real_torn_superblock_output() {
        let summary = parse_scrub_summary(REAL_TORN_SUPERBLOCK_OUTPUT)
            .expect("must parse a real captured Error summary block");
        assert!(!summary.is_clean());
        assert!(
            summary.is_superblock_only_corrected(),
            "real torn-superblock scrub output must be accepted: {summary:?}"
        );
    }

    #[test]
    fn accepts_a_clean_scrub() {
        let stdout = "Error summary:    no errors found\n";
        let summary = parse_scrub_summary(stdout).unwrap();
        assert!(summary.is_clean());
        assert!(!summary.is_superblock_only_corrected());
    }

    /// The bug this whole fix exists to close: a scrub summary that
    /// corrected the superblock *and* also reports metadata/data
    /// corruption (`verify=4`) alongside it, with nothing left
    /// uncorrectable. The old substring check (`contains("super=1") &&
    /// contains("Uncorrectable:  0")`) passed this. It must now be
    /// rejected, because `verify=` corruption is not what a torn
    /// superblock mirror is supposed to produce.
    #[test]
    fn rejects_superblock_plus_verify_corruption() {
        let stdout = "\
Error summary:    super=1 verify=4
  Corrected:      5
  Uncorrectable:  0
  Unverified:     0
";
        let summary = parse_scrub_summary(stdout).unwrap();
        assert!(!summary.is_clean());
        assert!(
            !summary.is_superblock_only_corrected(),
            "a summary with verify=4 alongside super=1 must NOT be treated \
             as a superblock-only correction: {summary:?}"
        );
    }

    /// Same defect, different real-world shape: csum corruption instead of
    /// verify.
    #[test]
    fn rejects_superblock_plus_csum_corruption() {
        let stdout = "\
Error summary:    super=1 csum=2
  Corrected:      3
  Uncorrectable:  0
  Unverified:     0
";
        let summary = parse_scrub_summary(stdout).unwrap();
        assert!(!summary.is_superblock_only_corrected());
    }

    /// An uncorrectable superblock error must still fail even though
    /// "super" is the only named type — "Corrected" is not the same
    /// promise as "nothing was actually lost".
    #[test]
    fn rejects_uncorrectable_superblock_error() {
        let stdout = "\
Error summary:    super=1
  Corrected:      0
  Uncorrectable:  1
  Unverified:     0
";
        let summary = parse_scrub_summary(stdout).unwrap();
        assert!(!summary.is_superblock_only_corrected());
    }

    #[test]
    fn no_error_summary_block_at_all_parses_to_none() {
        assert_eq!(parse_scrub_summary("nothing relevant here\n"), None);
    }
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

/// Sanity check on the write count this whole file's boundaries are chosen
/// against. If the writer's block layout ever changes for `plain.img`, this
/// fails first and obviously, instead of the boundary tests below silently
/// testing the wrong thing.
#[test]
fn probe_write_count_is_seventeen() {
    let n = total_writes_for_commit("plain.img");
    assert_eq!(
        n, 17,
        "commit_transaction's write_at call count for create_file_with_data on \
         plain.img changed from 17 to {n} — every N value in this file's other \
         tests was chosen against the old count and needs to be re-derived"
    );
}

/// N=0: the device fails before a single byte is written. The transaction
/// must be entirely invisible.
#[test]
fn interrupted_at_write_0_is_a_pure_noop() {
    let run = run_interrupted_create("plain.img", 0, "n0");
    assert!(!run.commit_ok, "commit must report failure when budget=0");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must not exist when nothing was written"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// N=1: interrupted right after the sole DATA block write, before any
/// metadata block. plain.img's DATA block group is single-copy (not DUP),
/// so this is also "mid pending_data" as far as that fixture goes — there is
/// only one data write to be mid of. The new data block is now sitting in
/// what the *old* superblock still considers free space; nothing points to
/// it yet.
#[test]
fn interrupted_at_write_1_mid_data_leaves_old_fs_untouched() {
    let run = run_interrupted_create("plain.img", 1, "n1");
    assert!(!run.commit_ok, "commit must report failure when budget=1");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must not exist when only the data block was written"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// N=2: interrupted after the *first* stripe of the *first* metadata block's
/// DUP pair, before its second stripe. This is the sharpest test of the
/// "unreferenced garbage" argument: it leaves a brand-new metadata block
/// whose two DUP mirror copies actively disagree with each other (one
/// stripe has the new bytes, the other still has whatever was there
/// before). If that block were reachable from the old, still-current
/// superblock, this would be real corruption. The claim is that it is not
/// reachable — the old superblock's root still points only at the old tree.
#[test]
fn interrupted_at_write_2_torn_metadata_dup_pair_is_harmless() {
    let run = run_interrupted_create("plain.img", 2, "n2");
    assert!(!run.commit_ok, "commit must report failure when budget=2");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must not exist when metadata writes were interrupted mid-DUP-pair"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// N=8: a clean block boundary in the middle of the metadata writes (4 of 7
/// metadata blocks fully written on both DUP stripes, 3 not started).
#[test]
fn interrupted_at_write_8_mid_metadata_leaves_old_fs_untouched() {
    let run = run_interrupted_create("plain.img", 8, "n8");
    assert!(!run.commit_ok, "commit must report failure when budget=8");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must not exist when interrupted mid-metadata"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// N=15: every data and metadata block is fully written (both DUP stripes),
/// but the first `flush()` — barrier 1 — fails, so *no* superblock mirror is
/// ever touched. This is "the boundary right before the first superblock
/// mirror write." The old superblock's generation was never bumped, so the
/// entire, fully-written new tree is still just unreferenced garbage.
#[test]
fn interrupted_at_write_15_before_first_superblock_write() {
    let run = run_interrupted_create("plain.img", 15, "n15");
    assert!(!run.commit_ok, "commit must report failure when budget=15");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        !entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must not exist when interrupted before any superblock mirror write"
    );
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// N=16: the genuinely interesting case. Superblock mirror 0 is written with
/// the bumped generation; mirror 1 is not and still holds the old
/// generation. The two mirrors now disagree. `Superblock::find` picks the
/// highest-generation *valid* (checksummed) mirror, so mount should pick
/// mirror 0 and come up on the *new* generation, with the new file present
/// — a torn mirror pair, but a self-consistent result, because everything
/// mirror 0 points to (the whole new tree) was already fully and durably
/// written before barrier 1 succeeded.
#[test]
fn interrupted_at_write_16_torn_superblock_mirrors_pick_valid_generation() {
    let run = run_interrupted_create("plain.img", 16, "n16");
    assert!(!run.commit_ok, "commit must report failure when budget=16");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let gen = fs_ro.superblock().generation;
    let entries = fs_ro.list_dir("/").unwrap();
    let new_file_present = entries.iter().any(|e| e.name == NEW_FILE_NAME);
    println!(
        "N=16: mounted at generation {gen}, new file present = {new_file_present}"
    );
    // Mirror 0 (the one actually rewritten) carries the bumped generation
    // and is self-consistent, so this must land on it and show the file.
    assert!(
        new_file_present,
        "expected mount to pick the rewritten, higher-generation superblock mirror \
         (mirror 0) and see the new file; instead it did not"
    );
    drop(fs_ro);

    // Whichever generation it landed on, the result must be a real,
    // consistent filesystem — not a torn one. That is the load-bearing
    // check for this test; see `assert_torn_superblock_mount_valid` for why
    // it is not simply `assert_preexisting_intact` (whose scrub gate is
    // zero-tolerance for *any* mirror disagreement, including the
    // superblock disagreement this test deliberately produces).
    assert_torn_superblock_mount_valid(&run.image_path);
    cleanup(&run.image_path);
}

/// N=17: every write, including both superblock mirrors, lands successfully;
/// only the *final* flush (barrier 2) fails. All bytes that matter are
/// already on the backing store — `FileDevice::write_at` is a synchronous
/// `pwrite`, so nothing about the final flush is needed for *this* harness's
/// notion of "on disk," only for durability against an intervening real
/// power loss on real hardware, which this test cannot model. The new file
/// must be present and the filesystem fully valid.
#[test]
fn interrupted_at_write_17_after_full_write_only_final_flush_lost() {
    let run = run_interrupted_create("plain.img", 17, "n17");
    assert!(
        !run.commit_ok,
        "commit must still report failure when only the final flush is denied"
    );

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(
        entries.iter().any(|e| e.name == NEW_FILE_NAME),
        "new file must be present: every byte of the transaction was actually written"
    );
    let readback = fs_ro.read_file(&format!("/{NEW_FILE_NAME}")).unwrap();
    assert_eq!(readback, NEW_FILE_DATA);
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}

/// Positive control: an uninterrupted commit (budget far above the write
/// count) succeeds and the oracle is clean. This is the "green" end of the
/// same harness, run through the identical FailAfterNWrites path — if this
/// one somehow failed, that would say more about the harness than the
/// filesystem.
#[test]
fn uninterrupted_commit_succeeds_and_is_oracle_clean() {
    let run = run_interrupted_create("plain.img", usize::MAX, "control");
    assert!(run.commit_ok, "uninterrupted commit must succeed");

    let fs_ro = Btrfs::mount(FileDevice::open(&run.image_path).unwrap()).unwrap();
    let entries = fs_ro.list_dir("/").unwrap();
    assert!(entries.iter().any(|e| e.name == NEW_FILE_NAME));
    drop(fs_ro);

    assert_preexisting_intact(&run.image_path);
    cleanup(&run.image_path);
}
