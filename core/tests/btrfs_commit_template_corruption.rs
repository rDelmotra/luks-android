//! Regression test for H5 (`notes/btrfs-recon-2026-08-30/PLAN-2026-09-01.md`):
//! `commit_transaction` used to read superblock mirror 0 as a template with
//! **no magic check and no checksum verification** — the only unverified
//! superblock read anywhere in this codebase. `Superblock::emit_copy` then
//! stamps a *fresh, valid* checksum over whatever that read returned and
//! writes the result to every mirror. Before the fix, a transport glitch on
//! that one read (a desynced USB pipe, a torn cable) was not caught: this
//! crate's own checksum would certify the garbage and launder it into
//! permanent, "verified" corruption across all three superblock copies — a
//! mechanism by which a transient glitch survives a replug.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support --test btrfs_commit_template_corruption
//! ```
//!
//! # The claim under test
//!
//! `commit_transaction` (`core/src/fs/btrfs/write/commit.rs`) must validate
//! the template read (magic + checksum, via `Superblock::parse`) before
//! using it, and must fail closed — no write_at calls at all — if that read
//! comes back corrupted.
//!
//! # Vacuity control
//!
//! The same harness, same fixture, same transaction, with the corrupting
//! wrapper simply not injecting anything, must still succeed and produce a
//! filesystem a real kernel accepts. Without this, a test that always
//! errors (e.g. from a typo) would "pass" the corruption case for the wrong
//! reason.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::superblock::SUPER_OFFSETS;
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Copy the shared fixture to a uniquely named scratch file. Every test
/// below mounts and writes to the copy, never the fixture — the fixture is
/// shared across the whole test binary and other tests read it concurrently.
fn copy_to_temp(src_name: &str, tag: &str) -> PathBuf {
    let src = fixture(src_name);
    let dst = std::env::temp_dir().join(format!(
        "btrfs-commit-template-{src_name}-{tag}-{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

// ---------------------------------------------------------------------
// CorruptTemplateRead: a device wrapper that returns bit-flipped bytes for
// exactly one read — the template read at SUPER_OFFSETS[0] — and passes
// every other read_at/write_at straight through to the real, file-backed
// device. This is the narrowest possible stand-in for "the bytes coming
// back from this one read are wrong": every other superblock mirror, every
// tree block, everything else on the device is untouched.
// ---------------------------------------------------------------------
struct CorruptTemplateRead {
    inner: FileDevice,
    /// Flip a byte inside the checksum-covered region (offset >= 32) rather
    /// than the magic field at 0x40..0x48. This deliberately exercises the
    /// checksum check, not the magic check — the magic bytes of a garbled
    /// USB read are not reliably wrong just because other bytes are, and
    /// the whole point of H5 is that checksum verification, not eyeballing
    /// the magic, is what has to catch this.
    corrupt: bool,
    /// `Btrfs::mount` itself reads every `SUPER_OFFSETS` entry (via
    /// `Superblock::find`) to pick the highest-generation valid mirror —
    /// that is a *different* read than the one under test, and corrupting
    /// it would just make `find` fall back to another mirror rather than
    /// exercising `commit_transaction`'s template read. Corruption is
    /// therefore armed only after mount succeeds, immediately before the
    /// write call that triggers `commit_transaction`.
    armed: AtomicBool,
    /// How many times `write_at` was actually invoked, for diagnostics.
    /// This is *not* required to stay 0: `write_chunk` streams new data
    /// blocks straight to freshly allocated, not-yet-referenced bytenrs
    /// before a batch ever calls `commit_transaction` (see
    /// `core/src/fs/btrfs/write/file.rs`) — writing those is harmless by
    /// construction, since nothing in any tree points at them until a
    /// commit succeeds. What must stay 0 is `superblock_writes` below.
    writes_attempted: AtomicUsize,
    /// How many `write_at` calls targeted one of `SUPER_OFFSETS`. This is
    /// the actual fail-closed claim under test: `commit_transaction` must
    /// reject a corrupted template *before* patching and writing a single
    /// superblock mirror. Unlike `writes_attempted`, a nonzero value here
    /// after a rejected commit would mean the corrupted template reached
    /// `emit_copy` and got written out — the exact H5 defect.
    superblock_writes: AtomicUsize,
    /// How many times the corrupted offset was read. Used to assert the
    /// injection point was actually exercised — a test that corrupts an
    /// offset nothing reads would pass for the wrong reason.
    corruption_reads: AtomicUsize,
}

impl CorruptTemplateRead {
    fn new(inner: FileDevice, corrupt: bool) -> Self {
        Self {
            inner,
            corrupt,
            armed: AtomicBool::new(false),
            writes_attempted: AtomicUsize::new(0),
            superblock_writes: AtomicUsize::new(0),
            corruption_reads: AtomicUsize::new(0),
        }
    }
}

impl ReadAt for CorruptTemplateRead {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(offset, buf)?;
        if self.corrupt && self.armed.load(Ordering::SeqCst) && offset == SUPER_OFFSETS[0] {
            self.corruption_reads.fetch_add(1, Ordering::SeqCst);
            // Flip a byte well inside the checksummed region (CSUM_START is
            // 32) and well clear of the magic field (0x40..0x48), e.g. a
            // byte in the generation field at 0x48. Real corruption does
            // not politely avoid the checksum's own coverage.
            buf[0x49] ^= 0xff;
        }
        Ok(())
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl WriteAt for CorruptTemplateRead {
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.writes_attempted.fetch_add(1, Ordering::SeqCst);
        if SUPER_OFFSETS.contains(&offset) {
            self.superblock_writes.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }
}

const NEW_FILE_NAME: &str = "template-corruption.txt";
const NEW_FILE_DATA: &[u8] = b"H5 regression: template read must be verified";

/// The corruption case: the template read at SUPER_OFFSETS[0] comes back
/// with a flipped bit inside the checksummed region. Before the fix,
/// `commit_transaction` used this garbage as-is, `emit_copy` computed a
/// brand-new valid checksum over it, and the corrupted template was written
/// to every superblock mirror on the device — the exact "our own checksum
/// certifies the garbage" failure H5 describes. After the fix,
/// `Superblock::parse` on the template must reject it and `commit_transaction`
/// must return an error before issuing a single `write_at`.
#[test]
fn commit_rejects_corrupted_template_read() {
    let temp_img = copy_to_temp("plain.img", "corrupt");
    let original_bytes = fs::read(&temp_img).expect("read scratch image before commit");

    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let wrapped = CorruptTemplateRead::new(dev, /* corrupt = */ true);
    let mut fs_ = Btrfs::mount(wrapped).expect("mount writable btrfs (template corruption is injected on commit, not mount)");
    fs_.device().armed.store(true, Ordering::SeqCst);

    let result = fs_.create_file_with_data("/", NEW_FILE_NAME, NEW_FILE_DATA);

    // The injection point must actually have fired, or this test would pass
    // even if the corrupting wrapper were a no-op.
    assert_eq!(
        fs_.device().corruption_reads.load(Ordering::SeqCst),
        1,
        "corrupting wrapper never intercepted the SUPER_OFFSETS[0] template read \
         — this test would be vacuous"
    );

    // The commit must fail, not silently launder the corrupted template.
    let err = result.expect_err(
        "commit_transaction accepted a corrupted superblock template instead of \
         failing closed — this is the H5 defect: our own checksum would have \
         certified the garbage and written it to every mirror",
    );
    match err {
        LuksError::FsChecksumMismatch(_) => {}
        other => panic!(
            "expected LuksError::FsChecksumMismatch from the template validation \
             (Superblock::parse's checksum check), got {other:?}"
        ),
    }

    // Fail-closed means the corrupted template never reaches `emit_copy`
    // and never gets written to a mirror. `write_chunk` streaming new data
    // blocks to unreferenced bytenrs before the batch commits is expected
    // and harmless (see `writes_attempted`'s doc comment) — what must be
    // exactly zero is writes to any of the three SUPER_OFFSETS.
    let sb_writes = fs_.device().superblock_writes.load(Ordering::SeqCst);
    assert_eq!(
        sb_writes, 0,
        "commit_transaction wrote {sb_writes} superblock mirror(s) after a \
         corrupted template read instead of rejecting it before patching and \
         emitting any mirror — this is exactly the H5 defect: a corrupted \
         template got a freshly computed, valid checksum and was written out"
    );

    drop(fs_);

    // Belt and suspenders on top of the superblock-write-count assertion:
    // every SUPER_OFFSETS mirror on disk must be byte-for-byte unchanged.
    // (Data blocks elsewhere on the scratch image are allowed to differ —
    // `write_chunk` legitimately streams new, not-yet-referenced blocks to
    // free space before the batch ever reaches `commit_transaction`.)
    let after_bytes = fs::read(&temp_img).expect("read scratch image after failed commit");
    for &off in SUPER_OFFSETS.iter() {
        let off = off as usize;
        if off + luks_core::fs::btrfs::superblock::SUPER_SIZE > after_bytes.len() {
            continue;
        }
        let before = &original_bytes[off..off + luks_core::fs::btrfs::superblock::SUPER_SIZE];
        let after = &after_bytes[off..off + luks_core::fs::btrfs::superblock::SUPER_SIZE];
        assert_eq!(
            before, after,
            "superblock mirror at offset {off:#x} changed on disk despite \
             commit_transaction reporting failure"
        );
    }

    // Best-effort scratch cleanup: a failure here is a leaked temp file, not
    // a signal about the behavior under test, but it must be observed
    // rather than silently discarded (see RULES.md).
    if let Err(e) = fs::remove_file(&temp_img) {
        eprintln!("warning: failed to remove scratch image {}: {e}", temp_img.display());
    }
}

/// Vacuity control: identical harness, identical fixture, identical
/// transaction, but the wrapper does not corrupt anything. This must
/// succeed, and a real kernel must accept the result — proving the failure
/// above comes from the injected corruption, not from some unrelated defect
/// (e.g. a typo that makes every commit fail) that would make the
/// corruption test "pass" for the wrong reason.
#[test]
fn commit_succeeds_with_uncorrupted_template_read() {
    let temp_img = copy_to_temp("plain.img", "control");

    let file_len = fs::metadata(&temp_img).unwrap().len();
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let wrapped = CorruptTemplateRead::new(dev, /* corrupt = */ false);
    let mut fs_ = Btrfs::mount(wrapped).expect("mount writable btrfs");

    fs_.create_file_with_data("/", NEW_FILE_NAME, NEW_FILE_DATA)
        .expect("uninterrupted, uncorrupted commit must succeed");

    // The corruption path must not have fired in the control run.
    assert_eq!(
        fs_.device().corruption_reads.load(Ordering::SeqCst),
        0,
        "control run's wrapper injected corruption — the control is not clean"
    );
    // And real writes must actually have happened — the control is
    // meaningless if the "successful" commit wrote nothing.
    let writes = fs_.device().writes_attempted.load(Ordering::SeqCst);
    assert!(
        writes > 0,
        "control commit reported success but issued zero write_at calls"
    );

    drop(fs_);

    // Ground truth: the real Linux kernel, not this crate's own reader,
    // has to agree the committed image is a valid, mountable btrfs
    // filesystem with the new file in it. Same oracle script and gating
    // convention as btrfs_crash_safety.rs.
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");
    assert!(script.exists(), "verify-btrfs.sh missing");

    if common::oracle::gate() {
        let output = Command::new(&script)
            .arg(&temp_img)
            .output()
            .expect("run verify-btrfs.sh");
        assert!(
            output.status.success(),
            "kernel oracle reported an unclean filesystem for the uncorrupted \
             control commit:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Best-effort scratch cleanup: a failure here is a leaked temp file, not
    // a signal about the behavior under test, but it must be observed
    // rather than silently discarded (see RULES.md).
    if let Err(e) = fs::remove_file(&temp_img) {
        eprintln!("warning: failed to remove scratch image {}: {e}", temp_img.display());
    }
}
