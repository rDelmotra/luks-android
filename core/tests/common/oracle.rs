//! The single gate every oracle-graded test goes through before it trusts a
//! real kernel's opinion (`btrfs check`, `e2fsck`, a real mount, `btrfs
//! scrub`) — colima has to actually be up.
//!
//! # History
//!
//! This used to be duplicated, slightly differently, in about twenty test
//! files. Every copy did the same wrong thing: if `colima status` failed, it
//! printed one `eprintln!` and returned "clean"/`None`/`true` — whatever
//! spelling of "skip" that file's caller expected. `cargo test --workspace`
//! on a machine with no colima therefore reported fully green with zero
//! kernel grading, silently. An opt-in `REQUIRE_ORACLE=1` panic existed to
//! fix this, but nothing ever set it, so the hole stayed open.
//!
//! The default is inverted here: **oracle-required is the norm.** If colima
//! is not up, [`gate`] panics, loudly, naming the call site. The explicit,
//! deliberate opt-out for someone working offline is `ALLOW_NO_ORACLE=1` —
//! not a variable nobody sets, but one a person has to type into their own
//! shell to get a green run without kernel grading.
//!
//! `REQUIRE_ORACLE` is gone. Two mechanisms that disagreed about the default
//! is exactly how the old hole stayed open; there is now exactly one.
//!
//! # Evidence (issue 35)
//!
//! This module used to claim that a binary which skipped every oracle "shows
//! a trail of skip lines, not silence". That was false, and it was false in
//! the only way that mattered: the trail was an `eprintln!`, and libtest
//! captures both stdout *and* stderr for tests that pass. Under the
//! documented `cargo test` command a fully-graded run and a fully-skipped
//! `ALLOW_NO_ORACLE=1` run printed the same thing — nothing. The trail
//! existed solely under `--nocapture`, which nobody was told to pass.
//!
//! Printing louder does not fix that, because a print is exactly the channel
//! a test harness is built to swallow. So the evidence is no longer a print:
//!
//! 1. **A ledger.** Every [`gate`] call appends one line to the file named by
//!    `LUKS_ORACLE_LEDGER`, defaulting to `<target>/oracle-ledger.log`. It
//!    survives capture, and it aggregates across the many test-binary
//!    processes that `cargo test --workspace` spawns, which no in-process
//!    counter can do.
//! 2. **Skips bypass the capture.** A `SKIPPED` line is written straight to
//!    file descriptor 2, under libtest's nose. The asymmetry is deliberate:
//!    the dangerous state is unsuppressable, the safe state is merely
//!    recorded, so a properly graded run does not bury its own output in
//!    several hundred lines of "yes, still fine".
//! 3. **A command whose exit status carries the answer.**
//!    `tools/test-graded.sh` clears the ledger, runs the suite, and fails the
//!    run if any gate was skipped. Human attention is no longer load-bearing.
//!
//! The in-process counters below are kept because they make the per-binary
//! `#N` in each message meaningful. They are not the evidence.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many times this test binary has actually run an oracle against a real
/// kernel.
pub static ORACLE_EXECUTED: AtomicUsize = AtomicUsize::new(0);
/// How many times this test binary has skipped one, under `ALLOW_NO_ORACLE=1`.
pub static ORACLE_SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// Ledger verb for a gate that really did hand an image to a kernel.
pub const KIND_RAN: &str = "RAN";
/// Ledger verb for a gate waved through by `ALLOW_NO_ORACLE=1`.
pub const KIND_SKIPPED: &str = "SKIPPED";

/// Where the ledger lives.
///
/// `LUKS_ORACLE_LEDGER` wins when set — that is how `tools/test-graded.sh`
/// keeps one run's evidence separate from the last one's. Otherwise it is
/// derived from this binary's own path: test binaries are built to
/// `<target>/debug/deps/<name>-<hash>`, so three levels up is `<target>`,
/// which is already git-ignored and already per-checkout.
pub fn ledger_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("LUKS_ORACLE_LEDGER") {
        if !explicit.is_empty() {
            return Some(PathBuf::from(explicit));
        }
    }
    let exe = std::env::current_exe().ok()?;
    let target = exe.parent()?.parent()?.parent()?;
    Some(target.join("oracle-ledger.log"))
}

/// One ledger record: verb, which test binary, which call site.
///
/// Tab-separated and newline-terminated so that a reader can split on tabs
/// without worrying about the spaces in a `Location`'s rendering, and short
/// enough that a single `write` of it is atomic under `O_APPEND` — which is
/// what lets the parallel test-binary processes share one file safely.
pub fn ledger_line(kind: &str, binary: &str, location: &str) -> String {
    format!("{kind}\t{binary}\t{location}\n")
}

/// Append one already-formatted record to the ledger.
///
/// `O_APPEND` plus a single `write_all` of a short line: every process seeks
/// to the end and writes under the same kernel-side lock, so records from
/// concurrently running test binaries interleave as whole lines and never
/// tear. `oracle_ledger.rs` proves that rather than trusting this paragraph.
pub fn append_line(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())
}

/// Write past libtest's output capture, straight to file descriptor 2.
///
/// `eprintln!` goes through `std::io::_eprint`, which honours the thread-local
/// capture buffer libtest installs — that is the whole of issue 35. Writing to
/// the descriptor itself does not. The handle is `ManuallyDrop` because
/// dropping a `File` closes its descriptor, and closing stderr for the rest of
/// the process would be a memorable way to fix a logging bug.
fn write_uncaptured(msg: &str) {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(2) });
        let _ = f.write_all(msg.as_bytes());
        let _ = f.flush();
    }
    #[cfg(not(unix))]
    {
        eprint!("{msg}");
    }
}

/// This test binary's file name, for the ledger.
fn binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown-binary".to_string())
}

/// Record one gate decision in the ledger.
///
/// A ledger that cannot be written is not silently tolerated: the complaint
/// goes to the uncapturable channel, so a run whose evidence is missing says
/// so instead of looking like a run with nothing to report. It does not panic
/// — an unwritable `target/` is a broken workspace, not a failed test, and
/// turning it into hundreds of failures would obscure the real cause.
fn record(kind: &str, location: &str) {
    let Some(path) = ledger_path() else {
        write_uncaptured(
            "\u{26A0}\u{FE0F}  ORACLE LEDGER: cannot determine a ledger path; \
             this run leaves no durable evidence of kernel grading.\n",
        );
        return;
    };
    let line = ledger_line(kind, &binary_name(), location);
    if let Err(e) = append_line(&path, &line) {
        write_uncaptured(&format!(
            "\u{26A0}\u{FE0F}  ORACLE LEDGER: cannot write {}: {e}. This run leaves \
             no durable evidence of kernel grading.\n",
            path.display()
        ));
    }
}

/// Is the real-kernel oracle (colima) available right now?
///
/// - Up: bumps [`ORACLE_EXECUTED`], records a `RAN` line in the ledger,
///   returns `true`. The caller should go run its script / kernel check.
/// - Down and `ALLOW_NO_ORACLE=1` is set: bumps [`ORACLE_SKIPPED`], records a
///   `SKIPPED` line, announces it on a channel libtest cannot capture, and
///   returns `false`. The caller should skip, the way it always did — but now
///   that only happens because someone explicitly asked for it, and it can no
///   longer happen quietly.
/// - Down and `ALLOW_NO_ORACLE` is not set: **panics.** A test that would
///   otherwise report "clean" without a kernel ever looking at the image is
///   worse than a failing test.
#[track_caller]
pub fn gate() -> bool {
    let loc = std::panic::Location::caller().to_string();

    let colima_up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if colima_up {
        let n = ORACLE_EXECUTED.fetch_add(1, Ordering::SeqCst) + 1;
        record(KIND_RAN, &loc);
        // Left as a capturable print on purpose: this is the safe outcome, and
        // several hundred of these would drown the SKIPPED lines that matter.
        // `--nocapture` shows them; the ledger always has them.
        eprintln!("oracle #{n} (this binary): colima is up, verifying at {loc}");
        return true;
    }

    let allow_offline = std::env::var("ALLOW_NO_ORACLE")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !allow_offline {
        panic!(
            "ORACLE UNAVAILABLE at {loc}: colima is not running, so this test \
             cannot be graded against a real kernel. Refusing to report success \
             without that grading — a green run must mean the kernel actually \
             looked at the image. Set ALLOW_NO_ORACLE=1 to explicitly opt out \
             and run offline (e.g. `ALLOW_NO_ORACLE=1 cargo test ...`)."
        );
    }

    let n = ORACLE_SKIPPED.fetch_add(1, Ordering::SeqCst) + 1;
    record(KIND_SKIPPED, &loc);
    write_uncaptured(&format!(
        "\u{26A0}\u{FE0F}  ORACLE SKIPPED (#{n} this binary) at {loc}: colima is not \
         running and ALLOW_NO_ORACLE=1 permits it. This run did NOT verify \
         against a real kernel — treat it as unproven, not as passing.\n"
    ));
    false
}
