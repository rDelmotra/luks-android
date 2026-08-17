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
//! # Visibility
//!
//! Every `tests/*.rs` file is its own process, so there is no single
//! process-wide count across `cargo test --workspace`. What this module gives
//! instead: every gate call prints a running tally *for its own binary* —
//! "oracle #N (this binary)" for a real invocation, "ORACLE SKIPPED (#N this
//! binary)" for an `ALLOW_NO_ORACLE=1` skip — so a binary that skipped every
//! oracle shows a trail of skip lines, not silence, and cannot be confused in
//! the log for one that ran them.

#![allow(dead_code)]

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many times this test binary has actually run an oracle against a real
/// kernel.
pub static ORACLE_EXECUTED: AtomicUsize = AtomicUsize::new(0);
/// How many times this test binary has skipped one, under `ALLOW_NO_ORACLE=1`.
pub static ORACLE_SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// Is the real-kernel oracle (colima) available right now?
///
/// - Up: bumps [`ORACLE_EXECUTED`], announces it, returns `true`. The caller
///   should go run its script / kernel check.
/// - Down and `ALLOW_NO_ORACLE=1` is set: bumps [`ORACLE_SKIPPED`], announces
///   it loudly, returns `false`. The caller should skip, the way it always
///   did — but now that only happens because someone explicitly asked for it.
/// - Down and `ALLOW_NO_ORACLE` is not set: **panics.** A test that would
///   otherwise report "clean" without a kernel ever looking at the image is
///   worse than a failing test.
#[track_caller]
pub fn gate() -> bool {
    let loc = std::panic::Location::caller();

    let colima_up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if colima_up {
        let n = ORACLE_EXECUTED.fetch_add(1, Ordering::SeqCst) + 1;
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
    eprintln!(
        "\u{26A0}\u{FE0F}  ORACLE SKIPPED (#{n} this binary) at {loc}: colima is not \
         running and ALLOW_NO_ORACLE=1 permits it. This run did NOT verify \
         against a real kernel — treat it as unproven, not as passing."
    );
    false
}
