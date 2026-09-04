//! Tests for the oracle evidence ledger itself — issue 35.
//!
//! The ledger exists because the previous evidence channel (an `eprintln!`)
//! was swallowed by libtest's output capture, so a kernel-graded run and an
//! `ALLOW_NO_ORACLE=1` run were indistinguishable. Replacing one silent
//! mechanism with another would be no improvement, so the claims the new one
//! rests on are checked here rather than asserted in a doc comment:
//!
//! - it *appends*, so the second binary to write does not erase the first's;
//! - concurrent writers produce whole lines, never torn or interleaved ones,
//!   which is what `cargo test --workspace` does to it in practice;
//! - the record is parseable back into the three fields a report needs.
//!
//! These are deliberately not gated on colima: the point is to keep working
//! when the oracle is *absent*, since that is precisely the run whose honesty
//! is in question.

mod common;

use common::oracle::{append_line, ledger_line, KIND_RAN, KIND_SKIPPED};
use std::path::PathBuf;

/// A scratch ledger path unique to this test, under the same `target/` the
/// real ledger uses. Avoids `/tmp` so a stray file lands somewhere already
/// git-ignored and already cleaned by `cargo clean`.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::current_exe()
        .expect("test binary has a path")
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("target/ is three levels above tests/deps")
        .join("oracle-ledger-tests");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn a_record_carries_the_three_fields_a_report_needs() {
    let line = ledger_line(KIND_SKIPPED, "btrfs_delete-abc123", "core/tests/btrfs_delete.rs:61:9");

    assert!(line.ends_with('\n'), "records must be newline-terminated");
    assert_eq!(line.matches('\n').count(), 1, "one record is one line");

    let fields: Vec<&str> = line.trim_end().split('\t').collect();
    assert_eq!(
        fields,
        vec![
            "SKIPPED",
            "btrfs_delete-abc123",
            "core/tests/btrfs_delete.rs:61:9"
        ],
        "a reporting script splits on tabs and expects verb, binary, call site"
    );
}

#[test]
fn writing_appends_rather_than_truncating() {
    // The failure this guards against is the one that would quietly destroy
    // the evidence: `cargo test --workspace` runs ~50 test binaries, each
    // opening this same file. If any of them truncated, the surviving ledger
    // would describe one binary and look like a complete, clean record.
    let path = scratch("append.log");

    append_line(&path, &ledger_line(KIND_RAN, "first", "a.rs:1:1")).expect("first write");
    append_line(&path, &ledger_line(KIND_SKIPPED, "second", "b.rs:2:2")).expect("second write");

    let body = std::fs::read_to_string(&path).expect("read back");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "both records survive; got {body:?}");
    assert!(lines[0].starts_with("RAN\tfirst\t"));
    assert!(lines[1].starts_with("SKIPPED\tsecond\t"));
}

#[test]
fn concurrent_writers_produce_whole_lines() {
    // `O_APPEND` + a single `write` of a short line is the reason the ledger
    // can be shared by every test binary at once. Threads within one process
    // are a weaker test than separate processes, but they exercise the same
    // kernel path and will catch the regression that matters: someone
    // "improving" `append_line` into a seek-then-write, or a buffered writer
    // that flushes at partial-line boundaries.
    let path = scratch("concurrent.log");

    const WRITERS: usize = 8;
    const PER_WRITER: usize = 64;

    std::thread::scope(|s| {
        for w in 0..WRITERS {
            let path = path.clone();
            s.spawn(move || {
                for i in 0..PER_WRITER {
                    let line = ledger_line(KIND_RAN, &format!("writer{w}"), &format!("f.rs:{i}:1"));
                    append_line(&path, &line).expect("concurrent write");
                }
            });
        }
    });

    let body = std::fs::read_to_string(&path).expect("read back");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        WRITERS * PER_WRITER,
        "every record present exactly once"
    );
    for line in &lines {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            3,
            "record {line:?} is torn — a partial write interleaved with another"
        );
        assert_eq!(fields[0], "RAN");
        assert!(
            fields[1].starts_with("writer") && fields[2].starts_with("f.rs:"),
            "record {line:?} has fields from two different writers spliced together"
        );
    }
}
