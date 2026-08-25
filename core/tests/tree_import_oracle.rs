//! The kernel oracle for the Android directory-transfer feature (Pass 3).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test tree_import_oracle
//! ```
//!
//! # What is actually being graded
//!
//! `TreeImporter` is Kotlin and this harness is Rust, so `importTree` cannot
//! run inside a `cargo test`. Reimplementing its tree loop here would get the
//! kernel to bless code that does not ship — RULES.md's "grade against
//! ourselves" trap with an extra step, since the grading would be genuine and
//! the *subject* would not.
//!
//! Instead, `TreeImportTraceTest` (Android) records the exact ordered sequence
//! of volume operations the shipping Kotlin emits — it sits at the seam every
//! drive-touching call passes through — and writes it to
//! `fixtures/transfer/*.trace`. This test replays that sequence through the
//! real btrfs write path and hands the result to the kernel.
//!
//! So the chain is: real decisions (Kotlin) -> real writer (this crate) ->
//! real kernel (`btrfs check`, mount, scrub, and a mounted read of every
//! file). The only synthetic link is the transport between the first two, and
//! that link is asserted on the Kotlin side rather than assumed: the trace is
//! compared against the fixture on every unit-test run, so a `TreeImporter`
//! that changes behaviour fails there rather than silently leaving this test
//! grading a sequence nobody emits any more.
//!
//! # The Oracle
//!
//! 1. `tools/verify-btrfs.sh` — `btrfs check --readonly`, a real kernel mount,
//!    and `btrfs scrub start -Bdr`. Scrub is the one that reads file *data*
//!    against the checksum tree; check alone is metadata-only.
//! 2. `tools/tree-in-image.sh` — mounts read-only and emits a sorted manifest
//!    of the imported subtree with a sha256 per file. Compared whole, so an
//!    import that copied everything correctly *and* left junk behind fails,
//!    which a per-file check would pass.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;

/// Where the imported tree lands inside the fixture image. The traces are
/// recorded against this path, so it is not free to change on one side only.
const DEST_ROOT: &str = "/dst";

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_fixture_to_temp(src_name: &str, tag: &str) -> PathBuf {
    let src = repo_path(&format!("fixtures/btrfs/{src_name}"));
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = std::env::temp_dir().join(format!(
        "tree-import-{tag}-{}-{}.img",
        std::process::id(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

// ---- the trace format ------------------------------------------------------

/// One recorded operation. Mirrors the methods `TreeImporter` calls on
/// `LuksVolume`, one to one.
#[derive(Debug)]
enum Op {
    Mkdir { parent: String, name: String },
    Begin,
    /// `offset` is within the file being streamed; content is generated, see
    /// [`generated_content`].
    Write { offset: usize, length: usize, seed: u8 },
    Finish { parent: String, name: String },
    Rename { old_parent: String, old_name: String, new_parent: String, new_name: String },
    Delete { parent: String, name: String },
    Abandon,
}

/// Byte `i` of a file with seed `s` is `(s + i) & 0xFF` — the identical rule
/// `TreeImportTraceTest.contentFor` uses on the Kotlin side.
///
/// Generated rather than embedded so a multi-megabyte file costs a few bytes
/// of fixture. It varies per offset on purpose: under a constant fill, a
/// replay that dropped, duplicated, or reordered a chunk would hash the same
/// as a correct one, and the oracle would confirm a bug.
fn generated_content(seed: u8, offset: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (seed as usize).wrapping_add(offset).wrapping_add(i) as u8)
        .collect()
}

fn parse_trace(path: &Path) -> Vec<Op> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "missing trace {}: {e}\nRegenerate with \
             UPDATE_TRANSFER_TRACE=1 ./gradlew :app:test in android/",
            path.display()
        )
    });

    text.lines()
        .filter(|l| !l.trim().is_empty())
        // Tab-separated, because a filename may legitimately contain a space
        // and splitting on whitespace would mis-parse exactly the name most
        // worth testing.
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "mkdir" => Op::Mkdir { parent: f[1].into(), name: f[2].into() },
                "begin" => Op::Begin,
                "write" => Op::Write {
                    offset: f[1].parse().expect("write offset"),
                    length: f[2].parse().expect("write length"),
                    seed: f[3].parse().expect("write seed"),
                },
                "finish" => Op::Finish { parent: f[1].into(), name: f[2].into() },
                "rename" => Op::Rename {
                    old_parent: f[1].into(),
                    old_name: f[2].into(),
                    new_parent: f[3].into(),
                    new_name: f[4].into(),
                },
                "delete" => Op::Delete { parent: f[1].into(), name: f[2].into() },
                "abandon" => Op::Abandon,
                other => panic!("unknown trace op {other:?} in {}", path.display()),
            }
        })
        .collect()
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Replay a recorded sequence through the real write path.
fn replay(fs: &mut Btrfs<FileDevice>, ops: &[Op]) {
    let mut writer = None;

    for (i, op) in ops.iter().enumerate() {
        match op {
            Op::Mkdir { parent, name } => {
                fs.create_directory(parent, name)
                    .unwrap_or_else(|e| panic!("op {i}: mkdir {parent}/{name}: {e:?}"));
            }
            Op::Begin => {
                assert!(writer.is_none(), "op {i}: begin while a writer is still open");
                writer = Some(
                    fs.begin_file_streaming()
                        .unwrap_or_else(|e| panic!("op {i}: begin_file_streaming: {e:?}")),
                );
            }
            Op::Write { offset, length, seed } => {
                let w = writer.as_mut().unwrap_or_else(|| panic!("op {i}: write with no open writer"));
                let data = generated_content(*seed, *offset, *length);
                fs.write_chunk(w, &data)
                    .unwrap_or_else(|e| panic!("op {i}: write_chunk at {offset}: {e:?}"));
            }
            Op::Finish { parent, name } => {
                let w = writer.take().unwrap_or_else(|| panic!("op {i}: finish with no open writer"));
                fs.finish_file(w, parent, name)
                    .unwrap_or_else(|e| panic!("op {i}: finish_file {parent}/{name}: {e:?}"));
            }
            Op::Rename { old_parent, old_name, new_parent, new_name } => {
                fs.rename(old_parent, old_name, new_parent, new_name).unwrap_or_else(|e| {
                    panic!("op {i}: rename {old_parent}/{old_name} -> {new_parent}/{new_name}: {e:?}")
                });
            }
            Op::Delete { parent, name } => {
                let path = join(parent, name);
                fs.delete_file(&path).unwrap_or_else(|e| panic!("op {i}: delete {path}: {e:?}"));
            }
            Op::Abandon => {
                if let Some(w) = writer.take() {
                    fs.abandon_file(w);
                }
            }
        }
    }

    assert!(writer.is_none(), "trace ended with a file writer still open");
    fs.commit_active_batch().expect("commit trailing batch");
}

// ---- the oracle ------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn manifest_line_for_file(rel: &str, seed: u8, length: usize) -> String {
    format!("f {rel} {length} {}", sha256_hex(&generated_content(seed, 0, length)))
}

fn run_script(script: &str, args: &[&str]) -> std::process::Output {
    Command::new(repo_path(&format!("tools/{script}")))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {script}: {e}"))
}

/// `btrfs check` + kernel mount + scrub. Panics with the script's own output
/// on failure, because "the oracle said no" is useless without its reasons.
fn kernel_verify(image: &Path) {
    if !common::oracle::gate() {
        return;
    }
    let out = run_script("verify-btrfs.sh", &[image.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "verify-btrfs.sh failed (exit {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// The kernel's own view of the imported subtree, as a sorted manifest.
fn kernel_manifest(image: &Path, inner: &str) -> String {
    let out = run_script("tree-in-image.sh", &[image.to_str().unwrap(), inner]);
    assert!(
        out.status.success(),
        "tree-in-image.sh failed (exit {:?})\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn assert_manifest(image: &Path, expected: &[String]) {
    if !common::oracle::gate() {
        return;
    }
    let actual = kernel_manifest(image, DEST_ROOT.trim_start_matches('/'));
    let expected_text = {
        let mut lines = expected.to_vec();
        lines.sort();
        lines.join("\n") + "\n"
    };
    assert_eq!(
        expected_text, actual,
        "the kernel's view of {DEST_ROOT} does not match what the import should have produced.\n\
         Lines present in one and not the other are the finding: a missing line is a file that \
         never landed, an extra line is something the import created that nobody asked for."
    );
}

// ---- scenarios -------------------------------------------------------------

/// Build the pre-existing destination state the traces were recorded against.
///
/// This is not scenery. `/dst/Photos/existing.txt` must genuinely exist, with
/// content distinguishable from what the import writes, or the replace path in
/// the nested trace would collide with nothing and the assertion that it was
/// overwritten would pass vacuously.
fn seed_destination(fs: &mut Btrfs<FileDevice>, with_existing_file: bool) {
    fs.create_directory("/", "dst").expect("create /dst");
    if with_existing_file {
        fs.create_directory(DEST_ROOT, "Photos").expect("create /dst/Photos");
        let old = b"OLD CONTENT THAT MUST BE REPLACED".to_vec();
        let mut w = fs.begin_file_streaming().expect("begin existing.txt");
        fs.write_chunk(&mut w, &old).expect("write existing.txt");
        fs.finish_file(w, "/dst/Photos", "existing.txt").expect("finish existing.txt");
    }
}

#[test]
fn imports_a_nested_tree_the_kernel_agrees_with() {
    let img = copy_fixture_to_temp("plain.img", "nested");
    let len = fs::metadata(&img).unwrap().len();

    let ops = parse_trace(&repo_path("fixtures/transfer/nested-import.trace"));

    {
        let dev = FileDevice::open_writable(&img, len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");
        seed_destination(&mut fs, true);
        replay(&mut fs, &ops);
    }

    kernel_verify(&img);

    // 1.5 MiB: deliberately not a whole number of TreeImporter chunks, so the
    // final short chunk is exercised rather than only aligned ones.
    let big_len = (1 << 20) + (1 << 19);
    assert_manifest(
        &img,
        &[
            "d Empty".to_string(),
            "d Notes".to_string(),
            "d Notes/Deep".to_string(),
            "d Photos".to_string(),
            manifest_line_for_file("Notes/Deep/big.bin", 3, big_len),
            manifest_line_for_file("Notes/small.txt", 19, 11),
            // Seed 7, not the seeded "OLD CONTENT..." -- this is the assertion
            // that replace actually replaced.
            manifest_line_for_file("Photos/existing.txt", 7, 40),
        ],
    );
}

/// Pass 4's exit bar: a tree exported off the drive and re-imported must land
/// as exactly what it started as.
///
/// The destination of an export is a document provider, which no kernel can
/// grade — so exporting alone could only ever be checked against our own idea
/// of what should have been written. Feeding the exported bytes back through
/// the import path makes it answerable: a wrong export becomes a wrong tree on
/// a real filesystem, and that is something `btrfs check`, a mount, and a
/// sha256 per file can all disagree with.
///
/// The trace this replays comes from `TreeRoundTripTraceTest`, where the real
/// exporter, the real walker, and the real importer all run in sequence; only
/// the two endpoints are fakes.
#[test]
fn a_tree_survives_export_and_reimport() {
    let img = copy_fixture_to_temp("plain.img", "roundtrip");
    let len = fs::metadata(&img).unwrap().len();

    let ops = parse_trace(&repo_path("fixtures/transfer/roundtrip-import.trace"));

    {
        let dev = FileDevice::open_writable(&img, len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");
        seed_destination(&mut fs, false);
        replay(&mut fs, &ops);
    }

    kernel_verify(&img);

    let big_len = (1 << 20) + (1 << 19);
    assert_manifest(
        &img,
        &[
            "d Docs".to_string(),
            "d Docs/Sub".to_string(),
            "d Empty".to_string(),
            manifest_line_for_file("Docs/Sub/data.bin", 23, big_len),
            manifest_line_for_file("Docs/notes.txt", 11, 100),
            manifest_line_for_file("top.txt", 5, 7),
        ],
    );
}

/// §5.2 keeps whatever landed rather than rolling back, so a transfer that
/// stops partway must leave a filesystem the kernel still considers valid —
/// "half a tree" has to mean half a *correct* tree. This is the 2026-08-23
/// incident's shape, graded.
#[test]
fn a_cancelled_import_leaves_a_valid_filesystem() {
    let img = copy_fixture_to_temp("plain.img", "cancelled");
    let len = fs::metadata(&img).unwrap().len();

    let ops = parse_trace(&repo_path("fixtures/transfer/cancelled-import.trace"));

    {
        let dev = FileDevice::open_writable(&img, len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");
        seed_destination(&mut fs, false);
        replay(&mut fs, &ops);
    }

    kernel_verify(&img);

    // The completed prefix, and nothing beyond it: "B" and "B/three.txt" were
    // never reached, and their absence from this list is as much the assertion
    // as the presence of the rest. A cancel that had left a zero-length
    // three.txt behind -- the shape of the original incident -- adds a line
    // here and fails.
    assert_manifest(
        &img,
        &[
            "d A".to_string(),
            manifest_line_for_file("A/one.txt", 1, 12),
            manifest_line_for_file("A/two.txt", 2, 12),
        ],
    );
}
