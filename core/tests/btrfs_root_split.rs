//! Fix 4 (E.3): the interior-node-split and root-height-increment paths in
//! `fs/btrfs/write/cow.rs` have a real test now.
//!
//! Before this test, those branches had never executed: Pass E's own suite
//! creates 5 files, and an adversarial 5,557-file stress run during review
//! hit `FilesystemFull` on `plain.img` before the FS tree's interior root
//! (16 KiB nodes, 493-child capacity) ever needed to split.
//!
//! `mixed-4k.img` turned out to be enough on its own: 4 KiB nodes fill an
//! interior root at 121 children instead of 493 — `(4096 - 101) / 33 = 121`,
//! `HEADER_SIZE`/`KEY_PTR_SIZE` from `tree.rs` — and, once the bug below was
//! fixed, creating a few hundred files through the real `Btrfs::create_file`
//! path is enough to reach it without exhausting the fixture's 64 MiB.
//!
//! # A real bug, found by this test
//!
//! The first version of this test hit `FilesystemFull` after only ~318
//! files, with the FS tree still at level 1 — nowhere near a root split, and
//! nowhere near the fixture's actual free space (confirmed separately: the
//! metadata block group was <2% used at the point of failure). Instrumenting
//! every `FilesystemFull` call site pinned it to `Leaf::insert_item` inside
//! `txn.rs`'s fixed-point convergence loop, in the code that records each
//! newly allocated tree block as a `METADATA_ITEM` in the extent tree.
//!
//! That call used `cow_tree_mutate` — which has no leaf-split path at all;
//! its leaf branch runs the mutation closure and unconditionally emits, so
//! a full target leaf fails closed — for what is actually a brand new key
//! (a just-allocated block cannot already have a `METADATA_ITEM`), not an
//! edit of an existing one. `cow_tree_insert`, which does carry the
//! leaf-split/root-increment logic this needs, was already used two call
//! sites above for extent-tree *data*-extent inserts. `txn.rs` now uses it
//! for metadata-item inserts too, so the extent tree's own B-tree grows
//! properly instead of hard-failing while the disk is nearly empty.
//!
//! This makes the plan's "adversarial 5,557-file run hit FilesystemFull on
//! plain.img" almost certainly a case of the very same bug, not exhausted
//! media — plain.img's larger 16 KiB nodes just needed more churn to trigger
//! it first at the extent tree instead of anywhere near an FS-tree split.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_root_split
//! ```
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

/// See the note on the same counter in `btrfs_create_file.rs`: a timestamp
/// alone does not make this path unique, because this host's `SystemTime`
/// advances in 1 µs steps and `cargo` starts a binary's tests together.
static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-rootsplit-{src_name}-{}-{}-{}",
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

fn run_verify_script(image_path: &PathBuf) -> (bool, String, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !script.exists() {
        return (false, String::new(), "verify-btrfs.sh not found".into());
    }

    if !common::oracle::gate() {
        return (true, String::new(), String::new());
    }

    let output = Command::new(&script).arg(image_path).output();

    match output {
        Ok(out) => {
            let success = out.status.success();
            if success {
                println!("ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
            }
            (
                success,
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }
        Err(e) => (false, String::new(), format!("could not execute verify-btrfs.sh: {e}")),
    }
}

/// A cap on how many files this test will try to create before giving up.
/// Measured behavior (2026-08-15, post-fix): mixed-4k.img's FS tree reaches
/// level 2 at file 701 of ~702 created. This is set generously above that so
/// a moderate regression in packing density does not make the test flaky,
/// while still failing loudly — not silently proving nothing — if the split
/// is never reached at all.
const MAX_FILES: usize = 3000;

#[test]
fn interior_and_root_split_on_mixed_4k_img() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fsx = Btrfs::mount(dev).expect("mount writable btrfs");

    let start_level = fsx.fs_tree().level;

    // mixed-4k.img's FS tree starts as a single leaf (level 0). Assert that
    // rather than assume it, so a fixture change that pre-splits the tree
    // does not silently turn this into a no-op test.
    assert_eq!(
        start_level, 0,
        "fixture assumption violated: mixed-4k.img's FS tree is no longer a single leaf"
    );

    let mut created_names: Vec<String> = Vec::new();
    let mut level_after_leaf_split: Option<u8> = None;
    let mut root_split_file_count: Option<usize> = None;

    for i in 0..MAX_FILES {
        let name = format!("split_{i:05}.txt");
        fsx.create_file("/", &name)
            .unwrap_or_else(|e| panic!("create_file failed for {name} (file #{i}, level {} at failure): {e:?}", fsx.fs_tree().level));
        created_names.push(name);

        let lvl = fsx.fs_tree().level;
        if lvl == 1 && level_after_leaf_split.is_none() {
            level_after_leaf_split = Some(lvl);
        }
        if lvl >= 2 {
            root_split_file_count = Some(i + 1);
            break;
        }
    }

    // The whole point of this test: assert the split actually happened, not
    // just that a lot of files got created. A pass here with the level
    // unchanged would be worse than no test at all.
    let end_level = fsx.fs_tree().level;
    assert!(
        root_split_file_count.is_some(),
        "created {} files (MAX_FILES={MAX_FILES}) without the FS tree's root level ever \
         reaching 2 (interior root split never triggered) — level stayed at {end_level}",
        created_names.len()
    );
    assert!(
        end_level > start_level,
        "fs_tree().level did not increase: started at {start_level}, ended at {end_level}"
    );
    assert_eq!(
        end_level, 2,
        "expected the root to have grown to exactly level 2 (one split above the leaf-split \
         level 1), got {end_level}"
    );
    assert!(
        level_after_leaf_split.is_some(),
        "never observed the intermediate leaf-split level 1 — level jumped straight from \
         {start_level} to {end_level}, which would mean this test isn't exercising what it \
         claims to"
    );

    println!(
        "root split reached: {} files created, level {start_level} -> {end_level} \
         (intermediate leaf-split level observed: {:?})",
        created_names.len(),
        level_after_leaf_split
    );

    drop(fsx);

    // Remount fresh — drop the in-memory Btrfs and reopen the device — so
    // every check below reads through actual on-disk bytes, not anything
    // cached from the writing session.
    let dev_ro = FileDevice::open(&temp_img).expect("reopen read-only");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs read-only");

    assert_eq!(
        fs_ro.fs_tree().level,
        2,
        "root split did not survive a fresh remount from disk"
    );

    // Spot-check across the whole key range, not just the most recent
    // writes: first, middle, and last of the files this test created. A
    // broken interior split typically strands one subtree, so checking only
    // recently-written files can miss exactly the kind of corruption this
    // test exists to catch.
    let n = created_names.len();
    let check_indices = [0, n / 2, n - 1];
    for &idx in &check_indices {
        let name = &created_names[idx];
        let path = format!("/{name}");
        let info = fs_ro
            .file_info(&path)
            .unwrap_or_else(|e| panic!("file_info failed for {path} (index {idx} of {n}): {e:?}"));
        assert_eq!(info.size, 0, "{path} should be an empty file");
        assert!(info.file_type.is_file(), "{path} should be a regular file");
    }

    // The fixture's own pre-existing content must still be intact — proof
    // that growing the tree around it did not strand or corrupt anything
    // that predates this test's writes.
    let root_entries = fs_ro.list_dir("/").expect("list root dir on remount");
    assert!(root_entries.iter().any(|e| e.name == "hello.txt"));
    assert!(root_entries.iter().any(|e| e.name == "data.bin"));
    assert!(root_entries.iter().any(|e| e.name == "docs"));
    assert!(root_entries.iter().any(|e| e.name == created_names[0]));
    assert!(root_entries.iter().any(|e| e.name == created_names[n - 1]));

    let docs_entries = fs_ro.list_dir("/docs").expect("list /docs on remount");
    assert!(docs_entries.iter().any(|e| e.name == "readme.md"));

    drop(fs_ro);

    // Grade with the real kernel oracle: btrfs check --readonly, a real
    // kernel mount, and btrfs scrub — the only thing that actually proves
    // the tree this test built is structurally sound and every checksum
    // verifies, at a depth no fixture had previously reached.
    let (oracle_clean, stdout, stderr) = run_verify_script(&temp_img);
    if !oracle_clean {
        eprintln!("verify-btrfs.sh stdout:\n{stdout}");
        eprintln!("verify-btrfs.sh stderr:\n{stderr}");
    } else {
        // Surface the scrub verdict even on success, since that is the line
        // this whole oracle exists to make trustworthy (see verify-btrfs.sh's
        // own comments on scrub's self-healing exit-0 false negative).
        println!("verify-btrfs.sh output:\n{stdout}");
    }

    let _ = fs::remove_file(&temp_img);

    assert!(
        oracle_clean,
        "kernel oracle verification failed after triggering an FS-tree root split on mixed-4k.img"
    );
}
