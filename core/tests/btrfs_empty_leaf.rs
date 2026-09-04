//! Regression: a delete must never leave an empty leaf linked from its parent.
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_empty_leaf
//! ```
//!
//! # The bug this exists for
//!
//! Found on real hardware 2026-08-23, on the USB test stick, after the Android
//! app's directory export failed intermittently with `CorruptFs("btrfs node
//! has no items")`. That error is raised by `cursor.rs`'s `retreat_leaf` when
//! it descends a parent's block pointer and finds `nr_items == 0` — an honest
//! reader reporting damage, not the bug itself.
//!
//! The kernel agreed. `tools/verify-image.sh` on an image of the stick:
//!
//! ```text
//! Wrong key of child node/leaf, wanted: (299, 108, 2678784), have: (0, 0, 0)
//! root 5 inode 300 errors 2001, no inode item, link count wrong
//!         unresolved ref dir 256 index 36 namelen 6 name ggtyti ...
//! ERROR: errors found in fs roots
//! ```
//!
//! and `btrfs inspect-internal dump-tree -t 5` found five of them:
//!
//! ```text
//! leaf 30949376 items 0 free space 16283 generation 235 owner FS_TREE
//! leaf 31735808 items 0 free space 16283 generation 323 owner FS_TREE
//! leaf 31916032 items 0 free space 16283 generation 323 owner FS_TREE
//! leaf 31932416 items 0 free space 16283 generation 323 owner FS_TREE
//! leaf 31981568 items 0 free space 16283 generation 323 owner FS_TREE
//! ```
//!
//! Every one `flags 0x1(WRITTEN)`, every one parsing cleanly with a valid
//! checksum. So this was not a lost write, a zeroed block, or a bad chunk
//! mapping: our own writer serialised a zero-item leaf on purpose and linked
//! the parent to it. Four share `generation 323` — a single transaction
//! emptied four leaves at once, which is the shape of `Transaction::delete_file`
//! issuing one `cow_tree_mutate` per item across an inode's items and csums.
//!
//! The cause is `cow_descend` in `write/cow.rs`: its leaf branch runs
//! `mutate_fn` (which may `delete_item` the last item) and then emits and
//! links the leaf unconditionally. The insert path, `cow_descend_insert`,
//! documents that it never produces an empty leaf; the delete path had no
//! equivalent guarantee — no removal, no propagation, nothing.
//!
//! # Why the existing delete tests missed it
//!
//! `btrfs_delete.rs` deletes one or a few files from `plain.img`, whose 16 KiB
//! leaves comfortably hold every item those tests create in a single leaf.
//! Emptying a leaf needs a leaf that holds *only* the items being deleted,
//! which needs a tree deep enough to have more than one. This test uses
//! `mixed-4k.img` (4 KiB nodes) and enough churn to get there — the same
//! reason `btrfs_root_split.rs` uses that fixture.
//!
//! # Grading
//!
//! Two independent checks, because they fail differently:
//!
//! 1. A direct structural scan of every node reachable from the FS tree root,
//!    asserting no *child* has `nr_items == 0`. Fast, and it names the exact
//!    bytenr, which a kernel verdict does not.
//! 2. `tools/verify-btrfs.sh` — the kernel's own opinion, per RULES.md. The
//!    scan is our code checking our code; it is the oracle that makes this
//!    test mean something.
//!
//! A root that is itself a leaf with zero items is *not* flagged: it has no
//! parent, so it violates nothing. Only a child does.
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

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let dst = std::env::temp_dir().join(format!(
        "btrfs-empty-leaf-{src_name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_script(image_path: &PathBuf) -> (bool, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !script.exists() {
        return (false, "verify-btrfs.sh not found".to_string());
    }
    if !common::oracle::gate() {
        return (true, "oracle skipped".to_string());
    }

    match Command::new(&script).arg(image_path).output() {
        Ok(out) => (
            out.status.success(),
            format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ),
        Err(e) => (false, format!("could not execute verify-btrfs.sh: {e}")),
    }
}

/// Every child block reachable from `bytenr` that has no items, as
/// `(parent_bytenr, child_bytenr, child_level)`.
///
/// Deliberately walks the whole tree rather than searching for one key: the
/// damage on the stick sat in leaves nothing was looking up at the time, and a
/// targeted probe would have walked straight past four of the five.
fn find_empty_children<D: luks_core::device::ReadAt>(
    fs: &Btrfs<D>,
    bytenr: u64,
    out: &mut Vec<(u64, u64, u8)>,
) {
    let node = match fs.read_node(bytenr) {
        Ok(n) => n,
        // An unreadable node is a different bug, and the oracle will say so
        // far better than a panic here would.
        Err(_) => return,
    };
    if node.is_leaf() {
        return;
    }
    for i in 0..node.nr_items {
        let ptr = match node.key_ptr(i) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(child) = fs.read_node(ptr.blockptr) {
            if child.nr_items == 0 {
                out.push((bytenr, ptr.blockptr, child.level));
            }
            find_empty_children(fs, ptr.blockptr, out);
        }
    }
}

#[test]
fn deleting_files_never_leaves_an_empty_leaf_linked_from_its_parent() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fsx = Btrfs::mount(dev).expect("mount writable btrfs");

    assert_eq!(
        fsx.fs_tree().level,
        0,
        "fixture assumption violated: mixed-4k.img's FS tree is no longer a single leaf"
    );

    // Enough files to push the tree past a single leaf. Each carries data, so
    // it owns INODE_ITEM/INODE_REF/DIR_ITEM/DIR_INDEX/EXTENT_DATA items plus
    // csums — the same item mix `delete_file` later walks and removes, which
    // is what makes emptying a leaf reachable at all.
    const FILES: usize = 400;
    let payload = b"empty leaf regression payload";
    let mut names = Vec::with_capacity(FILES);
    for i in 0..FILES {
        let name = format!("victim_{i:05}.bin");
        fsx.create_file_with_data("/", &name, payload)
            .unwrap_or_else(|e| panic!("create_file_with_data failed for {name} (#{i}): {e:?}"));
        names.push(name);
    }

    let level_after_create = fsx.fs_tree().level;
    assert!(
        level_after_create >= 1,
        "FS tree never grew past a single leaf after {FILES} files (level {level_after_create}) — \
         with only one leaf there is no parent to dangle from, so this test would prove nothing"
    );

    // Delete most of them, keeping some so the tree stays multi-level. This
    // mirrors the stick: a live filesystem with a run of deletes through it,
    // not a wipe.
    let to_delete = names.len() * 3 / 4;
    for name in names.iter().take(to_delete) {
        fsx.delete_file(&format!("/{name}"))
            .unwrap_or_else(|e| panic!("delete_file failed for {name}: {e:?}"));
    }

    drop(fsx);

    // Remount from disk: the question is what was *written*, not what an
    // in-memory tree thinks it wrote.
    let dev_ro = FileDevice::open(&temp_img).expect("reopen read-only");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs read-only");

    let root = fs_ro.fs_tree();
    let mut empties = Vec::new();
    find_empty_children(&fs_ro, root.bytenr, &mut empties);

    assert!(
        empties.is_empty(),
        "delete left {} empty node(s) linked from a parent — the exact corruption found on the \
         USB test stick on 2026-08-23. (parent, child, child_level): {:?}",
        empties.len(),
        empties
    );

    let (ok, detail) = run_verify_script(&temp_img);
    assert!(ok, "kernel oracle rejected the filesystem after deletes:\n{detail}");

    let _ = fs::remove_file(&temp_img);
}
