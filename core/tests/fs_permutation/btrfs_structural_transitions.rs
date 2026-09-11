//! Phase 0.5: Structural Transition Conformance Tests.
//!
//! Covers three of the four gaps identified in Phase 0:
//! 1. GAP-1: Expanding `mutate_fn` under `cow_tree_mutate` fails closed with `Err(LuksError::CorruptFs)`.
//! 2. T8: Split at `pos == 0` inserting new tree minimum exercising `fixup_low_keys`.
//! 3. T12: Interior node splits on trees other than FS_TREE (EXTENT_TREE and CSUM_TREE).
//!
//! **T7 (shape 3) is not covered here and no test asserts it.** Four driver-level
//! workloads were built to reach it on 2026-09-09 — delete-and-refill, mixed-size
//! churn, fragmentation under space pressure, and an exact-fit adjacent-hole
//! recipe — and all four measured `leaf_split_shape_3 == 0` while `shape_1`
//! (3-7) and `shape_2` (23-30) fired and middle inserts did occur
//! (`leaf_split_pos_mid` 3-7), so the probes were live rather than vacuous.
//!
//! The mechanism: shape 3 needs `L + N > 3945` and `N + R > 3945` while
//! `L + R <= 3945`, so `N` must be large and land mid-leaf. EXTENT_CSUM is the
//! only driver item that reaches that size (every other type tops out near 439
//! bytes). A large csum item requires a large *contiguous* data extent, which
//! the allocator satisfies from a large free range or a fresh chunk — i.e. by
//! appending, giving `pos == len` and shape 2. Reused middle holes are small,
//! so their csum items are small and fit shape 1. Shape 3 is therefore
//! defensive code today.
//!
//! It should stay defensive rather than be deleted: `plan_leaf_split`'s three shapes
//! are what make that function total, and item widths are not fixed forever —
//! see `btrfs_csum_type_gate.rs` for what a 32-byte checksum does to csum item
//! sizing.

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::scratch::ScratchFixture;
use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::tree::{Key, FS_TREE_OBJECTID, INODE_ITEM_KEY};
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::cow::cow_tree_mutate;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;

fn run_verify_script(image_path: &Path) -> (bool, String, String) {
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
                println!(
                    "ORACLE VERIFIED: verify-btrfs.sh passed for {}",
                    image_path.display()
                );
            }
            (
                success,
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }
        Err(e) => (
            false,
            String::new(),
            format!("could not execute verify-btrfs.sh: {e}"),
        ),
    }
}

/// GAP-1 Regression: An in-place mutation closure that expands leaf size must fail
/// closed with Err(LuksError::CorruptFs) instead of corrupting or overflowing the leaf.
#[test]
fn test_gap1_expanding_mutate_fails_closed() {
    let scratch = ScratchFixture::new("btrfs/mixed-4k.img", "gap1_mutate_fails_closed");
    let file_len = fs::metadata(scratch.path()).unwrap().len();

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut allocator =
        FreeSpaceMap::from_extent_tree(&extent_tree).expect("create allocator");

    let root = fs.fs_tree();
    let root_key = Key::new(256, INODE_ITEM_KEY, 0);
    let pending = HashMap::new();

    // Invoke cow_tree_mutate with an expanding mutation closure.
    let result = cow_tree_mutate(
        &fs,
        &pending,
        root.bytenr,
        root.level,
        FS_TREE_OBJECTID,
        &root_key,
        root.generation + 1,
        &mut allocator,
        |leaf| {
            // Artificially expand an item in the leaf by appending bytes.
            assert!(!leaf.items.is_empty(), "leaf must have items");
            leaf.items[0].data.extend_from_slice(&[0xAA; 64]);
            Ok(())
        },
    );

    match result {
        Err(LuksError::CorruptFs(msg)) => {
            assert!(
                msg.contains("expanded leaf size"),
                "expected 'expanded leaf size' error message, got: {msg}"
            );
        }
        other => panic!("expected Err(LuksError::CorruptFs), got: {other:?}"),
    }
}

/// T8: Leaf split at `pos == 0` (new tree minimum), exercising `fixup_low_keys`.
#[test]
fn test_structural_pos_0_leaf_split_descending_keys() {
    use luks_core::forensic::{get_structural_counts, reset_structural_counts};
    use luks_core::fs::btrfs::write::cow::cow_tree_insert;

    let scratch = ScratchFixture::new("btrfs/mixed-4k.img", "t8_pos_0_leaf_split");
    let file_len = fs::metadata(scratch.path()).unwrap().len();

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut allocator = FreeSpaceMap::from_extent_tree(&extent_tree).expect("create allocator");

    // Start from a fresh empty leaf (tree owner = 9999)
    let generation = 100u64;
    let owner = 9999u64;
    let mut root_bytenr = allocator
        .allocate_metadata_for_owner(4096, owner)
        .expect("allocate root");
    let mut root_level = 0u8;
    let mut pending = HashMap::new();

    let leaf = luks_core::fs::btrfs::write::node::Leaf::new(
        root_bytenr,
        generation,
        owner,
        fs.superblock().metadata_uuid,
        fs.superblock().csum_type,
    );
    let emitted = leaf.emit(4096).expect("emit root leaf");
    pending.insert(root_bytenr, emitted);

    reset_structural_counts();

    // Insert keys in strictly descending order.
    // Since tree starts empty, every single insert is at pos == 0 (the new tree minimum).
    // When a leaf fills, it triggers a leaf split at pos == 0, exercising fixup_low_keys.
    let count = 200usize;
    for i in (0..count).rev() {
        let key = Key::new(1000, 1, i as u64);
        let data = vec![0x42u8; 32];
        let res = cow_tree_insert(
            &fs,
            &pending,
            root_bytenr,
            root_level,
            owner,
            key,
            data,
            generation,
            &mut allocator,
        )
        .expect("cow_tree_insert descending");

        root_bytenr = res.new_root_bytenr;
        root_level = res.new_root_level;
        for (b, data) in res.emitted_blocks {
            pending.insert(b, data);
        }
    }

    let counts = get_structural_counts();
    println!(
        "Descending insert results: pos_0={}, pos_len={}, pos_mid={}, shape_1={}, shape_2={}, height_grew={}",
        counts.leaf_split_pos_0,
        counts.leaf_split_pos_len,
        counts.leaf_split_pos_mid,
        counts.leaf_split_shape_1,
        counts.leaf_split_shape_2,
        counts.height_grew,
    );

    assert!(
        counts.leaf_split_pos_0 > 0,
        "T8 violation: expected at least 1 leaf split at pos == 0, got 0"
    );

    // Read the new root node to verify fixup_low_keys: child 0's key must be the absolute tree minimum (key 0).
    let root_node = luks_core::fs::btrfs::write::cow::read_node(&fs, &pending, root_bytenr)
        .expect("read root");
    assert!(root_level >= 1, "tree must have grown to at least level 1");
    let first_kp = root_node.key_ptr(0).expect("first key_ptr");
    assert_eq!(
        first_kp.key,
        Key::new(1000, 1, 0),
        "fixup_low_keys failed: root interior entry 0 did not receive new minimum key 0"
    );

    // Verify all children in root_node: each child's first key must match the interior key_ptr key,
    // and collecting all keys across leaves must produce strictly sorted 0..200 without gaps or duplicates.
    let mut collected_keys = Vec::with_capacity(count);
    for child_idx in 0..root_node.nr_items {
        let kp = root_node.key_ptr(child_idx).expect("key_ptr");
        let child_leaf = luks_core::fs::btrfs::write::cow::read_node(&fs, &pending, kp.blockptr)
            .expect("read leaf");
        assert_eq!(child_leaf.level, 0, "child must be a leaf at level 0");
        assert!(child_leaf.nr_items > 0, "child leaf must not be empty");
        let leaf_min_key = child_leaf.key(0).expect("leaf min key");
        assert_eq!(
            leaf_min_key, kp.key,
            "interior key_ptr key mismatch with leaf minimum key"
        );
        for item_idx in 0..child_leaf.nr_items {
            collected_keys.push(child_leaf.key(item_idx).expect("item key"));
        }
    }

    let expected_keys: Vec<Key> = (0..count as u64)
        .map(|i| Key::new(1000, 1, i))
        .collect();
    assert_eq!(
        collected_keys, expected_keys,
        "tree traversal across all leaves failed to produce exact sorted keys"
    );
}

/// T12: Interior node split on EXTENT_TREE driven through high-level streaming API.
///
/// An interior node with 4096-byte nodes holds (4096 - 101) / 33 = 121 key_ptrs.
/// Reaching level 2 in EXTENT_TREE requires >121 leaves.
/// Each leaf holds ~51 extent items.
/// Streaming 4,750 4k files forces EXTENT_TREE to exceed 121 leaves and triggers
/// interior node splits, growing the EXTENT_TREE root to level 2.
#[test]
fn test_interior_split_extent_tree_streaming() {
    use luks_core::forensic::get_structural_counts;
    use luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID;

    let scratch = ScratchFixture::new("btrfs/nonmixed-4k.img", "interior_split_extent");
    let file_len = fs::metadata(scratch.path()).unwrap().len();

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_ext_lvl = fs.tree_root(EXTENT_TREE_OBJECTID).unwrap().level;
    assert!(
        initial_ext_lvl < 2,
        "EXTENT_TREE must start below level 2 (got {initial_ext_lvl})"
    );

    let data_4k = vec![0x33u8; 4096];
    let start = std::time::Instant::now();
    let max_files = 6000;

    let mut split_at_file = None;

    for i in 0..max_files {
        let name = format!("stream_{i:05}.bin");
        let mut writer = match fs.begin_file(data_4k.len() as u64) {
            Ok(w) => w,
            Err(e) => {
                panic!("begin_file failed at file {i}: {e:?}");
            }
        };
        fs.write_chunk(&mut writer, &data_4k).expect("write_chunk");
        fs.finish_file(writer, "/", &name).expect("finish_file");

        if i % 50 == 0 {
            let ext_lvl = fs.tree_root(EXTENT_TREE_OBJECTID).unwrap().level;
            if ext_lvl >= 2 && split_at_file.is_none() {
                split_at_file = Some(i);
                println!("EXTENT_TREE reached level {ext_lvl} at file {i}!");
                break;
            }
        }
    }
    fs.commit_active_batch().expect("final commit");

    let ext_lvl = fs.tree_root(EXTENT_TREE_OBJECTID).unwrap().level;
    let elapsed = start.elapsed();
    println!(
        "EXTENT_TREE streaming test finished in {:?}. Final level: {ext_lvl} (split at {:?})",
        elapsed, split_at_file
    );

    assert_eq!(
        ext_lvl, 2,
        "EXTENT_TREE root level must have grown to level 2 (interior node split)"
    );

    let counts = get_structural_counts();
    assert!(
        counts.interior_splits > 0,
        "expected interior node splits recorded in forensic counts, got 0"
    );

    // Verify against Linux kernel oracle (btrfs check, mount, btrfs scrub)
    let (ok, out, err) = run_verify_script(scratch.path());
    assert!(
        ok,
        "kernel oracle verification failed on EXTENT_TREE level 2 image: {err}\n{out}"
    );
}

/// T12: Interior node split on CSUM_TREE driven through high-level streaming API.
///
/// 950 sectors * 4096 = 3,891,200 bytes (~3.71 MiB).
/// Generates 950 * 4 = 3800 bytes of CRC32c checksum payload.
/// Plus 25 bytes item overhead = 3825 bytes, nearly filling a 4096-byte leaf.
/// Each file forces a new leaf in CSUM_TREE.
/// Writing 125 files forces CSUM_TREE's root interior node to exceed 121 children and split to level 2.
#[test]
fn test_interior_split_csum_tree_large_files() {
    use luks_core::forensic::get_structural_counts;
    use luks_core::fs::btrfs::tree::CSUM_TREE_OBJECTID;

    let scratch = ScratchFixture::new("btrfs/nonmixed-4k.img", "interior_split_csum");
    let file_len = fs::metadata(scratch.path()).unwrap().len();

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_csum_lvl = fs.tree_root(CSUM_TREE_OBJECTID).unwrap().level;
    assert!(
        initial_csum_lvl < 2,
        "CSUM_TREE must start below level 2 (got {initial_csum_lvl})"
    );

    let data_len = 950 * 4096;
    let file_data = vec![0x77u8; data_len];
    let start = std::time::Instant::now();
    let num_files = 125;

    let mut split_at_file = None;

    for i in 0..num_files {
        let name = format!("csum_big_{i:03}.bin");
        let mut writer = match fs.begin_file(file_data.len() as u64) {
            Ok(w) => w,
            Err(e) => {
                panic!("CSUM test begin_file failed at file {i}: {e:?}");
            }
        };
        fs.write_chunk(&mut writer, &file_data).expect("write_chunk");
        fs.finish_file(writer, "/", &name).expect("finish_file");

        let csum_lvl = fs.tree_root(CSUM_TREE_OBJECTID).unwrap().level;
        if csum_lvl >= 2 && split_at_file.is_none() {
            split_at_file = Some(i);
            println!("CSUM_TREE reached level {csum_lvl} at file {i}!");
            break;
        }
    }
    fs.commit_active_batch().expect("final commit");

    let csum_lvl = fs.tree_root(CSUM_TREE_OBJECTID).unwrap().level;
    let elapsed = start.elapsed();
    println!(
        "CSUM test finished in {:?}. CSUM_TREE final level: {csum_lvl} (split at {:?})",
        elapsed, split_at_file
    );

    assert_eq!(
        csum_lvl, 2,
        "CSUM_TREE root level must have grown to level 2 (interior node split)"
    );

    let counts = get_structural_counts();
    assert!(
        counts.interior_splits > 0,
        "expected interior node splits recorded in forensic counts, got 0"
    );

    // Verify against Linux kernel oracle (btrfs check, mount, btrfs scrub)
    let (ok, out, err) = run_verify_script(scratch.path());
    assert!(
        ok,
        "kernel oracle verification failed on CSUM_TREE level 2 image: {err}\n{out}"
    );
}
