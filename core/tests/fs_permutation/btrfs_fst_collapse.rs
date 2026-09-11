//! Structural Free-Space Tree growth and collapse verification on 4K Btrfs medium.
//!
//! Exercises FST leaf splits, tree height scaling from level 0 to multi-leaf,
//! mass deletion causing extent coalescing, FST node removal, and tree root collapse back to level 0.
//! Also exercises deep B-tree height scaling (0 -> 1 -> 2 -> 1 -> 0) on FREE_SPACE_TREE_OBJECTID.
//!
//! Runs in its own process to guarantee isolated structural atomic counters.

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use common::accounting::AccountingOracle;
use common::btree_validator::TreeValidator;
use common::fs_model::ShadowModel;
use common::mem_device::MemoryDevice;
use common::scratch::ScratchFixture;
use luks_core::fs::btrfs::Btrfs;

#[test]
fn test_conformance_fst_growth_and_shrink() {
    let dev = MemoryDevice::from_fixture("btrfs/mixed-4k.img");
    let mut fs = Btrfs::mount(dev.clone()).expect("mount mixed-4k");
    let mut model = ShadowModel::from_fs(&fs).expect("init model from mixed-4k");

    let initial_val = TreeValidator::validate_all(&fs).expect("initial tree validation");
    let fst_init = initial_val
        .free_space_tree
        .expect("mixed-4k must have free space tree");
    assert_eq!(
        fst_init.tree_height, 0,
        "mixed-4k initial FST must be a single leaf"
    );

    luks_core::forensic::reset_structural_counts();

    // 1. Fragment free space: create 360 files with 4 KiB data each.
    // In 4 KiB nodes, a single leaf holds max ~158 extent items.
    // Deleting every other file will create ~350 free holes, pushing FST past the single-leaf ceiling.
    const TOTAL_FILES: usize = 700;
    println!("[TEST] Creating {TOTAL_FILES} files of 4 KiB each in / ...");
    let chunk_data = vec![0xAA; 4096];
    for i in 0..TOTAL_FILES {
        let name = format!("fst_frag_{i:04}.dat");
        fs.create_file_with_data("/", &name, &chunk_data)
            .unwrap_or_else(|e| panic!("create_file_with_data failed at #{i}: {e:?}"));
        model
            .create_file("", &name, chunk_data.clone(), 0, 0)
            .expect("model create file");
    }

    // Now delete all even-indexed files (180 files)
    println!("[TEST] Deleting 180 alternate files to fragment free space...");
    for i in (0..TOTAL_FILES).step_by(2) {
        let name = format!("fst_frag_{i:04}.dat");
        let path = format!("/{name}");
        fs.delete_file(&path)
            .unwrap_or_else(|e| panic!("delete_file failed at #{i}: {e:?}"));
        model.delete(&name).expect("model delete file");
    }

    let counts_after_fragment = luks_core::forensic::get_structural_counts();
    println!(
        "[FST] Counts after fragmentation:\n{}",
        luks_core::forensic::dump_structural_counts_summary()
    );

    assert!(
        counts_after_fragment.fst_leaf_split > 0,
        "expected fst_leaf_split > 0, got {}",
        counts_after_fragment.fst_leaf_split
    );
    assert!(
        counts_after_fragment.fst_height_grew > 0,
        "expected fst_height_grew > 0, got {}",
        counts_after_fragment.fst_height_grew
    );

    let tree_val_split = TreeValidator::validate_all(&fs).expect("validate all trees after FST split");
    let fst_split = tree_val_split
        .free_space_tree
        .expect("FST must exist after split");
    assert!(
        fst_split.tree_height >= 1,
        "FST root level must reach at least 1, got {}",
        fst_split.tree_height
    );

    AccountingOracle::assert_clean(&fs);

    // --- Phase 4a: Grade Post-Split State (Multi-Leaf FST) with Linux Kernel Oracle ---
    fs.commit_active_batch().expect("commit active batch post-split");
    let mut scratch_split = ScratchFixture::new_empty(
        "fst_split_level1.img",
        dev.len() as u64,
        "fst_post_split",
    );
    dev.dump_to_file(scratch_split.path())
        .expect("dump post-split device to scratch");
    let verdict_split = common::oracle::verify_btrfs_verdict(scratch_split.path());
    if let common::oracle::OracleVerdict::Failed { ref stdout, ref stderr } = verdict_split {
        scratch_split.preserve();
        panic!(
            "[PHASE F3 KERNEL ORACLE FAILURE] Post-split multi-leaf FST filesystem failed kernel verification:\n\
             STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
    }
    if verdict_split.was_graded() {
        if counts_after_fragment.fst_leaf_split > 0 {
            luks_core::forensic::record_kernel_graded("fst_leaf_split");
        }
        if counts_after_fragment.fst_height_grew > 0 {
            luks_core::forensic::record_kernel_graded("fst_height_grew");
        }
    }

    // 2. Coalesce free space: delete all remaining odd-indexed files (180 files)
    println!("[TEST] Deleting all remaining files to coalesce free extents...");
    for i in (1..TOTAL_FILES).step_by(2) {
        let name = format!("fst_frag_{i:04}.dat");
        let path = format!("/{name}");
        fs.delete_file(&path)
            .unwrap_or_else(|e| panic!("delete_file failed at #{i}: {e:?}"));
        model.delete(&name).expect("model delete file");
    }

    let final_counts = luks_core::forensic::get_structural_counts();
    println!(
        "[FST] Counts after all deletes:\n{}",
        luks_core::forensic::dump_structural_counts_summary()
    );

    assert!(
        final_counts.fst_node_removed > 0,
        "expected fst_node_removed > 0, got {}",
        final_counts.fst_node_removed
    );
    assert!(
        final_counts.fst_root_collapsed > 0,
        "expected fst_root_collapsed > 0, got {}",
        final_counts.fst_root_collapsed
    );

    // Remount fresh and verify model, 6 trees, and accounting oracle
    fs.commit_active_batch().expect("commit active batch post-collapse");
    let final_fs = Btrfs::mount(dev.clone()).expect("remount fs");
    model
        .verify_against_fs(&final_fs)
        .expect("final shadow model verify");
    let final_report = TreeValidator::validate_all(&final_fs).expect("final 6-tree validate");
    let final_fst = final_report
        .free_space_tree
        .expect("FST must exist post-collapse");
    assert_eq!(
        final_fst.tree_height, 0,
        "FST root level must have collapsed back to 0, got {}",
        final_fst.tree_height
    );
    AccountingOracle::assert_clean(&final_fs);

    // --- Phase 4a: Grade Post-Collapse State (Level 0 Tree) with Linux Kernel Oracle ---
    let mut scratch_collapse = ScratchFixture::new_empty(
        "fst_collapsed.img",
        dev.len() as u64,
        "fst_post_collapse",
    );
    dev.dump_to_file(scratch_collapse.path())
        .expect("dump post-collapse device to scratch");
    let verdict_collapse = common::oracle::verify_btrfs_verdict(scratch_collapse.path());
    if let common::oracle::OracleVerdict::Failed { ref stdout, ref stderr } = verdict_collapse {
        scratch_collapse.preserve();
        panic!(
            "[PHASE F3 KERNEL ORACLE FAILURE] Post-collapse level 0 FST filesystem failed kernel verification:\n\
             STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
    }
    if verdict_collapse.was_graded() {
        if final_counts.fst_node_removed > counts_after_fragment.fst_node_removed {
            luks_core::forensic::record_kernel_graded("fst_node_removed");
        }
        if final_counts.fst_root_collapsed > counts_after_fragment.fst_root_collapsed {
            luks_core::forensic::record_kernel_graded("fst_root_collapsed");
        }
    }

    println!("[TEST] test_conformance_fst_growth_and_shrink successfully completed.");
}
