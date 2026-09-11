//! Structural interior node growth and collapse verification on 4K non-mixed Btrfs medium.
//!
//! Exercises interior node splits (>121 children), tree height scaling from level 0 to 2,
//! mass deletion causing node removal and tree root collapse from level 2 back to 0.
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
fn test_conformance_interior_growth_and_shrink() {
    let dev = MemoryDevice::from_fixture("btrfs/nonmixed-4k.img");
    let mut fs = Btrfs::mount(dev.clone()).expect("mount nonmixed-4k");
    let mut model = ShadowModel::from_fs(&fs).expect("init model from nonmixed-4k");

    // 1. High fanout workload: create one directory and 2,000 files with 180-byte names
    fs.create_directory("/", "scale_dir").expect("create scale_dir");
    model
        .create_directory("", "scale_dir", 0, 0)
        .expect("model create scale_dir");

    luks_core::forensic::reset_structural_counts();

    const TOTAL_FILES: usize = 2000;
    println!("[TEST] Creating {TOTAL_FILES} files with 180-byte names in /scale_dir...");
    for i in 0..TOTAL_FILES {
        let name = format!("file_{i:04}_{}", "a".repeat(170));
        fs.create_file("/scale_dir", &name)
            .unwrap_or_else(|e| panic!("create_file failed at #{i}: {e:?}"));
        model
            .create_file("scale_dir", &name, Vec::new(), 0, 0)
            .expect("model create file");
    }

    let counts_after_create = luks_core::forensic::get_structural_counts();
    println!(
        "[5a] Counts after {TOTAL_FILES} creates:\n{}",
        luks_core::forensic::dump_structural_counts_summary()
    );

    assert!(
        counts_after_create.interior_splits > 0,
        "expected interior splits > 0, got {}",
        counts_after_create.interior_splits
    );
    assert!(
        counts_after_create.height_grew >= 2,
        "expected height grew >= 2, got {}",
        counts_after_create.height_grew
    );

    let tree_val = TreeValidator::validate_all(&fs).expect("validate all trees after 2000 creates");
    assert!(
        tree_val.fs_tree.tree_height >= 2,
        "FS tree height must reach at least 2, got {}",
        tree_val.fs_tree.tree_height
    );

    // --- Phase 4a: Grade Post-Create State (Level 2 Tree) with Linux Kernel Oracle ---
    fs.commit_active_batch().expect("commit active batch post-create");
    let mut scratch_create = ScratchFixture::new_empty(
        "interior_level2.img",
        dev.len() as u64,
        "interior_post_create",
    );
    dev.dump_to_file(scratch_create.path())
        .expect("dump post-create device to scratch");
    let verdict_create = common::oracle::verify_btrfs_verdict(scratch_create.path());
    if let common::oracle::OracleVerdict::Failed { ref stdout, ref stderr } = verdict_create {
        scratch_create.preserve();
        panic!(
            "[PHASE 4a KERNEL ORACLE FAILURE] Post-create level 2 filesystem failed kernel verification:\n\
             STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
    }
    if verdict_create.was_graded() {
        if counts_after_create.leaf_split_shape_1 > 0 { luks_core::forensic::record_kernel_graded("shape1"); }
        if counts_after_create.leaf_split_shape_2 > 0 { luks_core::forensic::record_kernel_graded("shape2"); }
        if counts_after_create.leaf_split_pos_len > 0 { luks_core::forensic::record_kernel_graded("pos_len"); }
        if counts_after_create.leaf_split_pos_mid > 0 { luks_core::forensic::record_kernel_graded("pos_mid"); }
        if counts_after_create.interior_splits > 0 { luks_core::forensic::record_kernel_graded("interior_splits"); }
        if counts_after_create.height_grew > 0 { luks_core::forensic::record_kernel_graded("height_grew"); }
        if counts_after_create.block_reused > 0 { luks_core::forensic::record_kernel_graded("block_reused"); }
        if counts_after_create.block_cowed > 0 { luks_core::forensic::record_kernel_graded("block_cowed"); }
        if counts_after_create.converge_total_calls > 0 { luks_core::forensic::record_kernel_graded("converge_calls"); }
    }

    // 2. Mass delete workload: delete ~90% (1,800 files)
    const DELETE_COUNT: usize = 1800;
    println!("[TEST] Deleting {DELETE_COUNT} files from /scale_dir...");
    for i in 0..DELETE_COUNT {
        let name = format!("file_{i:04}_{}", "a".repeat(170));
        let path = format!("/scale_dir/{name}");
        fs.delete_file(&path)
            .unwrap_or_else(|e| panic!("delete_file failed at #{i}: {e:?}"));
        model
            .delete(&format!("scale_dir/{name}"))
            .expect("model delete file");
    }

    let counts_after_delete = luks_core::forensic::get_structural_counts();
    println!(
        "[5a] Counts after {DELETE_COUNT} deletes (fs_tree level={}):\n{}",
        fs.fs_tree().level,
        luks_core::forensic::dump_structural_counts_summary()
    );
    assert!(
        counts_after_delete.node_removed > 0,
        "expected node removed > 0 after 1800 deletes, got {}",
        counts_after_delete.node_removed
    );

    println!("[TEST] Continuing delete of all remaining files from {DELETE_COUNT} to {TOTAL_FILES}...");
    for i in DELETE_COUNT..TOTAL_FILES {
        let name = format!("file_{i:04}_{}", "a".repeat(170));
        let path = format!("/scale_dir/{name}");
        fs.delete_file(&path)
            .unwrap_or_else(|e| panic!("delete_file failed at #{i}: {e:?}"));
        model
            .delete(&format!("scale_dir/{name}"))
            .expect("model delete file");
    }

    // Delete the empty scale_dir directory itself
    fs.delete_file("/scale_dir").expect("delete /scale_dir");
    model.delete("scale_dir").expect("model delete scale_dir");

    let final_counts = luks_core::forensic::get_structural_counts();
    println!(
        "[5a] Counts after all deletes (fs_tree level={}):\n{}",
        fs.fs_tree().level,
        luks_core::forensic::dump_structural_counts_summary()
    );

    assert!(
        final_counts.node_removed > 0,
        "expected node removed > 0, got {}",
        final_counts.node_removed
    );
    assert!(
        final_counts.root_collapsed > 0,
        "expected root collapsed > 0, got {}",
        final_counts.root_collapsed
    );

    // 3. Remount and verify model, trees, and accounting
    fs.commit_active_batch().expect("commit active batch");
    let final_fs = Btrfs::mount(dev.clone()).expect("remount fs");
    model
        .verify_against_fs(&final_fs)
        .expect("final shadow model verify");
    TreeValidator::validate_all(&final_fs).expect("final tree validate");
    AccountingOracle::assert_clean(&final_fs);

    // --- Phase 4a: Grade Post-Collapse State (Level 0 Tree) with Linux Kernel Oracle ---
    let mut scratch_collapse = ScratchFixture::new_empty(
        "interior_collapsed.img",
        dev.len() as u64,
        "interior_post_collapse",
    );
    dev.dump_to_file(scratch_collapse.path())
        .expect("dump post-collapse device to scratch");
    let verdict_collapse = common::oracle::verify_btrfs_verdict(scratch_collapse.path());
    if let common::oracle::OracleVerdict::Failed { ref stdout, ref stderr } = verdict_collapse {
        scratch_collapse.preserve();
        panic!(
            "[PHASE 4a KERNEL ORACLE FAILURE] Post-collapse level 0 filesystem failed kernel verification:\n\
             STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
    }
    if verdict_collapse.was_graded() {
        if final_counts.node_removed > counts_after_create.node_removed {
            luks_core::forensic::record_kernel_graded("node_removed");
        }
        if final_counts.root_collapsed > counts_after_create.root_collapsed {
            luks_core::forensic::record_kernel_graded("root_collapsed");
        }
    }

    println!("[TEST] test_conformance_interior_growth_and_shrink successfully completed.");
}
