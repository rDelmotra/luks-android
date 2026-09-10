//! Btrfs Structural Conformance & Permutation Test Suite (Phase 3).
//!
//! Exercises end-to-end Btrfs filesystem conformance via the high-level driver API
//! using an independent in-memory shadow model (`ShadowModel`) and deterministic
//! pseudo-random operation sequences (`OpGenerator`).
//!
//! Two-Tier In-Process Grading:
//! - **Tier A** (After Every Operation): In-memory structural verification across all
//!   five trees (`TreeValidator::validate_all`) and immediate model correspondence.
//! - **Tier B** (On Commit / Remount): Remounts from device bytes, validates full
//!   shadow model (`model.verify_against_fs`), and asserts clean space accounting
//!   (`AccountingOracle::assert_clean`).
//!
//! Replayability:
//! - Every test prints its seed prominently.
//! - Any test run can be deterministically reproduced by setting `LUKS_CONFORMANCE_SEED`.

#![cfg(feature = "dangerous-write-support")]

mod common;

use common::accounting::AccountingOracle;
use common::btree_validator::TreeValidator;
use common::fs_model::{
    execute_op_tier_ab, ConformanceRng, OpGenerator, ShadowModel,
};
use common::mem_device::MemoryDevice;
use luks_core::fs::btrfs::Btrfs;

#[test]
fn test_shadow_model_basic_lifecycle() {
    let mem_dev = MemoryDevice::from_fixture("btrfs/plain.img");
    let mut fs = Btrfs::mount(mem_dev.clone()).expect("mount plain fixture");

    // 1. Initialize shadow model from existing fixture
    let mut model = ShadowModel::from_fs(&fs).expect("populate shadow model from fs");
    assert!(!model.is_empty(), "model should contain fixture entries");
    model.verify_against_fs(&fs).expect("initial model verify");

    // 2. Execute discrete driver mutations and verify model sync
    // a. Create directory
    fs.create_directory("/", "conf_dir").expect("create dir");
    model
        .create_directory("", "conf_dir", 0, 0)
        .expect("model create dir");
    fs.set_mtime("/conf_dir", 1_700_000_000, 0).expect("set mtime");
    model
        .set_mtime("conf_dir", 1_700_000_000, 0)
        .expect("model set mtime");
    model.verify_against_fs(&fs).expect("verify after mkdir");

    // b. Create file with data
    let test_data = b"Hello Conformance World! 1234567890".to_vec();
    fs.create_file_with_data("/conf_dir", "hello.txt", &test_data)
        .expect("create file");
    fs.set_mtime("/conf_dir/hello.txt", 1_700_000_001, 0).expect("set mtime");
    model
        .create_file("conf_dir", "hello.txt", test_data.clone(), 1_700_000_001, 0)
        .expect("model create file");
    model.verify_against_fs(&fs).expect("verify after create file");

    // c. Create empty file and write data to it
    fs.create_file("/conf_dir", "written.txt")
        .expect("create empty file");
    fs.set_mtime("/conf_dir/written.txt", 1_700_000_002, 0).expect("set mtime");
    model
        .create_file("conf_dir", "written.txt", Vec::new(), 1_700_000_002, 0)
        .expect("model create empty file");
    model.verify_against_fs(&fs).expect("verify after create empty file");

    let written_data = b"Written data into empty file".to_vec();
    fs.write_file("/conf_dir/written.txt", &written_data)
        .expect("write file");
    fs.set_mtime("/conf_dir/written.txt", 1_700_000_003, 0).expect("set mtime");
    model
        .write_file("conf_dir/written.txt", written_data, 1_700_000_003, 0)
        .expect("model write file");
    model.verify_against_fs(&fs).expect("verify after write file");

    // d. Rename file
    fs.rename("/conf_dir", "hello.txt", "/conf_dir", "renamed.txt")
        .expect("rename file");
    model
        .rename(
            "conf_dir",
            "hello.txt",
            "conf_dir",
            "renamed.txt",
            1_700_000_004,
            0,
        )
        .expect("model rename file");
    model.verify_against_fs(&fs).expect("verify after rename file");

    // e. Delete files
    fs.delete_file("/conf_dir/renamed.txt").expect("delete renamed file");
    model
        .delete("conf_dir/renamed.txt")
        .expect("model delete file");
    model.verify_against_fs(&fs).expect("verify after delete renamed file");

    fs.delete_file("/conf_dir/written.txt").expect("delete written file");
    model
        .delete("conf_dir/written.txt")
        .expect("model delete file");
    model.verify_against_fs(&fs).expect("verify after delete written file");

    // f. Delete directory
    fs.delete_file("/conf_dir").expect("delete dir");
    model.delete("conf_dir").expect("model delete dir");
    model.verify_against_fs(&fs).expect("verify after delete dir");

    // Validate tree and accounting invariants
    TreeValidator::validate_all(&fs).expect("validate all trees");
    AccountingOracle::assert_clean(&fs);
}

#[test]
fn test_conformance_deterministic_replay() {
    let (rng, seed) = ConformanceRng::from_env_or_default(0x436f_6e66_6f72_6d31);
    println!("[TEST] Deterministic Replay Test starting with seed: {seed:#018x}");

    const STEPS: usize = 25;

    // Run 1
    let dev1 = MemoryDevice::from_fixture("btrfs/plain.img");
    let mut fs1 = Btrfs::mount(dev1.clone()).expect("mount 1");
    let mut model1 = ShadowModel::from_fs(&fs1).expect("model 1");
    let mut gen1 = OpGenerator::new(rng.clone());

    let mut ops1 = Vec::new();
    for step in 1..=STEPS {
        let op = gen1.next_op(&model1);
        ops1.push(op.clone());
        execute_op_tier_ab(step, &op, &mut fs1, &mut model1, &dev1)
            .unwrap_or_else(|e| panic!("run 1 failed at step {step} with seed {seed:#018x}: {e}"));
    }

    // Run 2 (fresh device with identical seed)
    let dev2 = MemoryDevice::from_fixture("btrfs/plain.img");
    let mut fs2 = Btrfs::mount(dev2.clone()).expect("mount 2");
    let mut model2 = ShadowModel::from_fs(&fs2).expect("model 2");
    let mut gen2 = OpGenerator::new(ConformanceRng::new(seed));

    let mut ops2 = Vec::new();
    for step in 1..=STEPS {
        let op = gen2.next_op(&model2);
        ops2.push(op.clone());
        execute_op_tier_ab(step, &op, &mut fs2, &mut model2, &dev2)
            .unwrap_or_else(|e| panic!("run 2 failed at step {step} with seed {seed:#018x}: {e}"));
    }

    // Assert: Generated operations must be 100% identical
    assert_eq!(
        ops1, ops2,
        "Operation sequences diverged between run 1 and run 2 with seed {seed:#018x}"
    );

    // Assert: Model entries must have identical keys and file contents
    assert_eq!(
        model1.all_entries(),
        model2.all_entries(),
        "Model entries diverged"
    );
    for file in model1.all_files() {
        assert_eq!(
            model1.get_file(&file),
            model2.get_file(&file),
            "File content diverged for '{file}'"
        );
    }

    // Assert: Both filesystems must produce identical TreeValidator structural reports
    let rep1 = TreeValidator::validate_all(&fs1).expect("rep1");
    let rep2 = TreeValidator::validate_all(&fs2).expect("rep2");
    assert_eq!(
        rep1, rep2,
        "TreeValidator structural reports diverged with seed {seed:#018x}"
    );

    // Assert: Both filesystems must produce identical Accounting reports
    let acct1 = AccountingOracle::assert_clean(&fs1);
    let acct2 = AccountingOracle::assert_clean(&fs2);
    assert_eq!(
        acct1, acct2,
        "Accounting reports diverged with seed {seed:#018x}"
    );
}

#[test]
fn test_conformance_mixed_4k_stress() {
    let (rng, seed) = ConformanceRng::from_env_or_default(0x6d69_7865_6434_6b31);
    println!("[TEST] mixed-4k.img Conformance Stress Test with seed: {seed:#018x}");
    println!(
        "To reproduce: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_mixed_4k_stress"
    );

    let dev = MemoryDevice::from_fixture("btrfs/mixed-4k.img");
    let mut fs = Btrfs::mount(dev.clone()).expect("mount mixed-4k");
    let mut model = ShadowModel::from_fs(&fs).expect("init model from mixed-4k");
    let mut gen = OpGenerator::new(rng);

    const STEPS: usize = 50;
    let mut total_ops_succeeded = 0;
    let mut total_full_events = 0;
    let mut remount_count = 0;

    for step in 1..=STEPS {
        let op = gen.next_op(&model);
        let res = execute_op_tier_ab(step, &op, &mut fs, &mut model, &dev).unwrap_or_else(|e| {
            panic!(
                "[CONFORMANCE FAILURE] Step {step} failed with seed {seed:#018x}: {e}\n\
                 Reproduce with: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_mixed_4k_stress"
            );
        });

        if res.skipped_full {
            total_full_events += 1;
        } else {
            total_ops_succeeded += 1;
        }
        if res.accounting_report.is_some() {
            remount_count += 1;
        }
    }

    // Final Tier B validation
    fs.commit_active_batch().expect("final commit");
    let final_fs = Btrfs::mount(dev.clone()).expect("final remount");
    model.verify_against_fs(&final_fs).expect("final shadow model verify");
    let final_trees = TreeValidator::validate_all(&final_fs).expect("final tree validate");
    let final_acct = AccountingOracle::assert_clean(&final_fs);

    assert!(
        total_full_events <= 5,
        "too many full events in mixed-4k stress: {total_full_events}"
    );
    assert!(
        total_ops_succeeded >= (STEPS * 80) / 100,
        "too few operations succeeded in mixed-4k stress: {total_ops_succeeded}/{STEPS}"
    );

    println!(
        "[TEST COMPLETED] mixed-4k: {STEPS} steps, {total_ops_succeeded} ops succeeded, \
         {total_full_events} space-limited, {remount_count} remounts. \
         Final state: {} trees nodes, {} items, {} used bytes",
        final_trees.total_nodes(),
        final_trees.total_items(),
        final_acct.superblock_bytes_used
    );
}

#[test]
fn test_conformance_nonmixed_4k_stress() {
    let (rng, seed) = ConformanceRng::from_env_or_default(0x6e6f_6e6d_6978_346b);
    println!("[TEST] nonmixed-4k.img Conformance Stress Test with seed: {seed:#018x}");
    println!(
        "To reproduce: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_nonmixed_4k_stress"
    );

    let dev = MemoryDevice::from_fixture("btrfs/nonmixed-4k.img");
    let mut fs = Btrfs::mount(dev.clone()).expect("mount nonmixed-4k");
    let mut model = ShadowModel::from_fs(&fs).expect("init model from nonmixed-4k");
    let mut gen = OpGenerator::new(rng);

    const STEPS: usize = 50;
    let mut total_ops_succeeded = 0;
    let mut total_full_events = 0;
    let mut remount_count = 0;

    for step in 1..=STEPS {
        let op = gen.next_op(&model);
        let res = execute_op_tier_ab(step, &op, &mut fs, &mut model, &dev).unwrap_or_else(|e| {
            panic!(
                "[CONFORMANCE FAILURE] Step {step} failed with seed {seed:#018x}: {e}\n\
                 Reproduce with: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_nonmixed_4k_stress"
            );
        });

        if res.skipped_full {
            total_full_events += 1;
        } else {
            total_ops_succeeded += 1;
        }
        if res.accounting_report.is_some() {
            remount_count += 1;
        }
    }

    // Final Tier B validation
    fs.commit_active_batch().expect("final commit");
    let final_fs = Btrfs::mount(dev.clone()).expect("final remount");
    model.verify_against_fs(&final_fs).expect("final shadow model verify");
    let final_trees = TreeValidator::validate_all(&final_fs).expect("final tree validate");
    let final_acct = AccountingOracle::assert_clean(&final_fs);

    assert!(
        total_full_events <= 5,
        "too many full events in nonmixed-4k stress: {total_full_events}"
    );
    assert!(
        total_ops_succeeded >= (STEPS * 80) / 100,
        "too few operations succeeded in nonmixed-4k stress: {total_ops_succeeded}/{STEPS}"
    );

    println!(
        "[TEST COMPLETED] nonmixed-4k: {STEPS} steps, {total_ops_succeeded} ops succeeded, \
         {total_full_events} space-limited, {remount_count} remounts. \
         Final state: {} trees nodes, {} items, {} used bytes",
        final_trees.total_nodes(),
        final_trees.total_items(),
        final_acct.superblock_bytes_used
    );
}

#[test]
fn test_conformance_long_names_and_csum_split() {
    let (rng, seed) = ConformanceRng::from_env_or_default(0x6c6f_6e67_6373_756d);
    println!("[TEST] Long Names & CSUM Split Conformance Test with seed: {seed:#018x}");
    println!(
        "To reproduce: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_long_names_and_csum_split"
    );

    let dev = MemoryDevice::from_fixture("btrfs/plain.img");
    let mut fs = Btrfs::mount(dev.clone()).expect("mount plain");
    let mut model = ShadowModel::from_fs(&fs).expect("init model from plain");
    let mut gen = OpGenerator::new(rng);

    const STEPS: usize = 40;
    let mut total_ops_succeeded = 0;
    let mut total_full_events = 0;

    for step in 1..=STEPS {
        // Force long names (64-180 bytes) and ~16 KiB file sizes to trigger leaf splits
        let op = gen.next_op_biased(&model, true, true);
        let res = execute_op_tier_ab(step, &op, &mut fs, &mut model, &dev).unwrap_or_else(|e| {
            panic!(
                "[CONFORMANCE FAILURE] Step {step} failed with seed {seed:#018x}: {e}\n\
                 Reproduce with: LUKS_CONFORMANCE_SEED={seed:#018x} cargo test --test btrfs_conformance test_conformance_long_names_and_csum_split"
            );
        });

        if res.skipped_full {
            total_full_events += 1;
        } else {
            total_ops_succeeded += 1;
        }
    }

    // Final Tier B validation
    fs.commit_active_batch().expect("final commit");
    let final_fs = Btrfs::mount(dev.clone()).expect("final remount");
    model.verify_against_fs(&final_fs).expect("final shadow model verify");
    let final_trees = TreeValidator::validate_all(&final_fs).expect("final tree validate");
    let final_acct = AccountingOracle::assert_clean(&final_fs);

    assert!(
        total_full_events <= 5,
        "too many full events in long names & csum split: {total_full_events}"
    );
    assert!(
        total_ops_succeeded >= (STEPS * 80) / 100,
        "too few operations succeeded in long names & csum split: {total_ops_succeeded}/{STEPS}"
    );

    println!(
        "[TEST COMPLETED] long names & csum split: {STEPS} steps, {total_ops_succeeded} ops succeeded. \
         Final state: {} trees nodes, {} items, {} used bytes",
        final_trees.total_nodes(),
        final_trees.total_items(),
        final_acct.superblock_bytes_used
    );
}

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
    println!("[TEST] test_conformance_interior_growth_and_shrink successfully completed.");
}
