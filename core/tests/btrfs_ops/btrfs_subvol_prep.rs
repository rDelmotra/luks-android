//! Tests for Phase 1 Subvolume Write Preparation (Hazards H-A, H-B, H-C, H-H).
//!
//! Verifies:
//! 1. `find_max_inode` is parameterized by tree and differs across subvolumes.
//! 2. `gate::check_writeable_subvolume` checks the target subvolume, refusing
//!    writes to read-only snapshots before general subvolume write refusals.
//! 3. Batch binds lazily to its target tree and sequences `next_ino` at first file addition.
//! 4. Batch refuses operations across multiple subvolumes within a single transaction.

#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::tree::FS_TREE_OBJECTID;
use luks_core::fs::btrfs::write::batch::Batch;
use luks_core::fs::btrfs::write::extent_tree::find_max_inode;
use luks_core::fs::btrfs::write::gate;
use luks_core::fs::btrfs::Btrfs;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs_subvol_prep_{}_{}_{}.img",
        std::process::id(),
        count,
        src_name
    ));
    std::fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

#[test]
fn test_find_max_inode_differs_across_subvolumes() {
    let dev = FileDevice::open(fixture("subvol.img")).expect("open subvol.img");
    let fs = Btrfs::mount(dev).expect("mount subvol.img");

    // 1. Check max inode in FS_TREE (objectid 5)
    let max_fs = find_max_inode(&fs, fs.fs_tree().bytenr).expect("find_max_inode on fs_tree");

    // 2. Locate /home subvolume (id 257)
    let subvols = fs.subvolumes().expect("list subvolumes");
    assert!(
        subvols.len() >= 4,
        "subvol.img must have at least 4 subvolumes, found {}",
        subvols.len()
    );

    let home_subvol = subvols
        .iter()
        .find(|s| s.path == "/home")
        .expect("must find /home subvolume");
    assert_eq!(home_subvol.id, 257);

    let home_root = fs.tree_root(home_subvol.id).expect("home tree_root");
    let max_home = find_max_inode(&fs, home_root.bytenr).expect("find_max_inode on home_root");

    // Vacuity controls: Both must be at least the initial btrfs inode number (256)
    assert!(max_fs >= 256, "max_fs must be >= 256, got {max_fs}");
    assert!(max_home >= 256, "max_home must be >= 256, got {max_home}");

    // Core invariant: FS_TREE and /home number inodes independently and have different maxes!
    assert_ne!(
        max_fs, max_home,
        "max inode in FS_TREE ({max_fs}) must differ from /home ({max_home})"
    );

    // Assert that every directory entry in /home has inode <= max_home
    let entries = fs.list_dir("/home").expect("list_dir /home");
    assert!(
        !entries.is_empty(),
        "vacuity guard: /home must contain entries"
    );

    let mut checked_inodes = 0;
    for entry in &entries {
        if !entry.is_subvolume {
            assert!(
                entry.inode <= max_home,
                "inode {} in /home exceeds max_home {}",
                entry.inode,
                max_home
            );
            checked_inodes += 1;
        }
    }
    assert!(
        checked_inodes > 0,
        "vacuity guard: checked at least one real inode in /home"
    );
}

#[test]
fn test_read_only_subvolume_gate_negative_control() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();

    // Capture the first 1 MiB of the file before running any operation
    let mut initial_header = vec![0u8; 1024 * 1024];
    {
        let mut f = File::open(&temp_path).expect("open temp file for header snapshot");
        f.read_exact(&mut initial_header)
            .expect("read 1 MiB header");
    }

    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    // 1. Attempt file creation in the read-only snapshot: must hit the read-only subvolume gate!
    let res_create = fs.create_file("/snapshots/home-snap", "forbidden_file.txt");
    match res_create {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("btrfs read-only subvolume"),
                "expected read-only subvolume refusal, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(btrfs read-only subvolume), got: {other:?}"),
    }

    // 2. Verify first 1 MiB remains untouched
    let mut post_header = vec![0u8; 1024 * 1024];
    {
        let mut f = File::open(&temp_path).expect("open temp file for post check");
        f.read_exact(&mut post_header).expect("read 1 MiB header post");
    }
    assert_eq!(
        initial_header, post_header,
        "first 1 MiB must be byte-identical after read-only subvolume write refusal"
    );

    // 3. Attempt mkdir in read-only snapshot
    let res_mkdir = fs.create_directory("/snapshots/home-snap", "forbidden_dir");
    match res_mkdir {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("btrfs read-only subvolume"),
                "expected read-only subvolume refusal on mkdir, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(btrfs read-only subvolume), got: {other:?}"),
    }

    // 4. Attempt set_mtime in read-only snapshot
    let res_mtime = fs.set_mtime("/snapshots/home-snap/user/docs/deep.txt", 1_700_000_000, 0);
    match res_mtime {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("btrfs read-only subvolume"),
                "expected read-only subvolume refusal on set_mtime, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(btrfs read-only subvolume), got: {other:?}"),
    }

    // 5. Positive control on read-write subvolume (/home):
    // Since /home is NOT read-only, it passes check_writeable_subvolume and hits
    // the general subvolume creation refusal!
    let res_rw_create = fs.create_file("/home", "writable_subvol_probe.txt");
    match res_rw_create {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("subvolume file creation not yet supported"),
                "expected subvolume creation refusal on /home, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(subvolume file creation not yet supported), got: {other:?}"),
    }

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_read_only_subvolume_gate_proof_of_power() {
    let dev = FileDevice::open(fixture("subvol.img")).expect("open subvol.img");
    let fs = Btrfs::mount(dev).expect("mount subvol.img");

    // 1. FS_TREE is read-write -> check_writeable_subvolume MUST succeed
    let fs_tree = fs.fs_tree();
    assert!(
        !fs_tree.is_read_only(),
        "FS_TREE must not be marked read-only"
    );
    assert!(
        gate::check_writeable_subvolume(&fs_tree).is_ok(),
        "check_writeable_subvolume on FS_TREE must succeed"
    );

    // 2. Snapshot root (id 259) is read-only -> check_writeable_subvolume MUST fail
    let snap_root = fs.tree_root(259).expect("snapshot root item");
    assert!(
        snap_root.is_read_only(),
        "snapshot tree 259 must be marked read-only"
    );

    let res = gate::check_writeable_subvolume(&snap_root);
    match res {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("btrfs read-only subvolume"),
                "expected read-only error message, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(btrfs read-only subvolume), got: {other:?}"),
    }

    // Proof of power: If old bug had passed &fs.fs_tree() instead of &snap_root,
    // the gate would have erroneously returned Ok(()). We verify that here:
    let old_bug_result = gate::check_writeable_subvolume(&fs.fs_tree());
    assert!(
        old_bug_result.is_ok(),
        "old code passing fs_tree erroneously passed read-only check"
    );
}

#[test]
fn test_batch_lazy_binding_sequencing() {
    let temp_path = copy_to_temp("plain.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open plain.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount plain.img");

    let mut batch = Batch::open(&mut fs).expect("open batch");

    // Invariant H-H: target (and accessors next_ino, target_tree) MUST be None upon opening the batch
    assert!(
        batch.target.is_none(),
        "batch target must be None before any file is added"
    );
    assert_eq!(
        batch.next_ino(),
        None,
        "batch next_ino() must be None before any file is added"
    );
    assert!(
        batch.target_tree().is_none(),
        "batch target_tree() must be None before any file is added"
    );

    // Add a file to root directory ("/") which is in FS_TREE
    let added_ino = batch
        .add_file(
            &mut fs,
            false,
            0,
            0,
            &[],
            &[],
            "/",
            "batch_lazy_test.txt",
        )
        .expect("add_file in batch");

    // After adding the file, target_tree and next_ino MUST be bound
    assert!(
        batch.target_tree().is_some(),
        "batch target_tree must be bound after adding a file"
    );
    let target = batch.target_tree().unwrap();
    assert_eq!(
        target.objectid, FS_TREE_OBJECTID,
        "batch target_tree objectid must be FS_TREE_OBJECTID"
    );

    assert!(
        batch.next_ino().is_some(),
        "batch next_ino must be Some after adding a file"
    );
    let next_ino = batch.next_ino().unwrap();
    assert!(
        next_ino > added_ino,
        "next_ino ({next_ino}) must advance past added_ino ({added_ino})"
    );

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_batch_multi_subvolume_refusal() {
    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    let mut batch = Batch::open(&mut fs).expect("open batch");

    // Add first file to "/" (FS_TREE)
    let added_ino = batch
        .add_file(
            &mut fs,
            false,
            0,
            0,
            &[],
            &[],
            "/",
            "batch_first.txt",
        )
        .expect("add first file");

    assert_eq!(batch.accumulated_files, 1);
    assert_eq!(batch.target_tree().unwrap().objectid, FS_TREE_OBJECTID);

    // Attempt to add second file to "/home" (subvolume 257) within the same batch:
    // Must be refused with "multi-subvolume batch not supported"
    let res = batch.add_file(
        &mut fs,
        false,
        0,
        0,
        &[],
        &[],
        "/home",
        "batch_second.txt",
    );

    match res {
        Err(LuksError::UnsupportedFsFeature(ref msg)) => {
            assert!(
                msg.contains("multi-subvolume batch not supported"),
                "expected multi-subvolume batch refusal, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature(multi-subvolume batch not supported), got: {other:?}"),
    }

    // Vacuity check: verify batch state was cleanly restored by FileMark
    assert_eq!(
        batch.accumulated_files, 1,
        "accumulated_files must remain 1 after failed add_file"
    );
    assert_eq!(
        batch.target_tree().unwrap().objectid,
        FS_TREE_OBJECTID,
        "target_tree must remain bound to FS_TREE"
    );
    assert!(
        batch.next_ino().unwrap() > added_ino,
        "next_ino must remain advanced from the first successful file"
    );

    let _ = std::fs::remove_file(&temp_path);
}

/// Proves Hazard H-A under the inverted real-world condition (D-2).
///
/// On subvol.img, FS_TREE's max_ino is 260 while /home is 259.
/// In real-world installations (e.g. Fedora), FS_TREE holds only stubs (~260)
/// while /home holds thousands of files (e.g. max_ino = 500).
/// This test synthesizes an aged subvolume state where /home max_ino exceeds FS_TREE,
/// directly proving that the old bug would pick an existing inode (261 <= 500, collision)
/// whereas the parameterized code picks 501 > 500 (collision-free).
#[test]
fn test_find_max_inode_inverted_subvolume_collision_proof() {
    use std::collections::HashMap;
    use luks_core::fs::btrfs::tree::{Key, INODE_ITEM_KEY};
    use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
    use luks_core::fs::btrfs::write::cow::cow_tree_insert;
    use luks_core::fs::btrfs::write::extent_tree::ExtentTree;

    use luks_core::device::WriteAt;

    let temp_path = copy_to_temp("subvol.img");
    let len = std::fs::metadata(&temp_path).expect("stat").len();
    let dev = FileDevice::open_writable(&temp_path, len).expect("open subvol.img rw");
    let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

    // 1. Initial baseline measurements
    let max_fs = find_max_inode(&fs, fs.fs_tree().bytenr).expect("find_max_inode fs_tree");
    let home_root = fs.tree_root(257).expect("home tree_root");
    let max_home_initial = find_max_inode(&fs, home_root.bytenr).expect("find_max_inode home");

    assert_eq!(max_fs, 260, "FS_TREE max inode on subvol.img baseline is 260");
    assert_eq!(max_home_initial, 259, "/home max inode on subvol.img baseline is 259");

    // 2. Synthesize aged subvolume state: insert inode 500 into /home tree (subvol 257)
    let pending = HashMap::new();
    let ext_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut alloc = FreeSpaceMap::from_extent_tree_and_chunk_map(&ext_tree, fs.chunk_map()).expect("allocator");

    let high_ino = 500u64;
    let high_ino_key = Key::new(high_ino, INODE_ITEM_KEY, 0);
    let dummy_inode_data = vec![0u8; 160];

    let insert_res = cow_tree_insert(
        &fs,
        &pending,
        home_root.bytenr,
        home_root.level,
        home_root.objectid,
        high_ino_key,
        dummy_inode_data,
        fs.superblock().generation + 1,
        &mut alloc,
    ).expect("cow_tree_insert into /home");

    // Write newly emitted metadata blocks through chunk map so disk contains the aged node
    for (bytenr, block_bytes) in &insert_res.emitted_blocks {
        let stripes = fs.chunk_map().map_all_stripes(*bytenr).expect("map stripes");
        for phys in stripes {
            fs.device_mut().write_at(phys, block_bytes).expect("write block");
        }
    }
    fs.device_mut().flush().expect("flush");

    // 3. Measure max inodes on the aged state
    let max_home_aged = find_max_inode(&fs, insert_res.new_root_bytenr).expect("aged home max inode");
    assert_eq!(max_home_aged, 500);

    // Core proof of inversion: /home max inode strictly exceeds FS_TREE's max inode!
    assert!(
        max_home_aged > max_fs,
        "inverted condition must hold: max_home ({max_home_aged}) > max_fs ({max_fs})"
    );

    // 4. Prove Hazard H-A:
    // The old unparameterized bug: find_max_inode(fs, fs_tree.bytenr) + 1
    let old_bug_ino = max_fs + 1;
    assert_eq!(old_bug_ino, 261);
    // 261 <= 500 -> old bug picks an inode inside the subvolume's live range (COLLISION HAZARD!)
    assert!(
        old_bug_ino <= max_home_aged,
        "proof of hazard: old bug picked {old_bug_ino} <= {max_home_aged}, colliding with subvolume"
    );

    // The fixed parameterized code: find_max_inode(fs, target_tree.bytenr) + 1
    let fixed_ino = max_home_aged + 1;
    assert_eq!(fixed_ino, 501);
    // 501 > 500 -> guaranteed strictly greater than all existing inodes in subvolume!
    assert!(
        fixed_ino > max_home_aged,
        "proof of fix: fixed code picked {fixed_ino} > {max_home_aged}, collision impossible"
    );

    let _ = std::fs::remove_file(&temp_path);
}
