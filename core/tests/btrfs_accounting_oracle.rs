//! Phase 1: Tier B Accounting Oracle Verification Suite.
//!
//! Tests the Accounting Oracle against both known-good fixtures (positive controls),
//! dynamic post-write driver states (cross-checked with the kernel oracle),
//! and deliberate corruption injections (negative controls required by RULES.md).

#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::accounting::{AccountingError, AccountingOracle};
use common::scratch::ScratchFixture;
use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
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

// =========================================================================
// POSITIVE CONTROLS: Standard Fixtures
// =========================================================================

#[test]
fn test_accounting_oracle_plain_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("plain.img");

    let dev = FileDevice::open(&fixture_path).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("plain.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, 2457600);
    assert_eq!(report.total_block_group_used, 2457600);
    assert_eq!(report.total_referenced_bytes, 2457600);
    assert_eq!(report.block_groups.len(), 3);
    assert!(report.total_metadata_blocks >= 22);
    assert!(report.total_data_extents >= 2);
}

#[test]
fn test_accounting_oracle_mixed_4k_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("mixed-4k.img");

    let dev = FileDevice::open(&fixture_path).expect("open mixed-4k.img");
    let fs = Btrfs::mount(dev).expect("mount mixed-4k.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("mixed-4k.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, 1085440);
    assert_eq!(report.total_block_group_used, 1085440);
    assert_eq!(report.total_referenced_bytes, 1085440);
    assert_eq!(report.block_groups.len(), 2);
}

#[test]
fn test_accounting_oracle_compress_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("compress.img");

    let dev = FileDevice::open(&fixture_path).expect("open compress.img");
    let fs = Btrfs::mount(dev).expect("mount compress.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("compress.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, 221184);
    assert_eq!(report.total_block_group_used, 221184);
    assert_eq!(report.total_referenced_bytes, 221184);
}

#[test]
fn test_accounting_oracle_subvol_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("subvol.img");

    let dev = FileDevice::open(&fixture_path).expect("open subvol.img");
    let fs = Btrfs::mount(dev).expect("mount subvol.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("subvol.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, 212992);
    assert_eq!(report.total_block_group_used, 212992);
    assert_eq!(report.total_referenced_bytes, 212992);
    // Subvol fixture has multiple subvolumes and snapshots
    assert!(report.trees_checked.len() >= 10);
}

#[test]
fn test_accounting_oracle_nonmixed_4k_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("nonmixed-4k.img");

    let dev = FileDevice::open(&fixture_path).expect("open nonmixed-4k.img");
    let fs = Btrfs::mount(dev).expect("mount nonmixed-4k.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("nonmixed-4k.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, report.total_block_group_used);
    assert_eq!(report.superblock_bytes_used, report.total_referenced_bytes);
}

#[test]
fn test_accounting_oracle_sha256_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("sha256-4k.img");

    let dev = FileDevice::open(&fixture_path).expect("open sha256-4k.img");
    let fs = Btrfs::mount(dev).expect("mount sha256-4k.img");

    let report = AccountingOracle::assert_clean(&fs);
    println!("sha256-4k.img report: {report:#?}");

    assert_eq!(report.superblock_bytes_used, report.total_block_group_used);
    assert_eq!(report.superblock_bytes_used, report.total_referenced_bytes);
}

// =========================================================================
// POSITIVE CONTROL: Live Driver Operations + Kernel Oracle Cross-Check
// =========================================================================

#[test]
fn test_accounting_oracle_after_live_writes_and_deletes() {
    let scratch = ScratchFixture::new("btrfs/nonmixed-4k.img", "live_accounting_test");
    let file_len = fs::metadata(scratch.path()).unwrap().len();

    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // Perform multiple operations across several transactions:
    // 1. Create directory
    fs.create_directory("/", "test_dir").expect("create_directory");

    // 2. Write several small and medium files
    let data_small = vec![0x41u8; 512];
    fs.create_file_with_data("/test_dir", "small.txt", &data_small)
        .expect("create small.txt");

    let data_medium = vec![0x42u8; 65536];
    fs.create_file_with_data("/test_dir", "medium.bin", &data_medium)
        .expect("create medium.bin");

    // 3. Streaming write with multiple chunks
    let mut writer = fs.begin_file(131072).expect("begin_file");
    fs.write_chunk(&mut writer, &vec![0x55u8; 65536]).expect("write_chunk 1");
    fs.write_chunk(&mut writer, &vec![0x56u8; 65536]).expect("write_chunk 2");
    fs.finish_file(writer, "/", "streamed.bin").expect("finish_file");

    // 4. Delete a file
    fs.delete_file("/test_dir/small.txt").expect("delete small.txt");

    fs.commit_active_batch().expect("commit");

    // Verify in-process accounting oracle first
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let allocator = FreeSpaceMap::from_extent_tree(&extent_tree).expect("allocator from extent tree");
    let report = AccountingOracle::check_with_allocator(&fs, &allocator)
        .expect("accounting check_with_allocator must pass");

    println!("Post-write accounting report: {report:#?}");
    assert!(report.total_data_extents >= 2);
    assert_eq!(report.superblock_bytes_used, report.total_block_group_used);
    assert_eq!(report.superblock_bytes_used, report.total_referenced_bytes);

    // Cross-check with Linux kernel oracle
    let (ok, out, err) = run_verify_script(scratch.path());
    assert!(
        ok,
        "kernel oracle failed on post-write accounting image: {err}\n{out}"
    );
}

// =========================================================================
// NEGATIVE CONTROLS: Proving Oracle Fails On Known-Bad Inputs (RULES.md)
// =========================================================================

#[test]
fn test_negative_control_superblock_bytes_used_mismatch() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_sb_bytes_used");
    let _file_len = fs::metadata(scratch.path()).unwrap().len();

    // Deliberately corrupt bytes_used in primary superblock (offset 0x10000, bytes_used at +0x78)
    let mut image_bytes = fs::read(scratch.path()).unwrap();
    let sb_offset = 0x10000usize;
    let bytes_used_offset = sb_offset + 0x78;
    let old_used = u64::from_le_bytes(image_bytes[bytes_used_offset..bytes_used_offset + 8].try_into().unwrap());
    let corrupted_used = old_used + 4096;
    image_bytes[bytes_used_offset..bytes_used_offset + 8].copy_from_slice(&corrupted_used.to_le_bytes());

    // Recompute primary superblock CRC32C (first 32 bytes is crc32c, computed over bytes 0x20..0x1000)
    let csum = luks_core::fs::btrfs::crc32c::crc32c(&image_bytes[sb_offset + 0x20..sb_offset + 0x1000]);
    image_bytes[sb_offset..sb_offset + 4].copy_from_slice(&csum.to_le_bytes());
    fs::write(scratch.path(), &image_bytes).unwrap();

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::SuperblockMismatch {
            superblock_bytes_used,
            total_bg_used,
            total_referenced_bytes,
        }) => {
            println!(
                "Negative control passed: detected SuperblockMismatch (sb={superblock_bytes_used}, bg={total_bg_used}, ref={total_referenced_bytes})"
            );
            assert_eq!(superblock_bytes_used, corrupted_used);
            assert_eq!(total_bg_used, old_used);
        }
        other => panic!("expected Err(AccountingError::SuperblockMismatch), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_allocator_overlap_fails() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join("plain.img");

    let dev = FileDevice::open(&fixture_path).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut allocator = FreeSpaceMap::from_extent_tree(&extent_tree).expect("allocator from extent tree");

    // Deliberately inject a fake FreeRange that overlaps an existing live extent into allocator
    let live_extent = &extent_tree.extents[0];
    allocator.block_groups[0].free_ranges.push(luks_core::fs::btrfs::write::alloc::FreeRange {
        start: live_extent.bytenr,
        length: live_extent.length,
    });

    let res = AccountingOracle::check_with_allocator(&fs, &allocator);
    match res {
        Err(AccountingError::AllocatorOverlap {
            bytenr,
            length,
            range_start,
            range_len,
            is_pinned,
        }) => {
            println!(
                "Negative control passed: detected AllocatorOverlap at {bytenr:#x} (len {length}) with range [{range_start:#x}..{:#x}] (pinned={is_pinned})",
                range_start + range_len
            );
            assert_eq!(bytenr, live_extent.bytenr);
            assert_eq!(length, live_extent.length);
        }
        other => panic!("expected Err(AccountingError::AllocatorOverlap), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_block_group_used_mismatch() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_bg_used");
    let dev = FileDevice::open(scratch.path()).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_root = fs
        .tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("extent root");
    let (phys, _) = fs
        .chunk_map()
        .map(extent_root.bytenr)
        .expect("map extent root");
    let node = fs
        .read_node(extent_root.bytenr)
        .expect("read extent root node");
    let mut leaf =
        luks_core::fs::btrfs::write::node::Leaf::from_node(&node, fs.superblock().csum_type)
            .expect("parse leaf");

    // Find the first BLOCK_GROUP_ITEM and corrupt its used counter
    let bg_item_idx = leaf
        .items
        .iter()
        .position(|it| {
            it.key.item_type == luks_core::fs::btrfs::tree::BLOCK_GROUP_ITEM_KEY
        })
        .expect("find block group item");
    let original_used =
        u64::from_le_bytes(leaf.items[bg_item_idx].data[0..8].try_into().unwrap());
    let corrupted_used = original_used + 4096;
    leaf.items[bg_item_idx].data[0..8].copy_from_slice(&corrupted_used.to_le_bytes());

    let emitted = leaf.emit(fs.superblock().node_size).expect("emit leaf");
    drop(fs);

    // Write emitted bytes to scratch file at physical location
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(scratch.path())
            .expect("open scratch for write");
        file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
        file.write_all(&emitted).expect("write emitted node");
        file.flush().expect("flush");
    }

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::BlockGroupUsedMismatch {
            bg_start,
            bg_len,
            bg_used,
            calculated_used,
        }) => {
            println!(
                "Negative control passed: detected BlockGroupUsedMismatch at [{bg_start:#x}..{:#x}] (recorded used={bg_used}, calculated={calculated_used})",
                bg_start + bg_len
            );
            assert_eq!(bg_used, corrupted_used);
            assert_eq!(calculated_used, original_used);
        }
        other => panic!("expected Err(AccountingError::BlockGroupUsedMismatch), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_unreferenced_extent_in_extent_tree() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_orphan_extent");
    let dev = FileDevice::open(scratch.path()).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_root = fs
        .tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("extent root");
    let (phys, _) = fs
        .chunk_map()
        .map(extent_root.bytenr)
        .expect("map extent root");
    let node = fs
        .read_node(extent_root.bytenr)
        .expect("read extent root node");
    let mut leaf =
        luks_core::fs::btrfs::write::node::Leaf::from_node(&node, fs.superblock().csum_type)
            .expect("parse leaf");

    // Insert an orphan EXTENT_ITEM in DATA block group ([13631488..22020096)) that no file references
    let orphan_bytenr = 16777216u64;
    let orphan_len = 4096u64;
    let (key, data) =
        luks_core::fs::btrfs::write::extent_tree::ExtentItem::emit_data_extent(
            orphan_bytenr,
            orphan_len,
            1,
            5,
            257,
            0,
        );
    leaf.insert_item(key, data, fs.superblock().node_size)
        .expect("insert orphan item");

    let emitted = leaf.emit(fs.superblock().node_size).expect("emit leaf");
    drop(fs);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(scratch.path())
            .expect("open scratch for write");
        file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
        file.write_all(&emitted).expect("write emitted node");
        file.flush().expect("flush");
    }

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::UnreferencedExtentInExtentTree {
            bytenr,
            length,
            is_metadata,
        }) => {
            println!(
                "Negative control passed: detected UnreferencedExtentInExtentTree at {bytenr:#x} (len {length}, is_metadata={is_metadata})"
            );
            assert_eq!(bytenr, orphan_bytenr);
            assert_eq!(length, orphan_len);
            assert!(!is_metadata);
        }
        other => panic!("expected Err(AccountingError::UnreferencedExtentInExtentTree), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_overlapping_extents() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_overlapping_extents");
    let dev = FileDevice::open(scratch.path()).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_root = fs
        .tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("extent root");
    let (phys, _) = fs
        .chunk_map()
        .map(extent_root.bytenr)
        .expect("map extent root");
    let node = fs
        .read_node(extent_root.bytenr)
        .expect("read extent root node");
    let mut leaf =
        luks_core::fs::btrfs::write::node::Leaf::from_node(&node, fs.superblock().csum_type)
            .expect("parse leaf");

    // In plain.img, extent 0 is at 13631488 (len 1048576, end 14680064).
    // Inject an extent at 14155776 (len 65536), which overlaps with extent 0!
    let overlap_bytenr = 14155776u64;
    let overlap_len = 65536u64;
    let (key, data) =
        luks_core::fs::btrfs::write::extent_tree::ExtentItem::emit_data_extent(
            overlap_bytenr,
            overlap_len,
            1,
            5,
            257,
            0,
        );
    leaf.insert_item(key, data, fs.superblock().node_size)
        .expect("insert overlapping item");

    let emitted = leaf.emit(fs.superblock().node_size).expect("emit leaf");
    drop(fs);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(scratch.path())
            .expect("open scratch for write");
        file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
        file.write_all(&emitted).expect("write emitted node");
        file.flush().expect("flush");
    }

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::OverlappingExtents {
            first_bytenr,
            first_len,
            second_bytenr,
            second_len,
        }) => {
            println!(
                "Negative control passed: detected OverlappingExtents: [{first_bytenr:#x}..{:#x}] (len {first_len}) overlaps with [{second_bytenr:#x}..{:#x}] (len {second_len})",
                first_bytenr + first_len,
                second_bytenr + second_len
            );
            assert_eq!(first_bytenr, 13631488);
            assert_eq!(first_len, 1048576);
            assert_eq!(second_bytenr, overlap_bytenr);
            assert_eq!(second_len, overlap_len);
        }
        other => panic!("expected Err(AccountingError::OverlappingExtents), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_missing_extent_in_extent_tree() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_missing_extent");
    let dev = FileDevice::open(scratch.path()).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_root = fs
        .tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("extent root");
    let (phys, _) = fs
        .chunk_map()
        .map(extent_root.bytenr)
        .expect("map extent root");
    let node = fs
        .read_node(extent_root.bytenr)
        .expect("read extent root node");
    let mut leaf =
        luks_core::fs::btrfs::write::node::Leaf::from_node(&node, fs.superblock().csum_type)
            .expect("parse leaf");

    // Remove the EXTENT_ITEM for 13631488 (which is referenced by a live file)
    let extent_item_idx = leaf
        .items
        .iter()
        .position(|it| {
            it.key.objectid == 13631488
                && it.key.item_type == luks_core::fs::btrfs::tree::EXTENT_ITEM_KEY
        })
        .expect("find extent item for 13631488");
    leaf.items.remove(extent_item_idx);

    let emitted = leaf.emit(fs.superblock().node_size).expect("emit leaf");
    drop(fs);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(scratch.path())
            .expect("open scratch for write");
        file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
        file.write_all(&emitted).expect("write emitted node");
        file.flush().expect("flush");
    }

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::MissingExtentInExtentTree {
            bytenr,
            length,
            is_metadata,
            ..
        }) => {
            println!(
                "Negative control passed: detected MissingExtentInExtentTree at {bytenr:#x} (len {length}, is_metadata={is_metadata})"
            );
            assert_eq!(bytenr, 13631488);
            assert_eq!(length, 1048576);
            assert!(!is_metadata);
        }
        other => panic!("expected Err(AccountingError::MissingExtentInExtentTree), got: {other:?}"),
    }
}

#[test]
fn test_negative_control_extent_length_mismatch() {
    let scratch = ScratchFixture::new("btrfs/plain.img", "neg_len_mismatch");
    let dev = FileDevice::open(scratch.path()).expect("open plain.img");
    let fs = Btrfs::mount(dev).expect("mount plain.img");

    let extent_root = fs
        .tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("extent root");
    let (phys, _) = fs
        .chunk_map()
        .map(extent_root.bytenr)
        .expect("map extent root");
    let node = fs
        .read_node(extent_root.bytenr)
        .expect("read extent root node");
    let mut leaf =
        luks_core::fs::btrfs::write::node::Leaf::from_node(&node, fs.superblock().csum_type)
            .expect("parse leaf");

    // Corrupt the length (key.offset) of the EXTENT_ITEM for 13631488 (from 1048576 to 524288)
    let extent_item_idx = leaf
        .items
        .iter()
        .position(|it| {
            it.key.objectid == 13631488
                && it.key.item_type == luks_core::fs::btrfs::tree::EXTENT_ITEM_KEY
        })
        .expect("find extent item for 13631488");
    leaf.items[extent_item_idx].key.offset = 524288;

    let emitted = leaf.emit(fs.superblock().node_size).expect("emit leaf");
    drop(fs);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(scratch.path())
            .expect("open scratch for write");
        file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
        file.write_all(&emitted).expect("write emitted node");
        file.flush().expect("flush");
    }

    let dev = FileDevice::open(scratch.path()).expect("open corrupted");
    let fs = Btrfs::mount(dev).expect("mount corrupted");

    let res = AccountingOracle::check(&fs);
    match res {
        Err(AccountingError::ExtentLengthMismatch {
            bytenr,
            extent_tree_len,
            referenced_len,
        }) => {
            println!(
                "Negative control passed: detected ExtentLengthMismatch at {bytenr:#x} (extent_tree={extent_tree_len}, referenced={referenced_len})"
            );
            assert_eq!(bytenr, 13631488);
            assert_eq!(extent_tree_len, 524288);
            assert_eq!(referenced_len, 1048576);
        }
        other => panic!("expected Err(AccountingError::ExtentLengthMismatch), got: {other:?}"),
    }
}

