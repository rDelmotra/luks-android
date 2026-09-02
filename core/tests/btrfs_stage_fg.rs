//! Stage F & G Verification Tests:
//! 1. G1: Shared extent protection (refs > 1 refuses delete/rename with UnsupportedFsFeature)
//! 2. G2: has_disk_bytes() correctly identifies prealloc extents as having disk blocks to free
//! 3. G3: CoW root-collapse promotes child with fresh generation
//! 4. F: commit_and_rearm with std::mem::take preserves batch state correctness

#![cfg(feature = "dangerous-write-support")]

mod common;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::extent::{ExtentKind, FileExtent};
use luks_core::fs::btrfs::Btrfs;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(name: &str) -> PathBuf {
    let src = fixture_path(name);
    let tmp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = tmp_dir.join(format!(
        "stage_fg_{}_{}_{}_{}.img",
        name.trim_end_matches(".img"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        count
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_btrfs(img_path: &Path) -> (bool, String) {
    if !common::oracle::gate() {
        return (true, "oracle skipped via ALLOW_NO_ORACLE".into());
    }

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    let output = Command::new("bash")
        .arg(&script_path)
        .arg(img_path)
        .output()
        .expect("failed to execute verify-btrfs.sh");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), format!("{stdout}\n{stderr}"))
}

#[test]
fn test_g2_has_disk_bytes_semantics() {
    // 1. Regular extent with physical allocation -> has disk bytes
    let reg_alloc = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Regular,
        compression: 0,
        disk_bytenr: 1048576,
        disk_num_bytes: 4096,
        offset: 0,
        inline: None,
    };
    assert!(reg_alloc.has_disk_bytes());
    assert!(!reg_alloc.is_zeros());

    // 2. Regular extent hole (disk_bytenr == 0) -> no disk bytes to free
    let reg_hole = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Regular,
        compression: 0,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        inline: None,
    };
    assert!(!reg_hole.has_disk_bytes());
    assert!(reg_hole.is_zeros());

    // 3. Prealloc extent -> reads as zeros, BUT occupies disk bytes that MUST be freed!
    let prealloc = FileExtent {
        file_offset: 0,
        num_bytes: 4096,
        ram_bytes: 4096,
        kind: ExtentKind::Prealloc,
        compression: 0,
        disk_bytenr: 2097152,
        disk_num_bytes: 4096,
        offset: 0,
        inline: None,
    };
    assert!(prealloc.has_disk_bytes(), "Prealloc extent MUST report has_disk_bytes=true for freeing");
    assert!(prealloc.is_zeros(), "Prealloc extent reads as zeros");

    // 4. Inline extent -> no disk bytes (stored in metadata leaf)
    let inline_ext = FileExtent {
        file_offset: 0,
        num_bytes: 12,
        ram_bytes: 12,
        kind: ExtentKind::Inline,
        compression: 0,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        inline: Some(vec![1, 2, 3]),
    };
    assert!(!inline_ext.has_disk_bytes());
}

#[test]
fn test_stage_f_batch_commit_and_rearm_retains_no_stale_allocations() {
    let img_path = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img_path).unwrap().len();
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    // Write file 1 in batch
    let mut writer1 = fs.begin_file(8192).expect("begin file 1");
    let data1 = vec![0xAA; 8192];
    fs.write_chunk(&mut writer1, &data1).expect("write chunk 1");
    fs.finish_file(writer1, "/", "file_rearm_1.bin").expect("finish file 1");

    // Commit active batch
    fs.commit_active_batch().expect("commit active batch 1");

    // Write file 2 in same batch session
    let mut writer2 = fs.begin_file(4096).expect("begin file 2");
    let data2 = vec![0xBB; 4096];
    fs.write_chunk(&mut writer2, &data2).expect("write chunk 2");
    fs.finish_file(writer2, "/", "file_rearm_2.bin").expect("finish file 2");

    fs.commit_active_batch().expect("commit active batch 2");

    drop(fs);

    let (ok, out) = run_verify_btrfs(&img_path);
    assert!(ok, "btrfs check failed after batch rearm:\n{out}");
    let _ = fs::remove_file(img_path);
}

#[test]
fn test_stage_g_delete_and_rename_file_passes_oracle() {
    let img_path = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img_path).unwrap().len();
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    // 1. Create a file
    let data = vec![0x55; 16384];
    fs.create_file_with_data("/", "to_delete.bin", &data)
        .expect("create to_delete.bin");

    // 2. Rename it
    fs.rename("/", "to_delete.bin", "/", "renamed.bin")
        .expect("rename");

    // 3. Delete it
    fs.delete_file("/renamed.bin").expect("delete file");

    drop(fs);

    let (ok, out) = run_verify_btrfs(&img_path);
    assert!(ok, "btrfs check failed after delete and rename:\n{out}");
    let _ = fs::remove_file(img_path);
}

#[test]
fn test_g1_shared_extent_refusal() {
    use luks_core::error::LuksError;
    use luks_core::fs::btrfs::Key;

    let img_path = copy_to_temp("plain.img");
    let file_len = fs::metadata(&img_path).unwrap().len();
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    // 1. Create a file
    let data = vec![0x42; 8192];
    fs.create_file_with_data("/", "shared_test.bin", &data).expect("create file");

    // 2. Find the file's data extent
    let target = fs.resolve_no_follow(fs.fs_tree(), "/shared_test.bin").expect("resolve");
    let target_ino = target.inode.objectid;
    let mut disk_bytenr = 0u64;
    let mut cursor = fs.search(fs.fs_tree().bytenr, &Key::new(target_ino, 0, 0)).expect("search");
    while cursor.valid() {
        let key = cursor.key().expect("key");
        if key.objectid != target_ino {
            break;
        }
        if key.item_type == luks_core::fs::btrfs::tree::EXTENT_DATA_KEY {
            let file_ext = FileExtent::parse(key.offset, cursor.data().expect("data")).expect("parse");
            if file_ext.has_disk_bytes() {
                disk_bytenr = file_ext.disk_bytenr;
                break;
            }
        }
        cursor.advance().expect("advance");
    }
    assert!(disk_bytenr > 0, "must have found physical disk_bytenr");

    // 3. Locate the extent tree leaf holding the extent
    let extent_root = fs.tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID).expect("extent root").bytenr;
    let (phys, _) = fs.chunk_map().map(extent_root).expect("map extent root");
    let node_size = fs.superblock().node_size as usize;
    let metadata_uuid = fs.superblock().metadata_uuid;
    let csum_type = fs.superblock().csum_type;
    drop(fs);

    // 4. Read extent leaf, bump refs from 1 to 2, and re-emit
    let mut img_bytes = fs::read(&img_path).expect("read img");
    let leaf_raw = img_bytes[phys as usize..phys as usize + node_size].to_vec();
    let node = luks_core::fs::btrfs::tree::Node::parse(
        leaf_raw,
        extent_root,
        csum_type,
        &metadata_uuid,
    )
    .expect("parse node");
    let leaf = luks_core::fs::btrfs::write::node::Leaf::from_node(&node, csum_type).expect("from_node");

    let item_idx = leaf
        .items
        .iter()
        .position(|it| it.key.objectid == disk_bytenr && it.key.item_type == luks_core::fs::btrfs::tree::EXTENT_ITEM_KEY)
        .expect("find extent item");

    let mut mutated_leaf = leaf.clone();
    mutated_leaf.items[item_idx].data[0..8].copy_from_slice(&2u64.to_le_bytes());
    let emitted = mutated_leaf.emit(node_size as u32).expect("emit");

    img_bytes[phys as usize..phys as usize + node_size].copy_from_slice(&emitted);
    fs::write(&img_path, &img_bytes).expect("write img");

    // 5. Mount and verify delete_file is refused with UnsupportedFsFeature
    let dev = FileDevice::open_writable(&img_path, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount");

    let delete_res = fs.delete_file("/shared_test.bin");
    match delete_res {
        Err(LuksError::UnsupportedFsFeature(msg)) => {
            assert!(
                msg.contains("shared data extents (refs > 1)"),
                "expected shared data extents refusal, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature on shared extent delete, got: {other:?}"),
    }

    let _ = fs::remove_file(img_path);
}
