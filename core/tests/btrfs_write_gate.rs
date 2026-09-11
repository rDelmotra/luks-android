//! Refusal gate tests for btrfs write support (Pass D).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_write_gate
//! ```
mod common;

use common::scratch::ScratchFixture;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::superblock::Superblock;
use luks_core::fs::btrfs::write::gate::{
    check_sys_chunk_array_capacity, check_writeable_fs,
    check_writeable_subvolume, BTRFS_SYSTEM_CHUNK_ARRAY_SIZE, BTRFS_SYSTEM_CHUNK_ENTRY_SIZE,
    SUPPORTED_WRITE_COMPAT_RO,
};
use luks_core::fs::btrfs::TreeRoot;

fn dummy_superblock() -> Superblock {
    Superblock {
        fsid: [0; 16],
        bytenr: 0x10000,
        generation: 1,
        root: 1048576,
        chunk_root: 2097152,
        chunk_root_generation: 1,
        log_root: 0,
        total_bytes: 104857600,
        bytes_used: 1048576,
        root_dir_objectid: 6,
        num_devices: 1,
        dev_id: 1,
        sector_size: 4096,
        node_size: 16384,
        stripe_size: 65536,
        incompat_flags: 0x100, // INCOMPAT_SKINNY_METADATA
        compat_ro_flags: SUPPORTED_WRITE_COMPAT_RO,
        csum_type: luks_core::fs::btrfs::superblock::CsumType::Crc32c,
        root_level: 0,
        chunk_root_level: 0,
        label: "test".into(),
        metadata_uuid: [0; 16],
        sys_chunk_array: vec![],
    }
}

#[test]
fn clean_superblock_passes_gate() {
    let sb = dummy_superblock();
    assert!(check_writeable_fs(&sb).is_ok());
}

#[test]
fn dirty_log_tree_is_refused() {
    let mut sb = dummy_superblock();
    sb.log_root = 3145728;
    match check_writeable_fs(&sb).unwrap_err() {
        LuksError::FsNeedsRecovery => {}
        other => panic!("expected FsNeedsRecovery, got {other:?}"),
    }
}

#[test]
fn non_skinny_metadata_is_refused() {
    let mut sb = dummy_superblock();
    sb.incompat_flags &= !0x100; // Clear INCOMPAT_SKINNY_METADATA
    match check_writeable_fs(&sb).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("skinny"));
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

#[test]
fn unsupported_compat_ro_is_refused() {
    let mut sb = dummy_superblock();
    sb.compat_ro_flags |= 0x4; // BLOCK_GROUP_TREE (unsupported)
    match check_writeable_fs(&sb).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("compat_ro"));
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

#[test]
fn multi_device_is_refused() {
    let mut sb = dummy_superblock();
    sb.num_devices = 2;
    match check_writeable_fs(&sb).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("devices"));
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

#[test]
fn read_only_subvolume_is_refused() {
    let mut root = TreeRoot::default();
    root.flags = 1; // ROOT_SUBVOL_RDONLY
    match check_writeable_subvolume(&root).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(msg.contains("read-only"));
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

/// Phase F4: Multi-leaf free-space trees are now fully supported by the incremental
/// CoW engine, so check_free_space_tree_shape has been removed.
#[test]
fn fixture_fst_multileaf_has_root_level_1() {
    let path = fixture_path("fst-multileaf.img");
    let dev = luks_core::device::FileDevice::open(&path).expect("open fst-multileaf");
    let fs = luks_core::fs::btrfs::Btrfs::mount(dev).expect("mount fst-multileaf");
    let fst_root = fs
        .tree_root(luks_core::fs::btrfs::tree::FREE_SPACE_TREE_OBJECTID)
        .expect("fst root");
    assert_eq!(
        fst_root.level, 1,
        "fst-multileaf.img must have FST root level 1, got {}",
        fst_root.level
    );
    let node = fs.read_node(fst_root.bytenr).expect("read fst root node");
    assert!(
        node.nr_items >= 2,
        "fst-multileaf root must have >= 2 children, got {}",
        node.nr_items
    );
}

#[test]
fn sys_chunk_array_capacity_gate_allows_room_and_refuses_exhaustion() {
    let mut sb = dummy_superblock();

    // Default empty array passes
    assert!(check_sys_chunk_array_capacity(&sb).is_ok());

    // Max allowable size (1919 bytes) passes
    sb.sys_chunk_array = vec![0u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE - BTRFS_SYSTEM_CHUNK_ENTRY_SIZE];
    assert!(check_sys_chunk_array_capacity(&sb).is_ok());

    // 1920 bytes fails (near 2048 capacity, deliberate break)
    sb.sys_chunk_array = vec![0u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE - BTRFS_SYSTEM_CHUNK_ENTRY_SIZE + 1];
    match check_sys_chunk_array_capacity(&sb).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(
                msg.contains("sys_chunk_array capacity exhausted"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }

    // Full 2048 bytes fails
    sb.sys_chunk_array = vec![0u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
    assert!(check_sys_chunk_array_capacity(&sb).is_err());
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}



#[test]
fn fixture_fst_bitmap_has_bitmaps() {
    let path = fixture_path("fst-bitmap.img");
    let dev = luks_core::device::FileDevice::open(&path).expect("open fst-bitmap");
    let fs = luks_core::fs::btrfs::Btrfs::mount(dev).expect("mount fst-bitmap");
    let fst_root = fs
        .tree_root(luks_core::fs::btrfs::tree::FREE_SPACE_TREE_OBJECTID)
        .expect("fst root");

    let mut bitmap_count = 0;
    let mut extent_count = 0;
    fs.walk_tree(fst_root.bytenr, &mut |key, _| {
        if key.item_type == luks_core::fs::btrfs::tree::FREE_SPACE_BITMAP_KEY {
            bitmap_count += 1;
        } else if key.item_type == luks_core::fs::btrfs::tree::FREE_SPACE_EXTENT_KEY {
            extent_count += 1;
        }
        Ok(())
    })
    .expect("walk fst");

    assert!(
        bitmap_count >= 50,
        "fst-bitmap.img must have >= 50 bitmaps, got {bitmap_count}"
    );
    assert!(
        extent_count >= 40,
        "fst-bitmap.img must have >= 40 extents, got {extent_count}"
    );
}

#[test]
fn fixture_fst_bitmap_is_refused_by_bitmap_gate() {
    let path = fixture_path("fst-bitmap.img");
    let dev = luks_core::device::FileDevice::open(&path).expect("open fst-bitmap");
    let fs = luks_core::fs::btrfs::Btrfs::mount(dev).expect("mount fst-bitmap");
    let err = luks_core::fs::btrfs::write::gate::check_free_space_tree_no_bitmaps(&fs).unwrap_err();
    match err {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(
                msg.contains("btrfs free-space tree bitmap items (key type 200) not supported"),
                "unexpected refusal message: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

#[test]
fn fixture_fst_aged_has_high_extent_count_under_single_leaf() {
    let path = fixture_path("fst-aged.img");
    let dev = luks_core::device::FileDevice::open(&path).expect("open fst-aged");
    let fs = luks_core::fs::btrfs::Btrfs::mount(dev).expect("mount fst-aged");
    let fst_root = fs
        .tree_root(luks_core::fs::btrfs::tree::FREE_SPACE_TREE_OBJECTID)
        .expect("fst root");
    assert_eq!(
        fst_root.level, 0,
        "fst-aged.img must have FST root level 0, got {}",
        fst_root.level
    );

    let mut extent_count = 0;
    fs.walk_tree(fst_root.bytenr, &mut |key, _| {
        if key.item_type == luks_core::fs::btrfs::tree::FREE_SPACE_EXTENT_KEY {
            extent_count += 1;
        }
        Ok(())
    })
    .expect("walk fst");

    assert!(
        extent_count >= 500,
        "fst-aged.img must have >= 500 free extents, got {extent_count}"
    );
}

#[test]
fn fixture_fst_multileaf_write_succeeds() {
    let scratch = ScratchFixture::new("btrfs/fst-multileaf.img", "fst_multileaf_write_succeeds");
    let len = scratch.path().metadata().expect("metadata").len();
    let dev = luks_core::device::FileDevice::open_writable(scratch.path(), len).expect("open writable");
    let mut fs = luks_core::fs::btrfs::Btrfs::mount(dev).expect("mount fst-multileaf");
    let ino = fs
        .create_file_with_data("/", "test.txt", b"hello btrfs multi-leaf")
        .expect("write to multi-leaf FST succeeds");
    assert!(ino > 0);
}
