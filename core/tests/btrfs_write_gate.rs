//! Refusal gate tests for btrfs write support (Pass D).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_write_gate
//! ```
#![cfg(feature = "dangerous-write-support")]

use luks_core::error::LuksError;
use luks_core::fs::btrfs::superblock::Superblock;
use luks_core::fs::btrfs::write::gate::{
    check_free_space_tree_shape, check_sys_chunk_array_capacity, check_writeable_fs,
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

/// Fix 1 (D.1). Every commit rewrites the free-space tree as a single leaf,
/// so a tree with an interior root must be refused rather than flattened —
/// flattening it would strand the real child leaves, still charged to the
/// extent tree but unreachable from it.
#[test]
fn multi_leaf_free_space_tree_is_refused() {
    let mut fst_root = TreeRoot::default();
    fst_root.level = 1;
    match check_free_space_tree_shape(&fst_root).unwrap_err() {
        LuksError::UnsupportedFsFeature(msg) => {
            assert!(
                msg.contains("free-space tree"),
                "refusal must name the free-space tree, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedFsFeature, got {other:?}"),
    }
}

/// The control for the test above. Without it, a gate that refused *every*
/// free-space tree — including the single-leaf ones this writer handles
/// correctly, i.e. all four fixtures — would look identically green.
#[test]
fn single_leaf_free_space_tree_is_allowed() {
    let fst_root = TreeRoot::default();
    assert_eq!(fst_root.level, 0, "default TreeRoot must be a leaf for this control to mean anything");
    check_free_space_tree_shape(&fst_root)
        .expect("a single-leaf free-space tree is exactly what this writer supports");
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
