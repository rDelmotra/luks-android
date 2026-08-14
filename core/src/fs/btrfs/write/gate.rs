//! The refusal gate for btrfs write operations.
//!
//! Every condition that would make writing unsafe or unsupported is checked here
//! before any allocation, CoW path computation, or device access begins.

use crate::error::{LuksError, Result};
use crate::fs::btrfs::superblock::{
    Superblock, BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE,
    BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID,
};
use crate::fs::btrfs::TreeRoot;

/// All `compat_ro` flags our write path can safely handle.
///
/// Any other flag (e.g. block-group-tree 0x4, verity 0x8) is refused.
pub const SUPPORTED_WRITE_COMPAT_RO: u64 =
    BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE | BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID;

/// Check that the filesystem geometry and superblock state permit writing.
pub fn check_writeable_fs(sb: &Superblock) -> Result<()> {
    // 1. Filesystem must have been unmounted cleanly.
    if sb.log_root != 0 {
        return Err(LuksError::FsNeedsRecovery);
    }

    // 2. Extent bookkeeping requires skinny metadata format.
    if !sb.has_skinny_metadata() {
        return Err(LuksError::UnsupportedFsFeature(
            "btrfs non-skinny metadata".into(),
        ));
    }

    // 3. Reject unrecognised compat_ro flags.
    let unsupported_compat_ro = sb.compat_ro_flags & !SUPPORTED_WRITE_COMPAT_RO;
    if unsupported_compat_ro != 0 {
        return Err(LuksError::UnsupportedFsFeature(format!(
            "btrfs unsupported compat_ro flags: 0x{unsupported_compat_ro:x}"
        )));
    }

    // 4. Multi-device filesystems are single-device only for writing.
    if sb.num_devices != 1 {
        return Err(LuksError::UnsupportedFsFeature(format!(
            "btrfs spanning {} devices",
            sb.num_devices
        )));
    }

    Ok(())
}

/// Check that the target subvolume is writeable.
pub fn check_writeable_subvolume(root: &TreeRoot) -> Result<()> {
    if root.is_read_only() {
        return Err(LuksError::UnsupportedFsFeature(
            "btrfs read-only subvolume".into(),
        ));
    }
    Ok(())
}

/// Refuse a free-space tree this writer cannot rewrite correctly.
///
/// Every commit rewrites the free-space tree wholesale from the allocator's
/// own view of free space (`txn.rs`), emitting it as **one leaf**. That is
/// sound only while the tree really is a single leaf — true of every fixture
/// here, and false of any drive large enough to need an interior root, where
/// the rewrite would install a level-0 node as the root and strand the real
/// child leaves: still charged to the extent tree, no longer reachable from
/// it.
///
/// Refusing by name is the project convention for a shape we understand but
/// have not implemented (§1). It is deliberately *not* worked around by
/// clearing `FREE_SPACE_TREE_VALID` and letting the kernel rebuild the tree:
/// measured 2026-08-14, `btrfs check` validates free-space-tree *contents*
/// against the extent tree whether or not that bit is set, so a stale tree
/// fails `check` until something mounts the filesystem read-write — see the
/// correction to §2 in `feature-btrfs-write.md`.
pub fn check_free_space_tree_shape(fst_root: &TreeRoot) -> Result<()> {
    if fst_root.level != 0 {
        return Err(LuksError::UnsupportedFsFeature(format!(
            "btrfs free-space tree spanning multiple leaves (root level {})",
            fst_root.level
        )));
    }
    Ok(())
}
