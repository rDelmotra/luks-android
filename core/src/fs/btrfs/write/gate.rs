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
