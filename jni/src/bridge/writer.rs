//! The currently whole-file write entry point for [`super::VolumeHandle`].
//!
//! This is deliberately a module boundary rather than a second public handle:
//! Pass 2b will replace the one-shot API with a streaming writer, and its
//! lifecycle must remain coupled to the per-device writer claim documented
//! here. Keeping that state in the bridge also preserves key zeroisation when
//! a volume is closed.

use luks_core::error::{LuksError, Result};
use luks_core::fs::{FileType, MountedFs as Fs};
use std::sync::atomic::Ordering;

use super::VolumeHandle;

/// Writing exists only when the write path was compiled in.
///
/// This separate implementation means a read-only build does not merely
/// refuse to write — it has nothing to refuse *with*.
impl VolumeHandle {
    /// Create `name` in the volume's root directory holding `data`, returning
    /// the new inode number.
    ///
    /// # Scope
    ///
    /// Root directory only, one whole file at a time, held in memory. That is
    /// what the phone needs to prove the path end to end; subdirectories and
    /// streaming are the next thing, not this thing. The size ceiling is real
    /// and comes from below: a new inode's extent tree is four inline extents,
    /// so a file too fragmented to describe in four runs is refused rather
    /// than truncated.
    ///
    /// # Ordering
    ///
    /// The flush is not optional and not the caller's to skip. A USB bridge
    /// acknowledges a write into its own buffer, so without it a "written"
    /// file is one yanked cable away from never having existed — and pulling
    /// the cable is how a phone transfer normally ends.
    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<u64> {
        // One writer per *device*, not per volume.
        //
        // `nativeUnlock` can be called twice on one device handle, and nothing
        // on the Kotlin side prevents it. Each call mounts its own `Ext4`,
        // which caches the superblock's free counters and every group
        // descriptor in memory. Two of those allocating against one disk do
        // not see each other's bitmap updates: measured, two volumes each
        // writing one small file left `e2fsck` reporting wrong free counts,
        // and racing them produced two files owning the same ten blocks —
        // the one kind of damage `e2fsck` cannot repair without deleting
        // something.
        //
        // A second *reader* is harmless and stays allowed: reads resolve
        // through the disk, and only allocation depends on the cached state.
        // So the claim is taken here, by the first write, rather than at
        // unlock — refusing a second unlock outright would break a UI that
        // re-prompts for a password without closing the first volume.
        // Taken *under the filesystem lock*, and after the btrfs refusal below.
        //
        // Under the lock because the two-step "load, then compare_exchange"
        // raced with itself otherwise: two threads writing through the *same*
        // handle could both read `holds_writer == false`, both attempt the
        // exchange, and the loser would be told another volume held the claim —
        // a statement that was simply false. The `fs` mutex already serialises
        // the work these two threads came to do, so it serialises the claim
        // too, and the second one now sees the flag this one set.
        //
        // After the btrfs check because a volume that cannot be written must
        // not walk away holding the device's only write claim until it is
        // closed, locking out the ext4 volume that could have used it.
        let mut fs = self.fs();
        let Fs::Ext4(ext4) = &mut *fs else {
            // Refused explicitly rather than by falling through to a missing
            // method: btrfs on this volume is a live filesystem we can read
            // and must not touch, and the caller deserves to be told which of
            // the two it got.
            return Err(LuksError::UnsupportedFsFeature(
                "writing to btrfs — this volume can be read but not written".into(),
            ));
        };

        if !self.holds_writer.load(Ordering::Acquire) {
            self.device_writer
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| LuksError::WriterBusy)?;
            self.holds_writer.store(true, Ordering::Release);
        }

        let ino = ext4.create_file(2, name, data, FileType::Regular)?;
        ext4.flush()?;
        Ok(ino)
    }
}
