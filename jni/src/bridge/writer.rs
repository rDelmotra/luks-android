//! The currently whole-file write entry point for [`super::VolumeHandle`].
//!
//! This is deliberately a module boundary rather than a second public handle:
//! Pass 2b will replace the one-shot API with a streaming writer, and its
//! lifecycle must remain coupled to the per-device writer claim documented
//! here. Keeping that state in the bridge also preserves key zeroisation when
//! a volume is closed.

use luks_core::error::{LuksError, Result};
use luks_core::fs::ext4::file::FileWriter;
use luks_core::fs::{FileType, MountedFs as Fs};
use std::sync::atomic::Ordering;

use super::VolumeHandle;

/// Writing exists only when the write path was compiled in.
///
/// This separate implementation means a read-only build does not merely
/// refuse to write — it has nothing to refuse *with*.
impl VolumeHandle {
    /// Begin a bounded-memory file transfer. The returned state has no volume
    /// reference, so storing it in a JNI handle cannot prolong key lifetime.
    pub fn begin_file(&self, size: u64) -> Result<FileWriter> {
        let mut fs = self.fs();
        let Fs::Ext4(ext4) = &mut *fs else {
            return Err(LuksError::UnsupportedFsFeature(
                "writing to btrfs — this volume can be read but not written".into(),
            ));
        };
        self.claim_writer()?;
        ext4.begin_file(size)
    }

    /// Feed one chunk to a stream begun on this volume.
    pub fn write_file_chunk(&self, writer: &mut FileWriter, data: &[u8]) -> Result<()> {
        let mut fs = self.fs();
        let Fs::Ext4(ext4) = &mut *fs else {
            unreachable!("writer began on ext4")
        };
        ext4.write_chunk(writer, data)
    }

    /// Publish a complete streamed file.
    pub fn finish_file(&self, writer: FileWriter, parent_path: &str, name: &str) -> Result<u64> {
        let mut fs = self.fs();
        let Fs::Ext4(ext4) = &mut *fs else {
            unreachable!("writer began on ext4")
        };
        let dir_ino = match ext4.resolve(parent_path) {
            Ok(d) => d.number,
            Err(e) => {
                ext4.abandon_file(writer);
                return Err(e);
            }
        };
        let ino = ext4.finish_file(writer, dir_ino, name, FileType::Regular)?;
        ext4.flush()?;
        Ok(ino)
    }

    /// Explicitly discard an interrupted stream.
    pub fn abandon_file(&self, writer: FileWriter) {
        let mut fs = self.fs();
        if let Fs::Ext4(ext4) = &mut *fs {
            ext4.abandon_file(writer);
        }
    }

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
    pub fn write_file(&self, parent_path: &str, name: &str, data: &[u8]) -> Result<u64> {
        // One writer per *device*, not per volume.
        //
        // `nativeUnlock` can be called twice on one device handle, and nothing
        // on the Kotlin side prevents it. Each call mounts its own filesystem
        // state — ext4's superblock free counters and group descriptors, or
        // btrfs's node cache — separately. Two of those allocating against one
        // disk do not see each other's bookkeeping updates: measured on ext4,
        // two volumes each writing one small file left `e2fsck` reporting
        // wrong free counts, and racing them produced two files owning the
        // same ten blocks — the one kind of damage `e2fsck` cannot repair
        // without deleting something. Nothing about that argument is specific
        // to ext4, so the same claim covers btrfs.
        //
        // A second *reader* is harmless and stays allowed: reads resolve
        // through the disk, and only allocation depends on the cached state.
        // So the claim is taken here, by the first write, rather than at
        // unlock — refusing a second unlock outright would break a UI that
        // re-prompts for a password without closing the first volume.
        // Taken *under the filesystem lock*.
        //
        // Under the lock because the two-step "load, then compare_exchange"
        // raced with itself otherwise: two threads writing through the *same*
        // handle could both read `holds_writer == false`, both attempt the
        // exchange, and the loser would be told another volume held the claim —
        // a statement that was simply false. The `fs` mutex already serialises
        // the work these two threads came to do, so it serialises the claim
        // too, and the second one now sees the flag this one set.
        let mut fs = self.fs();
        self.claim_writer()?;

        match &mut *fs {
            Fs::Ext4(ext4) => {
                let dir_ino = ext4.resolve(parent_path)?.number;
                let ino = ext4.create_file(dir_ino, name, data, FileType::Regular)?;
                ext4.flush()?;
                Ok(ino)
            }
            Fs::Btrfs(btrfs) => {
                // Two core calls, not one, matching how the write engine
                // itself is staged (Pass E creates the empty inode + dirent;
                // Pass F allocates and writes the data extent). Root-directory
                // and subdirectory writes only — anything outside the default
                // subvolume's FS_TREE is refused inside `write_file_data`
                // itself (feature-btrfs-write.md, "not doing this yet"), so
                // there is nothing to duplicate here.
                let full_path = if parent_path == "/" {
                    format!("/{name}")
                } else {
                    format!("{parent_path}/{name}")
                };
                btrfs.create_file(parent_path, name)?;
                btrfs.write_file(&full_path, data)?;
                // btrfs's own inode numbers are objectids, and this is the
                // only way to learn the one `create_file` picked — its
                // signature returns `()`, unlike ext4's `create_file`, which
                // hands the number straight back.
                let located = btrfs.resolve_no_follow(btrfs.fs_tree(), &full_path)?;
                Ok(located.inode.objectid)
            }
        }
    }

    /// Delete a file by path from the encrypted volume.
    pub fn delete_file(&self, path: &str) -> Result<()> {
        let mut fs = self.fs();
        let Fs::Ext4(ext4) = &mut *fs else {
            return Err(LuksError::UnsupportedFsFeature(
                "deleting from btrfs — this volume can be read but not written".into(),
            ));
        };
        self.claim_writer()?;
        ext4.delete_file(path)
    }

    fn claim_writer(&self) -> Result<()> {
        if !self.holds_writer.load(Ordering::Acquire) {
            self.device_writer
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| LuksError::WriterBusy)?;
            self.holds_writer.store(true, Ordering::Release);
        }
        Ok(())
    }
}
