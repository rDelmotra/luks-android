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
    /// Begin a bounded-memory file transfer. The returned state has no volume
    /// reference, so storing it in a JNI handle cannot prolong key lifetime.
    pub fn begin_file(&self, size: u64) -> Result<crate::bridge::FileWriterEnum> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;
            match &mut *fs {
                Fs::Ext4(ext4) => Ok(crate::bridge::FileWriterEnum::Ext4(ext4.begin_file(size)?)),
                Fs::Btrfs(btrfs) => Ok(crate::bridge::FileWriterEnum::Btrfs(btrfs.begin_file(size)?)),
            }
        })
    }

    /// Begin an unknown-size file transfer. Unlike `begin_file`, no upfront
    /// size is required — extents are allocated as chunks arrive in
    /// `write_chunk`. The returned state has no volume reference, so storing
    /// it in a JNI handle cannot prolong key lifetime.
    pub fn begin_file_streaming(&self) -> Result<crate::bridge::FileWriterEnum> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;
            match &mut *fs {
                Fs::Ext4(ext4) => Ok(crate::bridge::FileWriterEnum::Ext4(ext4.begin_file_streaming()?)),
                Fs::Btrfs(btrfs) => Ok(crate::bridge::FileWriterEnum::Btrfs(btrfs.begin_file_streaming()?)),
            }
        })
    }

    pub fn write_file_chunk_with_cancel(
        &self,
        writer: &mut crate::bridge::FileWriterEnum,
        data: &[u8],
        cancel_token: u64,
    ) -> Result<()> {
        if cancel_token != 0 && crate::bridge::is_cancelled(cancel_token) {
            return Err(LuksError::Cancelled);
        }
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            match (&mut *fs, writer) {
                (Fs::Ext4(ext4), crate::bridge::FileWriterEnum::Ext4(w)) => ext4.write_chunk(w, data),
                (Fs::Btrfs(btrfs), crate::bridge::FileWriterEnum::Btrfs(w)) => btrfs.write_chunk(w, data),
                _ => unreachable!("writer type mismatch"),
            }
        })
    }

    pub fn write_file_chunk(&self, writer: &mut crate::bridge::FileWriterEnum, data: &[u8]) -> Result<()> {
        self.write_file_chunk_with_cancel(writer, data, 0)
    }

    pub fn finish_file(&self, writer: crate::bridge::FileWriterEnum, parent_path: &str, name: &str) -> Result<u64> {
        self.guarding_writes(move || {
        let mut fs = self.fs_for_writing()?;
        match (&mut *fs, writer) {
            (Fs::Ext4(ext4), crate::bridge::FileWriterEnum::Ext4(w)) => {
                let dir_ino = match ext4.resolve(parent_path) {
                    Ok(d) => d.number,
                    Err(e) => {
                        ext4.abandon_file(w);
                        return Err(e);
                    }
                };
                let ino = ext4.finish_file(w, dir_ino, name, FileType::Regular)?;
                ext4.flush()?;
                Ok(ino)
            }
            (Fs::Btrfs(btrfs), crate::bridge::FileWriterEnum::Btrfs(w)) => {
                let ino = btrfs.finish_file(w, parent_path, name)?;
                // btrfs adds to the active batch inside finish_file; explicitly call commit_active_batch later
                Ok(ino)
            }
            _ => unreachable!("writer type mismatch"),
        }
        })
    }

    pub fn commit_active_batch(&self) -> Result<()> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            match &mut *fs {
                Fs::Ext4(_) => Ok(()), // Ext4 commits immediately in finish_file
                Fs::Btrfs(btrfs) => btrfs.commit_active_batch(),
            }
        })
    }

    /// Roll back an in-flight write, freeing whatever it had reserved.
    ///
    /// # Why this is not wrapped in `guarding_writes`
    ///
    /// `ext4.abandon_file` / `btrfs.abandon_file` return `()`, not `Result` —
    /// they are cleanup, not a fallible write, so there is nothing for
    /// `guarding_writes` to inspect. That does not leave this path
    /// unguarded: the safety property that matters here is the same one
    /// every other mutator gets from `fs_for_writing` — a fenced or
    /// poisoned session must not touch the filesystem again. On btrfs,
    /// `abandon_file` can itself commit a transaction to disk (to rearm the
    /// active batch after freeing the writer's runs), which is exactly the
    /// kind of post-fence write this mechanism exists to prevent. Refusing
    /// to enter the `match` at all — the early `return` below — is what
    /// stops that.
    ///
    /// The writer's in-memory state (extents, runs, batch offsets) is not
    /// leaked by taking that early return: `writer` is owned by this
    /// function, and Rust drops it when the function returns regardless of
    /// which branch ran. Nothing here holds a raw resource that needs an
    /// explicit release — only heap-backed bookkeeping (`Vec`s of runs) that
    /// ordinary `Drop` reclaims. What is lost is the *filesystem's* record of
    /// the reservation, which is fine: a fenced or poisoned session is never
    /// going to commit anything again on this handle, so that on-disk state
    /// was already unreachable.
    pub fn abandon_file(&self, writer: crate::bridge::FileWriterEnum) {
        let Ok(mut fs) = self.fs_for_writing() else {
            return;
        };
        match (&mut *fs, writer) {
            (Fs::Ext4(ext4), crate::bridge::FileWriterEnum::Ext4(w)) => ext4.abandon_file(w),
            (Fs::Btrfs(btrfs), crate::bridge::FileWriterEnum::Btrfs(w)) => btrfs.abandon_file(w),
            _ => (), // If there's a mismatch we just let the writer drop
        }
    }

    /// Create `name` in `parent_path` holding `data`, returning the new inode number.
    ///
    /// # Ordering
    ///
    /// The flush is not optional and not the caller's to skip. A USB bridge
    /// acknowledges a write into its own buffer, so without it a "written"
    /// file is one yanked cable away from never having existed — and pulling
    /// the cable is how a phone transfer normally ends.
    pub fn write_file(&self, parent_path: &str, name: &str, data: &[u8]) -> Result<u64> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;

            match &mut *fs {
                Fs::Ext4(ext4) => {
                    let dir_ino = ext4.resolve(parent_path)?.number;
                    let ino = ext4.create_file(dir_ino, name, data, FileType::Regular)?;
                    ext4.flush()?;
                    Ok(ino)
                }
                Fs::Btrfs(btrfs) => {
                    // Now uses the single-transaction Phase 2 implementation,
                    // which guarantees atomicity: we either create the file AND write its data,
                    // or fail cleanly with no orphan file left behind.
                    let ino = btrfs.create_file_with_data(parent_path, name, data)?;
                    Ok(ino)
                }
            }
        })
    }

    /// Delete a file by path from the encrypted volume.
    pub fn delete_file(&self, path: &str) -> Result<()> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;
            match &mut *fs {
                Fs::Ext4(ext4) => ext4.delete_file(path),
                Fs::Btrfs(btrfs) => btrfs.delete_file(path),
            }
        })
    }

    /// Create a directory at `parent_path` with name `name`.
    pub fn create_directory(&self, parent_path: &str, name: &str) -> Result<u64> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;
            match &mut *fs {
                Fs::Ext4(ext4) => {
                    let dir_ino = ext4.resolve(parent_path)?.number as u32;
                    let ino = ext4.create_directory(dir_ino, name)?;
                    ext4.flush()?;
                    Ok(ino as u64)
                }
                Fs::Btrfs(btrfs) => {
                    let ino = btrfs.create_directory(parent_path, name)?;
                    Ok(ino)
                }
            }
        })
    }

    /// Rename an item from `(old_parent, old_name)` to `(new_parent, new_name)`.
    pub fn rename(&self, old_parent: &str, old_name: &str, new_parent: &str, new_name: &str) -> Result<()> {
        self.guarding_writes(|| {
            let mut fs = self.fs_for_writing()?;
            self.claim_writer()?;
            match &mut *fs {
                Fs::Ext4(ext4) => {
                    ext4.rename(old_parent, old_name, new_parent, new_name)?;
                    ext4.flush()?;
                    Ok(())
                }
                Fs::Btrfs(btrfs) => {
                    btrfs.rename(old_parent, old_name, new_parent, new_name)?;
                    Ok(())
                }
            }
        })
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
