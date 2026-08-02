//! One filesystem handle over either reader.
//!
//! An enum rather than a `Box<dyn Filesystem>` because the two readers do not
//! have the same shape and pretending they do costs more than it saves. ext4
//! identifies a file by inode number; btrfs needs an inode *and* the tree it
//! lives in, since subvolumes number their inodes independently. A trait
//! flattening both to `u64` is exactly the bug that `Located` exists to
//! prevent — an inode read against the wrong tree returns a real file, with
//! valid checksums, that nobody asked for.
//!
//! This lives in `core` rather than in the JNI bridge so that anything reading
//! a volume — the bridge, the host-side examples, a future desktop build —
//! makes the same decision the same way, and so the decision is testable
//! without an Android toolchain.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::{self, Btrfs};
use crate::fs::detect::{detect, FsKind};
use crate::fs::ext4::{self, Ext4};
use crate::fs::{DirEntry, FileInfo, FileType};

/// A mounted filesystem, whichever one the volume turned out to hold.
pub enum MountedFs<D: ReadAt> {
    Ext4(Ext4<D>),
    Btrfs(Btrfs<D>),
}

/// A resolved file, held open across a streaming read.
///
/// The reason this exists rather than passing a path to each read: hashing a
/// 1 GiB file in 1 MiB chunks would otherwise re-resolve the path a thousand
/// times, and each resolution is a directory walk — over USB, that is a
/// thousand round trips to answer a question already answered.
pub enum OpenFile {
    Ext4(ext4::Inode),
    /// The tree comes along because an inode number alone does not identify a
    /// file on btrfs.
    Btrfs { tree: u64, inode: btrfs::Inode },
}

impl OpenFile {
    pub fn size(&self) -> u64 {
        match self {
            OpenFile::Ext4(i) => i.info().size,
            OpenFile::Btrfs { inode, .. } => inode.size,
        }
    }

    pub fn file_type(&self) -> FileType {
        match self {
            OpenFile::Ext4(i) => i.file_type(),
            OpenFile::Btrfs { inode, .. } => inode.file_type(),
        }
    }
}

impl<D: ReadAt> MountedFs<D> {
    /// Decide what is on the volume, then hand it to exactly one reader.
    ///
    /// The decision comes first because mounting consumes the volume, so
    /// "try one, fall back to the other" is not available — and re-opening a
    /// `LuksVolume` to retry means running Argon2 a second time. See
    /// [`crate::fs::detect`].
    pub fn mount(device: D) -> Result<Self> {
        match detect(&device)? {
            FsKind::Ext4 => Ok(MountedFs::Ext4(Ext4::mount(device)?)),
            FsKind::Btrfs => Ok(MountedFs::Btrfs(Btrfs::mount(device)?)),
        }
    }

    pub fn kind(&self) -> FsKind {
        match self {
            MountedFs::Ext4(_) => FsKind::Ext4,
            MountedFs::Btrfs(_) => FsKind::Btrfs,
        }
    }

    /// `None` for a volume that was never given a label — distinct from one
    /// labelled with an empty string, which is why this is not a `&str`.
    pub fn label(&self) -> Option<&str> {
        match self {
            MountedFs::Ext4(fs) => {
                let name = fs.volume_name();
                (!name.is_empty()).then_some(name)
            }
            MountedFs::Btrfs(fs) => fs.volume_name(),
        }
    }

    pub fn uuid(&self) -> [u8; 16] {
        match self {
            MountedFs::Ext4(fs) => fs.uuid(),
            MountedFs::Btrfs(fs) => fs.fsid(),
        }
    }

    /// The allocation unit a user would recognise. ext4 calls it a block;
    /// btrfs calls the same thing a sector and reserves "block" for its
    /// 16 KiB metadata nodes.
    pub fn block_size(&self) -> u32 {
        match self {
            MountedFs::Ext4(fs) => fs.block_size(),
            MountedFs::Btrfs(fs) => fs.sector_size(),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        match self {
            MountedFs::Ext4(fs) => fs.superblock().blocks_count * fs.block_size() as u64,
            MountedFs::Btrfs(fs) => fs.superblock().total_bytes,
        }
    }

    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        match self {
            MountedFs::Ext4(fs) => fs.list_dir(path),
            MountedFs::Btrfs(fs) => fs.list_dir(path),
        }
    }

    pub fn file_info(&self, path: &str) -> Result<FileInfo> {
        match self {
            MountedFs::Ext4(fs) => fs.file_info(path),
            MountedFs::Btrfs(fs) => fs.file_info(path),
        }
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            MountedFs::Ext4(fs) => fs.read_file(path),
            MountedFs::Btrfs(fs) => fs.read_file(path),
        }
    }

    pub fn open(&self, path: &str) -> Result<OpenFile> {
        match self {
            MountedFs::Ext4(fs) => Ok(OpenFile::Ext4(fs.resolve(path)?)),
            MountedFs::Btrfs(fs) => {
                let found = fs.resolve_no_follow(fs.fs_tree(), path)?;
                Ok(OpenFile::Btrfs {
                    tree: found.tree.bytenr,
                    inode: found.inode,
                })
            }
        }
    }

    pub fn read_open(&self, file: &OpenFile, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match (self, file) {
            (MountedFs::Ext4(fs), OpenFile::Ext4(inode)) => fs.read_inode_data(inode, offset, buf),
            (MountedFs::Btrfs(fs), OpenFile::Btrfs { tree, inode }) => {
                fs.read_inode_data(*tree, inode, offset, buf)
            }
            // Only reachable by handing a file opened on one volume to another,
            // which no caller does — but returning an error beats a panic on a
            // path that runs with a device attached.
            _ => Err(LuksError::UnknownFs),
        }
    }

    /// Subvolumes, empty on a filesystem that has no such concept.
    pub fn subvolumes(&self) -> Result<Vec<btrfs::Subvolume>> {
        match self {
            MountedFs::Ext4(_) => Ok(Vec::new()),
            MountedFs::Btrfs(fs) => fs.subvolumes(),
        }
    }
}
