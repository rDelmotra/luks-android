//! Filesystem readers over a decrypted block device.
//!
//! Everything here reads through [`crate::device::ReadAt`], so a filesystem does
//! not know or care whether it sits on a plain image, a `LuksVolume`, or a USB
//! device. V1 is read-only by construction: there are no mutating methods.

pub mod btrfs;
pub mod ext4;

pub use btrfs::Btrfs;
pub use ext4::Ext4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

impl FileType {
    pub fn is_dir(self) -> bool {
        self == FileType::Directory
    }

    pub fn is_file(self) -> bool {
        self == FileType::Regular
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    /// Inode number — **except** when `is_subvolume` is set, in which case this
    /// is a btrfs tree id, and reading it as an inode number lands on an
    /// unrelated file that will happily pass every checksum.
    pub inode: u64,
    pub file_type: FileType,
    /// A btrfs subvolume boundary: still a directory, but a different fs tree
    /// underneath. Always false on ext4, which has no such thing.
    ///
    /// Worth surfacing rather than hiding, because it is the difference between
    /// a folder and something the user may know as a separate mount or a
    /// snapshot they cannot write to.
    pub is_subvolume: bool,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub size: u64,
    /// Unix mode bits, including the file-type nibble.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub file_type: FileType,
    /// Seconds since the Unix epoch.
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}
