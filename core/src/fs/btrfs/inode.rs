//! Inodes and directory entries.
//!
//! btrfs stores no directory *blocks*. A directory is just the set of items in
//! the fs tree whose objectid is the directory's, and each entry exists twice
//! under two different keys, for two different jobs:
//!
//! - `DIR_ITEM`, keyed by the hash of the name, so a lookup by name is one
//!   `O(log n)` search rather than a scan of the directory.
//! - `DIR_INDEX`, keyed by a sequence number, so listing yields entries in
//!   creation order and in one contiguous run.
//!
//! `.` and `..` are not stored at all, which is why nothing here has to filter
//! them out the way the ext4 reader does.
//!
//! Every field offset was read off real items in `fixtures/btrfs/plain.img` and
//! cross-checked against `btrfs inspect-internal dump-tree`.

use super::tree::Key;
use crate::error::{LuksError, Result};
use crate::fs::{FileInfo, FileType};

/// `btrfs_inode_item` is a fixed 160 bytes and always the whole item.
pub const INODE_ITEM_SIZE: usize = 160;

/// `location key (17) + transid (8) + data_len (2) + name_len (2) + type (1)`.
const DIR_ITEM_HEAD: usize = 30;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// One inode's metadata.
#[derive(Debug, Clone)]
pub struct Inode {
    pub objectid: u64,
    pub size: u64,
    /// Bytes actually allocated. Smaller than `size` for a compressed or
    /// sparse file, which is the cheapest signal that either is in play.
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Unix mode bits, including the file-type nibble.
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    pub atime: i64,
    pub ctime: i64,
    pub mtime: i64,
}

impl Inode {
    pub fn parse(objectid: u64, data: &[u8]) -> Result<Self> {
        if data.len() < INODE_ITEM_SIZE {
            return Err(LuksError::CorruptFs("btrfs inode item truncated"));
        }
        // Timestamps are `(u64 seconds, u32 nanoseconds)` pairs, 12 bytes each,
        // running atime / ctime / mtime / otime from offset 112. otime — the
        // creation time — has no place in `FileInfo`, so it is dropped.
        let secs = |at: usize| u64le(data, at) as i64;

        Ok(Inode {
            objectid,
            size: u64le(data, 16),
            nbytes: u64le(data, 24),
            nlink: u32le(data, 40),
            uid: u32le(data, 44),
            gid: u32le(data, 48),
            mode: u32le(data, 52),
            rdev: u64le(data, 56),
            flags: u64le(data, 64),
            atime: secs(112),
            ctime: secs(124),
            mtime: secs(136),
        })
    }

    pub fn file_type(&self) -> FileType {
        mode_to_type(self.mode)
    }

    pub fn info(&self) -> FileInfo {
        FileInfo {
            size: self.size,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            links: self.nlink,
            file_type: self.file_type(),
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }
}

fn mode_to_type(mode: u32) -> FileType {
    match mode & 0xF000 {
        0x8000 => FileType::Regular,
        0x4000 => FileType::Directory,
        0xA000 => FileType::Symlink,
        0x2000 => FileType::CharDevice,
        0x6000 => FileType::BlockDevice,
        0x1000 => FileType::Fifo,
        0xC000 => FileType::Socket,
        _ => FileType::Unknown,
    }
}

/// The `type` byte of a directory entry.
fn dir_type_to_file_type(raw: u8) -> FileType {
    match raw {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::CharDevice,
        4 => FileType::BlockDevice,
        5 => FileType::Fifo,
        6 => FileType::Socket,
        7 => FileType::Symlink,
        _ => FileType::Unknown,
    }
}

/// One directory entry, from either a `DIR_ITEM` or a `DIR_INDEX`.
#[derive(Debug, Clone)]
pub struct DirEntryItem {
    pub name: Vec<u8>,
    /// What the entry points at. `item_type` distinguishes an ordinary inode
    /// from a subvolume — see [`DirEntryItem::is_subvolume`].
    pub location: Key,
    pub file_type: FileType,
}

impl DirEntryItem {
    /// A directory entry whose location is a `ROOT_ITEM` is a subvolume mount
    /// point: it names a whole other tree, not an inode in this one. Reading it
    /// as an inode number would look up an unrelated file and succeed.
    pub fn is_subvolume(&self) -> bool {
        self.location.item_type == super::tree::ROOT_ITEM_KEY
    }

    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// Parse every entry packed into one `DIR_ITEM` or `DIR_INDEX` item.
///
/// A `DIR_INDEX` always holds exactly one. A `DIR_ITEM` holds one *per name
/// that hashes to the same value* — the item is keyed by the hash, so a
/// collision packs the colliding names end to end rather than creating a second
/// item. Stopping after the first entry would make a lookup silently fail for
/// one of any two colliding names, which is both rare and impossible to debug
/// from a bug report.
pub fn parse_dir_entries(mut data: &[u8]) -> Result<Vec<DirEntryItem>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < DIR_ITEM_HEAD {
            return Err(LuksError::CorruptFs("btrfs directory entry truncated"));
        }
        let data_len = u16le(data, 25) as usize;
        let name_len = u16le(data, 27) as usize;
        let total = DIR_ITEM_HEAD + name_len + data_len;
        if total > data.len() {
            return Err(LuksError::CorruptFs("btrfs directory entry overruns"));
        }

        out.push(DirEntryItem {
            name: data[DIR_ITEM_HEAD..DIR_ITEM_HEAD + name_len].to_vec(),
            location: Key {
                objectid: u64le(data, 0),
                item_type: data[8],
                offset: u64le(data, 9),
            },
            file_type: dir_type_to_file_type(data[29]),
        });

        data = &data[total..];
    }
    Ok(out)
}
