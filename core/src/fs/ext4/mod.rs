//! Read-only ext2/ext3/ext4 reader.
//!
//! Supports both block-mapping schemes: ext4 extent trees and the legacy
//! ext2/ext3 indirect block chain, so this works on old drives too.
//!
//! Directories are always scanned linearly. That is not a limitation: an htree
//! (`dir_index`) directory keeps its hash tree inside dirents whose inode number
//! is zero, precisely so that a reader ignorant of htree still sees every entry.
//! Skipping `inode == 0` is therefore both correct and complete — and it avoids
//! needing the hash code, which in lwext4 is the GPLv2 part.

#[cfg(feature = "dangerous-write-support")]
pub mod alloc;
pub mod csum;
#[cfg(feature = "dangerous-write-support")]
pub mod dirent;
#[cfg(feature = "dangerous-write-support")]
pub mod file;

use crate::device::ReadAt;
#[cfg(feature = "dangerous-write-support")]
use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::{DirEntry, FileInfo, FileType};

const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXTENT_MAGIC: u16 = 0xF30A;
const ROOT_INODE: u64 = 2;
const MAX_SYMLINK_DEPTH: usize = 8;

// s_feature_incompat bits
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
/// Inodes may carry extent trees. Absent on ext2/ext3 — where writing an
/// extent-mapped inode, as [`file`] does, produces an inode `e2fsck` rejects.
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
/// Small files and directories live inside `i_block` itself. An inline
/// directory has no extent tree, so mapping its "blocks" returns garbage —
/// which a writer would then write to.
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;

// s_feature_ro_compat bits beyond the checksum pair below
/// Quota usage is tracked in hidden inodes that a writer must update in step
/// with every allocation. This crate does not, so it must not write here.
const RO_COMPAT_QUOTA: u32 = 0x0100;
/// Block bitmaps address *clusters* of `2^(s_log_cluster_size - s_log_block_size)`
/// blocks, and the free counters count clusters. An allocator that assumes
/// bit == block hands out block numbers wrong by the cluster ratio — on top
/// of other files.
///
/// ⚠️ This is a **ro_compat** bit (0x0200 there), *not* incompat — old
/// kernels may still mount bigalloc read-only, which is exactly the situation
/// this crate is in. The same value in `feature_incompat` is `flex_bg`, which
/// nearly every modern filesystem has: testing the wrong field refuses to
/// write everything real and lets actual bigalloc straight through. That
/// exact mistake was made here and caught by the fixture suite within
/// minutes, because every fixture carries `flex_bg`.
const RO_COMPAT_BIGALLOC: u32 = 0x0200;

// s_state bits
/// The filesystem was cleanly unmounted. *Absent* means it is mounted right
/// now or died mid-write — either way the on-disk metadata cannot be trusted
/// as a base for further writes.
const STATE_CLEANLY_UNMOUNTED: u16 = 0x0001;
/// The kernel saw errors on this filesystem. `e2fsck` gets it first.
const STATE_ERRORS_SEEN: u16 = 0x0002;

// s_feature_ro_compat bits
/// Group descriptors carry a crc16 and bitmaps may be lazily initialised.
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
/// Everything — superblock, descriptors, bitmaps, inodes, extents, dirents —
/// carries a crc32c.
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

// Superblock offsets in the 64-bit tail.
//
// These are four adjacent fields of the same shape, and `s_r_blocks_count_hi`
// sits between the two block counts. Dropping it from a mental model shifts
// everything after it four bytes early — which is exactly what happened here:
// `s_free_blocks_count_hi` was read from `s_r_blocks_count_hi`, and
// `s_min_extra_isize` from `s_free_blocks_count_hi`. Both were invisible
// because every hi word is zero below 16 TiB. Named, not inlined, so the gap
// stays on screen.
//
//   0x150 s_blocks_count_hi
//   0x154 s_r_blocks_count_hi   <- read by nobody, and that is the trap
//   0x158 s_free_blocks_count_hi
//   0x15C s_min_extra_isize (u16) | 0x15E s_want_extra_isize (u16)
const SB_BLOCKS_COUNT_HI: usize = 0x150;
const SB_R_BLOCKS_COUNT_HI: usize = 0x154;
pub(crate) const SB_FREE_BLOCKS_COUNT_HI: usize = 0x158;
const SB_MIN_EXTRA_ISIZE: usize = 0x15C;

// bg_flags bits
/// The inode bitmap and table for this group have never been written.
pub const BG_INODE_UNINIT: u16 = 0x0001;
/// The block bitmap for this group have never been written.
pub const BG_BLOCK_UNINIT: u16 = 0x0002;

// i_flags bits
const INODE_FL_EXTENTS: u32 = 0x0008_0000;
const INODE_FL_INLINE_DATA: u32 = 0x1000_0000;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parsed ext4 superblock — only the fields a reader needs.
#[derive(Debug, Clone)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub s_r_blocks_count: u64,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub desc_size: u16,
    pub uuid: [u8; 16],
    pub volume_name: String,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub clusters_per_group: u32,
    /// First inode a file may use. Everything below is reserved (2 is root,
    /// 8 is the journal), so an allocator must never hand one of them out.
    pub first_ino: u32,
    /// `s_checksum_seed`, present only with the `csum_seed` incompat feature.
    /// Without it the seed is derived from the UUID — see [`csum::Seed`].
    pub checksum_seed: Option<u32>,
    /// `s_min_extra_isize`: how much of the extra area past the 128-byte base
    /// inode a new inode must reserve. A writer that ignores this and uses a
    /// smaller value produces an inode `e2fsck` rejects as too small to hold
    /// what the filesystem requires — the checksum's own `i_checksum_hi` among
    /// it, on any filesystem with `metadata_csum`.
    pub min_extra_isize: u16,
    /// `s_state`. Read for one purpose: refusing to *write* a filesystem that
    /// is not cleanly unmounted or has recorded errors — see
    /// [`csum::Seed::for_writing`].
    pub state: u16,
    pub reserved_gdt_blocks: u16,
}

pub const EXT4_FEATURE_COMPAT_RESIZE_INODE: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;

impl Superblock {
    fn parse(b: &[u8]) -> Result<Self> {
        let magic = u16le(b, 56);
        if magic != EXT4_MAGIC {
            return Err(LuksError::NotExt4(magic));
        }

        let log_block_size = u32le(b, 24);
        if log_block_size > 6 {
            return Err(LuksError::CorruptFs("implausible block size"));
        }
        let block_size = 1024u32 << log_block_size;

        let rev_level = u32le(b, 76);
        // Revision 0 predates configurable inode sizes and fixes them at 128.
        let (inode_size, feature_compat, feature_incompat, feature_ro_compat, desc_size) = if rev_level >= 1 {
            (
                u16le(b, 88),
                u32le(b, 92),
                u32le(b, 96),
                u32le(b, 100),
                u16le(b, 254),
            )
        } else {
            (128, 0, 0, 0, 0)
        };
        if inode_size < 128 {
            return Err(LuksError::CorruptFs("inode size below 128"));
        }

        let blocks_lo = u32le(b, 4) as u64;
        let blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 {
            u32le(b, SB_BLOCKS_COUNT_HI) as u64
        } else {
            0
        };

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[104..120]);

        let name_end = b[120..136].iter().position(|&c| c == 0).unwrap_or(16);
        let volume_name = String::from_utf8_lossy(&b[120..120 + name_end]).into_owned();

        let inodes_per_group = u32le(b, 40);
        let blocks_per_group = u32le(b, 32);
        if inodes_per_group == 0 || blocks_per_group == 0 {
            return Err(LuksError::CorruptFs("zero inodes or blocks per group"));
        }

        let free_blocks_lo = u32le(b, 12) as u64;
        let free_blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 {
            u32le(b, SB_FREE_BLOCKS_COUNT_HI) as u64
        } else {
            0
        };

        // s_clusters_per_group equals s_blocks_per_group unless bigalloc is on,
        // which we do not support; falling back keeps old revisions working.
        let clusters_per_group = match u32le(b, 36) {
            0 => blocks_per_group,
            n => n,
        };

        let checksum_seed = if feature_incompat & INCOMPAT_CSUM_SEED != 0 {
            Some(u32le(b, 0x270))
        } else {
            None
        };

        let min_extra_isize = if rev_level >= 1 {
            u16le(b, SB_MIN_EXTRA_ISIZE)
        } else {
            0
        };

        let r_blocks_lo = u32le(b, 8) as u64;
        let r_blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 {
            u32le(b, SB_R_BLOCKS_COUNT_HI) as u64
        } else {
            0
        };

        Ok(Superblock {
            inodes_count: u32le(b, 0),
            blocks_count: blocks_lo | (blocks_hi << 32),
            s_r_blocks_count: r_blocks_lo | (r_blocks_hi << 32),
            first_data_block: u32le(b, 20),
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            feature_incompat,
            feature_ro_compat,
            desc_size,
            uuid,
            volume_name,
            free_blocks_count: free_blocks_lo | (free_blocks_hi << 32),
            free_inodes_count: u32le(b, 16),
            clusters_per_group,
            first_ino: if rev_level >= 1 { u32le(b, 84) } else { 11 },
            checksum_seed,
            min_extra_isize,
            state: u16le(b, 0x3A),
            reserved_gdt_blocks: if feature_compat & EXT4_FEATURE_COMPAT_RESIZE_INODE != 0 {
                u16le(b, 206)
            } else {
                0
            },
        })
    }

    fn is_64bit(&self) -> bool {
        self.feature_incompat & INCOMPAT_64BIT != 0
    }

    pub fn group_first_block(&self, group: usize) -> u64 {
        group as u64 * self.blocks_per_group as u64 + self.first_data_block as u64
    }

    pub fn group_has_super(&self, group: usize) -> bool {
        if group <= 1 {
            return true;
        }
        if self.feature_ro_compat & EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER == 0 {
            return true;
        }

        let mut test = group;
        while test % 3 == 0 {
            test /= 3;
        }
        if test == 1 {
            return true;
        }

        let mut test = group;
        while test % 5 == 0 {
            test /= 5;
        }
        if test == 1 {
            return true;
        }

        let mut test = group;
        while test % 7 == 0 {
            test /= 7;
        }
        test == 1
    }

    /// Whether every metadata structure carries a crc32c.
    pub fn has_metadata_csum(&self) -> bool {
        self.feature_ro_compat & RO_COMPAT_METADATA_CSUM != 0
    }

    /// The older scheme: a crc16 on group descriptors only. We can read these
    /// filesystems but refuse to write them — see [`csum::Seed::for_writing`].
    pub fn has_gdt_csum_only(&self) -> bool {
        self.feature_ro_compat & RO_COMPAT_GDT_CSUM != 0 && !self.has_metadata_csum()
    }

    /// Bytes per block group descriptor.
    pub fn group_desc_size(&self) -> usize {
        if self.is_64bit() && self.desc_size >= 64 {
            self.desc_size as usize
        } else {
            32
        }
    }

    pub fn group_count(&self) -> u64 {
        let per = self.blocks_per_group as u64;
        (self.blocks_count - self.first_data_block as u64).div_ceil(per)
    }

    /// Byte offset of the group descriptor table.
    ///
    /// The table starts in the block after the superblock. With a 1 KiB block
    /// size the superblock occupies block 1, so the table is at block 2;
    /// otherwise the superblock shares block 0 and the table is at block 1.
    pub fn group_desc_offset(&self) -> u64 {
        (self.first_data_block as u64 + 1) * self.block_size as u64
    }
}

/// One block group descriptor, parsed whole.
///
/// The reader only ever needed `inode_table`. A writer needs all of it: the
/// bitmaps to allocate from, the counters to keep consistent with them, and the
/// checksum fields that make a stale counter a detectable error rather than a
/// silent one.
#[derive(Debug, Clone, Default)]
pub struct GroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub flags: u16,
    /// Inodes at the tail of this group's table that have never been used, so
    /// e2fsck may skip them. Allocating into that region must shrink it.
    pub itable_unused: u32,
    pub checksum: u16,
    pub block_bitmap_csum: u32,
    pub inode_bitmap_csum: u32,
}

impl GroupDesc {
    /// Parse one descriptor. `d` is exactly `desc_size` bytes.
    ///
    /// The high halves exist only in 64-byte descriptors. Reading them from a
    /// 32-byte descriptor would pick up the *next* group's fields, which is the
    /// kind of mistake that produces plausible numbers.
    fn parse(d: &[u8]) -> Self {
        let wide = d.len() >= 64;
        let hi16 = |o: usize| if wide { u16le(d, o) as u32 } else { 0 };
        let hi32 = |o: usize| if wide { u32le(d, o) as u64 } else { 0 };

        GroupDesc {
            block_bitmap: u32le(d, 0x00) as u64 | (hi32(0x20) << 32),
            inode_bitmap: u32le(d, 0x04) as u64 | (hi32(0x24) << 32),
            inode_table: u32le(d, 0x08) as u64 | (hi32(0x28) << 32),
            free_blocks_count: u16le(d, 0x0C) as u32 | (hi16(0x2C) << 16),
            free_inodes_count: u16le(d, 0x0E) as u32 | (hi16(0x2E) << 16),
            used_dirs_count: u16le(d, 0x10) as u32 | (hi16(0x30) << 16),
            flags: u16le(d, 0x12),
            block_bitmap_csum: u16le(d, 0x18) as u32 | (hi16(0x38) << 16),
            inode_bitmap_csum: u16le(d, 0x1A) as u32 | (hi16(0x3A) << 16),
            itable_unused: u16le(d, 0x1C) as u32 | (hi16(0x32) << 16),
            checksum: u16le(d, 0x1E),
        }
    }

    pub fn block_bitmap_uninit(&self) -> bool {
        self.flags & BG_BLOCK_UNINIT != 0
    }

    pub fn inode_bitmap_uninit(&self) -> bool {
        self.flags & BG_INODE_UNINIT != 0
    }
}

/// One inode's worth of metadata plus its raw block-mapping area.
#[derive(Debug, Clone)]
pub struct Inode {
    pub number: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub flags: u32,
    pub atime: i64,
    pub ctime: i64,
    pub mtime: i64,
    /// `i_generation`. Needed to check or write any checksum belonging to this
    /// inode or to a directory block it owns — both fold it into the seed.
    pub generation: u32,
    /// `i_block`: an extent tree, an indirect block chain, or inline data.
    pub block_area: [u8; 60],
}

impl Inode {
    pub fn file_type(&self) -> FileType {
        match self.mode & 0xF000 {
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

    pub(crate) fn uses_extents(&self) -> bool {
        self.flags & INODE_FL_EXTENTS != 0
    }

    pub(crate) fn is_inline(&self) -> bool {
        self.flags & INODE_FL_INLINE_DATA != 0
    }

    pub fn info(&self) -> FileInfo {
        FileInfo {
            size: self.size,
            mode: self.mode as u32,
            uid: self.uid,
            gid: self.gid,
            links: self.links as u32,
            file_type: self.file_type(),
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }
}

/// A mounted, read-only ext2/3/4 filesystem.
///
/// Owns its device. `D` is usually a reference (`&LuksVolume<..>`) via the
/// blanket `impl ReadAt for &D`, so `Ext4::mount(&volume)` still works; the
/// owning form is what lets a JNI handle hold the whole stack. See the note on
/// [`crate::luks::LuksVolume`].
pub struct Ext4<D: ReadAt> {
    device: D,
    sb: Superblock,
    /// Every block group descriptor, parsed at mount.
    groups: Vec<GroupDesc>,
}

impl<D: ReadAt> Ext4<D> {
    /// Read the superblock and group descriptors.
    ///
    /// Refuses filesystems whose on-disk state cannot be read correctly rather
    /// than returning plausible-looking wrong data.
    pub fn mount(device: D) -> Result<Self> {
        let mut sb_buf = [0u8; 1024];
        device.read_at(SUPERBLOCK_OFFSET, &mut sb_buf)?;
        let sb = Superblock::parse(&sb_buf)?;

        // A dirty journal means the newest metadata lives in the journal, not
        // in place. Reading anyway would show a filesystem that never existed.
        if sb.feature_incompat & INCOMPAT_RECOVER != 0 {
            return Err(LuksError::FsNeedsRecovery);
        }
        if sb.feature_incompat & INCOMPAT_ENCRYPT != 0 {
            return Err(LuksError::UnsupportedFsFeature(
                "fscrypt per-file encryption".into(),
            ));
        }
        if sb.feature_incompat & INCOMPAT_JOURNAL_DEV != 0 {
            return Err(LuksError::UnsupportedFsFeature(
                "external journal device".into(),
            ));
        }
        if sb.feature_incompat & INCOMPAT_META_BG != 0 {
            return Err(LuksError::UnsupportedFsFeature("meta_bg layout".into()));
        }

        let groups = Self::read_group_descriptors(&device, &sb)?;
        Ok(Ext4 {
            device,
            sb,
            groups,
        })
    }

    fn read_group_descriptors(device: &D, sb: &Superblock) -> Result<Vec<GroupDesc>> {
        let count = sb.group_count();
        let desc_size = sb.group_desc_size();

        let total = (count as usize)
            .checked_mul(desc_size)
            .ok_or(LuksError::CorruptFs("group descriptor table too large"))?;
        let mut buf = vec![0u8; total];
        device.read_at(sb.group_desc_offset(), &mut buf)?;

        Ok((0..count as usize)
            .map(|g| GroupDesc::parse(&buf[g * desc_size..(g + 1) * desc_size]))
            .collect())
    }

    /// The parsed block group descriptors.
    pub fn groups(&self) -> &[GroupDesc] {
        &self.groups
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    pub fn block_size(&self) -> u32 {
        self.sb.block_size
    }

    pub fn volume_name(&self) -> &str {
        &self.sb.volume_name
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.sb.uuid
    }

    pub fn statfs(&self) -> Result<crate::fs::StatFs> {
        let bs = self.sb.block_size as u64;
        let total_bytes = self.sb.blocks_count * bs;
        let free_bytes = self.sb.free_blocks_count * bs;
        let available_blocks = self.sb.free_blocks_count.saturating_sub(self.sb.s_r_blocks_count);
        let available_bytes = available_blocks * bs;
        let total_inodes = self.sb.inodes_count as u64;
        let free_inodes = self.sb.free_inodes_count as u64;
        let block_size = self.sb.block_size;

        Ok(crate::fs::StatFs {
            total_bytes,
            free_bytes,
            available_bytes,
            total_inodes,
            free_inodes,
            block_size,
        })
    }

    #[cfg(any(test, feature = "dangerous-write-support"))]
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    pub(crate) fn read_block(&self, block: u64, buf: &mut [u8]) -> Result<()> {
        if block >= self.sb.blocks_count {
            return Err(LuksError::CorruptFs("block pointer past end of filesystem"));
        }
        self.device
            .read_at(block * self.sb.block_size as u64, buf)
    }

    /// Byte offset of `block`, refusing numbers that cannot belong to a
    /// metadata or directory block on this filesystem.
    ///
    /// Every other offset this crate writes to is either fixed (the
    /// superblock) or derived from a bounded index (the descriptor table).
    /// This is for the rest: block numbers read *from the disk itself* — an
    /// extent's target, a descriptor's bitmap pointer — which are exactly as
    /// trustworthy as the disk. A single flipped bit in `ee_start_hi` moves a
    /// pointer by 4 TiB, and without this check that becomes a 4 KiB write at
    /// an arbitrary offset: past the filesystem, over the LUKS header, into a
    /// neighbouring partition.
    ///
    /// The lower bound also excludes block 0 on a 4 KiB filesystem and block 1
    /// on a 1 KiB one — both hold the superblock, which a valid pointer can
    /// never name.
    pub(crate) fn metadata_block_offset(&self, block: u64) -> Result<u64> {
        if block <= self.sb.first_data_block as u64 || block >= self.sb.blocks_count {
            return Err(LuksError::CorruptFs(
                "a block pointer reaches outside the filesystem",
            ));
        }
        Ok(block * self.sb.block_size as u64)
    }

    /// Byte offset of an inode's on-disk record.
    pub(crate) fn inode_offset(&self, ino: u64) -> Result<u64> {
        if ino == 0 || ino > self.sb.inodes_count as u64 {
            return Err(LuksError::BadInode(ino));
        }
        let group = (ino - 1) / self.sb.inodes_per_group as u64;
        let index = (ino - 1) % self.sb.inodes_per_group as u64;
        let table = self
            .groups
            .get(group as usize)
            .ok_or(LuksError::BadInode(ino))?
            .inode_table;

        // The table pointer comes from the disk, so it gets the same treatment
        // as any other on-disk block number: prove the record lands inside the
        // filesystem before anything reads it — or, worse, writes it.
        self.metadata_block_offset(table)?;
        let offset = table * self.sb.block_size as u64 + index * self.sb.inode_size as u64;
        let fs_bytes = self
            .sb
            .blocks_count
            .checked_mul(self.sb.block_size as u64)
            .ok_or(LuksError::CorruptFs("filesystem size overflows"))?;
        if offset
            .checked_add(self.sb.inode_size as u64)
            .is_none_or(|end| end > fs_bytes)
        {
            return Err(LuksError::CorruptFs(
                "an inode table places an inode outside the filesystem",
            ));
        }
        Ok(offset)
    }

    #[cfg(any(test, feature = "dangerous-write-support"))]
    pub fn test_inode_offset(&self, ino: u64) -> Result<u64> {
        self.inode_offset(ino)
    }

    /// An inode's raw on-disk bytes, `s_inode_size` long. Checksumming an
    /// inode needs the exact bytes, not a parsed subset.
    pub(crate) fn read_raw_inode(&self, ino: u64) -> Result<Vec<u8>> {
        let offset = self.inode_offset(ino)?;
        let mut raw = vec![0u8; self.sb.inode_size as usize];
        self.device.read_at(offset, &mut raw)?;
        Ok(raw)
    }

    /// Load an inode by number. Inode 1 is the bad-blocks inode; 2 is the root.
    pub fn read_inode(&self, ino: u64) -> Result<Inode> {
        let raw = self.read_raw_inode(ino)?;

        let mut block_area = [0u8; 60];
        block_area.copy_from_slice(&raw[40..100]);

        let size_lo = u32le(&raw, 4) as u64;
        let mode = u16le(&raw, 0);
        // i_size_high doubles as i_dir_acl for directories on old revisions;
        // only regular files may use it as the high half of the size.
        let size_hi = if mode & 0xF000 == 0x8000 {
            u32le(&raw, 108) as u64
        } else {
            0
        };

        Ok(Inode {
            number: ino,
            mode,
            uid: u16le(&raw, 2) as u32 | ((u16le(&raw, 120) as u32) << 16),
            gid: u16le(&raw, 24) as u32 | ((u16le(&raw, 122) as u32) << 16),
            size: size_lo | (size_hi << 32),
            links: u16le(&raw, 26),
            flags: u32le(&raw, 32),
            atime: u32le(&raw, 8) as i64,
            ctime: u32le(&raw, 12) as i64,
            mtime: u32le(&raw, 16) as i64,
            generation: u32le(&raw, 100),
            block_area,
        })
    }

    // --- block mapping -----------------------------------------------------

    /// Physical block backing logical block `lblock`, or `None` for a hole.
    fn map_block(&self, inode: &Inode, lblock: u64) -> Result<Option<u64>> {
        self.map_run(inode, lblock).map(|(phys, _)| phys)
    }

    /// Where `lblock` lives, **and how many consecutive logical blocks from
    /// there are contiguous with it**.
    ///
    /// The run length is the whole point. Mapping one block at a time makes a
    /// sequential read cost one device round trip per block — plus, for an
    /// extent tree deep enough to have interior nodes, another read to re-walk
    /// the tree for every one of them. Over USB that is fatal: reading a 1 GiB
    /// file in 4 KiB blocks is a quarter of a million SCSI command/data/status
    /// exchanges, and it measured in *minutes* on real hardware.
    ///
    /// An extent already records its own length, so the run comes for free —
    /// it was being computed and thrown away.
    ///
    /// `(None, n)` is a hole `n` blocks long, which reads as zeros.
    fn map_run(&self, inode: &Inode, lblock: u64) -> Result<(Option<u64>, u64)> {
        if inode.uses_extents() {
            self.map_run_extents(inode, lblock)
        } else {
            // ext2/ext3 indirect mapping still walks per block. Coalescing here
            // means reading an indirect block once and scanning it for
            // contiguity, which is real work for a case that no longer occurs
            // on drives anyone is likely to plug in. Correct, just not fast.
            self.map_via_indirect(inode, lblock).map(|phys| (phys, 1))
        }
    }

    fn map_run_extents(&self, inode: &Inode, lblock: u64) -> Result<(Option<u64>, u64)> {
        let mut node = inode.block_area.to_vec();

        loop {
            let magic = u16le(&node, 0);
            if magic != EXTENT_MAGIC {
                return Err(LuksError::BadExtentHeader(magic));
            }
            let entries = u16le(&node, 2) as usize;
            let depth = u16le(&node, 6);

            // 12-byte header followed by 12-byte entries.
            if 12 + entries * 12 > node.len() {
                return Err(LuksError::BadExtentTree("entry count exceeds node size"));
            }

            if depth == 0 {
                // Extents within a leaf are sorted by logical block, so the
                // first one starting past `lblock` bounds any hole at `lblock`.
                let mut next_start: Option<u64> = None;

                for i in 0..entries {
                    let e = &node[12 + i * 12..24 + i * 12];
                    let ee_block = u32le(e, 0) as u64;
                    let raw_len = u16le(e, 4);
                    // Lengths above 32768 mark an uninitialised extent, which
                    // reads as zeros; the real length is the low bits.
                    let (len, initialised) = if raw_len > 32768 {
                        ((raw_len - 32768) as u64, false)
                    } else {
                        (raw_len as u64, true)
                    };
                    if len == 0 {
                        continue;
                    }
                    if lblock >= ee_block && lblock < ee_block + len {
                        let offset = lblock - ee_block;
                        let run = len - offset;
                        if !initialised {
                            return Ok((None, run));
                        }
                        let start = u32le(e, 8) as u64 | ((u16le(e, 6) as u64) << 32);
                        return Ok((Some(start + offset), run));
                    }
                    if ee_block > lblock {
                        next_start = Some(ee_block);
                        break;
                    }
                }

                // A hole. Its length is known only as far as this leaf: if no
                // later extent is in *this* node, the next leaf may still hold
                // one, so claim a single block rather than guessing. Being
                // wrong here would read real data as zeros.
                let run = next_start.map_or(1, |n| n - lblock);
                return Ok((None, run));
            }

            // Interior node: descend into the last index whose block <= lblock.
            let mut next: Option<u64> = None;
            for i in 0..entries {
                let e = &node[12 + i * 12..24 + i * 12];
                let ei_block = u32le(e, 0) as u64;
                if ei_block <= lblock {
                    next = Some(u32le(e, 4) as u64 | ((u16le(e, 8) as u64) << 32));
                } else {
                    break;
                }
            }
            let child = next.ok_or(LuksError::BadExtentTree("no index covers this block"))?;

            let mut buf = vec![0u8; self.sb.block_size as usize];
            self.read_block(child, &mut buf)?;
            node = buf;
        }
    }

    /// ext2/ext3 mapping: 12 direct pointers, then single, double and triple
    /// indirect blocks.
    fn map_via_indirect(&self, inode: &Inode, lblock: u64) -> Result<Option<u64>> {
        let per_block = (self.sb.block_size / 4) as u64;

        let direct = |b: &[u8], i: usize| -> Option<u64> {
            let v = u32le(b, i * 4) as u64;
            if v == 0 {
                None
            } else {
                Some(v)
            }
        };

        if lblock < 12 {
            return Ok(direct(&inode.block_area, lblock as usize));
        }
        let mut idx = lblock - 12;

        // Depth 1, 2, 3 use i_block[12], [13], [14].
        for (depth, slot) in [(1u32, 12usize), (2, 13), (3, 14)] {
            let span = per_block.pow(depth);
            if idx < span {
                let mut ptr = match direct(&inode.block_area, slot) {
                    Some(p) => p,
                    None => return Ok(None),
                };
                // Walk down, peeling one level of indirection at a time.
                for level in (0..depth).rev() {
                    let stride = per_block.pow(level);
                    let within = (idx / stride) as usize;
                    idx %= stride;

                    let mut buf = vec![0u8; self.sb.block_size as usize];
                    self.read_block(ptr, &mut buf)?;
                    let next = u32le(&buf, within * 4) as u64;
                    if next == 0 {
                        return Ok(None);
                    }
                    ptr = next;
                }
                return Ok(Some(ptr));
            }
            idx -= span;
        }
        Ok(None)
    }

    // --- file contents -----------------------------------------------------

    /// Read from a file by inode. Holes read as zeros. Returns bytes read,
    /// which is short only at end of file.
    pub fn read_inode_data(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        let want = buf.len().min((inode.size - offset) as usize);
        if want == 0 {
            return Ok(0);
        }

        if inode.is_inline() {
            // Inline data lives in i_block; anything larger spills into an
            // extended attribute, which we do not read.
            if inode.size > 60 {
                return Err(LuksError::UnsupportedFsFeature(
                    "inline_data larger than 60 bytes".into(),
                ));
            }
            let start = offset as usize;
            buf[..want].copy_from_slice(&inode.block_area[start..start + want]);
            return Ok(want);
        }

        let bs = self.sb.block_size as u64;
        let mut done = 0usize;

        while done < want {
            let pos = offset + done as u64;
            let lblock = pos / bs;
            let within = pos % bs;

            let (phys, run_blocks) = self.map_run(inode, lblock)?;

            // How much of this contiguous run the caller still wants. The
            // saturating arithmetic matters: a hole can legitimately be
            // reported as an enormous run.
            let in_run = run_blocks.saturating_mul(bs).saturating_sub(within);
            let take = in_run.min((want - done) as u64) as usize;
            debug_assert!(take > 0, "map_run must make progress");

            match phys {
                Some(start) => {
                    // Bounds-check the whole run, not just the part read: an
                    // extent claiming blocks past the end of the filesystem is
                    // corrupt whether or not this call touches them.
                    let past_end = start
                        .checked_add(run_blocks)
                        .is_none_or(|end| end > self.sb.blocks_count);
                    if past_end {
                        return Err(LuksError::CorruptFs(
                            "block pointer past end of filesystem",
                        ));
                    }
                    // Straight into the caller's buffer. `ReadAt` handles
                    // arbitrary offsets and lengths, so there is no need to
                    // round to blocks and copy through a bounce buffer.
                    self.device
                        .read_at(start * bs + within, &mut buf[done..done + take])?;
                }
                None => buf[done..done + take].fill(0), // sparse hole
            }
            done += take;
        }
        Ok(done)
    }

    /// Read an entire file into a fresh buffer.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let inode = self.resolve(path)?;
        if inode.file_type().is_dir() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }
        let mut out = vec![0u8; inode.size as usize];
        let n = self.read_inode_data(&inode, 0, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    // --- directories -------------------------------------------------------

    /// List a directory. `.` and `..` are omitted; callers browsing a tree
    /// never want them, and navigation uses paths rather than those entries.
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let inode = self.resolve(path)?;
        if !inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(path.to_string()));
        }
        self.list_inode(&inode)
    }

    fn list_inode(&self, inode: &Inode) -> Result<Vec<DirEntry>> {
        let has_filetype = self.sb.feature_incompat & INCOMPAT_FILETYPE != 0;
        let bs = self.sb.block_size as usize;
        let mut out = Vec::new();
        let mut block_buf = vec![0u8; bs];

        let blocks = inode.size.div_ceil(bs as u64);
        for lblock in 0..blocks {
            match self.map_block(inode, lblock)? {
                Some(phys) => self.read_block(phys, &mut block_buf)?,
                None => continue,
            }

            let mut pos = 0usize;
            while pos + 8 <= bs {
                let ino = u32le(&block_buf, pos) as u64;
                let rec_len = u16le(&block_buf, pos + 4) as usize;

                // A zero or misaligned rec_len would loop forever.
                if rec_len < 8 || !rec_len.is_multiple_of(4) || pos + rec_len > bs {
                    break;
                }

                if ino != 0 {
                    let name_len = block_buf[pos + 6] as usize;
                    let file_type = if has_filetype {
                        match block_buf[pos + 7] {
                            1 => FileType::Regular,
                            2 => FileType::Directory,
                            3 => FileType::CharDevice,
                            4 => FileType::BlockDevice,
                            5 => FileType::Fifo,
                            6 => FileType::Socket,
                            7 => FileType::Symlink,
                            _ => FileType::Unknown,
                        }
                    } else {
                        // Without the filetype feature the type lives only in
                        // the inode, so it costs a read.
                        self.read_inode(ino)
                            .map(|i| i.file_type())
                            .unwrap_or(FileType::Unknown)
                    };

                    if pos + 8 + name_len <= bs {
                        let raw = &block_buf[pos + 8..pos + 8 + name_len];
                        if raw != b"." && raw != b".." {
                            out.push(DirEntry {
                                // ext4 stores bytes, not validated UTF-8.
                                name: String::from_utf8_lossy(raw).into_owned(),
                                inode: ino,
                                file_type,
                                is_subvolume: false,
                            });
                        }
                    }
                }
                pos += rec_len;
            }
        }
        Ok(out)
    }

    // --- path resolution ---------------------------------------------------

    pub fn file_info(&self, path: &str) -> Result<FileInfo> {
        Ok(self.resolve(path)?.info())
    }

    /// Read a symlink's target.
    pub fn read_link(&self, path: &str) -> Result<String> {
        let inode = self.resolve_no_follow(path)?;
        if inode.file_type() != FileType::Symlink {
            return Err(LuksError::NotFound(format!("{path} is not a symlink")));
        }
        self.link_target(&inode)
    }

    fn link_target(&self, inode: &Inode) -> Result<String> {
        // Targets shorter than 60 bytes are stored directly in i_block.
        if inode.size < 60 {
            let n = inode.size as usize;
            return Ok(String::from_utf8_lossy(&inode.block_area[..n]).into_owned());
        }
        let mut buf = vec![0u8; inode.size as usize];
        let n = self.read_inode_data(inode, 0, &mut buf)?;
        buf.truncate(n);
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Resolve a path to an inode, following a trailing symlink.
    pub fn resolve(&self, path: &str) -> Result<Inode> {
        let inode = self.resolve_no_follow(path)?;
        if inode.file_type() != FileType::Symlink {
            return Ok(inode);
        }
        let target = self.link_target(&inode)?;
        let resolved = if target.starts_with('/') {
            target
        } else {
            let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            format!("{parent}/{target}")
        };
        self.resolve_no_follow(&resolved)
    }

    /// Resolve a path without following a trailing symlink. Intermediate
    /// symlinks are still followed, as they must be.
    pub fn resolve_no_follow(&self, path: &str) -> Result<Inode> {
        let mut current = self.read_inode(ROOT_INODE)?;
        let mut walked: Vec<String> = Vec::new();

        let components: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();

        for (i, component) in components.iter().enumerate() {
            if *component == ".." {
                walked.pop();
                current = self.resolve_no_follow(&format!("/{}", walked.join("/")))?;
                continue;
            }
            if !current.file_type().is_dir() {
                return Err(LuksError::NotADirectory(format!("/{}", walked.join("/"))));
            }

            let entries = self.list_inode(&current)?;
            let found = entries
                .iter()
                .find(|e| e.name == *component)
                .ok_or_else(|| LuksError::NotFound(path.to_string()))?;

            current = self.read_inode(found.inode)?;
            walked.push((*component).to_string());

            // Follow symlinks on intermediate components only.
            let is_last = i == components.len() - 1;
            if !is_last && current.file_type() == FileType::Symlink {
                let mut depth = 0;
                while current.file_type() == FileType::Symlink {
                    depth += 1;
                    if depth > MAX_SYMLINK_DEPTH {
                        return Err(LuksError::SymlinkLoop(path.to_string()));
                    }
                    let target = self.link_target(&current)?;
                    let next = if target.starts_with('/') {
                        target
                    } else {
                        walked.pop();
                        format!("/{}/{}", walked.join("/"), target)
                    };
                    current = self.resolve_no_follow(&next)?;
                    walked = next
                        .split('/')
                        .filter(|c| !c.is_empty() && *c != ".")
                        .map(String::from)
                        .collect();
                }
            }
        }
        Ok(current)
    }
}

#[cfg(feature = "dangerous-write-support")]
impl<D: WriteAt> Ext4<D> {
    /// Delete a regular file by path. Refuses directories and hardlinks.
    /// Follows the Phase 0–4 ordering: collect -> sever name -> zero inode -> free blocks -> flush.
    pub fn delete_file(&mut self, path: &str) -> Result<()> {
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            return Err(LuksError::IsADirectory("/".into()));
        }

        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };

        let parent_dir = self.resolve(parent_path)?;
        if !parent_dir.file_type().is_dir() {
            return Err(LuksError::NotADirectory(format!("path /{parent_path}")));
        }

        let target_inode = self.resolve_no_follow(path)?;
        if target_inode.file_type().is_dir() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }

        if target_inode.links > 1 {
            return Err(LuksError::UnsupportedFsFeature(
                "deleting files with links_count > 1 (hardlinks)".into(),
            ));
        }

        // Phase 0: Collect extents (read-only)
        let (data_extents, index_extents) = self.collect_extents(&target_inode)?;

        // Phase 1: Sever the name (1 disk write)
        let removed_ino = self.unlink_file(parent_dir.number, name)?;
        if removed_ino != target_inode.number {
            return Err(LuksError::CorruptFs("unlinked inode number mismatch"));
        }

        // Phase 2: Invalidate the Inode (1 disk write inside free_inode)
        self.free_inode(target_inode.number, false)?;

        // Phase 3: Return Blocks to the Free Pool
        self.free_blocks(&data_extents)?;
        if !index_extents.is_empty() {
            self.free_blocks(&index_extents)?;
        }

        // Phase 4: Flush
        self.flush()
    }
}
