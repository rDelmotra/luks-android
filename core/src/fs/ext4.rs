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

use crate::device::ReadAt;
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
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;

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
}

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
        let (inode_size, feature_incompat, feature_ro_compat, desc_size) = if rev_level >= 1 {
            (
                u16le(b, 88),
                u32le(b, 96),
                u32le(b, 100),
                u16le(b, 254),
            )
        } else {
            (128, 0, 0, 0)
        };
        if inode_size < 128 {
            return Err(LuksError::CorruptFs("inode size below 128"));
        }

        let blocks_lo = u32le(b, 4) as u64;
        let blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 {
            u32le(b, 336) as u64
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

        Ok(Superblock {
            inodes_count: u32le(b, 0),
            blocks_count: blocks_lo | (blocks_hi << 32),
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
        })
    }

    fn is_64bit(&self) -> bool {
        self.feature_incompat & INCOMPAT_64BIT != 0
    }

    /// Bytes per block group descriptor.
    fn group_desc_size(&self) -> usize {
        if self.is_64bit() && self.desc_size >= 64 {
            self.desc_size as usize
        } else {
            32
        }
    }

    fn group_count(&self) -> u64 {
        let per = self.blocks_per_group as u64;
        (self.blocks_count - self.first_data_block as u64).div_ceil(per)
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

    fn uses_extents(&self) -> bool {
        self.flags & INODE_FL_EXTENTS != 0
    }

    fn is_inline(&self) -> bool {
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
    /// Block number of each group's inode table.
    inode_tables: Vec<u64>,
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

        let inode_tables = Self::read_group_descriptors(&device, &sb)?;
        Ok(Ext4 {
            device,
            sb,
            inode_tables,
        })
    }

    fn read_group_descriptors(device: &D, sb: &Superblock) -> Result<Vec<u64>> {
        let groups = sb.group_count();
        let desc_size = sb.group_desc_size();

        // The descriptor table starts in the block after the superblock. With a
        // 1 KiB block size the superblock occupies block 1, so the table is at
        // block 2; otherwise the superblock shares block 0 and the table is at 1.
        let table_block = sb.first_data_block as u64 + 1;
        let table_offset = table_block * sb.block_size as u64;

        let total = (groups as usize)
            .checked_mul(desc_size)
            .ok_or(LuksError::CorruptFs("group descriptor table too large"))?;
        let mut buf = vec![0u8; total];
        device.read_at(table_offset, &mut buf)?;

        let mut tables = Vec::with_capacity(groups as usize);
        for g in 0..groups as usize {
            let d = &buf[g * desc_size..(g + 1) * desc_size];
            let lo = u32le(d, 8) as u64;
            let hi = if desc_size >= 64 { u32le(d, 40) as u64 } else { 0 };
            tables.push(lo | (hi << 32));
        }
        Ok(tables)
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

    fn read_block(&self, block: u64, buf: &mut [u8]) -> Result<()> {
        if block >= self.sb.blocks_count {
            return Err(LuksError::CorruptFs("block pointer past end of filesystem"));
        }
        self.device
            .read_at(block * self.sb.block_size as u64, buf)
    }

    /// Load an inode by number. Inode 1 is the bad-blocks inode; 2 is the root.
    pub fn read_inode(&self, ino: u64) -> Result<Inode> {
        if ino == 0 || ino > self.sb.inodes_count as u64 {
            return Err(LuksError::BadInode(ino));
        }
        let group = (ino - 1) / self.sb.inodes_per_group as u64;
        let index = (ino - 1) % self.sb.inodes_per_group as u64;
        let table = *self
            .inode_tables
            .get(group as usize)
            .ok_or(LuksError::BadInode(ino))?;

        let offset = table * self.sb.block_size as u64 + index * self.sb.inode_size as u64;
        let mut raw = vec![0u8; self.sb.inode_size as usize];
        self.device.read_at(offset, &mut raw)?;

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
