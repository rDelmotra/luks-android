//! Linking an inode into a directory.
//!
//! This is the step that turns [`super::file`]'s orphan into a file: after it,
//! `e2fsck` should have **nothing** to say, and the Linux kernel should be able
//! to mount the filesystem and read the file by name.
//!
//! # How space is found
//!
//! A directory block is a chain of variable-length records. Each carries a
//! `rec_len` that is usually *larger* than the record actually needs — the last
//! record in a block stretches its `rec_len` all the way to the end, so the
//! free space in a directory is not a gap at the end but slack distributed
//! inside existing entries. Inserting means finding a record with enough slack
//! and splitting it: shrink its `rec_len` to what it really needs, and give the
//! remainder to the new record.
//!
//! Getting that arithmetic wrong does not produce an error. It produces a
//! directory whose chain of `rec_len`s walks off the end of the block or into
//! the middle of a name, which is how a directory silently loses every entry
//! after the one that was inserted.
//!
//! # What this does not do
//!
//! * **htree directories are refused.** A directory that has grown past one
//!   block carries `EXT4_INDEX_FL` and keeps a hash tree in dirents disguised
//!   as free space. Inserting a record into a leaf without updating that tree
//!   leaves lookups unable to find it. The read path deliberately ignores the
//!   hash tree (see the note at the top of [`super`]) — which is safe for
//!   reading and would be silent corruption for writing.
//! * **Directories are never extended.** If no existing block has room, this
//!   fails rather than allocating another block and appending it to the
//!   directory's extent tree. That is a real limit — a 4 KiB block holds
//!   roughly 170 average-length names — and it is a clean refusal, not a
//!   corruption.

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::ext4::csum::{Seed, DIR_TAIL_SIZE};
use crate::fs::ext4::Ext4;
use crate::fs::FileType;

/// `EXT4_INDEX_FL` — this directory is hash-indexed.
const INODE_FL_INDEX: u32 = 0x0000_1000;
/// Minimum bytes a record occupies: the 8-byte header plus a name, rounded up.
const DIRENT_HEADER: usize = 8;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// Bytes a record with this name length actually needs, rounded to 4.
fn record_len(name_len: usize) -> usize {
    (DIRENT_HEADER + name_len).div_ceil(4) * 4
}

fn type_code(t: FileType) -> u8 {
    match t {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::CharDevice => 3,
        FileType::BlockDevice => 4,
        FileType::Fifo => 5,
        FileType::Socket => 6,
        FileType::Symlink => 7,
        FileType::Unknown => 0,
    }
}

impl<D: WriteAt> Ext4<D> {
    /// Add `name` to directory `dir_ino`, pointing at `ino`.
    ///
    /// The target inode's link count is not touched: [`super::file`] already
    /// writes a new file with `i_links_count == 1`, which is exactly right once
    /// this one entry exists. Linking the *same* inode a second time would need
    /// that count incremented, which this does not do — so it is a create, not
    /// a general `link(2)`.
    pub fn link_file(
        &mut self,
        dir_ino: u64,
        name: &str,
        ino: u64,
        file_type: FileType,
    ) -> Result<()> {
        let seed = Seed::for_writing(&self.sb)?;

        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > 255 {
            return Err(LuksError::CorruptFs("directory entry name length"));
        }
        // A name containing '/' or NUL cannot be looked up and would make the
        // filesystem describe a path that cannot exist.
        if name_bytes.contains(&b'/') || name_bytes.contains(&0) {
            return Err(LuksError::CorruptFs("directory entry name characters"));
        }

        let dir = self.read_inode(dir_ino)?;
        if !dir.file_type().is_dir() {
            return Err(LuksError::NotADirectory(format!("inode {dir_ino}")));
        }
        if dir.flags & INODE_FL_INDEX != 0 {
            return Err(LuksError::UnsupportedFsFeature(
                "writing into a hash-indexed (htree) directory".into(),
            ));
        }
        // An inline directory keeps its entries inside `i_block` itself — no
        // extent tree, no blocks. Mapping its "blocks" anyway falls through to
        // the indirect-block walker, which reads `i_block[0]`: for an inline
        // directory that is the inode number of `.`, so for the root it is 2 —
        // and "insert a dirent into block 2" is a write into the group
        // descriptor table. The write gate refuses whole filesystems with the
        // feature; this refuses the per-inode flag, in case it is ever set
        // where the feature bit is not.
        if dir.is_inline() {
            return Err(LuksError::UnsupportedFsFeature(
                "writing into an inline_data directory".into(),
            ));
        }
        if self.find_entry(&dir, name_bytes)?.is_some() {
            return Err(LuksError::CorruptFs("a directory entry already exists"));
        }

        let bs = self.sb.block_size as usize;
        let needed = record_len(name_bytes.len());
        // The checksum tail is not a record and must never be overwritten, so
        // the usable region stops short of it.
        let usable = if seed.enabled() {
            bs - DIR_TAIL_SIZE
        } else {
            bs
        };

        let blocks = dir.size.div_ceil(bs as u64);
        for lblock in 0..blocks {
            let Some(phys) = self.map_block(&dir, lblock)? else {
                continue;
            };
            // `phys` came off the disk (an extent entry), so it is proven to
            // land inside the filesystem before anything is read from it —
            // and above all before anything is *written* to it. This is the
            // only loop in the crate that writes to an offset derived from
            // on-disk data.
            let at = self.metadata_block_offset(phys)?;

            let mut block = vec![0u8; bs];
            self.device.read_at(at, &mut block)?;

            if !insert_into_block(&mut block, usable, name_bytes, ino, file_type, needed)? {
                continue;
            }

            if let Some(csum) = seed.dir_block(dir_ino, dir.generation, &block) {
                put32(&mut block, bs - 4, csum);
            }
            self.device.write_at(at, &block)?;
            return Ok(());
        }

        Err(LuksError::UnsupportedFsFeature(
            "directory is full and extending a directory is not implemented".into(),
        ))
    }

    /// Whether `name` already exists in `dir`. Creating a duplicate would give
    /// the directory two records with one name, and which one a lookup finds
    /// depends on scan order.
    fn find_entry(
        &self,
        dir: &crate::fs::ext4::Inode,
        name: &[u8],
    ) -> Result<Option<u64>> {
        let bs = self.sb.block_size as usize;
        let blocks = dir.size.div_ceil(bs as u64);
        let mut block = vec![0u8; bs];

        for lblock in 0..blocks {
            let Some(phys) = self.map_block(dir, lblock)? else {
                continue;
            };
            // Same bound as the insert loop: a pointer off the disk proves
            // itself before it is used, or the answer here is meaningless.
            self.device
                .read_at(self.metadata_block_offset(phys)?, &mut block)?;

            let mut pos = 0usize;
            while pos + DIRENT_HEADER <= bs {
                let ino = u32le(&block, pos) as u64;
                let rec_len = u16le(&block, pos + 4) as usize;
                if rec_len < DIRENT_HEADER || !rec_len.is_multiple_of(4) || pos + rec_len > bs {
                    break;
                }
                let name_len = block[pos + 6] as usize;
                if ino != 0
                    && pos + DIRENT_HEADER + name_len <= bs
                    && &block[pos + DIRENT_HEADER..pos + DIRENT_HEADER + name_len] == name
                {
                    return Ok(Some(ino));
                }
                pos += rec_len;
            }
        }
        Ok(None)
    }
}

/// Try to place a record in `block`. Returns whether it fit.
///
/// `usable` is where the records end — before the checksum tail, if there is
/// one.
#[cfg(test)]
mod tests {
    use super::*;

    /// The walk guard must stop a live record whose `name_len` claims more
    /// bytes than its own `rec_len` provides. Without the guard the slack
    /// subtraction underflows — a panic in debug, a bogus enormous "slack"
    /// and an out-of-range slice index in release. Either way the process
    /// dies mid-transfer on a merely *corrupt* (not even hostile) directory.
    #[test]
    fn a_name_longer_than_its_record_stops_the_walk() {
        let mut block = vec![0u8; 64];
        block[0..4].copy_from_slice(&1u32.to_le_bytes()); // live: ino 1
        block[4..6].copy_from_slice(&64u16.to_le_bytes()); // rec_len: whole block
        block[6] = 200; // name_len: needs 208 bytes — more than rec_len has

        let fit = insert_into_block(&mut block, 64, b"x", 12, FileType::Regular, 12)
            .expect("malformed chain is 'no room', not an error");
        assert!(!fit, "a malformed record must not be split");
    }
}

fn insert_into_block(
    block: &mut [u8],
    usable: usize,
    name: &[u8],
    ino: u64,
    file_type: FileType,
    needed: usize,
) -> Result<bool> {
    let mut pos = 0usize;

    while pos + DIRENT_HEADER <= usable {
        let cur_ino = u32le(block, pos);
        let rec_len = u16le(block, pos + 4) as usize;
        let name_len = block[pos + 6] as usize;

        // A malformed chain must stop the walk rather than wrap around or run
        // past the block; treating it as "no room" is the safe answer. The
        // last clause guards the subtraction below: a live record whose
        // `name_len` needs more bytes than its own `rec_len` provides is
        // corrupt, and without the check `rec_len - in_use` underflows — a
        // panic in debug and a bogus enormous "slack" in release.
        if rec_len < DIRENT_HEADER
            || !rec_len.is_multiple_of(4)
            || pos + rec_len > usable
            || (cur_ino != 0 && record_len(name_len) > rec_len)
        {
            return Ok(false);
        }

        // A record with inode 0 is free space in its entirety; a live record
        // only yields whatever exceeds what its own name needs.
        let in_use = if cur_ino == 0 { 0 } else { record_len(name_len) };
        let slack = rec_len - in_use;

        if slack >= needed {
            let (at, len) = if in_use == 0 {
                (pos, rec_len)
            } else {
                put16(block, pos + 4, in_use as u16);
                (pos + in_use, rec_len - in_use)
            };

            put32(block, at, ino as u32);
            put16(block, at + 4, len as u16);
            block[at + 6] = name.len() as u8;
            block[at + 7] = type_code(file_type);
            block[at + DIRENT_HEADER..at + DIRENT_HEADER + name.len()].copy_from_slice(name);
            // Padding between the name and the next record is not covered by
            // name_len, and stale bytes there are visible to anything that
            // dumps the block.
            let pad_from = at + DIRENT_HEADER + name.len();
            block[pad_from..at + len].fill(0);
            return Ok(true);
        }

        pos += rec_len;
    }
    Ok(false)
}
