//! Allocating and freeing ext4 blocks and inodes.
//!
//! This is the layer under every filesystem write: before a file can exist,
//! something has to claim an inode and some blocks, and claiming them means
//! keeping **five** things consistent at once — the bitmap bit, the group's
//! free counter, the superblock's free counter, the bitmap's checksum, and the
//! group descriptor's checksum. Update four of the five and `e2fsck` reports a
//! filesystem that is quietly wrong.
//!
//! # What this deliberately does not do yet
//!
//! Groups flagged `BLOCK_UNINIT` or `INODE_UNINIT` are **skipped**. Those flags
//! mean the bitmap on disk was never written and holds whatever bytes were
//! there before, so allocating from such a group requires first *materialising*
//! its bitmap — computing which of its blocks are metadata and marking them —
//! and with `flex_bg` those metadata blocks may belong to a different group
//! entirely. That is a distinct problem with its own failure modes, so it gets
//! its own pass rather than being smuggled in here.
//!
//! The cost is real and worth stating plainly: on the 4 GiB test stick, 26 of
//! 33 groups are `BLOCK_UNINIT`, so only about 800 MiB of its 4 GiB is
//! reachable until that pass lands. Correctness first — an allocator that
//! quietly hands out blocks it believes are free, from a bitmap it never read,
//! overwrites live data.
//!
//! # Ordering
//!
//! Writes go bitmap → group descriptor → superblock, so an interruption leaves
//! the *bitmap* ahead of the counters. That direction is deliberate: a bitmap
//! bit set with a stale free count leaks a block, which `e2fsck` fixes with a
//! counter adjustment. The reverse — a counter claiming a block is taken while
//! the bitmap says free — invites the next allocation to hand out a block that
//! is already in use, which loses data.

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::ext4::csum::Seed;
use crate::fs::ext4::{Ext4, GroupDesc};

/// Which of a group's two bitmaps is being addressed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bitmap {
    Block,
    Inode,
}

impl<D: WriteAt> Ext4<D> {
    // --- bitmap primitives -------------------------------------------------

    /// Where a bitmap lives and how many bytes of it the checksum covers.
    ///
    /// The length is not the block size. The kernel checksums exactly
    /// `clusters_per_group / 8` (or `inodes_per_group / 8`) bytes, and using
    /// the whole block instead produces a checksum that never matches.
    fn bitmap_extent(&self, group: usize, which: Bitmap) -> (u64, usize) {
        let g = &self.groups[group];
        let bs = self.sb.block_size as u64;
        match which {
            Bitmap::Block => (
                g.block_bitmap * bs,
                (self.sb.clusters_per_group as usize).div_ceil(8),
            ),
            Bitmap::Inode => (
                g.inode_bitmap * bs,
                (self.sb.inodes_per_group as usize).div_ceil(8),
            ),
        }
    }

    fn read_bitmap(&self, group: usize, which: Bitmap) -> Result<Vec<u8>> {
        let (offset, len) = self.bitmap_extent(group, which);
        let mut buf = vec![0u8; len];
        self.device.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Write a bitmap back and record its new checksum in the group
    /// descriptor. The descriptor itself is not flushed here — the caller
    /// adjusts the counters first, so that it is written exactly once.
    fn write_bitmap(&mut self, group: usize, which: Bitmap, bm: &[u8], seed: &Seed) -> Result<()> {
        let (offset, _) = self.bitmap_extent(group, which);
        self.device.write_at(offset, bm)?;

        if let Some(csum) = seed.bitmap(bm) {
            let g = &mut self.groups[group];
            match which {
                Bitmap::Block => g.block_bitmap_csum = csum,
                Bitmap::Inode => g.inode_bitmap_csum = csum,
            }
        }
        Ok(())
    }

    // --- descriptor and superblock -----------------------------------------

    /// Serialise one group descriptor from the in-memory copy, checksum it and
    /// write it.
    ///
    /// The existing bytes are read first and patched rather than built from
    /// scratch: a descriptor has fields this crate does not model (the exclude
    /// bitmap, reserved space), and rebuilding it would zero them.
    fn write_group_desc(&mut self, group: usize, seed: &Seed) -> Result<()> {
        let size = self.sb.group_desc_size();
        let offset = self.sb.group_desc_offset() + (group * size) as u64;

        let mut d = vec![0u8; size];
        self.device.read_at(offset, &mut d)?;

        let g = self.groups[group].clone();
        let wide = size >= 64;

        put16(&mut d, 0x0C, g.free_blocks_count as u16);
        put16(&mut d, 0x0E, g.free_inodes_count as u16);
        put16(&mut d, 0x10, g.used_dirs_count as u16);
        put16(&mut d, 0x12, g.flags);
        put16(&mut d, 0x18, g.block_bitmap_csum as u16);
        put16(&mut d, 0x1A, g.inode_bitmap_csum as u16);
        put16(&mut d, 0x1C, g.itable_unused as u16);
        if wide {
            put16(&mut d, 0x2C, (g.free_blocks_count >> 16) as u16);
            put16(&mut d, 0x2E, (g.free_inodes_count >> 16) as u16);
            put16(&mut d, 0x30, (g.used_dirs_count >> 16) as u16);
            put16(&mut d, 0x32, (g.itable_unused >> 16) as u16);
            put16(&mut d, 0x38, (g.block_bitmap_csum >> 16) as u16);
            put16(&mut d, 0x3A, (g.inode_bitmap_csum >> 16) as u16);
        }

        // The checksum covers the field's own bytes as zeros, so it must be
        // computed after every other field is in place.
        if let Some(csum) = seed.group_desc(group as u64, &d) {
            put16(&mut d, 0x1E, csum);
            self.groups[group].checksum = csum;
        }

        self.device.write_at(offset, &d)?;
        Ok(())
    }

    /// Write the superblock's free counters and re-checksum it.
    ///
    /// Backup superblocks are left alone. That matches what the kernel does on
    /// every ordinary write — backups are refreshed by `e2fsck` and `tune2fs`,
    /// not on the fly — so touching them here would be a deviation, not extra
    /// safety.
    fn write_superblock(&mut self, seed: &Seed) -> Result<()> {
        let mut sb = vec![0u8; 1024];
        self.device.read_at(1024, &mut sb)?;

        put32(&mut sb, 12, self.sb.free_blocks_count as u32);
        put32(&mut sb, 16, self.sb.free_inodes_count);
        if self.sb.is_64bit() {
            put32(&mut sb, 340, (self.sb.free_blocks_count >> 32) as u32);
        }

        if let Some(csum) = seed.superblock(&sb) {
            put32(&mut sb, 0x3FC, csum);
        }

        self.device.write_at(1024, &sb)?;
        Ok(())
    }

    /// Push a group's bitmap, descriptor and the superblock in the safe order.
    fn commit(&mut self, group: usize, which: Bitmap, bm: &[u8], seed: &Seed) -> Result<()> {
        self.write_bitmap(group, which, bm, seed)?;
        self.write_group_desc(group, seed)?;
        self.write_superblock(seed)
    }

    // --- blocks ------------------------------------------------------------

    /// Claim one free block, preferring one near `goal`.
    ///
    /// Locality is not cosmetic: a file whose blocks are scattered across the
    /// disk costs one SCSI round trip per fragment, and on this transport a
    /// round trip measured at 1.15 ms. Starting the search in `goal`'s own
    /// group is what keeps a file's extents contiguous.
    pub fn alloc_block(&mut self, goal: u64) -> Result<u64> {
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64;
        let count = self.groups.len();

        let start = if goal >= first {
            (((goal - first) / per) as usize).min(count.saturating_sub(1))
        } else {
            0
        };

        for n in 0..count {
            let g = (start + n) % count;
            if self.groups[g].block_bitmap_uninit() || self.groups[g].free_blocks_count == 0 {
                continue;
            }

            let mut bm = self.read_bitmap(g, Bitmap::Block)?;
            let limit = self.blocks_in_group(g);
            let Some(bit) = find_free_bit(&bm, limit) else {
                // The descriptor claimed free blocks the bitmap does not have.
                // Skipping is the safe reading: trusting the counter here would
                // hand out a block that is already in use.
                continue;
            };

            set_bit(&mut bm, bit);
            self.groups[g].free_blocks_count -= 1;
            self.sb.free_blocks_count -= 1;
            self.commit(g, Bitmap::Block, &bm, &seed)?;

            return Ok(first + g as u64 * per + bit as u64);
        }
        Err(LuksError::FilesystemFull)
    }

    /// Release a block previously allocated. Freeing a block that is already
    /// free is refused rather than silently accepted — it means the caller has
    /// lost track, and double-freeing is how two files come to share a block.
    pub fn free_block(&mut self, block: u64) -> Result<()> {
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64;

        if block < first || block >= self.sb.blocks_count {
            return Err(LuksError::CorruptFs("free of a block outside the filesystem"));
        }
        let g = ((block - first) / per) as usize;
        let bit = ((block - first) % per) as usize;

        if self.groups[g].block_bitmap_uninit() {
            return Err(LuksError::CorruptFs(
                "free of a block in an uninitialised group",
            ));
        }

        let mut bm = self.read_bitmap(g, Bitmap::Block)?;
        if !test_bit(&bm, bit) {
            return Err(LuksError::CorruptFs("double free of a block"));
        }

        clear_bit(&mut bm, bit);
        self.groups[g].free_blocks_count += 1;
        self.sb.free_blocks_count += 1;
        self.commit(g, Bitmap::Block, &bm, &seed)
    }

    /// How many blocks this group actually contains. The last group is usually
    /// short, and its bitmap's trailing bits are set so they can never be
    /// allocated — but relying on that rather than on the real count would put
    /// the search one bad bitmap away from returning a block past the end.
    fn blocks_in_group(&self, group: usize) -> usize {
        let per = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64;
        let start = first + group as u64 * per;
        (self.sb.blocks_count - start).min(per) as usize
    }

    // --- inodes ------------------------------------------------------------

    /// Claim one free inode.
    ///
    /// `is_dir` is not bookkeeping trivia: `bg_used_dirs_count` feeds the
    /// allocator's directory-spreading heuristic, and `e2fsck` checks it.
    pub fn alloc_inode(&mut self, is_dir: bool) -> Result<u64> {
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.inodes_per_group as usize;
        let first_ino = self.sb.first_ino as u64;

        for g in 0..self.groups.len() {
            if self.groups[g].inode_bitmap_uninit() || self.groups[g].free_inodes_count == 0 {
                continue;
            }

            let mut bm = self.read_bitmap(g, Bitmap::Inode)?;
            let Some(bit) = find_free_bit(&bm, per) else {
                continue;
            };

            let ino = (g * per + bit) as u64 + 1;
            // Inodes below s_first_ino are reserved — 2 is the root, 8 is the
            // journal. Handing one out corrupts the filesystem's own metadata.
            if ino < first_ino {
                continue;
            }

            set_bit(&mut bm, bit);
            self.groups[g].free_inodes_count -= 1;
            self.sb.free_inodes_count -= 1;
            if is_dir {
                self.groups[g].used_dirs_count += 1;
            }

            // `itable_unused` counts never-used inodes at the *tail* of the
            // table, so it must shrink to exclude the one just taken. Leaving
            // it too large tells e2fsck it may skip an inode that is now live.
            let used_through = bit + 1;
            let unused = per.saturating_sub(used_through) as u32;
            if self.groups[g].itable_unused > unused {
                self.groups[g].itable_unused = unused;
            }

            self.commit(g, Bitmap::Inode, &bm, &seed)?;
            return Ok(ino);
        }
        Err(LuksError::NoFreeInodes)
    }

    /// Release an inode. `was_dir` must match what it was allocated as, or the
    /// directory count drifts.
    ///
    /// `itable_unused` is intentionally *not* restored. It is a lower bound on
    /// how much of the inode table has ever been touched, and growing it again
    /// would tell `e2fsck` to skip inodes beyond this one that may still be in
    /// use. The kernel leaves it alone for the same reason.
    pub fn free_inode(&mut self, ino: u64, was_dir: bool) -> Result<()> {
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.inodes_per_group as u64;

        if ino < self.sb.first_ino as u64 || ino > self.sb.inodes_count as u64 {
            return Err(LuksError::BadInode(ino));
        }
        let g = ((ino - 1) / per) as usize;
        let bit = ((ino - 1) % per) as usize;

        let mut bm = self.read_bitmap(g, Bitmap::Inode)?;
        if !test_bit(&bm, bit) {
            return Err(LuksError::CorruptFs("double free of an inode"));
        }

        clear_bit(&mut bm, bit);
        self.groups[g].free_inodes_count += 1;
        self.sb.free_inodes_count += 1;
        if was_dir && self.groups[g].used_dirs_count > 0 {
            self.groups[g].used_dirs_count -= 1;
        }

        self.commit(g, Bitmap::Inode, &bm, &seed)
    }

    /// Flush the underlying device. A USB bridge acknowledges a write once it
    /// reaches its own buffer, so without this a "completed" allocation can
    /// still be lost to a pulled cable.
    pub fn flush(&self) -> Result<()> {
        self.device.flush()
    }

    /// The in-memory descriptor for one group, for tests and diagnostics.
    pub fn group(&self, index: usize) -> Option<&GroupDesc> {
        self.groups.get(index)
    }
}

// --- bit twiddling ---------------------------------------------------------
//
// ext4 bitmaps are little-endian *bit* order: bit 0 of byte 0 is the first
// block of the group. Using a big-endian convention here still round-trips
// perfectly in our own tests while disagreeing with the kernel on every byte.

fn test_bit(bm: &[u8], bit: usize) -> bool {
    bm[bit / 8] & (1 << (bit % 8)) != 0
}

fn set_bit(bm: &mut [u8], bit: usize) {
    bm[bit / 8] |= 1 << (bit % 8);
}

fn clear_bit(bm: &mut [u8], bit: usize) {
    bm[bit / 8] &= !(1 << (bit % 8));
}

/// Index of the first zero bit below `limit`, or `None`.
fn find_free_bit(bm: &[u8], limit: usize) -> Option<usize> {
    for (i, &byte) in bm.iter().enumerate() {
        if byte == 0xFF {
            continue;
        }
        let bit = byte.trailing_ones() as usize;
        let index = i * 8 + bit;
        if index >= limit {
            return None;
        }
        return Some(index);
    }
    None
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_free_bit_is_found_in_little_endian_order() {
        // 0b0000_0101 — bits 0 and 2 taken, so bit 1 is the first free one.
        // A big-endian reading would answer 5, and would be self-consistent.
        assert_eq!(find_free_bit(&[0b0000_0101], 8), Some(1));
        assert_eq!(find_free_bit(&[0xFF, 0b0000_0001], 16), Some(9));
        assert_eq!(find_free_bit(&[0xFF, 0xFF], 16), None);
    }

    #[test]
    fn the_limit_is_respected() {
        // A short final group: bits past the end must never be handed out even
        // though the bitmap byte says they are free.
        assert_eq!(find_free_bit(&[0b0000_1111], 4), None);
        assert_eq!(find_free_bit(&[0b0000_0111], 4), Some(3));
    }

    #[test]
    fn set_and_clear_are_inverses() {
        let mut bm = [0u8; 4];
        set_bit(&mut bm, 13);
        assert!(test_bit(&bm, 13));
        assert!(!test_bit(&bm, 12));
        clear_bit(&mut bm, 13);
        assert_eq!(bm, [0u8; 4]);
    }
}
