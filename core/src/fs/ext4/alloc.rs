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
//!
//! # Batching
//!
//! Blocks are claimed a *batch* at a time, not one at a time. The difference is
//! not a micro-optimisation: every allocation ends in a commit, and a commit is
//! three device writes — bitmap, group descriptor, superblock — none of which
//! is block-aligned, so each costs a read-modify-write on top. Measured through
//! the SCSI layer that came to **7.0 commands per 4 KiB block**, which for a
//! 50 MB file is over 85,000 round trips: on the phone's USB host that is the
//! five-minute hang that motivated this, spent entirely in bookkeeping while
//! the data itself needs a few hundred commands.
//!
//! [`alloc_blocks`](Ext4::alloc_blocks) reads each group's bitmap **once**,
//! claims every block it needs from it in memory, and commits **once per group
//! touched**, with a single superblock write closing the whole batch. A 50 MB
//! file fits in one group, so its bookkeeping is three writes rather than
//! 36,000. This is the same conclusion ext4 itself reached: ext3 allocated per
//! block at `write_begin` time, and ext4 replaced it with delayed allocation
//! plus a multi-block allocator for these exact reasons.
//!
//! The work is split into a **plan** phase that only reads, and a **commit**
//! phase that only writes. Nothing reaches the device until every block is
//! decided, so running out of space now costs a discarded `Vec` rather than an
//! unwind of already-committed bitmaps. The ordering above is unchanged —
//! bitmap before counters, per group — so an interruption still leaks blocks
//! and still cannot double-allocate. There are simply far fewer moments at
//! which it can be interrupted.

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

/// A contiguous run of physical blocks, as handed out by
/// [`alloc_blocks`](Ext4::alloc_blocks).
///
/// Deliberately without a logical offset: where a run sits inside a *file* is
/// the file layer's business, and the allocator has no opinion about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Extent {
    pub physical: u64,
    pub len: u64,
}

impl<D: WriteAt> Ext4<D> {
    // --- bitmap primitives -------------------------------------------------

    /// Where a bitmap lives and how many bytes of it the checksum covers.
    ///
    /// The length is not the block size. The kernel checksums exactly
    /// `clusters_per_group / 8` (or `inodes_per_group / 8`) bytes, and using
    /// the whole block instead produces a checksum that never matches.
    ///
    /// The bitmap's block number is an on-disk pointer (it came out of the
    /// group descriptor), so like every such pointer it is bounds-proven
    /// before anything reads through it — or writes, which is the case that
    /// matters: a corrupt descriptor must not aim a bitmap write at an
    /// arbitrary offset.
    fn bitmap_extent(&self, group: usize, which: Bitmap) -> Result<(u64, usize)> {
        let g = &self.groups[group];
        match which {
            Bitmap::Block => Ok((
                self.metadata_block_offset(g.block_bitmap)?,
                (self.sb.clusters_per_group as usize).div_ceil(8),
            )),
            Bitmap::Inode => Ok((
                self.metadata_block_offset(g.inode_bitmap)?,
                (self.sb.inodes_per_group as usize).div_ceil(8),
            )),
        }
    }

    fn read_bitmap(&self, group: usize, which: Bitmap) -> Result<Vec<u8>> {
        let (offset, len) = self.bitmap_extent(group, which)?;
        let mut buf = vec![0u8; len];
        self.device.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Write a bitmap back and record its new checksum in the group
    /// descriptor. The descriptor itself is not flushed here — the caller
    /// adjusts the counters first, so that it is written exactly once.
    fn write_bitmap(&mut self, group: usize, which: Bitmap, bm: &[u8], seed: &Seed) -> Result<()> {
        let (offset, _) = self.bitmap_extent(group, which)?;
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
            // 0x158, not 0x154 — 0x154 is s_r_blocks_count_hi, and writing the
            // free count there both loses the update and clobbers the reserved
            // count. Invisible below 16 TiB, where every hi word is zero.
            put32(
                &mut sb,
                super::SB_FREE_BLOCKS_COUNT_HI,
                (self.sb.free_blocks_count >> 32) as u32,
            );
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

    /// Claim `count` free blocks, preferring blocks near `goal`, and return
    /// them as contiguous runs.
    ///
    /// Locality is not cosmetic: a file whose blocks are scattered across the
    /// disk costs one SCSI round trip per fragment, and on this transport a
    /// round trip measured at 1.15 ms. Starting the search in `goal`'s own
    /// group is what keeps a file's extents contiguous.
    ///
    /// # Two phases
    ///
    /// The loop below only *reads*. Each group's bitmap is fetched once, the
    /// bits are claimed in the in-memory copy, and the dirty copy is parked in
    /// `plan`. Not one byte reaches the device until the whole request is
    /// satisfied, so the out-of-space path returns having changed nothing —
    /// where the per-block predecessor had to unwind every block it had
    /// already committed, at three device writes each.
    ///
    /// A group is never asked for more than its descriptor says it has free.
    /// Trusting the bitmap past that point would hand out blocks while the
    /// counter went its own way, and the counter is what `e2fsck` checks.
    ///
    /// The memory this holds is one bitmap per group *touched* — 4 KiB each on
    /// the test stick. A 50 MB file touches one; a 4 GiB file touches 33, so
    /// 132 KiB. Worth stating, not worth engineering around at these sizes.
    pub fn alloc_blocks(&mut self, goal: u64, count: u64) -> Result<Vec<Extent>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64;
        let ngroups = self.groups.len();

        let start = if goal >= first {
            (((goal - first) / per) as usize).min(ngroups.saturating_sub(1))
        } else {
            0
        };

        // --- plan: reads only ---------------------------------------------
        let mut plan: Vec<(usize, Vec<u8>, u64)> = Vec::new();
        let mut out: Vec<Extent> = Vec::new();
        let mut remaining = count;

        for n in 0..ngroups {
            if remaining == 0 {
                break;
            }
            let g = (start + n) % ngroups;
            if self.groups[g].block_bitmap_uninit() || self.groups[g].free_blocks_count == 0 {
                continue;
            }

            let mut bm = self.read_bitmap(g, Bitmap::Block)?;
            let limit = self.blocks_in_group(g);
            let allowance = (self.groups[g].free_blocks_count as u64).min(remaining);

            let mut taken = 0u64;
            let mut cursor = 0usize;
            while taken < allowance {
                // The descriptor may claim free blocks the bitmap does not
                // have. Stopping here is the safe reading: trusting the
                // counter would hand out a block that is already in use.
                let Some(bit) = find_free_bit_from(&bm, cursor, limit) else {
                    break;
                };
                set_bit(&mut bm, bit);
                cursor = bit + 1;

                let block = first + g as u64 * per + bit as u64;
                match out.last_mut() {
                    Some(e) if e.physical + e.len == block => e.len += 1,
                    _ => out.push(Extent {
                        physical: block,
                        len: 1,
                    }),
                }
                taken += 1;
                remaining -= 1;
            }

            if taken > 0 {
                plan.push((g, bm, taken));
            }
        }

        if remaining > 0 {
            return Err(LuksError::FilesystemFull);
        }

        // --- commit: bitmap → descriptor, per group; superblock once ------
        //
        // An I/O error partway through leaves the groups already written
        // holding blocks nothing references — a leak, which is the same
        // failure the per-block version had and the one `e2fsck` repairs with
        // a counter adjustment. The direction that loses data, a counter
        // ahead of its bitmap, is still impossible.
        for (g, bm, taken) in &plan {
            self.groups[*g].free_blocks_count -= *taken as u32;
            // Saturating: the superblock counter can already be stale-low on a
            // filesystem that saw an unclean unmount. Wrapping it to 2^64-1
            // and re-checksumming would *sign* the nonsense; sticking at 0
            // leaves an off-by-some counter, which is exactly what e2fsck
            // knows how to fix.
            self.sb.free_blocks_count = self.sb.free_blocks_count.saturating_sub(*taken);
            self.write_bitmap(*g, Bitmap::Block, bm, &seed)?;
            self.write_group_desc(*g, &seed)?;
        }
        self.write_superblock(&seed)?;

        Ok(out)
    }

    /// Claim one free block, preferring one near `goal`.
    pub fn alloc_block(&mut self, goal: u64) -> Result<u64> {
        let runs = self.alloc_blocks(goal, 1)?;
        runs.first()
            .map(|e| e.physical)
            .ok_or(LuksError::FilesystemFull)
    }

    /// Release a batch of previously allocated runs.
    ///
    /// Freeing a block that is already free is refused rather than silently
    /// accepted — it means the caller has lost track, and double-freeing is how
    /// two files come to share a block. Because the batch is planned in memory
    /// first, that check also catches a batch that names the same block twice,
    /// which the per-block version could not see.
    ///
    /// Like [`alloc_blocks`](Self::alloc_blocks), nothing is written until the
    /// whole batch validates.
    pub fn free_blocks(&mut self, extents: &[Extent]) -> Result<()> {
        if extents.is_empty() {
            return Ok(());
        }
        let seed = Seed::for_writing(&self.sb)?;
        let per = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64;

        // group index, dirty bitmap, how many bits were cleared in it
        let mut plan: Vec<(usize, Vec<u8>, u32)> = Vec::new();

        for e in extents {
            for block in e.physical..e.physical + e.len {
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

                let slot = match plan.iter().position(|(gi, _, _)| *gi == g) {
                    Some(i) => i,
                    None => {
                        let bm = self.read_bitmap(g, Bitmap::Block)?;
                        plan.push((g, bm, 0));
                        plan.len() - 1
                    }
                };

                if !test_bit(&plan[slot].1, bit) {
                    return Err(LuksError::CorruptFs("double free of a block"));
                }
                clear_bit(&mut plan[slot].1, bit);
                plan[slot].2 += 1;
            }
        }

        for (g, bm, freed) in &plan {
            self.groups[*g].free_blocks_count += *freed;
            self.sb.free_blocks_count += *freed as u64;
            self.write_bitmap(*g, Bitmap::Block, bm, &seed)?;
            self.write_group_desc(*g, &seed)?;
        }
        self.write_superblock(&seed)
    }

    /// Release a single block previously allocated.
    pub fn free_block(&mut self, block: u64) -> Result<()> {
        self.free_blocks(&[Extent {
            physical: block,
            len: 1,
        }])
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
            // Saturating for the same reason as the block counter above.
            self.sb.free_inodes_count = self.sb.free_inodes_count.saturating_sub(1);
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

            // Erase the record before the bitmap claims the slot — the mirror
            // of the argument in `free_inode`, and for the same reason.
            //
            // The record is not written for real until `write_inode_record`,
            // which on this path runs only after every data block has crossed
            // the cable: minutes, on USB, with a file of any size. For that
            // whole window the bitmap says "in use" while the record still
            // describes whatever occupied the slot before — typically a
            // deleted file, with its extents still naming blocks. Interrupted
            // there, `e2fsck` finds a live-looking inode pointing at blocks
            // that are now somebody else's, and the file reads back as a
            // deleted file's plaintext under a new name. On a volume that
            // exists for confidentiality that is the failure that matters.
            //
            // Zeroed first, the same interruption leaves "in use, record
            // zeroed", which `e2fsck` resolves by marking the inode free. A
            // repair complaint instead of a disclosure. The reverse order
            // would reintroduce the window it is meant to close, so the write
            // goes before the commit, not after.
            let blank = vec![0u8; self.sb.inode_size as usize];
            let offset = self.inode_offset(ino)?;
            self.device.write_at(offset, &blank)?;

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

        // `s_inodes_count` is not proof that the group exists: `groups` is
        // sized from the block count, and nothing on disk guarantees the two
        // agree. A superblock claiming more inodes than its groups can hold
        // would otherwise index past the end and panic — in a library whose
        // whole input is attacker- or failure-controlled metadata.
        // `inode_offset` has always got this right; this did not.
        if g >= self.groups.len() {
            return Err(LuksError::BadInode(ino));
        }

        // Same refusal as `free_block`'s: an uninitialised group's bitmap was
        // never written, so reading it yields noise — and if a noise bit
        // happened to be set, the "freed" bitmap written back would be noise
        // *with a valid checksum*. No inode from such a group can have been
        // allocated by this crate, so the request is itself evidence of a
        // caller that has lost track.
        if self.groups[g].inode_bitmap_uninit() {
            return Err(LuksError::CorruptFs(
                "free of an inode in an uninitialised group",
            ));
        }

        let mut bm = self.read_bitmap(g, Bitmap::Inode)?;
        if !test_bit(&bm, bit) {
            return Err(LuksError::CorruptFs("double free of an inode"));
        }

        // Clearing the bitmap bit does not, on its own, make an inode free.
        // `e2fsck` walks the inode *table* independently of the bitmap, and a
        // record still carrying a mode and a link count is reported as an
        // unattached inode however the bitmap reads — which is precisely what
        // a rolled-back `create_file` used to leave behind, with the freed
        // block showing up as a bitmap difference alongside it.
        //
        // Erased before the bitmap is committed, not after. Neither order has
        // a clean crash window, so this is the lesser of two: interrupted
        // here, the slot reads as "in use, record zeroed", which `e2fsck`
        // resolves by marking it free — it is losing an inode that was
        // already being discarded. The other order leaves a live-looking file
        // in a slot the bitmap has already offered to the next allocation.
        //
        // This is deliberately *not* conditional on how the inode was written.
        // The slot may hold a stale record from an earlier deletion by some
        // other implementation, and an allocation that rolls back must not
        // resurrect it.
        let blank = vec![0u8; self.sb.inode_size as usize];
        let offset = self.inode_offset(ino)?;
        self.device.write_at(offset, &blank)?;

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
    find_free_bit_from(bm, 0, limit)
}

/// Index of the first zero bit at or after `from` and below `limit`.
///
/// Resuming from a cursor is what makes claiming N blocks from one bitmap an
/// O(bitmap) scan rather than N scans from byte zero: the caller has just set
/// every bit it found below `from`, so re-examining them can only find them
/// taken. Bits below `from` inside the first byte are masked to 1 for exactly
/// that reason — they are taken *for this search*, whatever they are on disk.
fn find_free_bit_from(bm: &[u8], from: usize, limit: usize) -> Option<usize> {
    if from >= limit {
        return None;
    }
    let mut i = from / 8;
    let mut byte = *bm.get(i)? | (((1u16 << (from % 8)) - 1) as u8);
    loop {
        if byte != 0xFF {
            let index = i * 8 + byte.trailing_ones() as usize;
            return if index >= limit { None } else { Some(index) };
        }
        i += 1;
        byte = *bm.get(i)?;
    }
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
    fn the_cursor_resumes_without_re_finding_what_it_already_took() {
        // Claiming N blocks from one bitmap walks it once with a cursor rather
        // than restarting at byte zero N times. Bits below the cursor are
        // masked to "taken" for the search — get that mask wrong and the batch
        // hands out the same block repeatedly, each one passing every
        // single-block test.
        let bm = [0b0000_0000u8, 0b0000_0000];

        assert_eq!(find_free_bit_from(&bm, 0, 16), Some(0));
        assert_eq!(find_free_bit_from(&bm, 1, 16), Some(1));
        assert_eq!(find_free_bit_from(&bm, 7, 16), Some(7));
        // Crossing a byte boundary: the mask applies to the first byte only.
        assert_eq!(find_free_bit_from(&bm, 8, 16), Some(8));

        // A cursor past a fully taken byte must skip it, not stall on it.
        let bm = [0xFF, 0b0000_0010];
        assert_eq!(find_free_bit_from(&bm, 0, 16), Some(8));
        assert_eq!(find_free_bit_from(&bm, 9, 16), Some(10));

        // The limit still binds when resuming, not only from zero.
        assert_eq!(find_free_bit_from(&[0u8], 4, 6), Some(4));
        assert_eq!(find_free_bit_from(&[0b0011_1111u8], 4, 6), None);

        // A cursor at or past the limit has nothing left to find.
        assert_eq!(find_free_bit_from(&[0u8], 8, 8), None);
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
