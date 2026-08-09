//! Writing a file's inode, data blocks and extent tree.
//!
//! [`Ext4::write_new_file`] deliberately produces something incomplete: an
//! inode with content, not a file anyone can open by name. The inode it
//! creates is an **orphan** — allocated, holding real data, reachable by
//! nothing. `e2fsck` will say so — "Unattached inode N", "ref count is 1,
//! should be 0" — and that complaint is *expected*, not a sign of corruption.
//! The oracle test for that function asserts exactly those two complaints and
//! nothing else.
//!
//! [`Ext4::create_file`] is the one callers should reach for: it pairs that
//! write with the directory link from [`super::dirent`], and undoes the write
//! if the link fails, so it either produces a named file or leaves nothing
//! behind. The two-call sequence remains available for the oracle test that
//! needs to observe the orphan state on purpose.
//!
//! # Extent placement
//!
//! A new inode's 60-byte `i_block` area holds an extent tree with **no room
//! for an index block** — 12 bytes of header plus at most four 12-byte leaf
//! entries. A file needing a fifth non-contiguous run would require an
//! interior node, which is real complexity (allocating an index block, walking
//! two levels instead of one) with its own failure modes, deliberately not
//! attempted here. [`write_new_file`] refuses rather than silently truncating
//! or corrupting the extent header.
//!
//! Locality is what keeps this from mattering in practice: [`super::alloc`]'s
//! `alloc_block` searches from a goal, so blocks for one file tend to land
//! together. It is not a guarantee — a fragmented filesystem can still exhaust
//! four extents — which is exactly why this is checked rather than assumed.

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::ext4::alloc::Extent;
use crate::fs::ext4::csum::Seed;
use crate::fs::ext4::Ext4;

const EXTENT_MAGIC: u16 = 0xF30A;
/// Header (12 bytes) + four 12-byte entries fills exactly the 60-byte
/// `i_block` area with no room left for a fifth.
const MAX_INLINE_EXTENTS: usize = 4;

fn now_unix() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// One contiguous run: `len` logical blocks starting at `logical`, backed by
/// `len` physical blocks starting at `physical`.
struct Run {
    logical: u64,
    physical: u64,
    len: u64,
}

/// State for one file whose contents arrive incrementally.
///
/// It owns no device reference: the caller supplies the mounted [`Ext4`] for
/// each operation. That keeps a higher-layer writer handle from extending the
/// lifetime of an unlocked LUKS volume (and therefore its master key).
pub struct FileWriter {
    ino: u64,
    extents: Vec<Extent>,
    runs: Vec<Run>,
    seed: Seed,
    size: u64,
    written: u64,
    blocks_needed: u64,
    /// At most one filesystem block. A caller may give arbitrary chunk sizes;
    /// holding this tail until it is complete avoids writing zero padding that
    /// a later chunk would need to overwrite.
    tail: Vec<u8>,
}

/// `ee_len` is 16 bits, and values above 32768 mean "uninitialised extent" —
/// so a run longer than that is not merely unrepresentable, it would be read
/// back as a hole.
const MAX_EXTENT_LEN: u64 = 32768;

/// Lay the allocator's physical runs out as logical file extents.
///
/// The allocator has no reason to respect `ee_len`'s ceiling — it hands back
/// whatever contiguity it found — so a long run is cut here, at the layer that
/// knows why the ceiling exists.
fn runs_from(extents: &[Extent]) -> Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut logical = 0u64;
    for e in extents {
        let mut offset = 0u64;
        while offset < e.len {
            let len = (e.len - offset).min(MAX_EXTENT_LEN);
            runs.push(Run {
                logical,
                physical: e.physical + offset,
                len,
            });
            logical += len;
            offset += len;
        }
    }
    if runs.len() > MAX_INLINE_EXTENTS {
        return Err(LuksError::UnsupportedFsFeature(
            "file needs more than 4 extents — interior extent \
             nodes are not yet implemented"
                .into(),
        ));
    }
    Ok(runs)
}

impl<D: WriteAt> Ext4<D> {
    /// Reserve an inode and blocks for a file of `size`, before its bytes are
    /// available. Call [`write_chunk`](Self::write_chunk), then either
    /// [`finish_file`](Self::finish_file) or [`abandon_file`](Self::abandon_file).
    pub fn begin_file(&mut self, size: u64) -> Result<FileWriter> {
        let seed = Seed::for_writing(&self.sb)?;
        let bs = self.sb.block_size as u64;
        let blocks_needed = size.div_ceil(bs.max(1));
        let ino = self.alloc_inode(false)?;
        let extents = match self.alloc_blocks(0, blocks_needed) {
            Ok(extents) => extents,
            Err(e) => {
                self.undo_new_file(ino, &[]);
                return Err(e);
            }
        };
        let runs = match runs_from(&extents) {
            Ok(runs) => runs,
            Err(e) => {
                self.undo_new_file(ino, &extents);
                return Err(e);
            }
        };
        Ok(FileWriter {
            ino,
            extents,
            runs,
            seed,
            size,
            written: 0,
            blocks_needed,
            tail: Vec::new(),
        })
    }

    /// Append one chunk. Chunks may have any length; only a final partial
    /// filesystem block is retained, so payload residency stays bounded.
    pub fn write_chunk(&mut self, writer: &mut FileWriter, data: &[u8]) -> Result<()> {
        let end = writer
            .written
            .checked_add(data.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;
        if end > writer.size {
            return Err(LuksError::OutOfBounds);
        }

        let block_size = self.sb.block_size as usize;
        let mut input = data;
        if !writer.tail.is_empty() {
            let needed = block_size - writer.tail.len();
            let take = needed.min(input.len());
            writer.tail.extend_from_slice(&input[..take]);
            input = &input[take..];
            if writer.tail.len() == block_size {
                let at = writer.written - (block_size - take) as u64;
                self.write_full_blocks(&writer.runs, at, &writer.tail)?;
                writer.tail.clear();
            }
        }

        let full = input.len() / block_size * block_size;
        if full != 0 {
            let at = end - input.len() as u64;
            self.write_full_blocks(&writer.runs, at, &input[..full])?;
        }
        writer.tail.extend_from_slice(&input[full..]);
        writer.written = end;
        Ok(())
    }

    /// Finish a complete stream, publish it in `dir_ino`, and return its inode.
    pub fn finish_file(
        &mut self,
        mut writer: FileWriter,
        dir_ino: u64,
        name: &str,
        file_type: crate::fs::FileType,
    ) -> Result<u64> {
        if let Err(e) = super::dirent::validate_name(name.as_bytes()) {
            self.abandon_file(writer);
            return Err(e);
        }
        let ino = match self.finish_unlinked(&mut writer) {
            Ok(ino) => ino,
            Err(e) => {
                self.abandon_file(writer);
                return Err(e);
            }
        };
        if let Err(e) = self.link_file(dir_ino, name, ino, file_type) {
            self.abandon_file(writer);
            return Err(e);
        }
        Ok(ino)
    }

    /// Roll back a stream that will never be published. Safe to call after an
    /// interrupted transfer; cleanup errors cannot replace its original cause.
    pub fn abandon_file(&mut self, writer: FileWriter) {
        self.undo_new_file(writer.ino, &writer.extents);
    }

    fn finish_unlinked(&mut self, writer: &mut FileWriter) -> Result<u64> {
        if writer.written != writer.size {
            return Err(LuksError::OutOfBounds);
        }
        if !writer.tail.is_empty() {
            let block_size = self.sb.block_size as usize;
            let mut padded = vec![0u8; block_size];
            padded[..writer.tail.len()].copy_from_slice(&writer.tail);
            let at = writer.written - writer.tail.len() as u64;
            self.write_full_blocks(&writer.runs, at, &padded)?;
            writer.tail.clear();
        }
        self.flush()?;
        self.write_inode_record(
            writer.ino,
            writer.size,
            writer.blocks_needed,
            &writer.runs,
            &writer.seed,
        )?;
        Ok(writer.ino)
    }

    /// Write whole filesystem blocks at a logical file offset, translating
    /// across the preallocated physical runs without staging a run-sized copy.
    fn write_full_blocks(&mut self, runs: &[Run], mut at: u64, mut data: &[u8]) -> Result<()> {
        let bs = self.sb.block_size as u64;
        debug_assert_eq!(at % bs, 0);
        debug_assert_eq!(data.len() as u64 % bs, 0);
        while !data.is_empty() {
            let logical = at / bs;
            let run = runs
                .iter()
                .find(|r| logical >= r.logical && logical < r.logical + r.len)
                .ok_or(LuksError::OutOfBounds)?;
            let in_run = logical - run.logical;
            let bytes = ((run.len - in_run) * bs).min(data.len() as u64) as usize;
            self.device
                .write_at((run.physical + in_run) * bs, &data[..bytes])?;
            at += bytes as u64;
            data = &data[bytes..];
        }
        Ok(())
    }

    /// Allocate blocks for `data`, write it, and create an inode pointing at
    /// it. Returns the new inode number.
    ///
    /// The inode is a regular file, mode `0o644`, link count 1 — the count a
    /// file with one directory entry would have, even though no entry exists
    /// yet. That is what makes `e2fsck`'s complaint predictable: a link count
    /// that does not match the (zero) directory references it can find, not
    /// some other mismatch.
    ///
    /// On any failure every block and the inode allocated so far are freed
    /// before returning, so a failed write cannot leak space.
    pub fn write_new_file(&mut self, data: &[u8]) -> Result<u64> {
        self.write_new_file_runs(data).map(|(ino, _)| ino)
    }

    /// Create a file *and* give it a name, or leave the filesystem as it was.
    ///
    /// # Why this exists rather than two calls
    ///
    /// [`write_new_file`](Self::write_new_file) rolls back its own failures,
    /// and [`link_file`](Self::link_file) refuses cleanly, so each is safe
    /// alone. The gap is *between* them: once the data is written and the link
    /// then fails — a name already taken, an htree directory, an I/O error —
    /// the inode is allocated, holds real data, and nothing references it.
    /// `e2fsck` calls that an unattached inode, and every caller sequencing the
    /// two calls by hand had to remember to undo the first. Callers do not
    /// remember; that is what this is for.
    ///
    /// A duplicate name is the realistic trigger, not an exotic one — it is
    /// what happens the second time someone sends the same file.
    ///
    /// # Ordering
    ///
    /// Two barriers, and both are load-bearing rather than caution:
    ///
    /// * **Data before the inode that points at it.** Without this, metadata
    ///   can reach the medium while the data behind it does not, and the file
    ///   then reads back whatever those blocks held before — on a drive that
    ///   has seen deletions, a previously deleted file's plaintext, under a
    ///   new name. On a volume whose whole purpose is confidentiality that is
    ///   the worst of the failure modes, not the mildest.
    /// * **The inode before the name that reaches it.** A dirent pointing at
    ///   an inode that never landed is a directory entry for a file that
    ///   cannot be read.
    ///
    /// Both cost a flush, which on USB is a `SYNCHRONIZE CACHE` round trip.
    /// Three per file, counting the caller's final one. That is the price of
    /// the guarantee and it is not adjustable from here.
    pub fn create_file(
        &mut self,
        dir_ino: u64,
        name: &str,
        data: &[u8],
        file_type: crate::fs::FileType,
    ) -> Result<u64> {
        // Before anything is allocated. A name that cannot be linked is worth
        // discovering now rather than after every block of the file has
        // crossed a USB cable — and the error then names the real problem
        // instead of surfacing as "no space" when the transient allocation is
        // what ran out.
        super::dirent::validate_name(name.as_bytes())?;

        let (ino, extents) = self.write_new_file_runs(data)?;
        self.flush()?;

        if let Err(e) = self.link_file(dir_ino, name, ino, file_type) {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }

        Ok(ino)
    }

    /// Undo a file that was written but never named.
    ///
    /// Order matters more than it looks. The inode goes first — [`free_inode`]
    /// zeroes its record, so after that step nothing on disk points at these
    /// blocks. Freeing the blocks first would leave, for the width of the
    /// window, an inode still marked in use whose extents name blocks the
    /// bitmap has already offered to the next allocation: two files, same
    /// blocks. That is the one outcome `e2fsck` cannot repair without losing
    /// something.
    ///
    /// Flushed at the end because a rollback that only reaches the bridge's
    /// write cache is not a rollback — and the failure that got us here is
    /// disproportionately likely to be a link that is about to disappear.
    /// Errors are swallowed deliberately: the caller is owed the reason the
    /// write failed, not the reason the cleanup did.
    ///
    /// The whole batch is freed in one call. Undoing a 50 MB file used to mean
    /// three device writes per 4 KiB block — a rollback that cost more round
    /// trips than the write it was undoing, on a path taken precisely when
    /// something has already gone wrong.
    fn undo_new_file(&mut self, ino: u64, extents: &[Extent]) {
        let _ = self.free_inode(ino, false);
        let _ = self.free_blocks(extents);
        let _ = self.flush();
    }

    /// The body of [`write_new_file`], keeping the block runs so a caller that
    /// needs to undo the whole thing can free exactly what was allocated
    /// without re-parsing the extent tree it just wrote.
    fn write_new_file_runs(&mut self, data: &[u8]) -> Result<(u64, Vec<Extent>)> {
        let seed = Seed::for_writing(&self.sb)?;
        let bs = self.sb.block_size as u64;
        let blocks_needed = (data.len() as u64).div_ceil(bs.max(1));

        let ino = self.alloc_inode(false)?;

        // Every failure below unwinds through `undo_new_file`, the same
        // rollback `create_file` uses. This used to be a local closure with the
        // opposite ordering — blocks freed first, the inode last with its
        // result discarded, and no flush — which is exactly the shape
        // `undo_new_file`'s comment argues against. Two implementations of one
        // operation meant the fix landed on one of them; there is now one.
        //
        // One call, not one per block. The allocator commits its bookkeeping
        // once per group it touches instead of once per block, which is the
        // difference between a 50 MB file costing ~85,000 SCSI commands and
        // costing a few hundred.
        let extents = match self.alloc_blocks(0, blocks_needed) {
            Ok(e) => e,
            Err(e) => {
                self.undo_new_file(ino, &[]);
                return Err(e);
            }
        };

        // The four-extent ceiling is checked here, after the allocation rather
        // than during it. Nothing is wasted by that: a batch that turns out
        // too fragmented is handed straight back to `free_blocks`, which
        // releases it in the same one-commit-per-group way it was taken.
        let runs = match runs_from(&extents) {
            Ok(r) => r,
            Err(e) => {
                self.undo_new_file(ino, &extents);
                return Err(e);
            }
        };

        if let Err(e) = self.write_file_data(&runs, data) {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }

        // The barrier that keeps a file from ever reading back as somebody
        // else's deleted plaintext: the data must be on the medium before the
        // inode that names those blocks is. See `create_file`.
        if let Err(e) = self.flush() {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.write_inode_record(ino, data.len() as u64, blocks_needed, &runs, &seed)
        {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }

        Ok((ino, extents))
    }

    fn write_file_data(&mut self, runs: &[Run], data: &[u8]) -> Result<()> {
        let bs = self.sb.block_size as u64;
        let block_size = self.sb.block_size as usize;
        let mut done = 0usize;
        for r in runs {
            let run_bytes = (r.len * bs) as usize;
            let take = run_bytes.min(data.len() - done);
            let full_bytes = take / block_size * block_size;
            if full_bytes != 0 {
                self.device
                    .write_at(r.physical * bs, &data[done..done + full_bytes])?;
            }
            if full_bytes != take {
                // Only the final partial block needs a scratch buffer. Its
                // zero tail prevents bytes from a previously deleted file
                // becoming visible through this new inode.
                let mut tail = vec![0u8; block_size];
                tail[..take - full_bytes].copy_from_slice(&data[done + full_bytes..done + take]);
                self.device
                    .write_at(r.physical * bs + full_bytes as u64, &tail)?;
            }
            done += take;
        }
        Ok(())
    }

    fn write_inode_record(
        &mut self,
        ino: u64,
        size: u64,
        blocks_needed: u64,
        runs: &[Run],
        seed: &Seed,
    ) -> Result<()> {
        let isize_ = self.sb.inode_size as usize;
        let mut raw = vec![0u8; isize_];

        const MODE_REGULAR_0644: u16 = 0x8000 | 0o644;
        const FL_EXTENTS: u32 = 0x0008_0000;

        put16(&mut raw, 0x00, MODE_REGULAR_0644); // i_mode
        put32(&mut raw, 0x04, size as u32); // i_size_lo
        let now = now_unix();
        put32(&mut raw, 0x08, now); // i_atime
        put32(&mut raw, 0x0C, now); // i_ctime
        put32(&mut raw, 0x10, now); // i_mtime
        put16(&mut raw, 0x1A, 1); // i_links_count — see doc comment
        let sectors_per_block = self.sb.block_size / 512;
        put32(&mut raw, 0x1C, blocks_needed as u32 * sectors_per_block); // i_blocks_lo
        put32(&mut raw, 0x20, FL_EXTENTS); // i_flags

        write_extent_tree(&mut raw[0x28..0x28 + 60], runs)?;

        if isize_ > 128 {
            // Clamped to the room that actually exists past the base inode,
            // and rounded up to 4 — e2fsck rejects an `i_extra_isize` that is
            // odd-sized or larger than `s_inode_size - 128`. The cap is a
            // multiple of 4 (inode sizes are powers of two), so rounding
            // cannot push a clamped value back over it.
            let cap = (isize_ - 128) as u16;
            let extra = self.sb.min_extra_isize.max(32).min(cap);
            let extra = (extra + 3) & !3;
            put16(&mut raw, 0x80, extra); // i_extra_isize
        }
        if isize_ > 128 && size > u32::MAX as u64 {
            put32(&mut raw, 0x6C, (size >> 32) as u32); // i_size_high
        }

        if let Some(csum) = seed.inode(ino, &raw) {
            put16(&mut raw, 0x7C, csum as u16);
            if seed.inode_has_csum_hi(&raw) {
                put16(&mut raw, 0x82, (csum >> 16) as u16);
            }
        }

        let offset = self.inode_offset(ino)?;
        self.device.write_at(offset, &raw)?;
        Ok(())
    }
}

/// Serialise up to [`MAX_INLINE_EXTENTS`] runs into the 60-byte `i_block`
/// extent tree. `area` must be exactly 60 bytes.
fn write_extent_tree(area: &mut [u8], runs: &[Run]) -> Result<()> {
    debug_assert_eq!(area.len(), 60);
    if runs.len() > MAX_INLINE_EXTENTS {
        return Err(LuksError::UnsupportedFsFeature(
            "more extents than fit inline".into(),
        ));
    }

    put16(area, 0, EXTENT_MAGIC); // eh_magic
    put16(area, 2, runs.len() as u16); // eh_entries
    put16(area, 4, MAX_INLINE_EXTENTS as u16); // eh_max
    put16(area, 6, 0); // eh_depth — 0: this node is a leaf
    put32(area, 8, 0); // eh_generation

    for (i, r) in runs.iter().enumerate() {
        let e = &mut area[12 + i * 12..24 + i * 12];
        put32(e, 0, r.logical as u32); // ee_block
        put16(e, 4, r.len as u16); // ee_len (initialised: <= 32768)
        put16(e, 6, (r.physical >> 32) as u16); // ee_start_hi
        put32(e, 8, r.physical as u32); // ee_start_lo
    }
    Ok(())
}
