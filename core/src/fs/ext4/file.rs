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
use crate::fs::ext4::csum::{Seed, DIR_TAIL_SIZE};
use crate::fs::ext4::{Ext4, Inode};
use crate::fs::FileType;

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

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
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
    leaf_block: Option<u64>,
    /// At most one filesystem block. A caller may give arbitrary chunk sizes;
    /// holding this tail until it is complete avoids writing zero padding that
    /// a later chunk would need to overwrite.
    tail: Vec<u8>,
    is_streaming: bool,
}

/// `ee_len` is 16 bits, and values above 32768 mean "uninitialised extent" —
/// so a run longer than that is not merely unrepresentable, it would be read
/// back as a hole.
const MAX_EXTENT_LEN: u64 = 32768;

/// Coalesce contiguous physical extents before mapping to file runs.
fn coalesce_extents(extents: &[Extent]) -> Vec<Extent> {
    let mut merged: Vec<Extent> = Vec::new();
    for e in extents {
        if let Some(last) = merged.last_mut() {
            if last.physical + last.len == e.physical {
                last.len += e.len;
                continue;
            }
        }
        merged.push(*e);
    }
    merged
}

/// Lay the allocator's physical runs out as logical file extents.
///
/// Extent tree depth ceiling (how many discontiguous physical runs a single *file's data*
/// can consist of before a depth-2 extent tree would be required — not to be confused with
/// the directory-entry ceiling below, which is a different structure entirely: extent records
/// here are 12 bytes each, directory entries are 20 bytes each with a different block layout):
/// - Depth 0 (inline): at most 4 entries in `i_block` (48 bytes / 12 = 4).
/// - Depth 1 (single leaf block): at most `(block_size - 12 - 4) / 12` entries:
///   - 340 entries on a 4 KiB filesystem (up to 42.5 GiB contiguous, or 1.36 MiB fully fragmented).
///   - 84 entries on a 1 KiB filesystem.
///
/// These two figures are an arithmetic derivation, not directly measured, but audited
/// 2026-08-17 (`notes/feature-remediation.md`) and found to be a distinct ceiling from the
/// measured *directory*-entry ceiling of 203 (4 KiB) / 49 (1 KiB) entries recorded in
/// `core/tests/statfs.rs::measure_ext4_directory_capacity_ceiling` — do not conflate the two
/// when updating either.
///
/// If fragmentation or size requires more runs than fit in a single leaf block, depth 2
/// would be required. The writer refuses cleanly and early before block allocation.
fn runs_from(extents: &[Extent], max_runs: usize) -> Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut logical = 0u64;
    let merged = coalesce_extents(extents);
    for e in &merged {
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
    if runs.len() > max_runs {
        return Err(LuksError::UnsupportedFsFeature(
            "file needs more extents than the max leaf node size — multi-leaf \
             extent trees (depth > 1) are not supported"
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
        let mut extents = match self.alloc_blocks(0, blocks_needed) {
            Ok(extents) => extents,
            Err(e) => {
                self.undo_new_file(ino, &[]);
                return Err(e);
            }
        };
        let max_runs = (bs as usize - 12 - 4) / 12;
        let runs = match runs_from(&extents, max_runs) {
            Ok(runs) => runs,
            Err(e) => {
                self.undo_new_file(ino, &extents);
                return Err(e);
            }
        };
        let mut leaf_block = None;
        if runs.len() > MAX_INLINE_EXTENTS {
            match self.alloc_blocks(0, 1) {
                Ok(mut e) => {
                    leaf_block = Some(e[0].physical);
                    extents.append(&mut e);
                }
                Err(e) => {
                    self.undo_new_file(ino, &extents);
                    return Err(e);
                }
            }
        }
        Ok(FileWriter {
            ino,
            extents,
            runs,
            seed,
            size,
            written: 0,
            blocks_needed,
            leaf_block,
            tail: Vec::new(),
            is_streaming: false,
        })
    }

    /// Begin a streaming file transfer whose final size is not known up-front.
    ///
    /// Extents are allocated incrementally as data arrives via [`write_chunk`](Self::write_chunk).
    pub fn begin_file_streaming(&mut self) -> Result<FileWriter> {
        let seed = Seed::for_writing(&self.sb)?;
        let ino = self.alloc_inode(false)?;
        Ok(FileWriter {
            ino,
            extents: Vec::new(),
            runs: Vec::new(),
            seed,
            size: 0,
            written: 0,
            blocks_needed: 0,
            leaf_block: None,
            tail: Vec::new(),
            is_streaming: true,
        })
    }

    /// Append one chunk. Chunks may have any length; only a final partial
    /// filesystem block is retained, so payload residency stays bounded.
    pub fn write_chunk(&mut self, writer: &mut FileWriter, data: &[u8]) -> Result<()> {
        let end = writer
            .written
            .checked_add(data.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;

        let bs = self.sb.block_size as u64;
        let block_size = self.sb.block_size as usize;
        let max_runs = (block_size - 12 - 4) / 12;

        if writer.is_streaming {
            let blocks_needed = end.div_ceil(bs.max(1));
            let current_data_blocks: u64 = writer.runs.iter().map(|r| r.len).sum();
            if blocks_needed > current_data_blocks {
                let delta = blocks_needed - current_data_blocks;
                // Refusal gate before block allocation: if we already have max_runs runs,
                // adding more cannot fit in depth <= 1
                if writer.runs.len() >= max_runs {
                    return Err(LuksError::UnsupportedFsFeature(
                        "file needs more extents than the max leaf node size — multi-leaf \
                         extent trees (depth > 1) are not supported"
                            .into(),
                    ));
                }
                let goal = writer
                    .extents
                    .iter().rfind(|e| Some(e.physical) != writer.leaf_block)
                    .map(|e| e.physical + e.len)
                    .unwrap_or(0);
                let new_extents = self.alloc_blocks(goal, delta)?;
                writer.extents.extend_from_slice(&new_extents);

                let data_extents: Vec<Extent> = writer
                    .extents
                    .iter()
                    .copied()
                    .filter(|e| Some(e.physical) != writer.leaf_block)
                    .collect();
                let runs = match runs_from(&data_extents, max_runs) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = self.free_blocks(&new_extents);
                        writer
                            .extents
                            .truncate(writer.extents.len() - new_extents.len());
                        return Err(e);
                    }
                };
                writer.runs = runs;
                writer.blocks_needed = blocks_needed;

                if writer.runs.len() > MAX_INLINE_EXTENTS && writer.leaf_block.is_none() {
                    match self.alloc_blocks(0, 1) {
                        Ok(mut e) => {
                            writer.leaf_block = Some(e[0].physical);
                            writer.extents.append(&mut e);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }
            writer.size = end;
        } else if end > writer.size {
            return Err(LuksError::OutOfBounds);
        }

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
        if writer.is_streaming {
            writer.size = writer.written;
            writer.blocks_needed = writer.written.div_ceil(self.sb.block_size as u64);
        }
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
        if let Some(lb) = writer.leaf_block {
            self.write_extent_leaf_block(lb, writer.ino, &writer.runs, &writer.seed)?;
        }
        self.flush()?;
        self.write_inode_record(
            writer.ino,
            writer.size,
            writer.blocks_needed,
            &writer.runs,
            writer.leaf_block,
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
        let mut extents = match self.alloc_blocks(0, blocks_needed) {
            Ok(e) => e,
            Err(e) => {
                self.undo_new_file(ino, &[]);
                return Err(e);
            }
        };

        let max_runs = (bs as usize - 12 - 4) / 12;
        let runs = match runs_from(&extents, max_runs) {
            Ok(r) => r,
            Err(e) => {
                self.undo_new_file(ino, &extents);
                return Err(e);
            }
        };

        let mut leaf_block = None;
        if runs.len() > MAX_INLINE_EXTENTS {
            match self.alloc_blocks(0, 1) {
                Ok(mut e) => {
                    leaf_block = Some(e[0].physical);
                    extents.append(&mut e);
                }
                Err(e) => {
                    self.undo_new_file(ino, &extents);
                    return Err(e);
                }
            }
        }

        if let Err(e) = self.write_file_data(&runs, data) {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }
        if let Some(lb) = leaf_block {
            if let Err(e) = self.write_extent_leaf_block(lb, ino, &runs, &seed) {
                self.undo_new_file(ino, &extents);
                return Err(e);
            }
        }

        // The barrier that keeps a file from ever reading back as somebody
        // else's deleted plaintext: the data must be on the medium before the
        // inode that names those blocks is. See `create_file`.
        if let Err(e) = self.flush() {
            self.undo_new_file(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.write_inode_record(ino, data.len() as u64, blocks_needed, &runs, leaf_block, &seed)
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
    fn write_extent_leaf_block(
        &mut self,
        leaf_block: u64,
        ino: u64,
        runs: &[Run],
        seed: &Seed,
    ) -> Result<()> {
        let bs = self.sb.block_size as usize;
        let mut block = vec![0u8; bs];

        put16(&mut block, 0, EXTENT_MAGIC); // eh_magic
        put16(&mut block, 2, runs.len() as u16); // eh_entries
        let max = (bs - 12 - 4) / 12;
        put16(&mut block, 4, max as u16); // eh_max
        put16(&mut block, 6, 0); // eh_depth — leaf node
        put32(&mut block, 8, 0); // eh_generation

        for (i, r) in runs.iter().enumerate() {
            let e = &mut block[12 + i * 12..24 + i * 12];
            put32(e, 0, r.logical as u32);
            put16(e, 4, r.len as u16);
            put16(e, 6, (r.physical >> 32) as u16);
            put32(e, 8, r.physical as u32);
        }

        if let Some(csum) = seed.extent_block(ino, 0, &block) {
            let tail = &mut block[bs - 4..bs];
            put32(tail, 0, csum);
        }

        self.device.write_at(leaf_block * bs as u64, &block)?;
        Ok(())
    }

    fn write_inode_record(
        &mut self,
        ino: u64,
        size: u64,
        blocks_needed: u64,
        runs: &[Run],
        leaf_block: Option<u64>,
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
        let total_blocks = if leaf_block.is_some() { blocks_needed + 1 } else { blocks_needed };
        let sectors_per_block = self.sb.block_size / 512;
        put32(&mut raw, 0x1C, total_blocks as u32 * sectors_per_block); // i_blocks_lo
        put32(&mut raw, 0x20, FL_EXTENTS); // i_flags

        write_extent_tree(&mut raw[0x28..0x28 + 60], runs, leaf_block)?;

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

    /// Walk an inode's extent tree and return all physical block runs (data)
    /// plus any index blocks used by the tree itself (depth > 0).
    ///
    /// Must be called BEFORE the inode is zeroed — after Phase 2 the extents
    /// are unrecoverable.
    pub fn collect_extents(&self, inode: &Inode) -> Result<(Vec<Extent>, Vec<Extent>)> {
        if inode.is_inline() {
            return Ok((Vec::new(), Vec::new()));
        }

        if !inode.uses_extents() {
            return Err(LuksError::UnsupportedFsFeature(
                "deleting files with indirect block mapping".into(),
            ));
        }

        let magic = u16le(&inode.block_area, 0);
        if magic != EXTENT_MAGIC {
            return Err(LuksError::BadExtentHeader(magic));
        }
        let entries = u16le(&inode.block_area, 2) as usize;
        let depth = u16le(&inode.block_area, 6);

        if 12 + entries * 12 > inode.block_area.len() {
            return Err(LuksError::BadExtentTree("entry count exceeds node size"));
        }

        if depth == 0 {
            let mut data_extents = Vec::new();
            for i in 0..entries {
                let e = &inode.block_area[12 + i * 12..24 + i * 12];
                let raw_len = u16le(e, 4);
                let len = if raw_len > 32768 {
                    (raw_len - 32768) as u64
                } else {
                    raw_len as u64
                };
                if len == 0 {
                    continue;
                }
                let start = u32le(e, 8) as u64 | ((u16le(e, 6) as u64) << 32);
                data_extents.push(Extent { physical: start, len });
            }
            Ok((data_extents, Vec::new()))
        } else if depth == 1 {
            let mut data_extents = Vec::new();
            let mut index_extents = Vec::new();
            let bs = self.sb.block_size as usize;

            for i in 0..entries {
                let e = &inode.block_area[12 + i * 12..24 + i * 12];
                let child_phys = u32le(e, 4) as u64 | ((u16le(e, 8) as u64) << 32);
                index_extents.push(Extent {
                    physical: child_phys,
                    len: 1,
                });

                let mut buf = vec![0u8; bs];
                self.read_block(child_phys, &mut buf)?;

                let child_magic = u16le(&buf, 0);
                if child_magic != EXTENT_MAGIC {
                    return Err(LuksError::BadExtentHeader(child_magic));
                }
                let child_entries = u16le(&buf, 2) as usize;
                let child_depth = u16le(&buf, 6);
                if child_depth != 0 {
                    return Err(LuksError::BadExtentTree(
                        "expected leaf node at depth 0 in extent tree",
                    ));
                }
                if 12 + child_entries * 12 > buf.len() {
                    return Err(LuksError::BadExtentTree("child entry count exceeds block size"));
                }

                for j in 0..child_entries {
                    let ce = &buf[12 + j * 12..24 + j * 12];
                    let raw_len = u16le(ce, 4);
                    let len = if raw_len > 32768 {
                        (raw_len - 32768) as u64
                    } else {
                        raw_len as u64
                    };
                    if len == 0 {
                        continue;
                    }
                    let start = u32le(ce, 8) as u64 | ((u16le(ce, 6) as u64) << 32);
                    data_extents.push(Extent { physical: start, len });
                }
            }
            Ok((data_extents, index_extents))
        } else {
            Err(LuksError::UnsupportedFsFeature(
                "file has extent tree depth > 1".into(),
            ))
        }
    }

    /// Update `i_links_count` for inode `ino` by adding `delta`.
    ///
    /// Reads raw inode table block for `ino`, updates `i_links_count` at offset 0x1A,
    /// recomputes Castagnoli CRC32C inode checksum using `csum.rs`, writes block
    /// back to device and flushes.
    pub fn patch_inode_links_count(&mut self, ino: u32, delta: i16) -> Result<()> {
        let seed = Seed::for_writing(&self.sb)?;
        let offset = self.inode_offset(ino as u64)?;
        let isize_ = self.sb.inode_size as usize;
        let mut raw = vec![0u8; isize_];
        self.device.read_at(offset, &mut raw)?;

        let current_links = u16le(&raw, 0x1A);
        let new_links = current_links as i32 + delta as i32;
        if new_links < 0 || new_links > u16::MAX as i32 {
            return Err(LuksError::CorruptFs("inode links count underflow/overflow"));
        }
        put16(&mut raw, 0x1A, new_links as u16);

        if let Some(csum) = seed.inode(ino as u64, &raw) {
            put16(&mut raw, 0x7C, csum as u16);
            if seed.inode_has_csum_hi(&raw) {
                put16(&mut raw, 0x82, (csum >> 16) as u16);
            }
        }

        self.device.write_at(offset, &raw)?;
        self.flush()
    }

    fn write_directory_inode_record(
        &mut self,
        ino: u64,
        block_phys: u64,
        seed: &Seed,
    ) -> Result<()> {
        let isize_ = self.sb.inode_size as usize;
        let mut raw = vec![0u8; isize_];

        const MODE_DIR_0755: u16 = 0x4000 | 0o755;
        const FL_EXTENTS: u32 = 0x0008_0000;

        put16(&mut raw, 0x00, MODE_DIR_0755); // i_mode
        put32(&mut raw, 0x04, self.sb.block_size); // i_size_lo
        let now = now_unix();
        put32(&mut raw, 0x08, now); // i_atime
        put32(&mut raw, 0x0C, now); // i_ctime
        put32(&mut raw, 0x10, now); // i_mtime
        put16(&mut raw, 0x1A, 2); // i_links_count = 2 (parent dirent + '.' in self)
        let sectors_per_block = self.sb.block_size / 512;
        put32(&mut raw, 0x1C, sectors_per_block); // i_blocks_lo
        put32(&mut raw, 0x20, FL_EXTENTS); // i_flags

        let runs = [Run {
            logical: 0,
            physical: block_phys,
            len: 1,
        }];
        write_extent_tree(&mut raw[0x28..0x28 + 60], &runs, None)?;

        if isize_ > 128 {
            let cap = (isize_ - 128) as u16;
            let extra = self.sb.min_extra_isize.max(32).min(cap);
            let extra = (extra + 3) & !3;
            put16(&mut raw, 0x80, extra); // i_extra_isize
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

    fn undo_new_dir(&mut self, ino: u64, extents: &[Extent]) {
        let _ = self.free_inode(ino, true);
        let _ = self.free_blocks(extents);
        let _ = self.flush();
    }

    /// Create a new directory `name` in parent directory `dir_ino`.
    /// Returns the new directory's inode number.
    ///
    /// 1. Allocates an inode with `alloc_inode(true)`.
    /// 2. Allocates 1 block with `alloc_blocks(0, 1)`.
    /// 3. Formats fresh dirent block: `.` (`ino`, len 12, `FT_DIR`), `..` (`dir_ino`, len `usable - 12`, `FT_DIR`), and directory checksum tail (`Seed::dir_block`).
    /// 4. Writes directory inode record (`mode = 0x4000 | 0755`, `i_links_count = 2`, `i_size = block_size`, single-extent pointing to the dirent block).
    /// 5. Links into parent directory with `link_file`.
    /// 6. Bumps parent directory's `i_links_count` using `patch_inode_links_count`.
    /// 7. Provides compensation rollback on any failure before completion.
    pub fn create_directory(&mut self, dir_ino: u32, name: &str) -> Result<u32> {
        let seed = Seed::for_writing(&self.sb)?;

        super::dirent::validate_name(name.as_bytes())?;

        let parent = self.read_inode(dir_ino as u64)?;
        if !parent.file_type().is_dir() {
            return Err(LuksError::NotADirectory(format!("inode {dir_ino}")));
        }

        let ino = self.alloc_inode(true)?;
        let ino_u32 = ino as u32;

        let extents = match self.alloc_blocks(0, 1) {
            Ok(e) => e,
            Err(e) => {
                let _ = self.free_inode(ino, true);
                let _ = self.flush();
                return Err(e);
            }
        };
        let block_phys = extents[0].physical;

        let bs = self.sb.block_size as usize;
        let mut block = vec![0u8; bs];

        // First entry: "."
        put32(&mut block, 0, ino_u32);
        put16(&mut block, 4, 12);
        block[6] = 1; // name_len
        block[7] = 2; // FT_DIR
        block[8] = b'.';
        block[9..12].fill(0);

        // Second entry: ".."
        let dotdot_len = if seed.enabled() {
            bs - 12 - DIR_TAIL_SIZE
        } else {
            bs - 12
        };
        put32(&mut block, 12, dir_ino);
        put16(&mut block, 16, dotdot_len as u16);
        block[18] = 2; // name_len
        block[19] = 2; // FT_DIR
        block[20] = b'.';
        block[21] = b'.';
        block[22..12 + dotdot_len].fill(0);

        // Checksum tail
        if seed.enabled() {
            let tail_off = bs - DIR_TAIL_SIZE;
            put32(&mut block, tail_off, 0);
            put16(&mut block, tail_off + 4, DIR_TAIL_SIZE as u16);
            block[tail_off + 6] = 0;
            block[tail_off + 7] = 0xDE;
            if let Some(csum) = seed.dir_block(ino, 0, &block) {
                put32(&mut block, bs - 4, csum);
            }
        }

        let at = match self.metadata_block_offset(block_phys) {
            Ok(offset) => offset,
            Err(e) => {
                self.undo_new_dir(ino, &extents);
                return Err(e);
            }
        };
        if let Err(e) = self.device.write_at(at, &block) {
            self.undo_new_dir(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.write_directory_inode_record(ino, block_phys, &seed) {
            self.undo_new_dir(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.flush() {
            self.undo_new_dir(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.link_file(dir_ino as u64, name, ino, FileType::Directory) {
            self.undo_new_dir(ino, &extents);
            return Err(e);
        }

        if let Err(e) = self.patch_inode_links_count(dir_ino, 1) {
            let _ = self.unlink_file(dir_ino as u64, name);
            self.undo_new_dir(ino, &extents);
            return Err(e);
        }

        Ok(ino_u32)
    }

    /// Rename a regular file from `old_name` to `new_name` in directory `dir_ino`.
    ///
    /// Refuses directory renames (`UnsupportedFsFeature`), cross-directory renames
    /// (`UnsupportedFsFeature`), and non-regular file renames.
    ///
    /// If `new_name` exists and is a regular file, unlinks and frees the destination
    /// before linking `old_name` under `new_name`.
    pub fn rename_file(&mut self, dir_ino: u32, old_name: &str, new_name: &str) -> Result<()> {
        let _seed = Seed::for_writing(&self.sb)?;

        // Refusal gate: cross-directory move
        if old_name.contains('/') || new_name.contains('/') {
            return Err(LuksError::UnsupportedFsFeature(
                "cross-directory rename is not supported".into(),
            ));
        }

        super::dirent::validate_name(old_name.as_bytes())?;
        super::dirent::validate_name(new_name.as_bytes())?;

        if old_name == new_name {
            let dir = self.read_inode(dir_ino as u64)?;
            if self.find_entry(&dir, old_name.as_bytes())?.is_none() {
                return Err(LuksError::NotFound(old_name.to_string()));
            }
            return Ok(());
        }

        let dir = self.read_inode(dir_ino as u64)?;
        if !dir.file_type().is_dir() {
            return Err(LuksError::NotADirectory(format!("inode {dir_ino}")));
        }

        let old_ino = self
            .find_entry(&dir, old_name.as_bytes())?
            .ok_or_else(|| LuksError::NotFound(old_name.to_string()))?;

        let old_inode = self.read_inode(old_ino)?;
        // Refusal gate: directory rename
        if old_inode.file_type().is_dir() {
            return Err(LuksError::UnsupportedFsFeature(
                "renaming a directory is not supported".into(),
            ));
        }
        if !old_inode.file_type().is_file() {
            return Err(LuksError::UnsupportedFsFeature(
                "renaming non-regular files is not supported".into(),
            ));
        }

        // Check if destination exists
        let dest_entry = self.find_entry(&dir, new_name.as_bytes())?;
        if let Some(dest_ino) = dest_entry {
            let dest_inode = self.read_inode(dest_ino)?;
            if dest_inode.file_type().is_dir() {
                return Err(LuksError::UnsupportedFsFeature(
                    "overwriting a directory with a file is not supported".into(),
                ));
            }
            if dest_inode.links > 1 {
                return Err(LuksError::UnsupportedFsFeature(
                    "overwriting a hardlinked file is not supported".into(),
                ));
            }
            // Delete destination file completely
            let (data_extents, index_extents) = self.collect_extents(&dest_inode)?;
            let removed_ino = self.unlink_file(dir_ino as u64, new_name)?;
            if removed_ino != dest_ino {
                return Err(LuksError::CorruptFs("unlinked dest inode number mismatch"));
            }
            self.free_inode(dest_ino, false)?;
            self.free_blocks(&data_extents)?;
            if !index_extents.is_empty() {
                self.free_blocks(&index_extents)?;
            }
            self.flush()?;
        }

        // Unlink old name
        let removed_ino = self.unlink_file(dir_ino as u64, old_name)?;
        if removed_ino != old_ino {
            return Err(LuksError::CorruptFs("unlinked old inode number mismatch"));
        }

        // Link new name
        if let Err(e) = self.link_file(dir_ino as u64, new_name, old_ino, FileType::Regular) {
            // Attempt rollback: re-link old name
            let _ = self.link_file(dir_ino as u64, old_name, old_ino, FileType::Regular);
            let _ = self.flush();
            return Err(e);
        }

        self.flush()?;
        Ok(())
    }

    /// Rename an item given old and new parent directory paths and names.
    pub fn rename(&mut self, old_parent: &str, old_name: &str, new_parent: &str, new_name: &str) -> Result<()> {
        let old_dir = self.resolve(old_parent)?;
        let new_dir = self.resolve(new_parent)?;
        if old_dir.number != new_dir.number {
            return Err(LuksError::UnsupportedFsFeature(
                "ext4 cross-directory rename is not supported".into(),
            ));
        }
        self.rename_file(old_dir.number as u32, old_name, new_name)
    }
}

/// Serialise up to [`MAX_INLINE_EXTENTS`] runs into the 60-byte `i_block`
/// extent tree, or write an interior node if `leaf_block` is provided. `area` must be exactly 60 bytes.
fn write_extent_tree(area: &mut [u8], runs: &[Run], leaf_block: Option<u64>) -> Result<()> {
    debug_assert_eq!(area.len(), 60);

    if let Some(lb) = leaf_block {
        put16(area, 0, EXTENT_MAGIC); // eh_magic
        put16(area, 2, 1); // eh_entries
        put16(area, 4, MAX_INLINE_EXTENTS as u16); // eh_max
        put16(area, 6, 1); // eh_depth — 1: this node points to leaves
        put32(area, 8, 0); // eh_generation

        let e = &mut area[12..24];
        put32(e, 0, runs[0].logical as u32); // ei_block
        put32(e, 4, lb as u32); // ei_leaf_lo
        put16(e, 8, (lb >> 32) as u16); // ei_leaf_hi
        put16(e, 10, 0); // ei_unused
        return Ok(());
    }

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
