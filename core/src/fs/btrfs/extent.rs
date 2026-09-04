//! File contents: `EXTENT_DATA` items.
//!
//! A file's bytes are described by items keyed `(inode, EXTENT_DATA, file
//! offset)`. Three kinds, and the differences matter for correctness rather
//! than performance:
//!
//! - **inline** — the bytes live in the leaf itself, no data block at all.
//!   Small files (under `max_inline`, 2 KiB by default) and most symlink
//!   targets are stored this way.
//! - **regular** — an allocated extent. `disk_bytenr == 0` marks a hole, which
//!   reads as zeros.
//! - **prealloc** — space reserved by `fallocate` and never written. It has a
//!   real address holding whatever was there before, and **must** read as
//!   zeros. Treating it as regular would hand the caller the previous owner's
//!   data, which is an information leak rather than a wrong-file-contents bug.
//!
//! And a fourth case that is not an item at all: with `NO_HOLES` set — the
//! default on every modern filesystem — a gap in a sparse file has *no*
//! `EXTENT_DATA` covering it. The reader has to infer zeros from an item that
//! is missing, which is why the loop below is driven by file offset rather than
//! by iterating items.
//!
//! Field offsets verified against real items with `btrfs inspect-internal
//! dump-tree`: inline data starts at 21, and the non-inline tail runs
//! `disk_bytenr` 21, `disk_num_bytes` 29, `offset` 37, `num_bytes` 45 — an item
//! size of exactly 53.

use super::inode::Inode;
use super::tree;
use super::{Btrfs, Key};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// Bytes before an inline extent's payload.
pub const INLINE_HEADER: usize = 21;
/// Total size of a non-inline `EXTENT_DATA` item.
const REGULAR_ITEM_SIZE: usize = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    Inline,
    Regular,
    Prealloc,
}

fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// One `EXTENT_DATA` item, parsed.
#[derive(Debug, Clone)]
pub struct FileExtent {
    /// File offset this extent starts at — the key's offset field.
    pub file_offset: u64,
    pub kind: ExtentKind,
    /// Uncompressed size of the whole extent this item refers to.
    pub ram_bytes: u64,
    /// 0 none, 1 zlib, 2 lzo, 3 zstd.
    pub compression: u8,
    pub disk_bytenr: u64,
    pub disk_num_bytes: u64,
    /// Offset into the (decompressed) extent at which this item's range begins.
    /// Non-zero when a write split an existing extent rather than replacing it.
    pub offset: u64,
    /// How many bytes of the file this item covers.
    pub num_bytes: u64,
    /// Inline payload, copied out of the leaf.
    pub inline: Option<Vec<u8>>,
}

impl FileExtent {
    pub fn parse(file_offset: u64, data: &[u8]) -> Result<Self> {
        if data.len() <= 20 {
            return Err(LuksError::CorruptFs("btrfs extent item truncated"));
        }
        let ram_bytes = u64le(data, 8);
        let compression = data[16];
        let encryption = data[17];
        let kind = match data[20] {
            0 => ExtentKind::Inline,
            1 => ExtentKind::Regular,
            2 => ExtentKind::Prealloc,
            _ => return Err(LuksError::CorruptFs("btrfs extent has an unknown type")),
        };

        if encryption != 0 {
            // No btrfs release has ever produced this. If one does, refusing is
            // the only honest option — the bytes on disk are not the file's.
            return Err(LuksError::UnsupportedFsFeature(
                "btrfs encrypted extent".into(),
            ));
        }

        if kind == ExtentKind::Inline {
            let payload = data[INLINE_HEADER..].to_vec();
            return Ok(FileExtent {
                file_offset,
                kind,
                ram_bytes,
                compression,
                disk_bytenr: 0,
                disk_num_bytes: payload.len() as u64,
                offset: 0,
                num_bytes: ram_bytes,
                inline: Some(payload),
            });
        }

        if data.len() < REGULAR_ITEM_SIZE {
            return Err(LuksError::CorruptFs("btrfs extent item truncated"));
        }
        Ok(FileExtent {
            file_offset,
            kind,
            ram_bytes,
            compression,
            disk_bytenr: u64le(data, 21),
            disk_num_bytes: u64le(data, 29),
            offset: u64le(data, 37),
            num_bytes: u64le(data, 45),
            inline: None,
        })
    }

    /// One past the last file offset this item covers.
    pub fn end(&self) -> u64 {
        self.file_offset.saturating_add(self.num_bytes)
    }

    /// Whether this extent reads as zeros without touching the device.
    pub fn is_zeros(&self) -> bool {
        // A regular extent with no address is a hole. Prealloc has an address
        // but has never been written, so its contents are not the file's.
        (self.kind == ExtentKind::Regular && self.disk_bytenr == 0)
            || self.kind == ExtentKind::Prealloc
    }

    /// Whether this extent occupies real disk blocks that should be freed
    /// when the owning file is deleted. Unlike `is_zeros()` (which is correct
    /// for *reading* — prealloc extents should read as zeros), this predicate
    /// is correct for *freeing*: a Prealloc extent has a real `disk_bytenr`
    /// that must be returned to the allocator.
    pub fn has_disk_bytes(&self) -> bool {
        self.kind != ExtentKind::Inline && self.disk_bytenr > 0 && self.disk_num_bytes > 0
    }

    pub fn is_compressed(&self) -> bool {
        self.compression != 0
    }
}

impl<D: ReadAt> Btrfs<D> {
    /// Read from a file by inode. Returns the number of bytes read, which is
    /// short only at end of file.
    pub fn read_inode_data(
        &self,
        tree: u64,
        inode: &Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        let want = buf.len().min((inode.size - offset) as usize);
        if want == 0 {
            return Ok(0);
        }

        // Position at the extent covering `offset`, which is filed under the
        // offset it *starts* at and so is usually not an exact match.
        let mut cursor = self.search_le(
            tree,
            &Key::new(inode.objectid, tree::EXTENT_DATA_KEY, offset),
        )?;

        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;

            // Whether the cursor points at one of this file's extents.
            //
            // It can legitimately sit *before* them: `search_le` returns the
            // last key at or below the target, and for a file whose first
            // extent starts past `offset` — any sparse file, and every file
            // read from byte 0 that begins with a hole — that key belongs to
            // the preceding item, usually this inode's own INODE_REF. Treating
            // that as "no extents exist" zero-fills the entire file, which is
            // exactly what a sparse file's tail data looks like it should do
            // right up until the last few bytes are checked.
            let first_extent = Key::new(inode.objectid, tree::EXTENT_DATA_KEY, 0);
            let covering = if cursor.valid() {
                let key = cursor.key()?;
                if key.objectid == inode.objectid && key.item_type == tree::EXTENT_DATA_KEY {
                    Some(FileExtent::parse(key.offset, cursor.data()?)?)
                } else if key < first_extent {
                    cursor.advance()?;
                    continue;
                } else {
                    None
                }
            } else {
                None
            };

            let extent = match covering {
                // The item starts after `pos`: everything up to it is a gap.
                Some(e) if e.file_offset > pos => {
                    let gap = (e.file_offset - pos).min((want - done) as u64) as usize;
                    buf[done..done + gap].fill(0);
                    done += gap;
                    continue;
                }
                // The item ends at or before `pos`: step forward and re-decide.
                // Without this a short extent followed by a gap would loop.
                Some(e) if e.end() <= pos => {
                    cursor.advance()?;
                    // A file whose last extent ends before its declared size is
                    // sparse at the tail, and the next `advance` leaves the
                    // cursor invalid — handled by the `None` arm next time
                    // round, so there is no special case here.
                    continue;
                }
                Some(e) => e,
                // No item at all from here on: the rest of the range is a hole.
                None => {
                    buf[done..want].fill(0);
                    done = want;
                    break;
                }
            };

            let within = pos - extent.file_offset;
            let available = extent.num_bytes - within;
            let take = available.min((want - done) as u64) as usize;
            let out = &mut buf[done..done + take];

            if extent.is_zeros() {
                out.fill(0);
            } else if extent.is_compressed() {
                // Compression is per *extent*, so serving any part of one means
                // decompressing all of it — bounded at 128 KiB by btrfs itself.
                // A sequential reader whose chunks are smaller than an extent
                // will therefore decompress the same extent more than once;
                // acceptable, and noted rather than cached, because the reads
                // that matter are far larger than 128 KiB.
                let plain = self.decompress_extent(&extent)?;
                let start = (extent.offset + within) as usize;
                let end = start
                    .checked_add(take)
                    .filter(|e| *e <= plain.len())
                    .ok_or(LuksError::CorruptFs(
                        "btrfs compressed extent is shorter than the range it covers",
                    ))?;
                out.copy_from_slice(&plain[start..end]);
            } else if let Some(inline) = &extent.inline {
                let start = (extent.offset + within) as usize;
                let end = start
                    .checked_add(take)
                    .filter(|e| *e <= inline.len())
                    .ok_or(LuksError::CorruptFs("btrfs inline extent is too short"))?;
                out.copy_from_slice(&inline[start..end]);
            } else {
                // `offset` is where this item's range begins inside the extent
                // it points at — non-zero when a later write split an extent
                // rather than replacing it. Dropping it reads the right extent
                // at the wrong place, which returns plausible file data from
                // the wrong part of the file.
                let start = extent.offset + within;
                if start + take as u64 > extent.disk_num_bytes {
                    return Err(LuksError::CorruptFs(
                        "btrfs extent range falls outside the allocated extent",
                    ));
                }
                // `read_data`, not `read_logical`: file contents go through
                // the checksum tree. This is the difference between "we copied
                // the bytes that were there" and "we copied the bytes that
                // were written", which on a failing drive is the whole point.
                self.read_data(extent.disk_bytenr + start, out)?;
            }

            done += take;
            if pos + take as u64 >= extent.end() {
                cursor.advance()?;
            }
        }
        Ok(done)
    }

    /// Decompress a whole compressed extent, inline or not.
    fn decompress_extent(&self, extent: &FileExtent) -> Result<Vec<u8>> {
        let expected = extent.ram_bytes as usize;
        match &extent.inline {
            // An inline extent can be compressed too: the leaf holds the
            // compressed bytes and `ram_bytes` the size they expand to.
            Some(payload) => super::compress::decompress(
                extent.compression,
                payload,
                expected,
                self.sector_size(),
            ),
            None => {
                let mut raw = vec![0u8; extent.disk_num_bytes as usize];
                // Checksums cover the *compressed* bytes as they sit on disk,
                // so this verifies before decompressing — which also means a
                // corrupt extent is reported as corrupt rather than as a
                // decompression failure, and the decompressor is never fed
                // bytes the filesystem already knows are wrong.
                self.read_data(extent.disk_bytenr, &mut raw)?;
                super::compress::decompress(
                    extent.compression,
                    &raw,
                    expected,
                    self.sector_size(),
                )
            }
        }
    }

    /// Every extent item of a file, in order. Mostly useful for tests and for
    /// explaining what a file is made of.
    pub fn file_extents(&self, tree: u64, objectid: u64) -> Result<Vec<FileExtent>> {
        let mut out = Vec::new();
        let mut failure = None;
        self.for_each_item(tree, objectid, tree::EXTENT_DATA_KEY, &mut |key, data| {
            match FileExtent::parse(key.offset, data) {
                Ok(e) => {
                    out.push(e);
                    Ok(true)
                }
                Err(e) => {
                    failure = Some(e);
                    Ok(false)
                }
            }
        })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    // --- convenience over the top level -------------------------------------
    //
    // Each of these resolves the path and then reads through the tree that came
    // back with it, never through `fs_tree()`. On a path that crosses into a
    // subvolume those are different trees, and using the latter would read the
    // right inode number out of the wrong filesystem.

    /// Read a whole file.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let found = self.resolve_no_follow(self.fs_tree(), path)?;
        if found.inode.file_type().is_dir() {
            return Err(LuksError::IsADirectory(path.to_string()));
        }
        let mut out = vec![0u8; found.inode.size as usize];
        let n = self.read_inode_data(found.tree.bytenr, &found.inode, 0, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Read part of a file.
    pub fn read_chunk(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let found = self.resolve_no_follow(self.fs_tree(), path)?;
        self.read_inode_data(found.tree.bytenr, &found.inode, offset, buf)
    }

    /// A symlink's target.
    ///
    /// Stored exactly like file contents, which is why this could not exist
    /// before the extent reader did.
    pub fn read_link(&self, path: &str) -> Result<String> {
        let found = self.resolve_no_follow(self.fs_tree(), path)?;
        if found.inode.file_type() != crate::fs::FileType::Symlink {
            return Err(LuksError::NotFound(format!("{path} is not a symlink")));
        }
        let mut out = vec![0u8; found.inode.size as usize];
        let n = self.read_inode_data(found.tree.bytenr, &found.inode, 0, &mut out)?;
        out.truncate(n);
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}
