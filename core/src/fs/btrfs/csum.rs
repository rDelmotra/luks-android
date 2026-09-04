//! Verifying file *data* against the checksum tree.
//!
//! This is the guarantee btrfs offers that ext4 cannot, and the reason it is
//! worth having in a tool whose job is getting data off a drive that may be
//! failing. Without it, a bit rotted on the platter comes back as a byte that
//! is simply wrong: the copy succeeds, the size matches, and nothing anywhere
//! says the file is not what was written. With it, that read fails loudly.
//!
//! **Metadata was already covered — this is only about file contents.** Every
//! tree node carries its own checksum and [`Node::parse`](super::tree::Node)
//! has always enforced it. Data lives outside the trees, so its checksums are
//! kept in a tree of their own.
//!
//! The layout is unlike everything else here. `EXTENT_CSUM` items are not
//! filed under an inode or a file offset; they are filed under the **disk
//! address** the data occupies, in one shared tree:
//!
//! ```text
//! key (EXTENT_CSUM_OBJECTID, EXTENT_CSUM, disk_bytenr)
//!   -> [csum][csum][csum]...   one per sector, contiguously from disk_bytenr
//! ```
//!
//! Which follows from how btrfs works: an extent can be shared by a hundred
//! snapshots, and its bytes are the same bytes for all of them, so the checksum
//! belongs to the location rather than to any one file that references it.
//!
//! **Absence is not corruption.** A file created with `chattr +C` (nodatacow)
//! has no checksums at all, and neither does a preallocated extent that was
//! never written. So a missing checksum means *unverified*, never *bad* — this
//! module reports which, and refuses to turn one into the other.

use super::tree;
use super::{Btrfs, Key, TreeRoot};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// What a verification actually established.
///
/// Distinguished rather than collapsed to a `bool`, because "every byte
/// checked out" and "there was nothing to check against" are very different
/// things to tell someone rescuing data, and collapsing them would mean the
/// reassuring answer covering for the silent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// Every sector had a checksum and every checksum matched.
    All,
    /// No checksum exists for at least one sector. Whatever was checked
    /// matched, but this data is not covered.
    Partial { unchecked_sectors: usize },
    /// The filesystem keeps no data checksums at all.
    NoChecksumTree,
}

impl Verified {
    /// Whether every byte was covered by a checksum that matched.
    pub fn is_complete(self) -> bool {
        self == Verified::All
    }
}

impl<D: ReadAt> Btrfs<D> {
    /// Read `buf.len()` bytes of **file data** from logical address `logical`,
    /// verifying every sector it touches.
    ///
    /// Checksums cover whole sectors, so a read that starts or ends mid-sector
    /// cannot be verified from its own bytes alone. Rather than leave those
    /// edges unchecked — which would mean the first and last sector of every
    /// unaligned read going unverified, and those are most reads — the covering
    /// sector range is read and checked, and the requested slice copied out of
    /// it. The aligned case, which is every large sequential read, still goes
    /// straight into the caller's buffer with no copy.
    pub fn read_data(&self, logical: u64, buf: &mut [u8]) -> Result<Verified> {
        let sector = self.sector_size() as u64;
        let aligned_start = logical - (logical % sector);
        let end = logical + buf.len() as u64;
        let aligned_end = end.div_ceil(sector) * sector;

        if aligned_start == logical && aligned_end == end {
            self.read_logical(logical, buf)?;
            return self.verify_data(logical, buf);
        }

        let mut whole = vec![0u8; (aligned_end - aligned_start) as usize];
        self.read_logical(aligned_start, &mut whole)?;
        let outcome = self.verify_data(aligned_start, &whole)?;
        let from = (logical - aligned_start) as usize;
        buf.copy_from_slice(&whole[from..from + buf.len()]);
        Ok(outcome)
    }

    /// Check already-read data against the checksum tree.
    ///
    /// `logical` must be sector-aligned and `data` a whole number of sectors —
    /// a checksum covers a sector, so anything else cannot be checked.
    pub fn verify_data(&self, logical: u64, data: &[u8]) -> Result<Verified> {
        let Some(csum_root) = self.csum_tree() else {
            return Ok(Verified::NoChecksumTree);
        };
        let sector = self.sector_size() as usize;
        if sector == 0 || !logical.is_multiple_of(sector as u64) || !data.len().is_multiple_of(sector) {
            return Err(LuksError::CorruptFs(
                "btrfs data checksum asked for a range that is not whole sectors",
            ));
        }

        let width = self.superblock().csum_type.size();
        let mut unchecked = 0usize;

        // One cursor for the whole range. Checksums for consecutive sectors sit
        // in one item, and consecutive items sort next to each other, so a
        // multi-megabyte read walks forward through a handful of leaves rather
        // than searching the tree per sector.
        let mut cursor = self.search_le(
            csum_root.bytenr,
            &Key::new(tree::EXTENT_CSUM_OBJECTID, tree::EXTENT_CSUM_KEY, logical),
        )?;

        for (i, chunk) in data.chunks_exact(sector).enumerate() {
            let target = logical + (i * sector) as u64;

            // Walk forward until the item under the cursor could cover
            // `target`. `search_le` may also have landed *before* the csum
            // items entirely, on some other objectid, which this same loop
            // steps past.
            loop {
                if !cursor.valid() {
                    break;
                }
                let key = cursor.key()?;
                if key.objectid != tree::EXTENT_CSUM_OBJECTID
                    || key.item_type != tree::EXTENT_CSUM_KEY
                {
                    // Before the run: step in. After it: nothing more to find.
                    if key < Key::new(tree::EXTENT_CSUM_OBJECTID, tree::EXTENT_CSUM_KEY, 0) {
                        cursor.advance()?;
                        continue;
                    }
                    break;
                }
                let covered = (cursor.data()?.len() / width) as u64 * sector as u64;
                if key.offset + covered <= target {
                    cursor.advance()?;
                    continue;
                }
                break;
            }

            let Some(stored) = self.csum_at(&cursor, target, width, sector)? else {
                // No checksum covers this sector: nodatacow, or an extent that
                // was allocated and never written. Not an error, and not
                // something to quietly call verified either.
                unchecked += 1;
                continue;
            };

            if !self.superblock().csum_type.verify(stored, chunk) {
                return Err(LuksError::FsChecksumMismatch("btrfs file data"));
            }
        }

        Ok(match unchecked {
            0 => Verified::All,
            n => Verified::Partial {
                unchecked_sectors: n,
            },
        })
    }

    /// The stored checksum for the sector at `target`, if the item under the
    /// cursor holds one.
    fn csum_at<'c>(
        &self,
        cursor: &'c super::Cursor<'_, D>,
        target: u64,
        width: usize,
        sector: usize,
    ) -> Result<Option<&'c [u8]>> {
        if !cursor.valid() {
            return Ok(None);
        }
        let key = cursor.key()?;
        if key.objectid != tree::EXTENT_CSUM_OBJECTID
            || key.item_type != tree::EXTENT_CSUM_KEY
            || key.offset > target
        {
            return Ok(None);
        }
        let data = cursor.data()?;
        let index = ((target - key.offset) / sector as u64) as usize;
        let at = index * width;
        if at + width > data.len() {
            return Ok(None);
        }
        Ok(Some(&data[at..at + width]))
    }

    /// Where the checksum tree lives, or `None` on a filesystem that keeps
    /// none.
    pub fn csum_tree(&self) -> Option<TreeRoot> {
        self.csum_tree
    }
}

/// Resolved once at mount by [`Btrfs::mount`].
pub(super) fn load<D: ReadAt>(fs: &Btrfs<D>) -> Option<TreeRoot> {
    // A filesystem without a checksum tree is unusual but legal — every file
    // on it is simply unverifiable. Treating a missing root as "no checksums"
    // rather than as corruption keeps such a drive readable, which for a
    // rescue tool is the right trade as long as the reads are reported as
    // unverified, which `Verified::NoChecksumTree` does.
    fs.tree_root(tree::CSUM_TREE_OBJECTID).ok()
}
