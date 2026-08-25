//! Read-only btrfs reader.
//!
//! btrfs is not ext4 with different field names. The structural difference that
//! shapes this whole module is **indirection**: an ext4 inode names physical
//! block numbers, whereas every btrfs pointer is a *logical* address that has
//! to be translated through the chunk tree before it can be read. So the reader
//! is built bottom-up in that order:
//!
//! 1. [`superblock`] — geometry, feature gate, and the address of the chunk
//!    tree. Bootstrapped from a fixed offset, the only physical address on the
//!    whole filesystem.
//! 2. chunk tree — logical to physical. Itself reached through the superblock's
//!    embedded `sys_chunk_array`, which exists precisely to break the
//!    circularity of needing the chunk tree to find the chunk tree.
//! 3. root tree, then the fs trees — B-trees of `(key, item)` pairs.
//! 4. `EXTENT_DATA` items — file contents, inline or out of line, and
//!    optionally compressed.
//!
//! Only steps 1 and 2 exist so far.
//!
//! **Read-only means much of btrfs is simply not our problem.** The extent tree,
//! the free-space tree, the block-group tree and the back-references all exist
//! to make *allocation* work. A reader never consults them, which is why
//! several incompat flags that sound alarming are safe to accept.

mod cache;
pub mod chunk;
pub mod compress;
pub mod csum;
pub mod crc32c;
pub mod cursor;
pub mod dir;
pub mod extent;
pub mod inode;
pub mod subvol;
pub mod superblock;
pub mod tree;
#[cfg(feature = "dangerous-write-support")]
pub mod write;

pub use chunk::{Chunk, ChunkMap, DevExtent, Stripe};
pub use csum::Verified;
pub use cursor::Cursor;
pub use dir::Located;
pub use extent::{ExtentKind, FileExtent};
pub use inode::{DirEntryItem, Inode};
pub use subvol::Subvolume;
pub use superblock::{CsumType, Superblock};
pub use tree::{Key, Node};

use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// A tree deeper than this is corrupt: btrfs's own limit is 8 levels, and a
/// node's level must drop by exactly one per descent, so this doubles as the
/// termination proof for the walk below.
const MAX_LEVEL: u8 = 8;

/// Where one tree lives, from its `ROOT_ITEM`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeRoot {
    /// The tree's own id — 5 for the top level, 256 and up for a subvolume.
    pub objectid: u64,
    /// Logical address of the root node.
    pub bytenr: u64,
    pub level: u8,
    /// Objectid of this tree's root directory — 256 for any fs tree.
    pub root_dirid: u64,
    pub generation: u64,
    /// `btrfs_root_item.flags`. Only bit 0 means anything to a reader.
    pub flags: u64,
}

/// `BTRFS_ROOT_SUBVOL_RDONLY`.
const ROOT_SUBVOL_RDONLY: u64 = 1;

impl TreeRoot {
    /// Whether this subvolume is marked read-only — which is what a snapshot
    /// taken with `-r` is, and what every entry under openSUSE's `.snapshots`
    /// looks like.
    ///
    /// Informational only here: the whole reader is read-only regardless. It
    /// exists so the UI can say *why* a directory cannot be written to once
    /// there is anything that writes.
    pub fn is_read_only(&self) -> bool {
        self.flags & ROOT_SUBVOL_RDONLY != 0
    }
}

/// A mounted, read-only btrfs filesystem.
///
/// Owns its device, like [`crate::fs::Ext4`], so a JNI handle can hold the
/// whole stack. The blanket `impl ReadAt for &D` means `Btrfs::mount(&volume)`
/// still works.
pub struct Btrfs<D: ReadAt> {
    device: D,
    sb: Superblock,
    chunks: ChunkMap,
    /// Resolved once at mount. Every path operation needs it, and looking it up
    /// each time costs a root-tree search — two device reads before any real
    /// work, on a link where round trips are the whole cost.
    fs_tree: TreeRoot,
    /// Same reasoning, and it matters more: every data read consults this.
    /// `None` on a filesystem that keeps no data checksums.
    csum_tree: Option<TreeRoot>,
    /// Tree nodes already read and verified. See [`cache`] for the measurement
    /// that put it here — six metadata reads per data read, all of them
    /// re-descending the same two trees.
    nodes: cache::NodeCache,
    #[cfg(feature = "dangerous-write-support")]
    pub(crate) active_batch: Option<write::Batch>,
}

impl<D: ReadAt> Btrfs<D> {
    /// Find the newest valid superblock, then build the logical-to-physical
    /// map without which nothing else on the filesystem can be read.
    pub fn mount(device: D) -> Result<Self> {
        let sb = Superblock::find(&device)?;

        // A non-empty log tree means this filesystem was not unmounted
        // cleanly — a yanked drive, a crash, a phone that pulled the cable.
        // The newest writes live in that tree and **not** in the trees this
        // reader walks, so mounting anyway would show a filesystem as it was
        // some time before the interruption: files missing, or holding their
        // previous contents, with every checksum verifying.
        //
        // Replaying the log is a write operation and out of scope by design.
        // Refusing matches what ext4 already does with a dirty journal
        // (`INCOMPAT_RECOVER`), and for the same reason: silently handing back
        // stale data is worse than saying no. If the rescue case ever needs an
        // "I know, show me anyway" override, it belongs at the UI layer where
        // a person can consent to it, not as a default here.
        if sb.log_root != 0 {
            return Err(LuksError::FsNeedsRecovery);
        }

        let chunks = ChunkMap::bootstrap(&sb)?;
        let nodes = cache::NodeCache::new(sb.node_size);
        let mut fs = Btrfs {
            device,
            sb,
            chunks,
            nodes,
            // Placeholder: resolving it needs the chunk map that the next two
            // lines build. Nothing reads it in between.
            fs_tree: TreeRoot::default(),
            csum_tree: None,
            #[cfg(feature = "dangerous-write-support")]
            active_batch: None,
        };
        fs.load_chunk_tree()?;
        fs.chunks.check_single_device(fs.sb.dev_id)?;
        fs.fs_tree = fs.tree_root(tree::FS_TREE_OBJECTID)?;
        fs.csum_tree = csum::load(&fs);
        Ok(fs)
    }

    /// Replace the bootstrap map with the real one.
    ///
    /// The bootstrap map covers the chunk tree and, on a filesystem of any
    /// size, very little else — it is capped at 2 KiB of superblock space.
    /// Reading the chunk tree through it and adding every `CHUNK_ITEM` found is
    /// what makes the rest of the address space addressable.
    fn load_chunk_tree(&mut self) -> Result<()> {
        let mut found = Vec::new();
        self.walk_tree(self.sb.chunk_root, &mut |key, data| {
            if key.item_type == tree::CHUNK_ITEM_KEY
                && key.objectid == tree::FIRST_CHUNK_TREE_OBJECTID
            {
                found.push(Chunk::parse(key.offset, data)?);
            }
            Ok(())
        })?;

        if found.is_empty() {
            return Err(LuksError::CorruptFs("btrfs chunk tree holds no chunks"));
        }
        for chunk in found {
            self.chunks.insert(chunk);
        }
        Ok(())
    }

    // --- logical addressing -------------------------------------------------

    /// Read `buf.len()` bytes starting at logical address `logical`.
    ///
    /// A request may span chunks, so this loops — but the chunk map hands back
    /// a run length, and chunks are at least 8 MiB, so in practice this is one
    /// device read.
    pub fn read_logical(&self, logical: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let (physical, run) = self.chunks.map(logical + done as u64)?;
            let take = (buf.len() - done).min(run as usize);
            self.device
                .read_at(physical, &mut buf[done..done + take])?;
            done += take;
        }
        Ok(())
    }

    /// Read and verify the tree node at logical address `logical`.
    ///
    /// Served from the node cache when possible. A tree descent touches one
    /// node per level and every descent starts at the same root, so without the
    /// cache the top of each tree is re-read once per operation — which
    /// measured as 88% of all device reads on a large file. See [`cache`].
    pub fn read_node(&self, logical: u64) -> Result<Node> {
        if let Some(node) = self.nodes.get(logical) {
            return Ok(node);
        }
        // Node reads are always node_size, whatever the caller wants out of
        // them, because the checksum covers the whole block.
        let mut raw = vec![0u8; self.sb.node_size as usize];
        self.read_logical(logical, &mut raw)?;
        let node = Node::parse(raw, logical, self.sb.csum_type, &self.sb.metadata_uuid)?;
        self.nodes.insert(logical, &node);
        Ok(node)
    }

    /// Node-cache hits and misses since mount.
    ///
    /// Exposed so a diagnostic can show the hit rate rather than leaving it to
    /// be inferred from a device read count, which mixes metadata with data.
    pub fn node_cache_stats(&self) -> (u64, u64) {
        self.nodes.stats()
    }

    /// Visit every item in the tree rooted at `root`, in key order.
    ///
    /// Termination is structural rather than by a visit counter: each descent
    /// must drop the level by exactly one, and the root's level is bounded, so
    /// a corrupt tree pointing a node back at an ancestor is rejected instead
    /// of looping.
    pub fn walk_tree(
        &self,
        root: u64,
        visit: &mut dyn FnMut(Key, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let node = self.read_node(root)?;
        if node.level > MAX_LEVEL {
            return Err(LuksError::CorruptFs("btrfs tree is implausibly deep"));
        }
        self.walk_node(node, visit)
    }

    fn walk_node(
        &self,
        node: Node,
        visit: &mut dyn FnMut(Key, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if node.is_leaf() {
            for i in 0..node.nr_items {
                visit(node.key(i)?, node.item_data(i)?)?;
            }
            return Ok(());
        }

        for i in 0..node.nr_items {
            let ptr = node.key_ptr(i)?;
            let child = self.read_node(ptr.blockptr)?;
            if child.level + 1 != node.level {
                return Err(LuksError::CorruptFs(
                    "btrfs child node is not one level below its parent",
                ));
            }
            self.walk_node(child, visit)?;
        }
        Ok(())
    }

    // --- tree roots ---------------------------------------------------------

    /// Where the tree with this objectid is rooted, from its `ROOT_ITEM` in the
    /// root tree.
    ///
    /// Field offsets inside `btrfs_root_item` were read off the real item and
    /// cross-checked against dump-tree: the 160-byte inode item comes first,
    /// then generation, `root_dirid`, and `bytenr` at 176. `flags` is at 208 and
    /// `level` sits at 238, past a `drop_progress` key that is easy to miscount.
    ///
    /// **The key's offset is not always zero.** For an ordinary subvolume it is,
    /// but a *snapshot* is filed under the transid it was taken at —
    /// `(259 ROOT_ITEM 7)` in the subvol fixture. An exact-match lookup at
    /// offset 0 therefore reports a perfectly healthy snapshot as a corrupt
    /// filesystem, which is what this code did until a fixture with a snapshot
    /// in it existed. Searching backwards from `u64::MAX` and taking the last
    /// item for this objectid is what the kernel does, and it picks the newest
    /// root when there is more than one.
    pub fn tree_root(&self, objectid: u64) -> Result<TreeRoot> {
        let key = Key::new(objectid, tree::ROOT_ITEM_KEY, u64::MAX);
        let cursor = self.search_le(self.sb.root, &key)?;

        // A tree named in the superblock but absent from the root tree is
        // corruption, not an empty filesystem.
        let missing = || LuksError::CorruptFs("btrfs root item is missing");
        if !cursor.valid() {
            return Err(missing());
        }
        let found = cursor.key()?;
        if found.objectid != objectid || found.item_type != tree::ROOT_ITEM_KEY {
            return Err(missing());
        }
        let data = cursor.data()?;

        if data.len() < 239 {
            return Err(LuksError::CorruptFs("btrfs root item truncated"));
        }
        Ok(TreeRoot {
            objectid,
            bytenr: u64::from_le_bytes(data[176..184].try_into().unwrap()),
            level: data[238],
            root_dirid: u64::from_le_bytes(data[168..176].try_into().unwrap()),
            generation: u64::from_le_bytes(data[160..168].try_into().unwrap()),
            flags: u64::from_le_bytes(data[208..216].try_into().unwrap()),
        })
    }

    /// The top-level tree — where browsing starts.
    ///
    /// This is FS_TREE (id 5), which is what the kernel shows for a mount with
    /// `subvol=/`, and every subvolume is reachable from it by path because
    /// resolution crosses subvolume boundaries. Starting at
    /// [`default_subvolume`](Self::default_subvolume) instead would match a
    /// plain `mount` but hide everything outside it — on openSUSE the default
    /// is a snapshot several levels down, and choosing it would make the live
    /// filesystem unbrowsable.
    pub fn fs_tree(&self) -> TreeRoot {
        self.fs_tree
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    pub fn chunk_map(&self) -> &ChunkMap {
        &self.chunks
    }

    #[cfg(feature = "dangerous-write-support")]
    pub fn chunk_map_mut(&mut self) -> &mut ChunkMap {
        &mut self.chunks
    }

    pub fn label(&self) -> &str {
        &self.sb.label
    }

    pub fn fsid(&self) -> [u8; 16] {
        self.sb.fsid
    }

    /// Chunk tree UUID from the chunk tree root node.
    pub fn chunk_tree_uuid(&self) -> Result<[u8; 16]> {
        let node = self.read_node(self.sb.chunk_root)?;
        Ok(node.chunk_tree_uuid())
    }

    pub fn sector_size(&self) -> u32 {
        self.sb.sector_size
    }

    pub fn node_size(&self) -> u32 {
        self.sb.node_size
    }

    /// The underlying device, for layers that need to read past this one.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Mutable access to the underlying device for writer operations.
    #[cfg(feature = "dangerous-write-support")]
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Update the in-memory mount state (superblock and root trees) after a committed transaction,
    /// invalidating the node cache.
    #[cfg(feature = "dangerous-write-support")]
    pub fn update_mount_state(&mut self, sb: Superblock, fs_tree: TreeRoot) {
        self.sb = sb;
        self.fs_tree = fs_tree;
        self.nodes.clear();
        self.csum_tree = self.tree_root(tree::CSUM_TREE_OBJECTID).ok();
    }

    /// Read all `DEV_EXTENT` items for `devid` from the `DEV_TREE`.
    #[cfg(feature = "dangerous-write-support")]
    pub fn read_dev_extents(&self, devid: u64) -> Result<Vec<(u64, u64)>> {
        write::chunk_alloc::read_dev_extents(self, devid)
    }

    /// Filesystem capacity and allocation statistics.
    pub fn statfs(&self) -> Result<crate::fs::StatFs> {
        let total_bytes = self.sb.total_bytes;
        let sector_size = self.sb.sector_size;

        #[cfg(feature = "dangerous-write-support")]
        {
            let detailed_stat = (|| -> Result<crate::fs::StatFs> {
                let extent_tree = write::extent_tree::ExtentTree::read(self)?;
                let free_space_map = write::alloc::FreeSpaceMap::from_extent_tree_and_chunk_map(
                    &extent_tree,
                    self.chunk_map(),
                )?;

                let mut free_data = 0u64;
                let mut free_metadata = 0u64;
                let mut free_system = 0u64;

                for bg in &free_space_map.block_groups {
                    let flags = bg.block_group.flags;
                    if flags & 0x1 != 0 {
                        // DATA
                        free_data = free_data.saturating_add(bg.total_free_bytes);
                    }
                    if flags & 0x4 != 0 {
                        // METADATA
                        free_metadata = free_metadata.saturating_add(bg.total_free_bytes);
                    }
                    if flags & 0x2 != 0 {
                        // SYSTEM
                        free_system = free_system.saturating_add(bg.total_free_bytes);
                    }
                }

                // Unallocated device space
                let dev_extents = write::chunk_alloc::read_dev_extents(self, self.sb.dev_id).unwrap_or_default();
                let allocated_dev_bytes: u64 = dev_extents.iter().map(|(_, len)| *len).sum();
                let unalloc_dev_bytes = total_bytes
                    .saturating_sub(write::chunk_alloc::BTRFS_BLOCK_RESERVED_1M_FOR_SUPER)
                    .saturating_sub(allocated_dev_bytes);

                let allocatable_unalloc_dev_bytes = (unalloc_dev_bytes / (64 * 1024)) * (64 * 1024);

                let total_free_data = free_data.saturating_add(allocatable_unalloc_dev_bytes);

                // Metadata headroom:
                // In btrfs, each 4 KiB data sector needs 4 bytes of csum, plus extent item & extent data items.
                // Cost ratio: ~ 1 metadata byte per 256 data bytes.
                // When free_metadata < 512 KiB, compute available bytes proportionally without clamping to 0.
                let max_data_from_metadata = if free_metadata >= 512 * 1024 {
                    let excess = free_metadata - 512 * 1024;
                    (256 * 1024 * 256) + excess.saturating_mul(256)
                } else {
                    (free_metadata / 2).saturating_mul(256)
                };

                let data_safety_margin = 64 * 1024;
                let raw_available = total_free_data.min(max_data_from_metadata);
                let available_bytes = if raw_available > data_safety_margin {
                    raw_available - data_safety_margin
                } else {
                    raw_available
                };

                let total_free = total_free_data.min(total_bytes);

                Ok(crate::fs::StatFs {
                    total_bytes,
                    free_bytes: total_free,
                    available_bytes: available_bytes.min(total_free),
                    total_inodes: 0,
                    free_inodes: 0,
                    block_size: sector_size,
                })
            })();

            if let Ok(stat) = detailed_stat {
                return Ok(stat);
            }

            let free_bytes = total_bytes.saturating_sub(self.sb.bytes_used);
            Ok(crate::fs::StatFs {
                total_bytes,
                free_bytes,
                available_bytes: free_bytes,
                total_inodes: 0,
                free_inodes: 0,
                block_size: sector_size,
            })
        }

        #[cfg(not(feature = "dangerous-write-support"))]
        {
            let free_bytes = total_bytes.saturating_sub(self.sb.bytes_used);
            Ok(crate::fs::StatFs {
                total_bytes,
                free_bytes,
                available_bytes: free_bytes,
                total_inodes: 0,
                free_inodes: 0,
                block_size: sector_size,
            })
        }
    }
}
