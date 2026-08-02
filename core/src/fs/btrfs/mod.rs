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

pub mod chunk;
pub mod crc32c;
pub mod superblock;
pub mod tree;

pub use chunk::{Chunk, ChunkMap};
pub use superblock::{CsumType, Superblock};
pub use tree::{Key, Node};

use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// A tree deeper than this is corrupt: btrfs's own limit is 8 levels, and a
/// node's level must drop by exactly one per descent, so this doubles as the
/// termination proof for the walk below.
const MAX_LEVEL: u8 = 8;

/// A mounted, read-only btrfs filesystem.
///
/// Owns its device, like [`crate::fs::Ext4`], so a JNI handle can hold the
/// whole stack. The blanket `impl ReadAt for &D` means `Btrfs::mount(&volume)`
/// still works.
pub struct Btrfs<D: ReadAt> {
    device: D,
    sb: Superblock,
    chunks: ChunkMap,
}

impl<D: ReadAt> Btrfs<D> {
    /// Find the newest valid superblock, then build the logical-to-physical
    /// map without which nothing else on the filesystem can be read.
    pub fn mount(device: D) -> Result<Self> {
        let sb = Superblock::find(&device)?;
        let chunks = ChunkMap::bootstrap(&sb)?;
        let mut fs = Btrfs {
            device,
            sb,
            chunks,
        };
        fs.load_chunk_tree()?;
        fs.chunks.check_single_device(fs.sb.dev_id)?;
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
    pub fn read_node(&self, logical: u64) -> Result<Node> {
        // Node reads are always node_size, whatever the caller wants out of
        // them, because the checksum covers the whole block.
        let mut raw = vec![0u8; self.sb.node_size as usize];
        self.read_logical(logical, &mut raw)?;
        Node::parse(raw, logical, self.sb.csum_type, &self.sb.metadata_uuid)
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

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    pub fn chunk_map(&self) -> &ChunkMap {
        &self.chunks
    }

    pub fn label(&self) -> &str {
        &self.sb.label
    }

    pub fn fsid(&self) -> [u8; 16] {
        self.sb.fsid
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
}
