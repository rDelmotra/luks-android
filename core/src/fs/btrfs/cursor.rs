//! Searching a btrfs tree, rather than reading all of it.
//!
//! [`super::Btrfs::walk_tree`] visits every item, which is right for the chunk
//! tree — a few dozen items that all have to be collected anyway. It is
//! catastrophically wrong for anything else. The fs tree on the developer's
//! 1 TB drive holds millions of items across gigabytes of nodes; listing one
//! directory by walking it would read the whole filesystem over USB, which is
//! the same read-amplification mistake that made the ext4 reader take minutes
//! to hash a single file.
//!
//! A [`Cursor`] descends to one key in `O(log n)` and then steps forward in key
//! order. Every btrfs lookup has that shape, because keys are sorted by
//! `(objectid, type, offset)` and every item belonging to one file therefore
//! sits in one contiguous run: seek to `(inode, 0, 0)`, walk until the objectid
//! changes, stop.
//!
//! The nodes along the path are held, not re-read. A tree is at most 8 levels
//! and a node at most 64 KiB, so a cursor costs half a megabyte in the worst
//! case and saves a device round trip per step.

use super::tree::{Key, Node};
use super::Btrfs;
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// A position in a tree, and the path taken to reach it.
pub struct Cursor<'a, D: ReadAt> {
    fs: &'a Btrfs<D>,
    /// One entry per level, root first. The index is the entry *within* that
    /// node: a child index for interior nodes, an item index for the leaf.
    path: Vec<(Node, usize)>,
}

impl<'a, D: ReadAt> Cursor<'a, D> {
    /// Position at the first item whose key is >= `key`.
    ///
    /// Returns a cursor that may already be past the end, which
    /// [`Cursor::valid`] reports — "no item that large exists" is an ordinary
    /// answer, not an error, and callers scanning a range hit it every time.
    pub fn search(fs: &'a Btrfs<D>, root: u64, key: &Key) -> Result<Self> {
        let mut path = Vec::new();
        let mut node = fs.read_node(root)?;

        while !node.is_leaf() {
            let i = node.child_for(key)?;
            let ptr = node.key_ptr(i)?;
            let child = fs.read_node(ptr.blockptr)?;
            if child.level + 1 != node.level {
                return Err(LuksError::CorruptFs(
                    "btrfs child node is not one level below its parent",
                ));
            }
            path.push((node, i));
            node = child;
        }

        let i = node.lower_bound(key)?;
        path.push((node, i));

        let mut cursor = Cursor { fs, path };
        // `lower_bound` can land one past the end of this leaf when every key
        // in it is smaller than the target. The item wanted is then the first
        // one of the next leaf, so step across rather than reporting nothing —
        // getting this wrong makes a lookup fail only when the key happens to
        // fall on a leaf boundary, which is the kind of bug that survives every
        // small-fixture test.
        if !cursor.valid() {
            cursor.advance_leaf()?;
        }
        Ok(cursor)
    }

    fn leaf(&self) -> &(Node, usize) {
        self.path.last().expect("a cursor always has a leaf")
    }

    /// Whether the cursor points at an item.
    pub fn valid(&self) -> bool {
        let (node, i) = self.leaf();
        *i < node.nr_items
    }

    pub fn key(&self) -> Result<Key> {
        let (node, i) = self.leaf();
        node.key(*i)
    }

    pub fn data(&self) -> Result<&[u8]> {
        let (node, i) = self.leaf();
        node.item_data(*i)
    }

    /// Step to the next item in key order, crossing into the next leaf when
    /// this one runs out.
    pub fn advance(&mut self) -> Result<()> {
        {
            let last = self.path.len() - 1;
            let (node, i) = &mut self.path[last];
            if *i < node.nr_items {
                *i += 1;
            }
        }
        if !self.valid() {
            self.advance_leaf()?;
        }
        Ok(())
    }

    /// Move to the first item of the next leaf.
    ///
    /// Climb until a level has an unvisited child, then descend its leftmost
    /// path. If no level does, the cursor is at the end of the tree and stays
    /// invalid — which is the normal way a range scan finishes.
    fn advance_leaf(&mut self) -> Result<()> {
        loop {
            // Drop the exhausted level. Stopping at length 1 leaves the leaf in
            // place so the cursor stays structurally valid (and `valid()`
            // keeps reporting false) rather than panicking in `leaf()`.
            if self.path.len() == 1 {
                return Ok(());
            }
            self.path.pop();

            let last = self.path.len() - 1;
            let (node, i) = &mut self.path[last];
            *i += 1;
            if *i >= node.nr_items {
                continue;
            }

            // Descend leftmost from here.
            let mut ptr = node.key_ptr(*i)?.blockptr;
            let mut level = node.level;
            loop {
                let child = self.fs.read_node(ptr)?;
                if child.level + 1 != level {
                    return Err(LuksError::CorruptFs(
                        "btrfs child node is not one level below its parent",
                    ));
                }
                level = child.level;
                let leaf = child.is_leaf();
                let next = if leaf { 0 } else { child.key_ptr(0)?.blockptr };
                self.path.push((child, 0));
                if leaf {
                    return Ok(());
                }
                ptr = next;
            }
        }
    }
}

impl<D: ReadAt> Btrfs<D> {
    /// Position a cursor in the tree rooted at `root`.
    pub fn search(&self, root: u64, key: &Key) -> Result<Cursor<'_, D>> {
        Cursor::search(self, root, key)
    }

    /// Find the item with exactly this key, if it exists.
    pub fn find_item(&self, root: u64, key: &Key) -> Result<Option<Vec<u8>>> {
        let cursor = self.search(root, key)?;
        if cursor.valid() && cursor.key()? == *key {
            return Ok(Some(cursor.data()?.to_vec()));
        }
        Ok(None)
    }

    /// Visit every item belonging to `objectid` whose type is `item_type`, in
    /// key order, stopping as soon as the run ends.
    ///
    /// This is the shape of nearly every read: one file's extents, one
    /// directory's entries, one inode's references. Because keys sort by
    /// objectid first and type second, the run is contiguous and the scan stops
    /// at the first key outside it — so the cost is the size of the answer, not
    /// the size of the filesystem.
    pub fn for_each_item(
        &self,
        root: u64,
        objectid: u64,
        item_type: u8,
        visit: &mut dyn FnMut(Key, &[u8]) -> Result<bool>,
    ) -> Result<()> {
        let mut cursor = self.search(root, &Key::new(objectid, item_type, 0))?;
        while cursor.valid() {
            let key = cursor.key()?;
            if key.objectid != objectid || key.item_type != item_type {
                return Ok(());
            }
            if !visit(key, cursor.data()?)? {
                return Ok(());
            }
            cursor.advance()?;
        }
        Ok(())
    }
}
