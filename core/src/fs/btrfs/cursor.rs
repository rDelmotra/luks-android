//! Searching a btrfs tree, rather than reading all of it.
//!
//! [`super::Btrfs::walk_tree`] visits every item, which is right for the chunk
//! tree — a few dozen items that all have to be collected anyway. It is
//! catastrophically wrong for anything else. The fs tree on the developer's
//! A large drive holds millions of items across gigabytes of nodes; listing one
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

        while !node.is_leaf() && node.nr_items > 0 {
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

    /// Position at the last item whose key is <= `key`.
    ///
    /// The counterpart to [`Cursor::search`], and the one a file read needs:
    /// extents are keyed by the file offset they *start* at, so the extent
    /// covering byte 5000 is filed under some smaller offset and an
    /// equal-or-greater search would sail straight past it. Reading from the
    /// middle of a file is the common case — every chunk after the first — so
    /// getting this wrong would return zeros for most of a large file.
    ///
    /// Leaves the cursor invalid if every key in the tree is greater.
    pub fn search_le(fs: &'a Btrfs<D>, root: u64, key: &Key) -> Result<Self> {
        let mut cursor = Cursor::search(fs, root, key)?;
        if cursor.valid() && cursor.key()? == *key {
            return Ok(cursor);
        }
        // `search` left us on the first key strictly greater than the target
        // (or past the end), so the answer is one step back either way.
        cursor.retreat()?;
        Ok(cursor)
    }

    /// Step back one item in key order, crossing into the previous leaf when
    /// this one is exhausted.
    ///
    /// `pub(crate)` rather than private: `find_max_inode` in
    /// `write/txn.rs` needs to walk backwards past a run of reserved-objectid
    /// items (e.g. `ORPHAN_OBJECTID`) that can occupy the tail of the
    /// rightmost leaf, and `search_le` alone only steps back once.
    pub(crate) fn retreat(&mut self) -> Result<()> {
        let last = self.path.len() - 1;
        let (_, i) = &mut self.path[last];
        if *i > 0 {
            *i -= 1;
            return Ok(());
        }
        self.retreat_leaf()
    }

    /// Move to the last item of the previous leaf, mirroring [`advance_leaf`].
    fn retreat_leaf(&mut self) -> Result<()> {
        loop {
            if self.path.len() == 1 {
                // Nothing precedes the first item. Park past the end of the
                // leaf so `valid()` reports false rather than pointing at the
                // wrong item.
                let (node, i) = &mut self.path[0];
                *i = node.nr_items;
                return Ok(());
            }
            self.path.pop();

            let last = self.path.len() - 1;
            let (node, i) = &mut self.path[last];
            if *i == 0 {
                continue;
            }
            *i -= 1;

            // Descend rightmost from here.
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
                if child.nr_items == 0 {
                    return Err(LuksError::CorruptFs("btrfs node has no items"));
                }
                let last_index = child.nr_items - 1;
                let leaf = child.is_leaf();
                let next = if leaf {
                    0
                } else {
                    child.key_ptr(last_index)?.blockptr
                };
                self.path.push((child, last_index));
                if leaf {
                    return Ok(());
                }
                ptr = next;
            }
        }
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
    ///
    /// The climb is a read-only probe over `self.path` first, and only
    /// mutates the path once a usable ancestor is actually found. An earlier
    /// version popped path entries while probing and committed each pop
    /// immediately, so a probe that ran off the very end of a multi-level
    /// tree left `self.path` holding only interior-node frames — the leaf
    /// frame `lower_bound` had parked past-the-end was gone, popped and
    /// never restored. `valid()` still reported false by coincidence (it
    /// only compares the deepest index against the deepest node's item
    /// count, whichever node that is), but `retreat()` then read that
    /// interior node as if it were a leaf: decrementing a *child* index and
    /// calling `key()` on it returns the child's lowest key, not an error —
    /// silently wrong rather than merely invalid. Caught by
    /// `write/txn.rs`'s `find_max_inode`, the first caller to `search_le` a
    /// key past every real key in a tree with more than one leaf: measured
    /// returning the wrong-but-plausible-looking objectid 263249 (the
    /// rightmost leaf's *first* key) instead of retreating properly to
    /// 263276 (the true last key) on `fixtures/btrfs/plain.img`.
    fn advance_leaf(&mut self) -> Result<()> {
        let leaf_idx = self.path.len() - 1;
        let mut climb_to = None;
        for idx in (0..leaf_idx).rev() {
            let (node, i) = &self.path[idx];
            if *i + 1 < node.nr_items {
                climb_to = Some(idx);
                break;
            }
        }
        let last = match climb_to {
            Some(idx) => idx,
            // No ancestor has an unvisited child: end of tree. `self.path`
            // was never touched, so it is still exactly the leaf-terminated,
            // past-the-end state `search()` left it in.
            None => return Ok(()),
        };

        self.path.truncate(last + 1);
        let (node, i) = &mut self.path[last];
        *i += 1;

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

impl<D: ReadAt> Btrfs<D> {
    /// Position a cursor in the tree rooted at `root`.
    pub fn search(&self, root: u64, key: &Key) -> Result<Cursor<'_, D>> {
        Cursor::search(self, root, key)
    }

    /// Position a cursor at the last item at or before `key`.
    pub fn search_le(&self, root: u64, key: &Key) -> Result<Cursor<'_, D>> {
        Cursor::search_le(self, root, key)
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
