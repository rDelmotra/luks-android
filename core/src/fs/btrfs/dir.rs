//! Directory listing and path resolution.

use super::crc32c::name_hash;
use super::inode::{parse_dir_entries, DirEntryItem, Inode};
use super::tree;
use super::{Btrfs, Key, TreeRoot};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::{DirEntry, FileInfo};

/// An inode together with the tree it belongs to.
///
/// The pair is the unit of meaning, not the inode. Every fs tree numbers its
/// inodes from 256, so inode 257 exists in each of them and names a different
/// file in each; handing an inode number to a reader without saying which tree
/// it came from is how a path that crosses a subvolume ends up reading someone
/// else's data with a valid checksum. Returning them together makes that
/// mistake impossible to make by accident.
#[derive(Debug, Clone)]
pub struct Located {
    pub tree: TreeRoot,
    pub inode: Inode,
}

impl<D: ReadAt> Btrfs<D> {
    /// Load one inode from the fs tree.
    pub fn read_inode(&self, tree: u64, objectid: u64) -> Result<Inode> {
        let key = Key::new(objectid, tree::INODE_ITEM_KEY, 0);
        let data = self
            .find_item(tree, &key)?
            .ok_or(LuksError::BadInode(objectid))?;
        Inode::parse(objectid, &data)
    }

    /// Every entry in a directory, in creation order.
    ///
    /// Scans `DIR_INDEX` rather than `DIR_ITEM`: both describe the same
    /// entries, but the index is keyed by a sequence number, so the entries sit
    /// in one contiguous key run and come out in a stable order. `DIR_ITEM` is
    /// keyed by name hash, which would give an order that looks arbitrary to a
    /// user and puts colliding names in one packed item for no benefit here.
    pub fn list_dir_by_inode(&self, tree: u64, dir: u64) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        let mut failure = None;

        self.for_each_item(tree, dir, tree::DIR_INDEX_KEY, &mut |_, data| {
            match parse_dir_entries(data) {
                Ok(entries) => {
                    for e in entries {
                        // A subvolume's `location` is a tree id, not an inode
                        // in *this* tree — reading it as one would land on an
                        // unrelated file in this tree that happens to share
                        // the number. Its own size/mtime live in a different
                        // tree entirely, so it is reported as unknown here
                        // rather than fetched, which would need a second
                        // `tree_root` resolution per subvolume entry.
                        //
                        // For an ordinary entry the inode read reuses the
                        // upper levels of the same tree just walked for
                        // `DIR_INDEX`, which the node cache already holds —
                        // so this costs one new leaf read per entry, not a
                        // fresh descent from the root. A read failure (a
                        // dangling or corrupt entry) degrades to zero rather
                        // than failing the whole listing: one bad entry
                        // should not make a directory unbrowsable.
                        let (size, mtime) = if e.is_subvolume() {
                            (0, 0)
                        } else {
                            self.read_inode(tree, e.location.objectid)
                                .map(|inode| (inode.size, inode.mtime))
                                .unwrap_or((0, 0))
                        };
                        out.push(DirEntry {
                            name: e.name_lossy(),
                            // For a subvolume this is a tree id rather than an
                            // inode number — indistinguishable by value, so the
                            // flag beside it is the only thing that says which.
                            inode: e.location.objectid,
                            file_type: e.file_type,
                            is_subvolume: e.is_subvolume(),
                            size,
                            mtime,
                        });
                    }
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

    /// Find one name in a directory, without scanning it.
    ///
    /// The `DIR_ITEM` key's offset *is* the name hash, so this is a single
    /// search. The name still has to be compared afterwards: the key identifies
    /// a hash bucket, not a name, and two names in one directory may share a
    /// bucket.
    pub fn lookup(&self, tree: u64, dir: u64, name: &str) -> Result<Option<DirEntryItem>> {
        let key = Key::new(dir, tree::DIR_ITEM_KEY, name_hash(name.as_bytes()));
        let Some(data) = self.find_item(tree, &key)? else {
            return Ok(None);
        };
        Ok(parse_dir_entries(&data)?
            .into_iter()
            .find(|e| e.name == name.as_bytes()))
    }

    /// Resolve a path to an inode, **without** following a trailing symlink.
    ///
    /// Symlinks are not followed at all, at any position. A path through a
    /// symlinked directory fails with a clear error instead of resolving to
    /// the wrong file — see [`Btrfs::read_link`](crate::fs::Btrfs::read_link)
    /// for reading one deliberately.
    ///
    /// **Subvolume boundaries are crossed**, and the tree comes back with the
    /// inode because of it. A btrfs subvolume is a separate fs tree, so
    /// `/home/user/docs` on a standard Linux install is three components in one tree
    /// and the rest in another; refusing to cross would make most of such a
    /// drive unreachable, and crossing without saying so would leave the caller
    /// holding an inode number it would resolve against the wrong tree.
    ///
    /// This is what the kernel shows for a plain `mount` with `subvol=/`:
    /// subvolumes appear as ordinary directories you can walk into.
    pub fn resolve_no_follow(&self, start: TreeRoot, path: &str) -> Result<Located> {
        let mut tree = start;
        let mut current = start.root_dirid;

        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if component == ".." {
                // Walking up needs the INODE_REF chain, which `inode_path`
                // has — but across a subvolume boundary the parent lives in a
                // different tree, so ".." is not simply the reverse of a step
                // down. Nothing in the app navigates that way (the UI holds
                // whole paths), so it is refused rather than half-implemented.
                return Err(LuksError::UnsupportedFsFeature(
                    "btrfs path containing '..'".into(),
                ));
            }

            let parent = self.read_inode(tree.bytenr, current)?;
            if !parent.file_type().is_dir() {
                return Err(LuksError::NotADirectory(path.to_string()));
            }

            let entry = self
                .lookup(tree.bytenr, current, component)?
                .ok_or_else(|| LuksError::NotFound(path.to_string()))?;

            if entry.is_subvolume() {
                // The location is a *tree id*, not an inode number. Switch
                // trees and start again at the new tree's root directory —
                // which is 256 here as it is everywhere, and is exactly why
                // mistaking one for the other produces a plausible wrong
                // answer rather than an error.
                tree = self.tree_root(entry.location.objectid)?;
                current = tree.root_dirid;
                continue;
            }
            if entry.location.item_type != tree::INODE_ITEM_KEY {
                return Err(LuksError::CorruptFs(
                    "btrfs directory entry points at something that is not an inode",
                ));
            }
            current = entry.location.objectid;
        }

        Ok(Located {
            inode: self.read_inode(tree.bytenr, current)?,
            tree,
        })
    }

    // --- convenience over the top level -------------------------------------

    /// List a path, starting from the top level.
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let found = self.resolve_no_follow(self.fs_tree(), path)?;
        if !found.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(path.to_string()));
        }
        self.list_dir_by_inode(found.tree.bytenr, found.inode.objectid)
    }

    /// Metadata for a path, starting from the top level.
    pub fn file_info(&self, path: &str) -> Result<FileInfo> {
        Ok(self.resolve_no_follow(self.fs_tree(), path)?.inode.info())
    }

    /// The filesystem label, or `None` if `mkfs` was not given one.
    pub fn volume_name(&self) -> Option<&str> {
        if self.superblock().label.is_empty() {
            None
        } else {
            Some(&self.superblock().label)
        }
    }
}
