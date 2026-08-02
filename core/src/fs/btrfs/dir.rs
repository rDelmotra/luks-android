//! Directory listing and path resolution.

use super::crc32c::name_hash;
use super::inode::{parse_dir_entries, DirEntryItem, Inode};
use super::tree;
use super::{Btrfs, Key};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::fs::{DirEntry, FileInfo};

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
                        out.push(DirEntry {
                            name: e.name_lossy(),
                            // For a subvolume this is a tree id rather than an
                            // inode number. Both are u64 and the caller cannot
                            // tell them apart, which is why crossing into a
                            // subvolume is refused rather than guessed at in
                            // `lookup`.
                            inode: e.location.objectid,
                            file_type: e.file_type,
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
    /// Symlinks are not followed at all yet, at any position. Their targets are
    /// stored as file contents, which needs the extent reader — so following
    /// one now would mean guessing at data this layer cannot read. A path
    /// through a symlinked directory therefore fails with a clear error instead
    /// of resolving to the wrong file.
    pub fn resolve_no_follow(&self, tree: u64, root_dir: u64, path: &str) -> Result<Inode> {
        let mut current = root_dir;

        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if component == ".." {
                // Walking up needs the INODE_REF that names this inode's
                // parent. Nothing in the app navigates that way — the UI holds
                // whole paths — so it is refused rather than half-implemented.
                return Err(LuksError::UnsupportedFsFeature(
                    "btrfs path containing '..'".into(),
                ));
            }

            let parent = self.read_inode(tree, current)?;
            if !parent.file_type().is_dir() {
                return Err(LuksError::NotADirectory(path.to_string()));
            }

            let entry = self
                .lookup(tree, current, component)?
                .ok_or_else(|| LuksError::NotFound(path.to_string()))?;

            if entry.is_subvolume() {
                // The entry names another fs tree. Following it means switching
                // trees mid-walk, which the caller has to opt into because it
                // changes which tree every subsequent inode number belongs to.
                return Err(LuksError::UnsupportedFsFeature(format!(
                    "btrfs subvolume boundary at '{component}'"
                )));
            }
            if entry.location.item_type != tree::INODE_ITEM_KEY {
                return Err(LuksError::CorruptFs(
                    "btrfs directory entry points at something that is not an inode",
                ));
            }
            current = entry.location.objectid;
        }

        self.read_inode(tree, current)
    }

    // --- convenience over the default subvolume -----------------------------

    /// List a path in the default subvolume.
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let root = self.fs_tree();
        let inode = self.resolve_no_follow(root.bytenr, root.root_dirid, path)?;
        if !inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(path.to_string()));
        }
        self.list_dir_by_inode(root.bytenr, inode.objectid)
    }

    /// Metadata for a path in the default subvolume.
    pub fn file_info(&self, path: &str) -> Result<FileInfo> {
        let root = self.fs_tree();
        Ok(self
            .resolve_no_follow(root.bytenr, root.root_dirid, path)?
            .info())
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
