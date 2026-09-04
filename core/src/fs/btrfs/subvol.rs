//! Subvolumes: the several filesystems inside a btrfs filesystem.
//!
//! A btrfs subvolume is not a directory. It is a **separate fs tree** with its
//! own inode numbering starting again at 256, and the only thing connecting it
//! to the rest is a directory entry whose location key carries a *tree id*
//! where every other entry carries an inode number. The two are both `u64` and
//! nothing distinguishes them but `location.item_type`, so a reader that does
//! not check it will follow the entry into an unrelated file in the wrong tree
//! — and every checksum on the way will verify, because the data it reads is
//! genuine, just not the data that was asked for.
//!
//! This is not an exotic corner. A standard Linux install puts `/` and `/home` in
//! separate subvolumes; openSUSE adds a `.snapshots` tree per rollback point.
//! On such a drive an FS_TREE-only reader shows a near-empty root and nothing
//! else, which looks far more like "the drive is broken" than like a missing
//! feature.
//!
//! Two directions of naming exist in the root tree, and only one is useful
//! here. `ROOT_REF` is filed under the parent and answers "what lives in me";
//! `ROOT_BACKREF` is filed under the child and answers "where do I appear",
//! which is what turns a bare tree id into a path a person can read.

use std::collections::HashMap;

use super::tree;
use super::{Btrfs, Key, TreeRoot};
use crate::device::ReadAt;
use crate::error::{LuksError, Result};

/// `btrfs_root_ref`: two u64s and a length before the name.
const ROOT_REF_HEADER: usize = 18;
/// `btrfs_inode_ref`: index, then the name length.
const INODE_REF_HEADER: usize = 10;

/// A subvolume, as a user would want it listed.
#[derive(Debug, Clone)]
pub struct Subvolume {
    /// The tree id. This is what `btrfs subvolume list` calls ID.
    pub id: u64,
    /// The name of the directory entry that points at it.
    pub name: String,
    /// The tree that entry lives in — 5 for one hanging off the top level.
    pub parent_id: u64,
    /// The directory inside `parent_id` that holds the entry. Not always the
    /// parent tree's root: a snapshot under `snapshots/` sits one level down.
    pub parent_dirid: u64,
    /// Absolute path from the top level, e.g. `/home/user/snap`.
    pub path: String,
    pub root: TreeRoot,
}

impl Subvolume {
    pub fn is_read_only(&self) -> bool {
        self.root.is_read_only()
    }
}

/// One `ROOT_BACKREF`, before its path has been worked out.
struct Backref {
    parent_id: u64,
    dirid: u64,
    name: String,
}

impl<D: ReadAt> Btrfs<D> {
    /// Every subvolume on the filesystem, in id order.
    ///
    /// One pass over the root tree collects the backrefs; the tree roots then
    /// come from `tree_root` per subvolume. The root tree is the smallest tree
    /// on the filesystem — a handful of leaves even on a large install — so the
    /// walk is cheap, and it is the only structure that knows subvolumes exist.
    ///
    /// The top level (id 5) is deliberately absent, exactly as
    /// `btrfs subvolume list` omits it: it is not something you can navigate
    /// *to*, it is where navigation starts.
    pub fn subvolumes(&self) -> Result<Vec<Subvolume>> {
        let mut backrefs: HashMap<u64, Backref> = HashMap::new();
        let mut failure = None;

        self.walk_tree(self.sb.root, &mut |key, data| {
            if key.item_type != tree::ROOT_BACKREF_KEY {
                return Ok(());
            }
            match parse_root_ref(data) {
                // The key's offset is the parent tree id; the item body names
                // the directory and the entry within it.
                Ok((dirid, name)) => {
                    backrefs.insert(
                        key.objectid,
                        Backref {
                            parent_id: key.offset,
                            dirid,
                            name,
                        },
                    );
                }
                Err(e) => failure = Some(e),
            }
            Ok(())
        })?;
        if let Some(e) = failure {
            return Err(e);
        }

        let mut ids: Vec<u64> = backrefs.keys().copied().collect();
        ids.sort_unstable();

        // Paths are memoised because siblings share ancestors: without this,
        // a subvolume nested n deep costs n tree walks and a directory holding
        // 50 snapshots pays for its own path 50 times.
        let mut paths: HashMap<u64, Option<String>> = HashMap::new();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let root = self.tree_root(id)?;
            let path = self.subvolume_path(id, &backrefs, &mut paths)?;
            let b = &backrefs[&id];
            out.push(Subvolume {
                id,
                name: b.name.clone(),
                parent_id: b.parent_id,
                parent_dirid: b.dirid,
                path,
                root,
            });
        }
        Ok(out)
    }

    /// Build one subvolume's absolute path, memoising as it climbs.
    ///
    /// The memo holds `None` while a subvolume's path is still being worked
    /// out, so a backref cycle is caught by hitting an in-progress entry rather
    /// than by recursing until the stack runs out. A plain "already seen" memo
    /// would terminate too — and hand back a confidently wrong path.
    fn subvolume_path(
        &self,
        id: u64,
        backrefs: &HashMap<u64, Backref>,
        memo: &mut HashMap<u64, Option<String>>,
    ) -> Result<String> {
        match memo.get(&id) {
            Some(Some(p)) => return Ok(p.clone()),
            Some(None) => {
                return Err(LuksError::CorruptFs(
                    "btrfs subvolume is nested inside itself",
                ))
            }
            None => {}
        }
        if id == tree::FS_TREE_OBJECTID {
            return Ok(String::new());
        }
        let Some(b) = backrefs.get(&id) else {
            // A tree with no backref is unreachable by name. Rather than
            // inventing a path, say so where a user can see it.
            return Ok(format!("<detached {id}>"));
        };

        memo.insert(id, None);
        let parent_path = self.subvolume_path(b.parent_id, backrefs, memo)?;
        let parent_root = self.tree_root(b.parent_id)?;
        // Where inside the parent tree the mount point sits. Empty when the
        // entry is directly in that tree's root directory, which is the common
        // case and the one that must not produce a doubled slash.
        let dir = self.inode_path(&parent_root, b.dirid)?;

        let mut path = parent_path;
        if !dir.is_empty() {
            path.push('/');
            path.push_str(&dir);
        }
        path.push('/');
        path.push_str(&b.name);

        memo.insert(id, Some(path.clone()));
        Ok(path)
    }

    /// The path of a directory inside its own tree, relative to that tree's
    /// root — `""` for the root itself.
    ///
    /// Climbs the `INODE_REF` chain, which is the only link from an inode back
    /// to its parent. Each `INODE_REF` key is
    /// `(objectid, INODE_REF, parent objectid)`, so the parent is in the key
    /// and the name is in the body.
    ///
    /// Only correct for directories, and only directories are asked for: a file
    /// with hard links has several `INODE_REF`s and therefore several equally
    /// true paths, whereas a directory always has exactly one.
    pub fn inode_path(&self, root: &TreeRoot, objectid: u64) -> Result<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut current = objectid;

        // btrfs imposes no depth limit, but a chain longer than this is a
        // corrupt tree pointing at itself, and unbounded climbing on a hostile
        // image is a hang rather than an error message.
        for _ in 0..128 {
            if current == root.root_dirid {
                parts.reverse();
                return Ok(parts.join("/"));
            }

            let cursor = self.search(
                root.bytenr,
                &Key::new(current, tree::INODE_REF_KEY, 0),
            )?;
            if !cursor.valid() {
                return Err(LuksError::CorruptFs("btrfs inode has no parent reference"));
            }
            let key = cursor.key()?;
            if key.objectid != current || key.item_type != tree::INODE_REF_KEY {
                return Err(LuksError::CorruptFs("btrfs inode has no parent reference"));
            }

            let (_, name) = parse_inode_ref(cursor.data()?)?;
            parts.push(name);
            current = key.offset;
        }

        Err(LuksError::CorruptFs("btrfs directory nesting is implausibly deep"))
    }

    /// The subvolume a plain `mount` of this filesystem would show.
    ///
    /// Stored as a single directory entry named `default` in the root tree's
    /// own directory. Absent on a filesystem nobody has run
    /// `btrfs subvolume set-default` on — standard Linux defaults, for one — in which case the
    /// answer is the top level.
    ///
    /// Reported rather than obeyed. Browsing starts at the top level whatever
    /// this says, because starting at the default would make every subvolume
    /// outside it unreachable, and on openSUSE the default is a snapshot
    /// several levels down.
    pub fn default_subvolume(&self) -> Result<u64> {
        let key = Key::new(
            tree::ROOT_TREE_DIR_OBJECTID,
            tree::DIR_ITEM_KEY,
            super::crc32c::name_hash(b"default"),
        );
        let Some(data) = self.find_item(self.sb.root, &key)? else {
            return Ok(tree::FS_TREE_OBJECTID);
        };
        let entry = super::inode::parse_dir_entries(&data)?
            .into_iter()
            .find(|e| e.name == b"default");
        match entry {
            Some(e) if e.location.item_type == tree::ROOT_ITEM_KEY => Ok(e.location.objectid),
            // An entry named `default` that does not point at a root is not
            // something to guess about.
            Some(_) => Err(LuksError::CorruptFs(
                "btrfs default subvolume entry does not name a tree",
            )),
            None => Ok(tree::FS_TREE_OBJECTID),
        }
    }
}

/// `btrfs_root_ref` / `btrfs_root_backref`: `{dirid, sequence, name_len, name}`.
fn parse_root_ref(data: &[u8]) -> Result<(u64, String)> {
    if data.len() < ROOT_REF_HEADER {
        return Err(LuksError::CorruptFs("btrfs root ref is truncated"));
    }
    let dirid = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let name_len = u16::from_le_bytes(data[16..18].try_into().unwrap()) as usize;
    let end = ROOT_REF_HEADER
        .checked_add(name_len)
        .filter(|e| *e <= data.len())
        .ok_or(LuksError::CorruptFs("btrfs root ref name overruns its item"))?;
    Ok((
        dirid,
        String::from_utf8_lossy(&data[ROOT_REF_HEADER..end]).into_owned(),
    ))
}

/// `btrfs_inode_ref`: `{index, name_len, name}`.
fn parse_inode_ref(data: &[u8]) -> Result<(u64, String)> {
    if data.len() < INODE_REF_HEADER {
        return Err(LuksError::CorruptFs("btrfs inode ref is truncated"));
    }
    let index = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let name_len = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
    let end = INODE_REF_HEADER
        .checked_add(name_len)
        .filter(|e| *e <= data.len())
        .ok_or(LuksError::CorruptFs("btrfs inode ref name overruns its item"))?;
    Ok((
        index,
        String::from_utf8_lossy(&data[INODE_REF_HEADER..end]).into_owned(),
    ))
}
