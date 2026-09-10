//! In-Memory Shadow Filesystem Model and Seeded Deterministic Operation Generator.
//!
//! Provides:
//! 1. `ShadowModel`: An independent reference model of directory hierarchy and
//!    file contents, supporting full two-tier in-process verification against `Btrfs<D>`.
//! 2. `ConformanceRng`: A deterministic 64-bit SplitMix64 pseudo-random generator
//!    supporting exact seed replay via `LUKS_CONFORMANCE_SEED`.
//! 3. `DriverOp`: High-level filesystem operations issued through public driver APIs.
//! 4. `OpGenerator`: Weighted grammar-based operation sequence generator stressing
//!    B-tree leaf splits, `DIR_ITEM` capacity, and checksum item boundaries.

#![allow(dead_code)]
#![cfg(feature = "dangerous-write-support")]

use std::collections::{BTreeMap, BTreeSet};

use luks_core::device::{ReadAt, WriteAt};
use luks_core::error::{LuksError, Result};
use luks_core::fs::btrfs::Btrfs;

use super::accounting::{AccountingOracle, AccountingReport};
use super::btree_validator::{AllTreesValidationReport, TreeValidator};

/// Normalize a path: strip leading and trailing slashes, resolve "." components.
/// The root directory is represented by the empty string `""`.
pub fn normalize_path(path: &str) -> String {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Convert a normalized path into a driver path (prefixed with `/`).
pub fn to_btrfs_path(norm: &str) -> String {
    if norm.is_empty() {
        "/".to_string()
    } else {
        format!("/{norm}")
    }
}

/// Split a normalized path into `(parent, name)`.
/// E.g. `"a/b/c"` -> `("a/b", "c")`, `"hello"` -> `("", "hello")`, `""` -> `("", "")`.
pub fn split_parent_name(path: &str) -> (&str, &str) {
    if path.is_empty() {
        ("", "")
    } else if let Some(idx) = path.rfind('/') {
        (&path[..idx], &path[idx + 1..])
    } else {
        ("", path)
    }
}

/// Represents the state of a single entry in the shadow filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    File {
        data: Vec<u8>,
        mtime_sec: u64,
        mtime_nsec: u32,
    },
    Directory {
        mtime_sec: u64,
        mtime_nsec: u32,
    },
    Symlink {
        target: String,
        mtime_sec: u64,
        mtime_nsec: u32,
    },
}

impl EntryState {
    pub fn is_dir(&self) -> bool {
        matches!(self, EntryState::Directory { .. })
    }

    pub fn is_file(&self) -> bool {
        matches!(self, EntryState::File { .. })
    }

    pub fn is_symlink(&self) -> bool {
        matches!(self, EntryState::Symlink { .. })
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self {
            EntryState::File { data, .. } => Some(data),
            _ => None,
        }
    }

    pub fn mtime(&self) -> (u64, u32) {
        match self {
            EntryState::File {
                mtime_sec,
                mtime_nsec,
                ..
            }
            | EntryState::Directory {
                mtime_sec,
                mtime_nsec,
            }
            | EntryState::Symlink {
                mtime_sec,
                mtime_nsec,
                ..
            } => (*mtime_sec, *mtime_nsec),
        }
    }
}

/// In-memory shadow model tracking directory tree and file contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowModel {
    /// Normalized paths mapped to entries. Root is `""`.
    entries: BTreeMap<String, EntryState>,
}

impl Default for ShadowModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowModel {
    /// Create a new shadow model containing only the root directory `""`.
    pub fn new() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "".to_string(),
            EntryState::Directory {
                mtime_sec: 0,
                mtime_nsec: 0,
            },
        );
        Self { entries }
    }

    /// Populate a shadow model by recursively scanning an existing Btrfs filesystem.
    pub fn from_fs<D: ReadAt>(fs: &Btrfs<D>) -> Result<Self> {
        let mut model = Self::new();
        model.populate_dir_from_fs(fs, "")?;
        Ok(model)
    }

    fn populate_dir_from_fs<D: ReadAt>(&mut self, fs: &Btrfs<D>, norm_dir: &str) -> Result<()> {
        let btrfs_dir = to_btrfs_path(norm_dir);
        let entries = fs.list_dir(&btrfs_dir)?;
        for entry in entries {
            if entry.is_subvolume {
                continue;
            }
            let child_norm = if norm_dir.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", norm_dir, entry.name)
            };
            if entry.file_type.is_dir() {
                self.entries.insert(
                    child_norm.clone(),
                    EntryState::Directory {
                        mtime_sec: 0,
                        mtime_nsec: 0,
                    },
                );
                self.populate_dir_from_fs(fs, &child_norm)?;
            } else if entry.file_type.is_file() {
                let data = fs.read_file(&to_btrfs_path(&child_norm))?;
                self.entries.insert(
                    child_norm,
                    EntryState::File {
                        data,
                        mtime_sec: entry.mtime.max(0) as u64,
                        mtime_nsec: 0,
                    },
                );
            } else if entry.file_type == luks_core::fs::FileType::Symlink {
                let target = fs.read_link(&to_btrfs_path(&child_norm))?;
                self.entries.insert(
                    child_norm,
                    EntryState::Symlink {
                        target,
                        mtime_sec: entry.mtime.max(0) as u64,
                        mtime_nsec: 0,
                    },
                );
            }
        }
        Ok(())
    }

    /// Return all immediate child entry names in `norm_dir`.
    pub fn immediate_children(&self, norm_dir: &str) -> BTreeSet<String> {
        let norm_dir = normalize_path(norm_dir);
        let mut children = BTreeSet::new();
        if norm_dir.is_empty() {
            for k in self.entries.keys() {
                if !k.is_empty() && !k.contains('/') {
                    children.insert(k.clone());
                }
            }
        } else {
            let prefix = format!("{norm_dir}/");
            for k in self.entries.keys() {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    if !rest.is_empty() && !rest.contains('/') {
                        children.insert(rest.to_string());
                    }
                }
            }
        }
        children
    }

    /// Return all directory paths in the model (including root `""`).
    pub fn all_directories(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|(k, v)| if v.is_dir() { Some(k.clone()) } else { None })
            .collect()
    }

    /// Return all file paths in the model.
    pub fn all_files(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|(k, v)| if v.is_file() { Some(k.clone()) } else { None })
            .collect()
    }

    /// Return all non-root paths in the model.
    pub fn all_entries(&self) -> Vec<String> {
        self.entries
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect()
    }

    pub fn get_entry(&self, path: &str) -> Option<&EntryState> {
        self.entries.get(&normalize_path(path))
    }

    pub fn get_file(&self, path: &str) -> Option<&[u8]> {
        self.get_entry(path).and_then(|e| e.data())
    }

    pub fn contains(&self, path: &str) -> bool {
        self.entries.contains_key(&normalize_path(path))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a file entry to the model.
    pub fn create_file(
        &mut self,
        parent: &str,
        name: &str,
        data: Vec<u8>,
        mtime_sec: u64,
        mtime_nsec: u32,
    ) -> Result<()> {
        let parent = normalize_path(parent);
        match self.entries.get_mut(&parent) {
            Some(EntryState::Directory {
                mtime_sec: sec,
                mtime_nsec: nsec,
            }) => {
                // In Btrfs, adding a child to a directory bumps its mtime
                *sec = 0;
                *nsec = 0;
            }
            Some(_) => return Err(LuksError::NotADirectory(to_btrfs_path(&parent))),
            None => return Err(LuksError::NotFound(to_btrfs_path(&parent))),
        }
        if name.is_empty() || name.contains('/') {
            return Err(LuksError::CorruptFs("invalid filename"));
        }
        let child_path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        if self.entries.contains_key(&child_path) {
            return Err(LuksError::AlreadyExists(child_path));
        }
        self.entries.insert(
            child_path,
            EntryState::File {
                data,
                mtime_sec,
                mtime_nsec,
            },
        );
        Ok(())
    }

    /// Add a directory entry to the model.
    pub fn create_directory(
        &mut self,
        parent: &str,
        name: &str,
        mtime_sec: u64,
        mtime_nsec: u32,
    ) -> Result<()> {
        let parent = normalize_path(parent);
        match self.entries.get_mut(&parent) {
            Some(EntryState::Directory {
                mtime_sec: sec,
                mtime_nsec: nsec,
            }) => {
                // In Btrfs, adding a child to a directory bumps its mtime
                *sec = 0;
                *nsec = 0;
            }
            Some(_) => return Err(LuksError::NotADirectory(to_btrfs_path(&parent))),
            None => return Err(LuksError::NotFound(to_btrfs_path(&parent))),
        }
        if name.is_empty() || name.contains('/') {
            return Err(LuksError::CorruptFs("invalid directory name"));
        }
        let child_path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        if self.entries.contains_key(&child_path) {
            return Err(LuksError::AlreadyExists(child_path));
        }
        self.entries.insert(
            child_path,
            EntryState::Directory {
                mtime_sec,
                mtime_nsec,
            },
        );
        Ok(())
    }

    /// Overwrite data in an existing file.
    pub fn write_file(
        &mut self,
        path: &str,
        data: Vec<u8>,
        mtime_sec: u64,
        mtime_nsec: u32,
    ) -> Result<()> {
        let path = normalize_path(path);
        match self.entries.get_mut(&path) {
            Some(EntryState::File {
                data: d,
                mtime_sec: sec,
                mtime_nsec: nsec,
            }) => {
                *d = data;
                *sec = mtime_sec;
                *nsec = mtime_nsec;
                Ok(())
            }
            Some(EntryState::Directory { .. }) => {
                Err(LuksError::IsADirectory(to_btrfs_path(&path)))
            }
            Some(EntryState::Symlink { .. }) => {
                Err(LuksError::UnsupportedFsFeature("cannot write to symlink".into()))
            }
            None => Err(LuksError::NotFound(to_btrfs_path(&path))),
        }
    }

    /// Rename or move an entry. If directory, recursively updates descendant paths.
    pub fn rename(
        &mut self,
        old_parent: &str,
        old_name: &str,
        new_parent: &str,
        new_name: &str,
        _mtime_sec: u64,
        _mtime_nsec: u32,
    ) -> Result<()> {
        let old_parent = normalize_path(old_parent);
        let new_parent = normalize_path(new_parent);
        let old_path = if old_parent.is_empty() {
            old_name.to_string()
        } else {
            format!("{old_parent}/{old_name}")
        };
        let new_path = if new_parent.is_empty() {
            new_name.to_string()
        } else {
            format!("{new_parent}/{new_name}")
        };

        if old_path.is_empty() {
            return Err(LuksError::IsADirectory("/".into()));
        }
        if !self.entries.contains_key(&old_path) {
            return Err(LuksError::NotFound(to_btrfs_path(&old_path)));
        }
        if !self.entries.contains_key(&new_parent) {
            return Err(LuksError::NotFound(to_btrfs_path(&new_parent)));
        }
        if self.entries.contains_key(&new_path) {
            return Err(LuksError::AlreadyExists(new_path));
        }

        // Btrfs bumps both old and new parent directories' mtimes on rename
        if let Some(EntryState::Directory {
            mtime_sec: sec,
            mtime_nsec: nsec,
        }) = self.entries.get_mut(&old_parent)
        {
            *sec = 0;
            *nsec = 0;
        }
        if let Some(EntryState::Directory {
            mtime_sec: sec,
            mtime_nsec: nsec,
        }) = self.entries.get_mut(&new_parent)
        {
            *sec = 0;
            *nsec = 0;
        }

        let entry = self.entries.remove(&old_path).expect("checked");
        match entry {
            EntryState::File {
                data,
                mtime_sec: orig_sec,
                mtime_nsec: orig_nsec,
            } => {
                self.entries.insert(
                    new_path,
                    EntryState::File {
                        data,
                        mtime_sec: orig_sec,
                        mtime_nsec: orig_nsec,
                    },
                );
            }
            EntryState::Symlink {
                target,
                mtime_sec: orig_sec,
                mtime_nsec: orig_nsec,
            } => {
                self.entries.insert(
                    new_path,
                    EntryState::Symlink {
                        target,
                        mtime_sec: orig_sec,
                        mtime_nsec: orig_nsec,
                    },
                );
            }
            EntryState::Directory {
                mtime_sec: orig_sec,
                mtime_nsec: orig_nsec,
            } => {
                self.entries.insert(
                    new_path.clone(),
                    EntryState::Directory {
                        mtime_sec: orig_sec,
                        mtime_nsec: orig_nsec,
                    },
                );
                // Move all descendants
                let old_prefix = format!("{old_path}/");
                let descendant_keys: Vec<String> = self
                    .entries
                    .keys()
                    .filter(|k| k.starts_with(&old_prefix))
                    .cloned()
                    .collect();

                let mut descendants = Vec::with_capacity(descendant_keys.len());
                for k in descendant_keys {
                    let val = self.entries.remove(&k).expect("descendant exists");
                    descendants.push((k, val));
                }

                for (old_k, val) in descendants {
                    let relative = &old_k[old_prefix.len()..];
                    let new_k = format!("{new_path}/{relative}");
                    self.entries.insert(new_k, val);
                }
            }
        }
        Ok(())
    }

    /// Delete an entry. If directory, recursively deletes all descendants.
    pub fn delete(&mut self, path: &str) -> Result<()> {
        let path = normalize_path(path);
        if path.is_empty() {
            return Err(LuksError::IsADirectory("/".into()));
        }
        if !self.entries.contains_key(&path) {
            return Err(LuksError::NotFound(to_btrfs_path(&path)));
        }

        // Btrfs bumps parent directory mtime on deletion
        let (parent, _) = split_parent_name(&path);
        let parent_norm = normalize_path(parent);
        if let Some(EntryState::Directory {
            mtime_sec: sec,
            mtime_nsec: nsec,
        }) = self.entries.get_mut(&parent_norm)
        {
            *sec = 0;
            *nsec = 0;
        }

        let is_dir = self.entries.get(&path).is_some_and(|e| e.is_dir());
        if is_dir {
            let prefix = format!("{path}/");
            let descendants: Vec<String> = self
                .entries
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for d in descendants {
                self.entries.remove(&d);
            }
        }
        self.entries.remove(&path);
        Ok(())
    }

    /// Update timestamps on an entry.
    pub fn set_mtime(&mut self, path: &str, mtime_sec: u64, mtime_nsec: u32) -> Result<()> {
        let path = normalize_path(path);
        match self.entries.get_mut(&path) {
            Some(
                EntryState::File {
                    mtime_sec: sec,
                    mtime_nsec: nsec,
                    ..
                }
                | EntryState::Directory {
                    mtime_sec: sec,
                    mtime_nsec: nsec,
                }
                | EntryState::Symlink {
                    mtime_sec: sec,
                    mtime_nsec: nsec,
                    ..
                },
            ) => {
                *sec = mtime_sec;
                *nsec = mtime_nsec;
                Ok(())
            }
            None => Err(LuksError::NotFound(to_btrfs_path(&path))),
        }
    }

    /// Verify the shadow model against a mounted Btrfs filesystem.
    ///
    /// Asserts:
    /// 1. Every file exists in fs with matching length and byte-exact data.
    /// 2. Every directory exists in fs with matching immediate child sets.
    /// 3. Every entry in fs exists in the shadow model (no orphan/untracked entries).
    pub fn verify_against_fs<D: ReadAt>(&self, fs: &Btrfs<D>) -> Result<()> {
        // 1. Check all model entries exist in fs
        for (norm_path, entry) in &self.entries {
            let btrfs_path = to_btrfs_path(norm_path);
            match entry {
                EntryState::File { data, .. } => {
                    let fs_data = fs.read_file(&btrfs_path)?;
                    assert_eq!(
                        fs_data.len(),
                        data.len(),
                        "file size mismatch for '{norm_path}': model has {} bytes, fs has {} bytes",
                        data.len(),
                        fs_data.len()
                    );
                    assert_eq!(
                        &fs_data, data,
                        "file content mismatch for '{norm_path}' (len {})",
                        data.len()
                    );
                }
                EntryState::Directory { .. } => {
                    let children = fs.list_dir(&btrfs_path)?;
                    let expected_children = self.immediate_children(norm_path);
                    let actual_children: BTreeSet<String> = children
                        .into_iter()
                        .filter(|c| !c.is_subvolume)
                        .map(|c| c.name)
                        .collect();
                    assert_eq!(
                        actual_children, expected_children,
                        "directory listing mismatch for '{norm_path}'"
                    );
                }
                EntryState::Symlink { target, .. } => {
                    let fs_target = fs.read_link(&btrfs_path)?;
                    assert_eq!(
                        &fs_target, target,
                        "symlink target mismatch for '{norm_path}'"
                    );
                }
            }

            // Verify modification timestamp (mtime) if recorded in model
            let (mtime_sec, _) = entry.mtime();
            if mtime_sec != 0 {
                let info = fs.file_info(&btrfs_path)?;
                assert_eq!(
                    info.mtime, mtime_sec as i64,
                    "mtime mismatch for '{norm_path}': model has {mtime_sec}, fs has {}",
                    info.mtime
                );
            }
        }

        // 2. Reverse walk from root to detect orphan entries in fs
        let mut queue = Vec::new();
        queue.push("".to_string());
        while let Some(curr_dir) = queue.pop() {
            let btrfs_dir = to_btrfs_path(&curr_dir);
            let entries = fs.list_dir(&btrfs_dir)?;
            for entry in entries {
                if entry.is_subvolume {
                    continue;
                }
                let child_norm = if curr_dir.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{}/{}", curr_dir, entry.name)
                };
                assert!(
                    self.entries.contains_key(&child_norm),
                    "orphan entry in filesystem not present in shadow model: '{child_norm}'"
                );
                if entry.file_type.is_dir() {
                    queue.push(child_norm);
                }
            }
        }

        Ok(())
    }
}

/// 64-bit deterministic SplitMix64 pseudo-random number generator.
#[derive(Debug, Clone)]
pub struct ConformanceRng {
    pub state: u64,
}

impl ConformanceRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Read seed from environment `LUKS_CONFORMANCE_SEED` if present,
    /// otherwise use default seed.
    pub fn from_env_or_default(default_seed: u64) -> (Self, u64) {
        if let Ok(val) = std::env::var("LUKS_CONFORMANCE_SEED") {
            let parsed = if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16).unwrap_or(default_seed)
            } else {
                val.parse::<u64>().unwrap_or(default_seed)
            };
            println!(
                "[CONFORMANCE] Using seed from LUKS_CONFORMANCE_SEED: {parsed:#018x} ({parsed})"
            );
            (Self::new(parsed), parsed)
        } else {
            println!("[CONFORMANCE] Using default seed: {default_seed:#018x} ({default_seed})");
            (Self::new(default_seed), default_seed)
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        assert!(min <= max);
        if min == max {
            return min;
        }
        let span = (max - min + 1) as u64;
        min + (self.next_u64() % span) as usize
    }

    pub fn gen_bool(&mut self, prob_pct: usize) -> bool {
        self.gen_range(1, 100) <= prob_pct
    }

    pub fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for chunk in buf.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&val[..n]);
        }
        buf
    }

    pub fn gen_name(&mut self, long: bool) -> String {
        let len = if long {
            self.gen_range(64, 180)
        } else {
            self.gen_range(4, 14)
        };
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
        let mut s = String::with_capacity(len);
        s.push(b'f' as char);
        for _ in 1..len {
            let idx = self.gen_range(0, CHARSET.len() - 1);
            s.push(CHARSET[idx] as char);
        }
        s
    }
}

/// High-level driver operations executed against Btrfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverOp {
    CreateFileWithData {
        parent: String,
        name: String,
        data: Vec<u8>,
    },
    StreamFile {
        parent: String,
        name: String,
        data: Vec<u8>,
        chunk_size: usize,
    },
    CreateDirectory {
        parent: String,
        name: String,
    },
    Rename {
        old_parent: String,
        old_name: String,
        new_parent: String,
        new_name: String,
    },
    Delete {
        path: String,
    },
    SetMtime {
        path: String,
        mtime_sec: u64,
        mtime_nsec: u32,
    },
    CommitAndRemount,
}

/// Seeded, deterministic operation generator based on a weighted grammar.
pub struct OpGenerator {
    pub rng: ConformanceRng,
    pub step: usize,
}

impl OpGenerator {
    pub fn new(rng: ConformanceRng) -> Self {
        Self { rng, step: 0 }
    }

    /// Generate next operation with default balanced distributions.
    pub fn next_op(&mut self, model: &ShadowModel) -> DriverOp {
        self.next_op_biased(model, false, false)
    }

    /// Generate next operation with optional biases toward long names or csum splits.
    pub fn next_op_biased(
        &mut self,
        model: &ShadowModel,
        force_long_names: bool,
        force_csum_split: bool,
    ) -> DriverOp {
        self.step += 1;

        // Ensure minimum tree population before deletes or renames
        let file_count = model.all_files().len();
        let dirs = model.all_directories();

        let roll = self.rng.gen_range(1, 100);

        if file_count < 3 || roll <= 30 {
            // CreateFileWithData
            let parent = self.pick_directory(model, 4);
            let long_name = force_long_names || self.rng.gen_bool(40);
            let name = self.pick_unique_name(model, &parent, long_name);
            let data = self.gen_file_data(force_csum_split);
            DriverOp::CreateFileWithData { parent, name, data }
        } else if roll <= 50 {
            // StreamFile
            let parent = self.pick_directory(model, 4);
            let long_name = force_long_names || self.rng.gen_bool(35);
            let name = self.pick_unique_name(model, &parent, long_name);
            let data = self.gen_file_data(force_csum_split);
            let chunk_size = if self.rng.gen_bool(50) { 4096 } else { 8192 };
            DriverOp::StreamFile {
                parent,
                name,
                data,
                chunk_size,
            }
        } else if roll <= 65 {
            // CreateDirectory (max depth 4)
            let parent = self.pick_directory(model, 3);
            let long_name = force_long_names || self.rng.gen_bool(30);
            let name = self.pick_unique_name(model, &parent, long_name);
            DriverOp::CreateDirectory { parent, name }
        } else if roll <= 80 && file_count > 0 {
            // Rename
            let entries = model.all_entries();
            let idx = self.rng.gen_range(0, entries.len() - 1);
            let old_path = entries[idx].clone();
            let (old_parent, old_name) = split_parent_name(&old_path);
            let is_dir = model.get_entry(&old_path).is_some_and(|e| e.is_dir());

            // Pick new parent
            let new_parent = if self.rng.gen_bool(50) {
                // Same parent rename (GAP-1 delete+insert path)
                old_parent.to_string()
            } else {
                // Cross-directory rename
                let valid_dirs: Vec<String> = dirs
                    .iter()
                    .filter(|d| {
                        if is_dir {
                            // Cannot move directory into its own child or itself
                            !d.starts_with(&format!("{old_path}/")) && *d != &old_path
                        } else {
                            true
                        }
                    })
                    .cloned()
                    .collect();
                if valid_dirs.is_empty() {
                    old_parent.to_string()
                } else {
                    let d_idx = self.rng.gen_range(0, valid_dirs.len() - 1);
                    valid_dirs[d_idx].clone()
                }
            };
            let long_name = force_long_names || self.rng.gen_bool(30);
            let new_name = self.pick_unique_name(model, &new_parent, long_name);
            DriverOp::Rename {
                old_parent: old_parent.to_string(),
                old_name: old_name.to_string(),
                new_parent,
                new_name,
            }
        } else if roll <= 90 && file_count > 0 {
            // Delete
            let entries = model.all_entries();
            let idx = self.rng.gen_range(0, entries.len() - 1);
            DriverOp::Delete {
                path: entries[idx].clone(),
            }
        } else if roll <= 95 && !model.all_entries().is_empty() {
            // SetMtime
            let entries = model.all_entries();
            let idx = self.rng.gen_range(0, entries.len() - 1);
            let mtime_sec = 1_700_000_000 + self.rng.gen_range(1, 1_000_000) as u64;
            let mtime_nsec = self.rng.gen_range(0, 999_999_999) as u32;
            DriverOp::SetMtime {
                path: entries[idx].clone(),
                mtime_sec,
                mtime_nsec,
            }
        } else {
            // CommitAndRemount
            DriverOp::CommitAndRemount
        }
    }

    fn pick_directory(&mut self, model: &ShadowModel, max_depth: usize) -> String {
        let dirs: Vec<String> = model
            .all_directories()
            .into_iter()
            .filter(|d| {
                if d.is_empty() {
                    true
                } else {
                    d.split('/').count() <= max_depth
                }
            })
            .collect();
        if dirs.is_empty() {
            "".to_string()
        } else {
            let idx = self.rng.gen_range(0, dirs.len() - 1);
            dirs[idx].clone()
        }
    }

    fn pick_unique_name(&mut self, model: &ShadowModel, parent: &str, long: bool) -> String {
        let existing = model.immediate_children(parent);
        for _ in 0..20 {
            let candidate = self.rng.gen_name(long);
            if !existing.contains(&candidate) {
                return candidate;
            }
        }
        format!("uniq_{}_{}", self.step, self.rng.gen_range(1000, 9999))
    }

    fn gen_file_data(&mut self, force_csum_split: bool) -> Vec<u8> {
        if force_csum_split {
            let len = self.rng.gen_range(15_000, 18_000);
            return self.rng.gen_bytes(len);
        }

        let roll = self.rng.gen_range(1, 100);
        let len = if roll <= 10 {
            0 // Empty file
        } else if roll <= 35 {
            self.rng.gen_range(1, 512) // Small inline extent
        } else if roll <= 60 {
            self.rng.gen_range(1024, 8192) // Single extent regular
        } else if roll <= 85 {
            self.rng.gen_range(15_000, 18_000) // CSUM split straddle (~16 KiB)
        } else {
            self.rng.gen_range(24_576, 65_536) // Multi-extent regular
        };
        self.rng.gen_bytes(len)
    }
}

/// Result report from executing an operation with Tier A / Tier B grading.
#[derive(Debug, Clone)]
pub struct StepReport {
    pub step: usize,
    pub op: DriverOp,
    pub succeeded: bool,
    pub skipped_full: bool,
    pub all_trees_report: Option<AllTreesValidationReport>,
    pub accounting_report: Option<AccountingReport>,
}

/// Execute a single driver operation against both `fs` and `model` with full two-tier grading:
/// - **Tier A (After Every Op)**: `TreeValidator::validate_all(&fs)` across all 5 trees
///   and verifies touched paths against `model`.
/// - **Tier B (On Commit / Remount)**: remounts `fs` from `mem_device`, asserts clean
///   accounting via `AccountingOracle::assert_clean(&fs)`, and validates entire model against `fs`.
pub fn execute_op_tier_ab<D: WriteAt + ReadAt + Clone>(
    step: usize,
    op: &DriverOp,
    fs: &mut Btrfs<D>,
    model: &mut ShadowModel,
    mem_device: &D,
) -> Result<StepReport> {
    let now_sec = 1_700_000_000 + step as u64;
    let now_nsec = ((step as u32).wrapping_mul(1_000_003)) % 1_000_000_000;

    let mut skipped_full = false;
    let mut is_remount = false;

    match op {
        DriverOp::CreateFileWithData { parent, name, data } => {
            let btrfs_parent = to_btrfs_path(parent);
            match fs.create_file_with_data(&btrfs_parent, name, data) {
                Ok(_) => {
                    let child_path = if parent.is_empty() {
                        format!("/{name}")
                    } else {
                        format!("/{parent}/{name}")
                    };
                    fs.set_mtime(&child_path, now_sec, now_nsec)?;
                    model.create_file(parent, name, data.clone(), now_sec, now_nsec)?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::StreamFile {
            parent,
            name,
            data,
            chunk_size,
        } => {
            let btrfs_parent = to_btrfs_path(parent);
            let mut stream_res = || -> Result<()> {
                let mut writer = fs.begin_file(data.len() as u64)?;
                let mut pos = 0;
                while pos < data.len() {
                    let end = (pos + chunk_size).min(data.len());
                    if let Err(e) = fs.write_chunk(&mut writer, &data[pos..end]) {
                        let _ = fs.abandon_file(writer);
                        return Err(e);
                    }
                    pos = end;
                }
                let _ino = fs.finish_file(writer, &btrfs_parent, name)?;
                fs.commit_active_batch()?;
                Ok(())
            };

            match stream_res() {
                Ok(()) => {
                    let child_path = if parent.is_empty() {
                        format!("/{name}")
                    } else {
                        format!("/{parent}/{name}")
                    };
                    fs.set_mtime(&child_path, now_sec, now_nsec)?;
                    model.create_file(parent, name, data.clone(), now_sec, now_nsec)?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::CreateDirectory { parent, name } => {
            let btrfs_parent = to_btrfs_path(parent);
            match fs.create_directory(&btrfs_parent, name) {
                Ok(_) => {
                    model.create_directory(parent, name, 0, 0)?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::Rename {
            old_parent,
            old_name,
            new_parent,
            new_name,
        } => {
            let btrfs_old_parent = to_btrfs_path(old_parent);
            let btrfs_new_parent = to_btrfs_path(new_parent);
            match fs.rename(&btrfs_old_parent, old_name, &btrfs_new_parent, new_name) {
                Ok(_) => {
                    model.rename(
                        old_parent, old_name, new_parent, new_name, now_sec, now_nsec,
                    )?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::Delete { path } => {
            let btrfs_path = to_btrfs_path(path);
            match fs.delete_file(&btrfs_path) {
                Ok(_) => {
                    model.delete(path)?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::SetMtime {
            path,
            mtime_sec,
            mtime_nsec,
        } => {
            let btrfs_path = to_btrfs_path(path);
            match fs.set_mtime(&btrfs_path, *mtime_sec, *mtime_nsec) {
                Ok(_) => {
                    model.set_mtime(path, *mtime_sec, *mtime_nsec)?;
                }
                Err(LuksError::FilesystemFull) => {
                    skipped_full = true;
                }
                Err(e) => return Err(e),
            }
        }
        DriverOp::CommitAndRemount => {
            fs.commit_active_batch()?;
            is_remount = true;
        }
    }

    // --- Tier A Verification (After Every Op) ---
    // Validate all 5 trees in-memory: structural invariants I-1..I-6,
    // search-vs-walk parity, and cursor bidirectionality.
    let all_trees = TreeValidator::validate_all(fs).unwrap_or_else(|e| {
        panic!("[CONFORMANCE TIER A FAILURE] Step {step} op {op:?} violated tree invariants: {e}");
    });

    // Immediate touched-path verification against model
    if !skipped_full {
        match op {
            DriverOp::CreateFileWithData { parent, name, data }
            | DriverOp::StreamFile {
                parent, name, data, ..
            } => {
                let norm = if parent.is_empty() {
                    name.clone()
                } else {
                    format!("{parent}/{name}")
                };
                let btrfs_p = to_btrfs_path(&norm);
                let read_back = fs.read_file(&btrfs_p).unwrap_or_else(|e| {
                    panic!("[CONFORMANCE TIER A FAILURE] Step {step}: file '{norm}' read failed: {e}");
                });
                assert_eq!(
                    &read_back, data,
                    "[CONFORMANCE TIER A FAILURE] Step {step}: file '{norm}' content mismatch"
                );
                let info = fs.file_info(&btrfs_p).unwrap_or_else(|e| {
                    panic!("[CONFORMANCE TIER A FAILURE] Step {step}: file '{norm}' file_info failed: {e}");
                });
                assert_eq!(
                    info.mtime, now_sec as i64,
                    "[CONFORMANCE TIER A FAILURE] Step {step}: file '{norm}' mtime mismatch"
                );
            }
            DriverOp::CreateDirectory { parent, name } => {
                let norm = if parent.is_empty() {
                    name.clone()
                } else {
                    format!("{parent}/{name}")
                };
                let btrfs_p = to_btrfs_path(&norm);
                let info = fs.file_info(&btrfs_p).unwrap_or_else(|e| {
                    panic!("[CONFORMANCE TIER A FAILURE] Step {step}: directory '{norm}' file_info failed: {e}");
                });
                assert!(
                    info.file_type.is_dir(),
                    "[CONFORMANCE TIER A FAILURE] Step {step}: '{norm}' is not a directory"
                );
            }
            DriverOp::Rename {
                old_parent,
                old_name,
                new_parent,
                new_name,
            } => {
                let old_norm = if old_parent.is_empty() {
                    old_name.clone()
                } else {
                    format!("{old_parent}/{old_name}")
                };
                let new_norm = if new_parent.is_empty() {
                    new_name.clone()
                } else {
                    format!("{new_parent}/{new_name}")
                };
                let btrfs_old = to_btrfs_path(&old_norm);
                let btrfs_new = to_btrfs_path(&new_norm);
                assert!(
                    fs.file_info(&btrfs_old).is_err(),
                    "[CONFORMANCE TIER A FAILURE] Step {step}: old renamed path '{old_norm}' still exists"
                );
                let info = fs.file_info(&btrfs_new).unwrap_or_else(|e| {
                    panic!("[CONFORMANCE TIER A FAILURE] Step {step}: new renamed path '{new_norm}' file_info failed: {e}");
                });
                if let Some(entry) = model.get_entry(&new_norm) {
                    let (msec, _) = entry.mtime();
                    if msec != 0 {
                        assert_eq!(
                            info.mtime, msec as i64,
                            "[CONFORMANCE TIER A FAILURE] Step {step}: renamed '{new_norm}' mtime mismatch"
                        );
                    }
                }
            }
            DriverOp::Delete { path } => {
                let btrfs_p = to_btrfs_path(path);
                assert!(
                    fs.file_info(&btrfs_p).is_err(),
                    "[CONFORMANCE TIER A FAILURE] Step {step}: deleted path '{path}' still exists"
                );
            }
            DriverOp::SetMtime {
                path, mtime_sec, ..
            } => {
                let btrfs_p = to_btrfs_path(path);
                let info = fs.file_info(&btrfs_p).unwrap_or_else(|e| {
                    panic!("[CONFORMANCE TIER A FAILURE] Step {step}: file_info for '{path}' failed: {e}");
                });
                assert_eq!(
                    info.mtime, *mtime_sec as i64,
                    "[CONFORMANCE TIER A FAILURE] Step {step}: '{path}' mtime was not updated to {mtime_sec}"
                );
            }
            DriverOp::CommitAndRemount => {}
        }
    }

    let mut acct_report = None;

    // --- Tier B Verification (On Remount or Periodic Check) ---
    if is_remount {
        // Remount from device bytes
        let remounted = Btrfs::mount(mem_device.clone()).unwrap_or_else(|e| {
            panic!("[CONFORMANCE TIER B FAILURE] Step {step} remount failed: {e}");
        });

        // 1. Accounting Oracle assertions
        let report = AccountingOracle::assert_clean(&remounted);
        acct_report = Some(report);

        // 2. Full shadow model verification against remounted fs
        model.verify_against_fs(&remounted).unwrap_or_else(|e| {
            panic!("[CONFORMANCE TIER B FAILURE] Step {step} model verification failed after remount: {e}");
        });

        // Re-assign remounted instance
        *fs = remounted;
    }

    Ok(StepReport {
        step,
        op: op.clone(),
        succeeded: !skipped_full,
        skipped_full,
        all_trees_report: Some(all_trees),
        accounting_report: acct_report,
    })
}
