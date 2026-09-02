//! Batch write transaction engine for Btrfs.
//!
//! A `Batch` maintains in-memory state (running roots, dirty `pending_blocks`,
//! allocator, and counters) across one or more file writes to eliminate redundant
//! full-tree scans and amortize transaction commit overhead.

use std::collections::HashMap;
use std::time::Instant;

use crate::device::WriteAt;
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{
    Key, DIR_INDEX_KEY, DIR_ITEM_KEY, EXTENT_DATA_KEY, FS_TREE_OBJECTID, INODE_ITEM_KEY,
    INODE_REF_KEY,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::extent_tree::{
    converge_and_finalize, find_item_in_tree, find_max_inode, record_cow_result, ExtentTree,
};
use crate::fs::btrfs::write::file::BtrfsFileWriter;
use crate::fs::btrfs::write::interval_set::IntervalSet;
use crate::fs::btrfs::write::node;
use crate::fs::btrfs::write::txn::Transaction;
use crate::fs::btrfs::Btrfs;

/// Snapshot of batch state taken before adding a file, enabling single-file rollback.
#[derive(Debug, Clone)]
pub struct FileMark {
    pub allocator: FreeSpaceMap,
    pub fs_root: (u64, u8),
    pub csum_root: Option<(u64, u8)>,
    pub pending_blocks: HashMap<u64, Vec<u8>>,
    pub blocks_to_add: Vec<(u64, u8, u64)>,
    pub blocks_to_remove: Vec<(u64, u8)>,
    pub data_extents_to_add: Vec<(u64, u64, u64, u64, u64)>,
    pub next_ino: u64,
    pub next_dir_index: HashMap<u64, u64>,
    pub handed_out: IntervalSet,
    pub accumulated_files: usize,
    pub accumulated_data_bytes: u64,
}

pub struct Batch {
    pub generation: u64,
    pub allocator: FreeSpaceMap,
    pub fs_root: (u64, u8),
    pub csum_root: Option<(u64, u8)>,
    pub pending_blocks: HashMap<u64, Vec<u8>>,
    pub blocks_to_add: Vec<(u64, u8, u64)>,
    pub blocks_to_remove: Vec<(u64, u8)>,
    pub data_extents_to_add: Vec<(u64, u64, u64, u64, u64)>,
    pub next_ino: u64,
    pub next_dir_index: HashMap<u64, u64>,
    pub parents: HashMap<String, (u64, u32, u32)>, // path -> (ino, uid, gid)
    pub handed_out: IntervalSet,
    pub accumulated_files: usize,
    pub accumulated_data_bytes: u64,
    pub start_time: Instant,
}

impl Batch {
    /// Open a new batch by scanning the filesystem's extent tree.
    pub fn open<D: WriteAt>(fs: &mut Btrfs<D>) -> Result<Self> {
        let ext_tree = ExtentTree::read(fs)?;
        let chunk_map = fs.chunk_map().clone();
        let allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&ext_tree, &chunk_map)?;
        Self::open_with_allocator(fs, allocator)
    }

    /// Open a new batch with a pre-existing FreeSpaceMap allocator.
    pub fn open_with_allocator<D: WriteAt>(
        fs: &mut Btrfs<D>,
        allocator: FreeSpaceMap,
    ) -> Result<Self> {
        let sb = fs.superblock();
        let generation = sb.generation + 1;
        let fs_tree = fs.fs_tree();
        let fs_root = (fs_tree.bytenr, fs_tree.level);

        let max_ino = find_max_inode(fs)?;
        let next_ino = if max_ino < 256 { 256 } else { max_ino + 1 };

        Ok(Self {
            generation,
            allocator,
            fs_root,
            csum_root: None,
            pending_blocks: HashMap::new(),
            blocks_to_add: Vec::new(),
            blocks_to_remove: Vec::new(),
            data_extents_to_add: Vec::new(),
            next_ino,
            next_dir_index: HashMap::new(),
            parents: HashMap::new(),
            handed_out: IntervalSet::new(),
            accumulated_files: 0,
            accumulated_data_bytes: 0,
            start_time: Instant::now(),
        })
    }

    /// Take a snapshot mark of current batch state before attempting to add a file.
    pub fn mark(&self) -> FileMark {
        FileMark {
            allocator: self.allocator.clone(),
            fs_root: self.fs_root,
            csum_root: self.csum_root,
            pending_blocks: self.pending_blocks.clone(),
            blocks_to_add: self.blocks_to_add.clone(),
            blocks_to_remove: self.blocks_to_remove.clone(),
            data_extents_to_add: self.data_extents_to_add.clone(),
            next_ino: self.next_ino,
            next_dir_index: self.next_dir_index.clone(),
            handed_out: self.handed_out.clone(),
            accumulated_files: self.accumulated_files,
            accumulated_data_bytes: self.accumulated_data_bytes,
        }
    }

    /// Roll back to a previously captured mark (reverting single failed file).
    pub fn rollback(&mut self, mark: FileMark) {
        self.allocator = mark.allocator;
        self.fs_root = mark.fs_root;
        self.csum_root = mark.csum_root;
        self.pending_blocks = mark.pending_blocks;
        self.blocks_to_add = mark.blocks_to_add;
        self.blocks_to_remove = mark.blocks_to_remove;
        self.data_extents_to_add = mark.data_extents_to_add;
        self.next_ino = mark.next_ino;
        self.next_dir_index = mark.next_dir_index;
        self.handed_out = mark.handed_out;
        self.accumulated_files = mark.accumulated_files;
        self.accumulated_data_bytes = mark.accumulated_data_bytes;
    }

    /// Whether this batch holds any uncommitted file mutations.
    pub fn has_uncommitted_files(&self) -> bool {
        self.accumulated_files > 0
            || !self.pending_blocks.is_empty()
            || !self.blocks_to_add.is_empty()
            || !self.blocks_to_remove.is_empty()
            || !self.data_extents_to_add.is_empty()
    }

    /// Check if batch commit threshold policy is satisfied:
    /// - 16 files
    /// - 8 MiB pending metadata memory
    /// - 64 MiB written data
    /// - 2.0s wall clock time
    pub fn should_commit(&self) -> bool {
        if self.accumulated_files >= 16 {
            return true;
        }
        let pending_bytes: usize = self.pending_blocks.values().map(|v| v.len()).sum();
        if pending_bytes >= 8 * 1024 * 1024 {
            return true;
        }
        if self.accumulated_data_bytes >= 64 * 1024 * 1024 {
            return true;
        }
        if self.start_time.elapsed() >= std::time::Duration::from_secs(2) {
            return true;
        }
        false
    }

    /// Record an allocated range in the double-allocation ledger guard.
    /// Fails immediately if an overlapping range was already handed out.
    pub fn record_allocation(&mut self, start: u64, length: u64) -> Result<()> {
        if !self.handed_out.insert(start, length) {
            return Err(LuksError::CorruptFs(
                "double allocation detected in batch allocation ledger",
            ));
        }
        Ok(())
    }

    /// Release an allocated range from the reservation ledger.
    /// Fails immediately with `CorruptFs` if the range was not present in the ledger.
    pub fn release_allocation(&mut self, start: u64, length: u64) -> Result<()> {
        if !self.handed_out.remove_exact(start, length) {
            return Err(LuksError::CorruptFs(
                "attempted to release allocation not present in reservation ledger",
            ));
        }
        Ok(())
    }

    /// Add a written file into this batch session via its writer.
    pub fn add_writer<D: WriteAt>(
        &mut self,
        fs: &mut Btrfs<D>,
        writer: &BtrfsFileWriter,
        parent_path: &str,
        name: &str,
    ) -> Result<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.add_writer_with_time(
            fs,
            writer,
            parent_path,
            name,
            now.as_secs(),
            now.subsec_nanos(),
        )
    }

    /// Add a written file into this batch session via its writer with deterministic timestamps.
    pub fn add_writer_with_time<D: WriteAt>(
        &mut self,
        fs: &mut Btrfs<D>,
        writer: &BtrfsFileWriter,
        parent_path: &str,
        name: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<u64> {
        self.add_file_internal(
            fs,
            writer.is_streaming,
            writer.written_bytes,
            writer.size,
            &writer.data_runs,
            &writer.checksums,
            parent_path,
            name,
            now_sec,
            now_nsec,
            true,
        )
    }

    /// Add a written file into this batch session.
    pub fn add_file<D: WriteAt>(
        &mut self,
        fs: &mut Btrfs<D>,
        is_streaming: bool,
        written_bytes: u64,
        declared_size: u64,
        data_runs: &[(u64, u64)],
        checksums: &[(u64, u32)],
        parent_path: &str,
        name: &str,
    ) -> Result<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.add_file_with_time(
            fs,
            is_streaming,
            written_bytes,
            declared_size,
            data_runs,
            checksums,
            parent_path,
            name,
            now.as_secs(),
            now.subsec_nanos(),
        )
    }

    /// Add a written file into this batch session with explicit timestamps.
    pub fn add_file_with_time<D: WriteAt>(
        &mut self,
        fs: &mut Btrfs<D>,
        is_streaming: bool,
        written_bytes: u64,
        declared_size: u64,
        data_runs: &[(u64, u64)],
        checksums: &[(u64, u32)],
        parent_path: &str,
        name: &str,
        now_sec: u64,
        now_nsec: u32,
    ) -> Result<u64> {
        self.add_file_internal(
            fs,
            is_streaming,
            written_bytes,
            declared_size,
            data_runs,
            checksums,
            parent_path,
            name,
            now_sec,
            now_nsec,
            false,
        )
    }

    fn add_file_internal<D: WriteAt>(
        &mut self,
        fs: &mut Btrfs<D>,
        is_streaming: bool,
        written_bytes: u64,
        declared_size: u64,
        data_runs: &[(u64, u64)],
        checksums: &[(u64, u32)],
        parent_path: &str,
        name: &str,
        now_sec: u64,
        now_nsec: u32,
        already_reserved: bool,
    ) -> Result<u64> {
        if !is_streaming && written_bytes != declared_size {
            return Err(LuksError::OutOfBounds);
        }
        let size = if is_streaming {
            written_bytes
        } else {
            declared_size
        };

        // Record data runs into double-allocation ledger (if not already reserved)
        // and promote reservations to batch allocator.
        for &(bytenr, run_len) in data_runs {
            if run_len > 0 {
                if !already_reserved {
                    self.record_allocation(bytenr, run_len)?;
                }
                self.allocator.mark_allocated(bytenr, run_len)?;
            }
        }

        let (parent_ino, parent_uid, parent_gid) =
            if let Some(&(ino, uid, gid)) = self.parents.get(parent_path) {
                (ino, uid, gid)
            } else {
                let located_parent = fs.resolve_no_follow(fs.fs_tree(), parent_path)?;
                if !located_parent.inode.file_type().is_dir() {
                    return Err(LuksError::NotADirectory(parent_path.to_string()));
                }
                if located_parent.tree.objectid != FS_TREE_OBJECTID {
                    return Err(LuksError::UnsupportedFsFeature(
                        "subvolume file creation not yet supported".into(),
                    ));
                }
                let ino = located_parent.inode.objectid;
                let uid = located_parent.inode.uid;
                let gid = located_parent.inode.gid;
                self.parents
                    .insert(parent_path.to_string(), (ino, uid, gid));
                (ino, uid, gid)
            };

        // Check if exists using pending-aware search
        let name_hash = crate::fs::btrfs::crc32c::name_hash(name.as_bytes());
        let dir_item_key = Key::new(parent_ino, DIR_ITEM_KEY, name_hash);
        if let Some(item_data) =
            find_item_in_tree(fs, &self.pending_blocks, self.fs_root.0, &dir_item_key)?
        {
            let entries = crate::fs::btrfs::inode::parse_dir_entries(&item_data)?;
            if entries.iter().any(|e| e.name == name.as_bytes()) {
                return Err(LuksError::AlreadyExists(format!(
                    "file '{}' already exists in '{}'",
                    name, parent_path
                )));
            }
        }

        let sb = fs.superblock();
        let node_size = sb.node_size as u64;
        let new_generation = self.generation;
        let new_ino = self.next_ino;
        self.next_ino += 1;

        let dir_index = if let Some(next_idx) = self.next_dir_index.get_mut(&parent_ino) {
            let idx = *next_idx;
            *next_idx += 1;
            idx
        } else {
            let mut max_dir_index = 1u64;
            fs.for_each_item(fs.fs_tree().bytenr, parent_ino, DIR_INDEX_KEY, &mut |key, _| {
                if key.offset > max_dir_index {
                    max_dir_index = key.offset;
                }
                Ok(true)
            })?;
            let idx = max_dir_index + 1;
            self.next_dir_index.insert(parent_ino, idx + 1);
            idx
        };

        let mut fs_root_bytenr = self.fs_root.0;
        let mut fs_root_level = self.fs_root.1;

        // 1. Update parent directory INODE_ITEM
        let parent_inode_key = Key::new(parent_ino, INODE_ITEM_KEY, 0);
        let name_len = name.len() as u64;
        let res = cow_tree_mutate(
            fs,
            &self.pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            &parent_inode_key,
            new_generation,
            &mut self.allocator,
            |leaf| {
                let idx = leaf
                    .find_item(&parent_inode_key)
                    .ok_or_else(|| LuksError::NotFound("parent inode not found in leaf".into()))?;
                let item = &mut leaf.items[idx].data;
                item[8..16].copy_from_slice(&new_generation.to_le_bytes());
                let cur_size = u64::from_le_bytes(item[16..24].try_into().unwrap());
                item[16..24].copy_from_slice(&(cur_size + name_len * 2).to_le_bytes());
                let seq = u64::from_le_bytes(item[72..80].try_into().unwrap()).wrapping_add(1);
                item[72..80].copy_from_slice(&seq.to_le_bytes());
                item[124..132].copy_from_slice(&now_sec.to_le_bytes());
                item[132..136].copy_from_slice(&now_nsec.to_le_bytes());
                item[136..144].copy_from_slice(&now_sec.to_le_bytes());
                item[144..148].copy_from_slice(&now_nsec.to_le_bytes());
                Ok(())
            },
        )?;
        for &(bytenr, _level) in &res.allocated {
            self.record_allocation(bytenr, node_size)?;
        }
        record_cow_result(
            &res,
            &mut self.blocks_to_add,
            &mut self.blocks_to_remove,
            &mut self.allocator,
            &mut self.pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 2. Insert DIR_ITEM
        let dir_item_data = node::build_dir_item(new_ino, new_generation, 1, name);
        let res = cow_tree_insert(
            fs,
            &self.pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            dir_item_key,
            dir_item_data.clone(),
            new_generation,
            &mut self.allocator,
        )?;
        for &(bytenr, _level) in &res.allocated {
            self.record_allocation(bytenr, node_size)?;
        }
        record_cow_result(
            &res,
            &mut self.blocks_to_add,
            &mut self.blocks_to_remove,
            &mut self.allocator,
            &mut self.pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 3. Insert DIR_INDEX
        let dir_index_key = Key::new(parent_ino, DIR_INDEX_KEY, dir_index);
        let res = cow_tree_insert(
            fs,
            &self.pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            dir_index_key,
            dir_item_data,
            new_generation,
            &mut self.allocator,
        )?;
        for &(bytenr, _level) in &res.allocated {
            self.record_allocation(bytenr, node_size)?;
        }
        record_cow_result(
            &res,
            &mut self.blocks_to_add,
            &mut self.blocks_to_remove,
            &mut self.allocator,
            &mut self.pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 4. Insert new INODE_ITEM
        let inode_key = Key::new(new_ino, INODE_ITEM_KEY, 0);
        let mode = 0o100644; // Regular file
        let total_disk_bytes: u64 = data_runs.iter().map(|(_, len)| *len).sum();
        let inode_data = {
            let mut data = node::build_empty_inode_item(
                new_generation,
                mode,
                parent_uid,
                parent_gid,
                1,
                now_sec,
                now_nsec,
            );
            data[16..24].copy_from_slice(&size.to_le_bytes()); // size
            data[24..32].copy_from_slice(&total_disk_bytes.to_le_bytes()); // nbytes
            data
        };
        let res = cow_tree_insert(
            fs,
            &self.pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            inode_key,
            inode_data,
            new_generation,
            &mut self.allocator,
        )?;
        for &(bytenr, _level) in &res.allocated {
            self.record_allocation(bytenr, node_size)?;
        }
        record_cow_result(
            &res,
            &mut self.blocks_to_add,
            &mut self.blocks_to_remove,
            &mut self.allocator,
            &mut self.pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 5. Insert INODE_REF
        let inode_ref_key = Key::new(new_ino, INODE_REF_KEY, parent_ino);
        let inode_ref_data = node::build_inode_ref(dir_index, name);
        let res = cow_tree_insert(
            fs,
            &self.pending_blocks,
            fs_root_bytenr,
            fs_root_level,
            FS_TREE_OBJECTID,
            inode_ref_key,
            inode_ref_data,
            new_generation,
            &mut self.allocator,
        )?;
        for &(bytenr, _level) in &res.allocated {
            self.record_allocation(bytenr, node_size)?;
        }
        record_cow_result(
            &res,
            &mut self.blocks_to_add,
            &mut self.blocks_to_remove,
            &mut self.allocator,
            &mut self.pending_blocks,
            sb.node_size,
            FS_TREE_OBJECTID,
        )?;
        fs_root_bytenr = res.new_root_bytenr;
        fs_root_level = res.new_root_level;

        // 6. Insert EXTENT_DATA (if any)
        let mut file_offset = 0u64;
        for &(bytenr, run_len) in data_runs {
            if run_len > 0 {
                let extent_data_key = Key::new(new_ino, EXTENT_DATA_KEY, file_offset);
                let extent_data_item = node::build_regular_file_extent(
                    new_generation,
                    run_len,
                    bytenr,
                    run_len,
                    run_len,
                );
                let res = cow_tree_insert(
                    fs,
                    &self.pending_blocks,
                    fs_root_bytenr,
                    fs_root_level,
                    FS_TREE_OBJECTID,
                    extent_data_key,
                    extent_data_item,
                    new_generation,
                    &mut self.allocator,
                )?;
                for &(bytenr, _level) in &res.allocated {
                    self.record_allocation(bytenr, node_size)?;
                }
                record_cow_result(
                    &res,
                    &mut self.blocks_to_add,
                    &mut self.blocks_to_remove,
                    &mut self.allocator,
                    &mut self.pending_blocks,
                    sb.node_size,
                    FS_TREE_OBJECTID,
                )?;
                fs_root_bytenr = res.new_root_bytenr;
                fs_root_level = res.new_root_level;
                self.data_extents_to_add.push((
                    bytenr,
                    run_len,
                    FS_TREE_OBJECTID,
                    new_ino,
                    file_offset,
                ));
                file_offset += run_len;
            }
        }

        self.fs_root = (fs_root_bytenr, fs_root_level);

        // 7. CoW CSUM_TREE: insert EXTENT_CSUM items covering all data runs (if CSUM tree is present and non-empty)
        if !checksums.is_empty() {
            if let Ok(csum_root) = fs.tree_root(crate::fs::btrfs::tree::CSUM_TREE_OBJECTID) {
                let mut csum_root_bytenr =
                    self.csum_root.map(|(b, _)| b).unwrap_or(csum_root.bytenr);
                let mut csum_root_level = self.csum_root.map(|(_, l)| l).unwrap_or(csum_root.level);

                let csum_items =
                    node::build_extent_csum_items_from_checksums(sb.node_size, checksums)?;

                for (range_start, csum_payload) in csum_items {
                    let csum_key = Key::new(
                        crate::fs::btrfs::tree::EXTENT_CSUM_OBJECTID,
                        crate::fs::btrfs::tree::EXTENT_CSUM_KEY,
                        range_start,
                    );
                    let res = cow_tree_insert(
                        fs,
                        &self.pending_blocks,
                        csum_root_bytenr,
                        csum_root_level,
                        crate::fs::btrfs::tree::CSUM_TREE_OBJECTID,
                        csum_key,
                        csum_payload,
                        new_generation,
                        &mut self.allocator,
                    )?;
                    for &(bytenr, _level) in &res.allocated {
                        self.record_allocation(bytenr, node_size)?;
                    }
                    record_cow_result(
                        &res,
                        &mut self.blocks_to_add,
                        &mut self.blocks_to_remove,
                        &mut self.allocator,
                        &mut self.pending_blocks,
                        sb.node_size,
                        crate::fs::btrfs::tree::CSUM_TREE_OBJECTID,
                    )?;
                    csum_root_bytenr = res.new_root_bytenr;
                    csum_root_level = res.new_root_level;
                }
                self.csum_root = Some((csum_root_bytenr, csum_root_level));
            }
        }

        self.accumulated_files += 1;
        self.accumulated_data_bytes += size;

        Ok(new_ino)
    }

    /// Commit the current batch state to disk and re-arm the batch for the next file
    /// while preserving the cached allocator, next_ino, next_dir_index, and parent directory cache.
    pub fn commit_and_rearm<D: WriteAt>(&mut self, fs: &mut Btrfs<D>) -> Result<Transaction> {
        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = self.fs_root.0;
        new_fs_tree.level = self.fs_root.1;
        new_fs_tree.generation = self.generation;

        // `converge_and_finalize` reads the current trees and can fail before
        // it returns a transaction. Keep the live batch untouched until it
        // succeeds; otherwise a later commit can retain an allocator `used`
        // counter while losing the matching extent-tree deltas.
        let txn = converge_and_finalize(
            fs,
            self.generation,
            new_fs_tree,
            self.csum_root,
            None,
            None,
            None,
            self.pending_blocks.clone(),
            Vec::new(),
            self.allocator.clone(),
            self.blocks_to_add.clone(),
            self.blocks_to_remove.clone(),
            self.data_extents_to_add.clone(),
            Vec::new(),
        )?;

        if let Some(ref final_alloc) = txn.final_allocator {
            self.allocator = final_alloc.clone();
            self.allocator.unpin_freed();
        }
        self.pending_blocks.clear();
        self.blocks_to_add.clear();
        self.blocks_to_remove.clear();
        self.data_extents_to_add.clear();
        self.fs_root = (txn.new_fs_tree.bytenr, txn.new_fs_tree.level);
        self.csum_root = None;
        self.generation = txn.new_generation;
        self.handed_out.clear();
        self.accumulated_files = 0;
        self.accumulated_data_bytes = 0;
        self.start_time = Instant::now();

        Ok(txn)
    }

    /// Commit the batch into a Transaction ready to be committed to disk.
    pub fn commit<D: WriteAt>(self, fs: &mut Btrfs<D>) -> Result<Transaction> {
        let mut new_fs_tree = fs.fs_tree();
        new_fs_tree.bytenr = self.fs_root.0;
        new_fs_tree.level = self.fs_root.1;
        new_fs_tree.generation = self.generation;

        converge_and_finalize(
            fs,
            self.generation,
            new_fs_tree,
            self.csum_root,
            None,
            None,
            None,
            self.pending_blocks,
            Vec::new(),
            self.allocator,
            self.blocks_to_add,
            self.blocks_to_remove,
            self.data_extents_to_add,
            Vec::new(),
        )
    }
}
