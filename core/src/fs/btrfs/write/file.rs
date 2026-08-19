use std::collections::HashMap;

use crate::device::{ReadAt, WriteAt};
use crate::error::{LuksError, Result};
use crate::fs::btrfs::tree::{
    Key, DIR_INDEX_KEY, DIR_ITEM_KEY, EXTENT_DATA_KEY, FS_TREE_OBJECTID,
    INODE_ITEM_KEY, INODE_REF_KEY,
};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::commit::commit_transaction;
use crate::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use crate::fs::btrfs::write::extent_tree::ExtentTree;
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::write::node;
use crate::fs::btrfs::write::txn::{find_max_inode, record_cow_result, converge_and_finalize};
use crate::fs::btrfs::Btrfs;

/// State for one btrfs file whose contents arrive incrementally.
pub struct BtrfsFileWriter {
    pub(crate) size: u64,
    pub(crate) written_bytes: u64,
    pub(crate) data_runs: Vec<(u64, u64)>, // (logical_bytenr, num_bytes)
    pub checksums: Vec<(u64, u32)>,        // (logical_bytenr, crc32c)
    pub(crate) allocator: FreeSpaceMap,
    pub(crate) is_streaming: bool,
    pub(crate) tail_buf: Vec<u8>,
}

impl BtrfsFileWriter {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn written_bytes(&self) -> u64 {
        self.written_bytes
    }

    pub fn data_runs(&self) -> &[(u64, u64)] {
        &self.data_runs
    }

    pub fn is_streaming(&self) -> bool {
        self.is_streaming
    }
}

impl<D: ReadAt + WriteAt> Btrfs<D> {
    pub fn begin_file(&mut self, size: u64) -> Result<BtrfsFileWriter> {
        gate::check_writeable_fs(self.superblock())?;
        gate::check_writeable_subvolume(&self.fs_tree())?;

        let extent_tree = ExtentTree::read(self)?;
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, self.chunk_map())?;

        let sector_size = self.superblock().sector_size as u64;
        let disk_num_bytes = if size == 0 {
            0
        } else {
            ((size + sector_size - 1) / sector_size) * sector_size
        };

        let mut total_free_data: u64 = allocator
            .block_groups
            .iter()
            .filter(|bg| {
                (bg.block_group.flags & crate::fs::btrfs::chunk::BLOCK_GROUP_DATA != 0)
                    || (bg.block_group.flags
                        & (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA
                            | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                        != 0)
            })
            .map(|bg| bg.total_free_bytes)
            .sum();

        while total_free_data < disk_num_bytes {
            self.allocate_data_chunk()?;
            let extent_tree = ExtentTree::read(self)?;
            allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
                &extent_tree,
                self.chunk_map(),
            )?;
            total_free_data = allocator
                .block_groups
                .iter()
                .filter(|bg| {
                    (bg.block_group.flags & crate::fs::btrfs::chunk::BLOCK_GROUP_DATA != 0)
                        || (bg.block_group.flags
                            & (crate::fs::btrfs::chunk::BLOCK_GROUP_DATA
                                | crate::fs::btrfs::chunk::BLOCK_GROUP_METADATA)
                            != 0)
                })
                .map(|bg| bg.total_free_bytes)
                .sum();
        }

        let mut data_runs = Vec::new();
        let mut allocated = 0u64;
        while allocated < disk_num_bytes {
            let remaining = disk_num_bytes - allocated;
            match allocator.allocate_data_chunk(remaining, sector_size as u32) {
                Ok((bytenr, chunk_len)) => {
                    data_runs.push((bytenr, chunk_len));
                    allocated += chunk_len;
                }
                Err(LuksError::FilesystemFull) => {
                    self.allocate_data_chunk()?;
                    let extent_tree = ExtentTree::read(self)?;
                    allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
                        &extent_tree,
                        self.chunk_map(),
                    )?;
                    for &(run_bytenr, run_len) in &data_runs {
                        allocator.mark_allocated(run_bytenr, run_len)?;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(BtrfsFileWriter {
            size,
            written_bytes: 0,
            data_runs,
            checksums: Vec::new(),
            allocator,
            is_streaming: false,
            tail_buf: Vec::new(),
        })
    }

    /// Begin an unknown-size streaming file write.
    ///
    /// Extents are allocated dynamically in `write_chunk` as data arrives,
    /// triggering chunk allocation if existing block groups fill up.
    pub fn begin_file_streaming(&mut self) -> Result<BtrfsFileWriter> {
        gate::check_writeable_fs(self.superblock())?;
        gate::check_writeable_subvolume(&self.fs_tree())?;

        let extent_tree = ExtentTree::read(self)?;
        let allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, self.chunk_map())?;

        Ok(BtrfsFileWriter {
            size: 0,
            written_bytes: 0,
            data_runs: Vec::new(),
            checksums: Vec::new(),
            allocator,
            is_streaming: true,
            tail_buf: Vec::new(),
        })
    }

    pub fn write_chunk(&mut self, writer: &mut BtrfsFileWriter, data: &[u8]) -> Result<()> {
        let end = writer
            .written_bytes
            .checked_add(data.len() as u64)
            .ok_or(LuksError::OutOfBounds)?;

        if writer.is_streaming {
            let total_allocated: u64 = writer.data_runs.iter().map(|(_, len)| *len).sum();
            if end > total_allocated {
                let sector_size = self.superblock().sector_size as u64;
                let needed_more = end - total_allocated;
                let disk_num_bytes = ((needed_more + sector_size - 1) / sector_size) * sector_size;
                let mut allocated_new = 0u64;

                while allocated_new < disk_num_bytes {
                    let remaining = disk_num_bytes - allocated_new;
                    match writer.allocator.allocate_data_chunk(remaining, sector_size as u32) {
                        Ok((bytenr, chunk_len)) => {
                            writer.data_runs.push((bytenr, chunk_len));
                            allocated_new += chunk_len;
                        }
                        Err(LuksError::FilesystemFull) => {
                            self.allocate_data_chunk()?;
                            let extent_tree = ExtentTree::read(self)?;
                            writer.allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
                                &extent_tree,
                                self.chunk_map(),
                            )?;
                            for &(run_bytenr, run_len) in &writer.data_runs {
                                writer.allocator.mark_allocated(run_bytenr, run_len)?;
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        } else if end > writer.size {
            return Err(LuksError::OutOfBounds);
        }

        let sector_size = self.superblock().sector_size as usize;
        let mut remaining = data;
        let mut written_so_far = writer.written_bytes;
        let mut file_cursor = 0u64;

        for &(bytenr, run_len) in &writer.data_runs {
            let run_file_start = file_cursor;
            let run_file_end = file_cursor + run_len;
            file_cursor = run_file_end;

            if written_so_far >= run_file_end {
                continue;
            }

            let offset_in_run = written_so_far - run_file_start;
            let space_in_run = run_len - offset_in_run;
            let take = (space_in_run.min(remaining.len() as u64)) as usize;
            let chunk = &remaining[..take];
            let write_addr = bytenr + offset_in_run;

            // 1. Handle unaligned tail from previous write_chunk if present
            let mut chunk_offset = 0usize;
            if !writer.tail_buf.is_empty() {
                let tail_len = writer.tail_buf.len();
                let needed = sector_size - tail_len;
                let take_tail = needed.min(chunk.len());
                let tail_data = &chunk[..take_tail];
                writer.tail_buf.extend_from_slice(tail_data);
                chunk_offset += take_tail;

                // Write the tail continuation to disk
                let mut done = 0usize;
                while done < tail_data.len() {
                    let logical_cur = write_addr + done as u64;
                    let (_, run) = self.chunk_map().map(logical_cur)?;
                    let take_stripe = (tail_data.len() - done).min(run as usize);
                    let stripes = self.chunk_map().map_all_stripes(logical_cur)?;
                    for phys_stripe in stripes {
                        self.device_mut().write_at(
                            phys_stripe,
                            &tail_data[done..done + take_stripe],
                        )?;
                    }
                    done += take_stripe;
                }

                let (prev_bytenr, _) = writer.checksums.pop().expect("checksum entry for tail");

                if writer.tail_buf.len() == sector_size {
                    let crc = crate::fs::btrfs::crc32c::crc32c(&writer.tail_buf);
                    writer.checksums.push((prev_bytenr, crc));
                    writer.tail_buf.clear();
                } else {
                    let mut sector_buf = vec![0u8; sector_size];
                    sector_buf[..writer.tail_buf.len()].copy_from_slice(&writer.tail_buf);
                    let crc = crate::fs::btrfs::crc32c::crc32c(&sector_buf);
                    writer.checksums.push((prev_bytenr, crc));
                }
            }

            // 2. Main aligned body
            let aligned_len = (chunk.len() - chunk_offset) / sector_size * sector_size;
            if aligned_len > 0 {
                let aligned_start_addr = write_addr + chunk_offset as u64;
                let aligned_data = &chunk[chunk_offset..chunk_offset + aligned_len];

                let mut done = 0usize;
                while done < aligned_len {
                    let logical_cur = aligned_start_addr + done as u64;
                    let (_, run) = self.chunk_map().map(logical_cur)?;
                    let take_stripe = (aligned_len - done).min(run as usize);
                    let stripes = self.chunk_map().map_all_stripes(logical_cur)?;
                    for phys_stripe in stripes {
                        self.device_mut().write_at(
                            phys_stripe,
                            &aligned_data[done..done + take_stripe],
                        )?;
                    }
                    done += take_stripe;
                }

                for i in (0..aligned_len).step_by(sector_size) {
                    let sector_bytenr = aligned_start_addr + i as u64;
                    let crc = crate::fs::btrfs::crc32c::crc32c(
                        &aligned_data[i..i + sector_size],
                    );
                    writer.checksums.push((sector_bytenr, crc));
                }

                chunk_offset += aligned_len;
            }

            // 3. Trailing partial sector
            if chunk.len() > chunk_offset {
                let rem_len = chunk.len() - chunk_offset;
                let sector_bytenr = write_addr + chunk_offset as u64;
                let rem_data = &chunk[chunk_offset..chunk_offset + rem_len];

                writer.tail_buf.clear();
                writer.tail_buf.extend_from_slice(rem_data);

                let mut sector_buf = vec![0u8; sector_size];
                sector_buf[..rem_len].copy_from_slice(rem_data);

                let mut done = 0usize;
                while done < sector_size {
                    let logical_cur = sector_bytenr + done as u64;
                    let (_, run) = self.chunk_map().map(logical_cur)?;
                    let take_stripe = (sector_size - done).min(run as usize);
                    let stripes = self.chunk_map().map_all_stripes(logical_cur)?;
                    for phys_stripe in stripes {
                        self.device_mut().write_at(
                            phys_stripe,
                            &sector_buf[done..done + take_stripe],
                        )?;
                    }
                    done += take_stripe;
                }

                let crc = crate::fs::btrfs::crc32c::crc32c(&sector_buf);
                writer.checksums.push((sector_bytenr, crc));
            }

            written_so_far += take as u64;
            remaining = &remaining[take..];
            if remaining.is_empty() {
                break;
            }
        }

        writer.written_bytes = end;
        if writer.is_streaming {
            writer.size = writer.written_bytes;
        }
        Ok(())
    }

    pub fn finish_file(
        &mut self,
        mut writer: BtrfsFileWriter,
        parent_path: &str,
        name: &str,
    ) -> Result<u64> {
        if !writer.is_streaming && writer.written_bytes != writer.size {
            return Err(LuksError::OutOfBounds);
        }
        if writer.is_streaming {
            writer.size = writer.written_bytes;
        }

        let located_parent = self.resolve_no_follow(self.fs_tree(), parent_path)?;
        if !located_parent.inode.file_type().is_dir() {
            return Err(LuksError::NotADirectory(parent_path.to_string()));
        }
        if located_parent.tree.objectid != FS_TREE_OBJECTID {
            return Err(LuksError::UnsupportedFsFeature(
                "subvolume file creation not yet supported".into(),
            ));
        }
        let parent_ino = located_parent.inode.objectid;

        // Check if exists
        let name_hash = crate::fs::btrfs::crc32c::name_hash(name.as_bytes());
        let dir_item_key = Key::new(parent_ino, DIR_ITEM_KEY, name_hash);
        if let Some(item_data) = self.find_item(self.fs_tree().bytenr, &dir_item_key)? {
            let entries = crate::fs::btrfs::inode::parse_dir_entries(&item_data)?;
            if entries.iter().any(|e| e.name == name.as_bytes()) {
                return Err(LuksError::AlreadyExists(format!(
                    "file '{}' already exists in '{}'",
                    name, parent_path
                )));
            }
        }

        let sb = self.superblock();
        let new_generation = sb.generation + 1;

        // Use the passed allocator
        let mut allocator = writer.allocator;
        let mut pending_blocks = HashMap::new();
        let mut blocks_to_add = Vec::new();
        let mut blocks_to_remove = Vec::new();
        let mut data_extents_to_add = Vec::new();
        
        let max_ino = find_max_inode(self)?;
        let new_ino = if max_ino < 256 { 256 } else { max_ino + 1 };

        let mut max_dir_index = 1u64;
        self.for_each_item(self.fs_tree().bytenr, parent_ino, DIR_INDEX_KEY, &mut |key, _| {
            if key.offset > max_dir_index { max_dir_index = key.offset; }
            Ok(true)
        })?;
        let dir_index = max_dir_index + 1;

        let mut fs_root_bytenr = self.fs_tree().bytenr;
        let mut fs_root_level = self.fs_tree().level;

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let now_sec = now.as_secs();
        let now_nsec = now.subsec_nanos();

        // 1. Update parent directory INODE_ITEM
        let parent_inode_key = Key::new(parent_ino, INODE_ITEM_KEY, 0);
        let name_len = name.len() as u64;
        let res = cow_tree_mutate(
            self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID,
            &parent_inode_key, new_generation, &mut allocator, |leaf| {
                let idx = leaf.find_item(&parent_inode_key).unwrap();
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
        record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
        fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;

        // 2. Insert DIR_ITEM
        let dir_item_data = node::build_dir_item(new_ino, new_generation, 1, name);
        let res = cow_tree_insert(self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID, dir_item_key, dir_item_data.clone(), new_generation, &mut allocator)?;
        record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
        fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;

        // 3. Insert DIR_INDEX
        let dir_index_key = Key::new(parent_ino, DIR_INDEX_KEY, dir_index);
        let res = cow_tree_insert(self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID, dir_index_key, dir_item_data, new_generation, &mut allocator)?;
        record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
        fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;

        // 4. Insert new INODE_ITEM
        let inode_key = Key::new(new_ino, INODE_ITEM_KEY, 0);
        let mode = 0o100644; // Regular file
        let total_disk_bytes: u64 = writer.data_runs.iter().map(|(_, len)| *len).sum();
        let inode_data = {
            let mut data = node::build_empty_inode_item(
                new_generation,
                mode,
                located_parent.inode.uid,
                located_parent.inode.gid,
                1,
                now_sec,
                now_nsec,
            );
            data[16..24].copy_from_slice(&writer.size.to_le_bytes()); // size
            data[24..32].copy_from_slice(&total_disk_bytes.to_le_bytes()); // nbytes
            data
        };
        let res = cow_tree_insert(self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID, inode_key, inode_data, new_generation, &mut allocator)?;
        record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
        fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;

        // 5. Insert INODE_REF
        let inode_ref_key = Key::new(new_ino, INODE_REF_KEY, parent_ino);
        let inode_ref_data = node::build_inode_ref(dir_index, name);
        let res = cow_tree_insert(self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID, inode_ref_key, inode_ref_data, new_generation, &mut allocator)?;
        record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
        fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;

        // 6. Insert EXTENT_DATA (if any)
        let mut file_offset = 0u64;
        for &(bytenr, run_len) in &writer.data_runs {
            if run_len > 0 {
                let extent_data_key = Key::new(new_ino, EXTENT_DATA_KEY, file_offset);
                let extent_data_item = node::build_regular_file_extent(new_generation, run_len, bytenr, run_len, run_len);
                let res = cow_tree_insert(self, &pending_blocks, fs_root_bytenr, fs_root_level, FS_TREE_OBJECTID, extent_data_key, extent_data_item, new_generation, &mut allocator)?;
                record_cow_result(&res, &mut blocks_to_add, &mut blocks_to_remove, &mut allocator, &mut pending_blocks, sb.node_size, FS_TREE_OBJECTID)?;
                fs_root_bytenr = res.new_root_bytenr; fs_root_level = res.new_root_level;
                data_extents_to_add.push((bytenr, run_len, FS_TREE_OBJECTID, new_ino, file_offset));
                file_offset += run_len;
            }
        }

        let mut new_fs_tree = self.fs_tree();
        new_fs_tree.bytenr = fs_root_bytenr;
        new_fs_tree.level = fs_root_level;
        new_fs_tree.generation = new_generation;

        // 7. CoW CSUM_TREE: insert the EXTENT_CSUM items covering all data runs (if CSUM tree is present)
        let mut csum_root_opt = None;
        if let Ok(csum_root) = self.tree_root(crate::fs::btrfs::tree::CSUM_TREE_OBJECTID) {
            let mut csum_root_bytenr = csum_root.bytenr;
            let mut csum_root_level = csum_root.level;

            if !writer.checksums.is_empty() {
                let csum_items = node::build_extent_csum_items_from_checksums(
                    sb.node_size,
                    &writer.checksums,
                )?;

                for (range_start, csum_payload) in csum_items {
                    let csum_key = Key::new(
                        crate::fs::btrfs::tree::EXTENT_CSUM_OBJECTID,
                        crate::fs::btrfs::tree::EXTENT_CSUM_KEY,
                        range_start,
                    );
                    let res = cow_tree_insert(
                        self,
                        &pending_blocks,
                        csum_root_bytenr,
                        csum_root_level,
                        crate::fs::btrfs::tree::CSUM_TREE_OBJECTID,
                        csum_key,
                        csum_payload,
                        new_generation,
                        &mut allocator,
                    )?;
                    record_cow_result(
                        &res,
                        &mut blocks_to_add,
                        &mut blocks_to_remove,
                        &mut allocator,
                        &mut pending_blocks,
                        sb.node_size,
                        crate::fs::btrfs::tree::CSUM_TREE_OBJECTID,
                    )?;
                    csum_root_bytenr = res.new_root_bytenr;
                    csum_root_level = res.new_root_level;
                }
                csum_root_opt = Some((csum_root_bytenr, csum_root_level));
            }
        }

        let txn = converge_and_finalize(
            self, new_generation, new_fs_tree, csum_root_opt, None, None, None,
            pending_blocks, Vec::new(), allocator, blocks_to_add, blocks_to_remove, data_extents_to_add,
            Vec::new(),
        )?;

        commit_transaction(self, txn)?;
        Ok(new_ino)
    }

    pub fn abandon_file(&mut self, _writer: BtrfsFileWriter) {
        // Safe to drop; extents mapped in memory but not linked to any tree yet, so they leak only in this run but will be valid on remount.
        // The real way to handle this without a transaction is just drop, as they aren't recorded in the extent tree.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::FileDevice;
    use crate::fs::btrfs::extent::ExtentKind;
    use crate::fs::btrfs::write::alloc::FreeRange;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("fixtures")
            .join("btrfs")
            .join(name)
    }

    fn copy_scratch(name: &str) -> std::path::PathBuf {
        let src = fixture_path(name);
        let temp_dir = std::env::temp_dir();
        let dst = temp_dir.join(format!(
            "btrfs-file-test-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::copy(&src, &dst).expect("copy fixture");
        dst
    }

    #[test]
    fn write_file_across_fragmented_extents_in_file_writer() {
        let temp_img = copy_scratch("plain.img");
        let file_len = std::fs::metadata(&temp_img).unwrap().len();

        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable");

        // 1. Read extent tree to derive base allocator
        let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
        let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map()).expect("derive allocator");

        // 2. Simulate fragmented free space in the DATA block group (plain.img DATA bg is 13_631_488..22_020_096):
        // Split free space into 3 small disjoint ranges:
        // Range 1: 16_777_216 .. 16_793_600 (16 KB)
        // Range 2: 17_825_792 .. 17_858_560 (32 KB)
        // Range 3: 18_874_368 .. 18_890_752 (16 KB)
        allocator.block_groups[0].free_ranges = vec![
            FreeRange {
                start: 16_777_216,
                length: 16_384,
            },
            FreeRange {
                start: 17_825_792,
                length: 32_768,
            },
            FreeRange {
                start: 18_874_368,
                length: 16_384,
            },
        ];
        allocator.block_groups[0].total_free_bytes = 16_384 + 32_768 + 16_384;

        let total_file_size = 49_152u64; // 48 KB: requires 32 KB from Range 2 + 16 KB from Range 1
        let sector_size = fs.superblock().sector_size;

        // Allocate chunks for the file
        let mut data_runs = Vec::new();
        let mut allocated = 0u64;
        while allocated < total_file_size {
            let remaining = total_file_size - allocated;
            let (bytenr, chunk_len) = allocator
                .allocate_data_chunk(remaining, sector_size)
                .expect("allocate chunk");
            data_runs.push((bytenr, chunk_len));
            allocated += chunk_len;
        }

        // Verify that allocation fragmented across 2 separate ranges
        assert_eq!(data_runs.len(), 2);
        assert_eq!(data_runs[0], (17_825_792, 32_768));
        assert_eq!(data_runs[1], (16_777_216, 16_384));

        let mut writer = BtrfsFileWriter {
            size: total_file_size,
            written_bytes: 0,
            data_runs,
            checksums: Vec::new(),
            allocator,
            is_streaming: false,
            tail_buf: Vec::new(),
        };

        // Prepare test payload (48 KB)
        let mut payload = vec![0u8; total_file_size as usize];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((i * 41 + 7) & 0xFF) as u8;
        }

        // Write across boundaries in odd chunk sizes (10_000, 25_000, remaining)
        fs.write_chunk(&mut writer, &payload[0..10_000])
            .expect("write chunk 1");
        assert_eq!(writer.written_bytes, 10_000);

        // Chunk 2 spans the boundary between run 0 (ends at 32768) and run 1
        fs.write_chunk(&mut writer, &payload[10_000..35_000])
            .expect("write chunk 2 (spanning boundary)");
        assert_eq!(writer.written_bytes, 35_000);

        fs.write_chunk(&mut writer, &payload[35_000..49_152])
            .expect("write chunk 3");
        assert_eq!(writer.written_bytes, 49_152);

        // Finish file
        let ino = fs
            .finish_file(writer, "/", "fragmented_test.bin")
            .expect("finish file");
        assert!(ino >= 256);

        // Verify reader sees correct file content
        let readback = fs.read_file("/fragmented_test.bin").expect("read file");
        assert_eq!(readback, payload);

        // Verify extents in fs_tree
        let found = fs
            .resolve_no_follow(fs.fs_tree(), "/fragmented_test.bin")
            .expect("resolve");
        let extents = fs
            .file_extents(found.tree.bytenr, found.inode.objectid)
            .expect("file extents");
        assert_eq!(extents.len(), 2);
        assert_eq!(extents[0].file_offset, 0);
        assert_eq!(extents[0].disk_bytenr, 17_825_792);
        assert_eq!(extents[0].num_bytes, 32_768);
        assert_eq!(extents[0].kind, ExtentKind::Regular);

        assert_eq!(extents[1].file_offset, 32_768);
        assert_eq!(extents[1].disk_bytenr, 16_777_216);
        assert_eq!(extents[1].num_bytes, 16_384);
        assert_eq!(extents[1].kind, ExtentKind::Regular);

        drop(fs);

        // Remount and check persistence
        let dev_ro = FileDevice::open(&temp_img).expect("open ro");
        let fs_ro = Btrfs::mount(dev_ro).expect("mount ro");
        let readback_ro = fs_ro
            .read_file("/fragmented_test.bin")
            .expect("read file ro");
        assert_eq!(readback_ro, payload);

        let _ = std::fs::remove_file(&temp_img);
    }
}
