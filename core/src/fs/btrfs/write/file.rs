use crate::device::{ReadAt, WriteAt};
use crate::error::{LuksError, Result};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::batch::Batch;
use crate::fs::btrfs::write::commit::commit_transaction;
use crate::fs::btrfs::write::extent_tree::ExtentTree;
use crate::fs::btrfs::write::gate;
use crate::fs::btrfs::Btrfs;

/// State for one btrfs file whose contents arrive incrementally.
#[derive(Debug)]
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

    pub fn allocator(&self) -> &FreeSpaceMap {
        &self.allocator
    }
}

impl<D: ReadAt + WriteAt> Btrfs<D> {
    pub fn begin_file(&mut self, size: u64) -> Result<BtrfsFileWriter> {
        gate::check_writeable_fs(self.superblock())?;
        gate::check_writeable_subvolume(&self.fs_tree())?;

        if self.has_open_writer {
            return Err(LuksError::WriterBusy);
        }

        let sector_size = self.superblock().sector_size as u64;
        let disk_num_bytes = if size == 0 {
            0
        } else {
            ((size + sector_size - 1) / sector_size) * sector_size
        };

        if self.active_batch.is_none() {
            self.active_batch = Some(Batch::open(self)?);
        }
        let mut allocator = self.active_batch.as_ref().unwrap().allocator.clone();

        let mut total_free_data: u64 = allocator
            .block_groups
            .iter()
            .filter(|bg| crate::fs::btrfs::write::alloc::bg_holds_data(bg.block_group.flags))
            .map(|bg| bg.total_free_bytes)
            .sum();

        while total_free_data < disk_num_bytes {
            self.allocate_data_chunk_excluding(&[])?;
            let extent_tree = ExtentTree::read(self)?;
            allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
                &extent_tree,
                self.chunk_map(),
            )?;
            total_free_data = allocator
                .block_groups
                .iter()
                .filter(|bg| crate::fs::btrfs::write::alloc::bg_holds_data(bg.block_group.flags))
                .map(|bg| bg.total_free_bytes)
                .sum();
            if let Some(ref mut batch) = self.active_batch {
                batch.allocator = allocator.clone();
            }
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
                    self.allocate_data_chunk_excluding(&data_runs)?;
                    let extent_tree = ExtentTree::read(self)?;
                    allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(
                        &extent_tree,
                        self.chunk_map(),
                    )?;
                    for &(run_bytenr, run_len) in &data_runs {
                        allocator.mark_allocated(run_bytenr, run_len)?;
                    }
                    if let Some(ref mut batch) = self.active_batch {
                        batch.allocator = allocator.clone();
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if let Some(ref mut batch) = self.active_batch {
            batch.allocator = allocator.clone();
        }

        self.has_open_writer = true;

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
    /// from existing free space. If free space is exhausted, `write_chunk`
    /// returns `FilesystemFull` (Valve A).
    pub fn begin_file_streaming(&mut self) -> Result<BtrfsFileWriter> {
        gate::check_writeable_fs(self.superblock())?;
        gate::check_writeable_subvolume(&self.fs_tree())?;

        if self.has_open_writer {
            return Err(LuksError::WriterBusy);
        }

        if self.active_batch.is_none() {
            self.active_batch = Some(Batch::open(self)?);
        }
        let allocator = self.active_batch.as_ref().unwrap().allocator.clone();

        self.has_open_writer = true;

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
                            // Valve A: Refuse mid-stream chunk allocation.
                            // Return FilesystemFull instead of triggering allocate_data_chunk_excluding.
                            return Err(LuksError::FilesystemFull);
                        }
                        Err(e) => return Err(e),
                    }
                }
                if let Some(ref mut batch) = self.active_batch {
                    batch.allocator = writer.allocator.clone();
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

                let prev_bytenr = writer.checksums.pop().map(|(b, _)| b).unwrap_or(write_addr);

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
        writer: BtrfsFileWriter,
        parent_path: &str,
        name: &str,
    ) -> Result<u64> {
        self.has_open_writer = false;
        let mut batch = if let Some(b) = self.active_batch.take() {
            b
        } else {
            Batch::open_with_allocator(self, writer.allocator.clone())?
        };

        let mark = batch.mark();
        let ino_res = batch.add_writer(self, &writer, parent_path, name);

        match ino_res {
            Ok(ino) => {
                if batch.should_commit() {
                    let txn = batch.commit_and_rearm(self)?;
                    commit_transaction(self, txn)?;
                }
                self.active_batch = Some(batch);
                Ok(ino)
            }
            Err(e) => {
                batch.rollback(mark);
                for &(bytenr, run_len) in &writer.data_runs {
                    let _ = batch.allocator.free_data(bytenr, run_len);
                    batch.handed_out.remove(bytenr, run_len);
                }
                if batch.has_uncommitted_files() {
                    if let Ok(txn) = batch.commit_and_rearm(self) {
                        let _ = commit_transaction(self, txn);
                    }
                }
                self.active_batch = Some(batch);
                Err(e)
            }
        }
    }

    pub fn abandon_file(&mut self, writer: BtrfsFileWriter) {
        self.has_open_writer = false;
        if let Some(mut batch) = self.active_batch.take() {
            for &(bytenr, run_len) in &writer.data_runs {
                let _ = batch.allocator.free_data(bytenr, run_len);
                batch.handed_out.remove(bytenr, run_len);
            }
            if batch.has_uncommitted_files() {
                if let Ok(txn) = batch.commit_and_rearm(self) {
                    let _ = commit_transaction(self, txn);
                }
            }
            self.active_batch = Some(batch);
        }
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
        fs.commit_active_batch().expect("commit");

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
