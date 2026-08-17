//! Integration tests for `statfs` across ext4 and btrfs, and ext4 directory ceiling measurement.
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test statfs
//! ```
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;

fn ext4_fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn btrfs_fixture(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn ext4_scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-statfs-{test}-{name}"));
    std::fs::copy(ext4_fixture(name), &dst).expect("copy ext4 fixture");
    dst.to_string_lossy().into_owned()
}

fn btrfs_scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("btrfs-statfs-{test}-{name}"));
    std::fs::copy(btrfs_fixture(name), &dst).expect("copy btrfs fixture");
    dst.to_string_lossy().into_owned()
}

fn open_ext4(path: &str) -> Ext4<FileDevice> {
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Ext4::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

fn open_btrfs(path: &str) -> Btrfs<FileDevice> {
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Btrfs::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

#[test]
fn ext4_statfs_matches_superblock_and_df_semantics() {
    let fixtures = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img", "small-1k.img"];

    for name in fixtures {
        let path = ext4_scratch(name, "statfs-verify");
        let fs = open_ext4(&path);
        let stat = fs.statfs().expect("statfs");

        let sb = fs.superblock();
        let bs = sb.block_size as u64;

        assert_eq!(stat.block_size, sb.block_size);
        assert_eq!(stat.total_bytes, sb.blocks_count * bs);
        assert_eq!(stat.free_bytes, sb.free_blocks_count * bs);
        let expected_avail = sb.free_blocks_count.saturating_sub(sb.s_r_blocks_count) * bs;
        assert_eq!(stat.available_bytes, expected_avail);
        assert_eq!(stat.total_inodes, sb.inodes_count as u64);
        assert_eq!(stat.free_inodes, sb.free_inodes_count as u64);
        assert!(stat.available_bytes <= stat.free_bytes);
        assert!(stat.free_bytes <= stat.total_bytes);
    }
}

#[test]
fn btrfs_statfs_computes_bounded_available_bytes() {
    let fixtures = ["plain.img", "mixed-4k.img", "compress.img"];

    for name in fixtures {
        let path = btrfs_scratch(name, "statfs-verify");
        let fs = open_btrfs(&path);
        let stat = fs.statfs().expect("btrfs statfs");

        let sb = fs.superblock();
        assert_eq!(stat.block_size, sb.sector_size);
        assert_eq!(stat.total_bytes, sb.total_bytes);
        assert!(stat.available_bytes <= stat.free_bytes, "available {} <= free {}", stat.available_bytes, stat.free_bytes);
        assert!(stat.free_bytes <= stat.total_bytes, "free {} <= total {}", stat.free_bytes, stat.total_bytes);
        assert!(stat.available_bytes > 0, "available bytes should be positive on test fixture");
    }
}

#[test]
fn ext4_statfs_write_reported_available_bytes_succeeds() {
    let path = ext4_scratch("big-4k.img", "write-avail");
    let mut fs = open_ext4(&path);
    let stat = fs.statfs().expect("statfs");

    // Write a test file within reported available bytes
    let write_size = (stat.available_bytes / 4).min(2 * 1024 * 1024) as usize;
    let data = vec![0xABu8; write_size];

    let ino = fs.create_file(2, "avail_test.bin", &data, FileType::Regular)
        .expect("write within reported available bytes must not fail with FilesystemFull");
    assert!(ino > 0);

    let stat_after = fs.statfs().expect("statfs after write");
    assert!(stat_after.free_bytes < stat.free_bytes);
    assert!(stat_after.available_bytes < stat.available_bytes);
}

#[test]
fn btrfs_statfs_write_reported_available_bytes_succeeds() {
    let path = btrfs_scratch("plain.img", "write-avail");
    let mut fs = open_btrfs(&path);
    let stat = fs.statfs().expect("btrfs statfs");

    // Write a test file within reported available bytes
    let write_size = (stat.available_bytes / 8).min(1024 * 1024) as usize;
    let data = vec![0xCDu8; write_size];

    let ino = fs.create_file_with_data("/", "avail_btrfs.bin", &data)
        .expect("write within reported available bytes must not fail with FilesystemFull");
    assert!(ino >= 256);

    let stat_after = fs.statfs().expect("statfs after write");
    assert!(stat_after.available_bytes < stat.available_bytes || stat_after.free_bytes < stat.free_bytes);
}

/// Measurement of ext4 directory capacity ceiling:
/// How many entries fit before block slack is exhausted or htree conversion is required.
///
/// On a 4 KiB block ext4 filesystem (`big-4k.img`):
/// - Usable directory block bytes = 4096 - 12 ('.') - 12 ('..') - 12 (csum tail) = 4060 bytes.
/// - With 10-byte filenames (`f_0000.txt` -> 8-byte dirent header + 10 bytes name + 2 bytes pad = 20 bytes/entry):
///   Ceiling is exactly 203 entries (203 * 20 = 4060 bytes).
///
/// On a 1 KiB block ext4 filesystem (`many-groups-1k.img`):
/// - Usable directory block bytes = 1024 - 12 ('.') - 12 ('..') - 12 (csum tail) = 988 bytes.
/// - With 10-byte filenames (20 bytes/entry):
///   Ceiling is exactly 49 entries (49 * 20 = 980 bytes <= 988 bytes).
#[test]
fn measure_ext4_directory_capacity_ceiling() {
    // Test 1: 4 KiB block size
    {
        let path = ext4_scratch("big-4k.img", "dir-ceiling-4k");
        let mut fs = open_ext4(&path);

        let sub_ino = fs.create_directory(2, "ceiling_test_4k").expect("create subdir");
        let mut count = 0;
        loop {
            let name = format!("f_{:04}.txt", count);
            match fs.create_file(sub_ino as u64, &name, b"test", FileType::Regular) {
                Ok(_) => count += 1,
                Err(e) => {
                    // Refusal when directory block slack is exhausted
                    eprintln!("Ext4 4KiB directory capacity ceiling reached at {count} entries: {e}");
                    break;
                }
            }
        }

        // 4 KiB block with 20-byte records holds 203 entries
        assert_eq!(count, 203, "4 KiB ext4 single-block directory ceiling should be 203 entries");

        let entries = fs.list_dir("/ceiling_test_4k").expect("list entries");
        assert_eq!(entries.len(), 203);
    }

    // Test 2: 1 KiB block size
    {
        let path = ext4_scratch("many-groups-1k.img", "dir-ceiling-1k");
        let mut fs = open_ext4(&path);

        let sub_ino = fs.create_directory(2, "ceiling_test_1k").expect("create subdir");
        let mut count = 0;
        loop {
            let name = format!("f_{:04}.txt", count);
            match fs.create_file(sub_ino as u64, &name, b"test", FileType::Regular) {
                Ok(_) => count += 1,
                Err(e) => {
                    eprintln!("Ext4 1KiB directory capacity ceiling reached at {count} entries: {e}");
                    break;
                }
            }
        }

        // 1 KiB block with 20-byte records holds 49 entries
        assert_eq!(count, 49, "1 KiB ext4 single-block directory ceiling should be 49 entries");

        let entries = fs.list_dir("/ceiling_test_1k").expect("list entries");
        assert_eq!(entries.len(), 49);
    }
}
