#![cfg(feature = "dangerous-write-support")]

mod common;

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-delete-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> Ext4<FileDevice> {
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Ext4::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

fn verify_script() -> Option<String> {
    let script = format!("{}/../tools/verify-ext4.sh", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    if !common::oracle::gate() {
        return None;
    }

    Some(script)
}

const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

#[test]
fn deleting_a_file_leaves_e2fsck_clean() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "clean-delete");
        let content = b"file to be deleted\n";

        // Create a file
        {
            let mut fs = open(&path);
            fs.create_file(2, "to_delete.txt", content, FileType::Regular)
                .expect("create file");
            fs.flush().expect("flush");
        }

        // Verify it was created and is visible
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let entries = fs.list_dir("/").expect("list root");
            assert!(entries.iter().any(|e| e.name == "to_delete.txt"));
        }

        // Delete the file
        {
            let mut fs = open(&path);
            fs.delete_file("/to_delete.txt").expect("delete file");
            fs.flush().expect("flush");
        }

        // Verify it is gone from the listing
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let entries = fs.list_dir("/").expect("list root");
            assert!(!entries.iter().any(|e| e.name == "to_delete.txt"));
        }

        // Check via e2fsck
        let out = Command::new("bash")
            .arg(&script)
            .arg(&path)
            .output()
            .expect("run verifier");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "{name}: e2fsck rejected filesystem after delete:\n{text}"
        );
    }
}

#[test]
fn the_deleted_files_blocks_are_returned_to_free_count() {
    for name in FIXTURES {
        let path = scratch(name, "free-counts");
        let content = vec![0xAAu8; 128 * 1024]; // 128 KiB = 32 blocks (at 4K block size)

        let mut fs = open(&path);
        let blocks_before = fs.superblock().free_blocks_count;
        let inodes_before = fs.superblock().free_inodes_count;

        fs.create_file(2, "counts.bin", &content, FileType::Regular)
            .expect("create file");
        fs.flush().expect("flush");

        let blocks_after_create = fs.superblock().free_blocks_count;
        let inodes_after_create = fs.superblock().free_inodes_count;
        assert!(blocks_after_create < blocks_before);
        assert_eq!(inodes_after_create, inodes_before - 1);

        fs.delete_file("/counts.bin").expect("delete file");
        fs.flush().expect("flush");

        assert_eq!(
            fs.superblock().free_blocks_count,
            blocks_before,
            "{name}: free block count mismatch after delete"
        );
        assert_eq!(
            fs.superblock().free_inodes_count,
            inodes_before,
            "{name}: free inode count mismatch after delete"
        );
    }
}

#[test]
fn deleting_does_not_disturb_other_files() {
    for name in FIXTURES {
        let path = scratch(name, "non-interference");
        let content1 = b"file to delete".to_vec();
        let content2 = b"file to keep".to_vec();

        {
            let mut fs = open(&path);
            fs.create_file(2, "delete.txt", &content1, FileType::Regular)
                .expect("create file 1");
            fs.create_file(2, "keep.txt", &content2, FileType::Regular)
                .expect("create file 2");
            fs.flush().expect("flush");
        }

        {
            let mut fs = open(&path);
            fs.delete_file("/delete.txt").expect("delete file");
            fs.flush().expect("flush");
        }

        // Verify keep.txt is still readable with correct content
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let entries = fs.list_dir("/").expect("list root");
            let keep_entry = entries.iter().find(|e| e.name == "keep.txt").expect("keep.txt exists");
            let keep_inode = fs.read_inode(keep_entry.inode).expect("read keep inode");
            let mut buf = vec![0u8; content2.len()];
            fs.read_inode_data(&keep_inode, 0, &mut buf).expect("read keep data");
            assert_eq!(buf, content2);
        }
    }
}

#[test]
fn deleting_a_nonexistent_file_returns_not_found() {
    let path = scratch("csum-uuid-4k.img", "not-found");
    let mut fs = open(&path);
    let res = fs.delete_file("/does-not-exist.txt");
    assert!(res.is_err());
    match res.unwrap_err() {
        luks_core::error::LuksError::NotFound(name) => {
            assert!(name.contains("does-not-exist.txt"));
        }
        other => panic!("expected LuksError::NotFound, got {:?}", other),
    }
}

#[test]
fn deleting_a_directory_is_refused() {
    let path = scratch("csum-uuid-4k.img", "delete-dir");
    let mut fs = open(&path);
    
    // Refuse root directory
    let res1 = fs.delete_file("/");
    assert!(res1.is_err());
    assert!(matches!(res1.unwrap_err(), luks_core::error::LuksError::IsADirectory(_)));

    // Refuse resolving intermediate or existing directories as files
    let res2 = fs.delete_file("/lost+found");
    assert!(res2.is_err());
    assert!(matches!(res2.unwrap_err(), luks_core::error::LuksError::IsADirectory(_)));
}

#[test]
fn the_space_can_be_reused_after_deletion() {
    let path = scratch("big-4k.img", "reuse");
    let bs = 4096;
    let size = 128 * bs;
    let content = vec![0xBBu8; size];

    let mut fs = open(&path);
    let blocks_before = fs.superblock().free_blocks_count;

    fs.create_file(2, "temp.bin", &content, FileType::Regular).expect("create file");
    fs.flush().expect("flush");

    fs.delete_file("/temp.bin").expect("delete");
    fs.flush().expect("flush");

    // Write a new file of same size. It should succeed using the same space
    fs.create_file(2, "new.bin", &content, FileType::Regular).expect("re-create file");
    fs.flush().expect("flush");

    assert_eq!(fs.superblock().free_blocks_count, blocks_before - (size as u64 / bs as u64));
}

#[test]
fn deleting_a_file_with_depth_1_extents_frees_the_index_block_too() {
    let path = scratch("many-groups-1k.img", "fragmented-delete");
    let mut fs = open(&path);

    let mut held = Vec::new();
    for _ in 0..64 {
        let b = fs.alloc_block(0).expect("checkerboard alloc");
        held.push(b);
    }
    for (i, b) in held.iter().enumerate() {
        if i % 2 == 0 {
            fs.free_block(*b).expect("free every other block");
        }
    }

    let free_blocks_before = fs.superblock().free_blocks_count;
    let free_inodes_before = fs.superblock().free_inodes_count;

    // Create a file that needs index block (depth 1)
    let block_size = fs.block_size() as usize;
    let content = vec![0xEEu8; 30 * block_size];
    let _ino = fs.create_file(2, "fragmented.bin", &content, FileType::Regular).expect("create file");
    fs.flush().expect("flush");

    // Confirm it consumed 30 data blocks + 1 index block = 31 blocks
    assert_eq!(fs.superblock().free_blocks_count, free_blocks_before - 31);
    assert_eq!(fs.superblock().free_inodes_count, free_inodes_before - 1);

    // Delete the file
    fs.delete_file("/fragmented.bin").expect("delete fragmented file");
    fs.flush().expect("flush");

    // Confirm it returned all 31 blocks and the inode
    assert_eq!(fs.superblock().free_blocks_count, free_blocks_before);
    assert_eq!(fs.superblock().free_inodes_count, free_inodes_before);
}

#[test]
fn deleting_a_hardlinked_file_is_refused() {
    let path = scratch("csum-uuid-4k.img", "hardlink-refused");
    let mut fs = open(&path);
    let ino = fs.create_file(2, "hl.txt", b"hardlink target", FileType::Regular).expect("create");
    fs.flush().expect("flush");

    // Manually increment links count of the inode on disk.
    // In ext4 inode structure, links count is a u16 at offset 26 (0x1A).
    let offset = fs.test_inode_offset(ino).expect("inode offset");
    let mut inode_bytes = vec![0u8; fs.superblock().inode_size as usize];
    fs.device_mut().read_at(offset, &mut inode_bytes).expect("read inode");
    let links = u16::from_le_bytes([inode_bytes[26], inode_bytes[27]]);
    let new_links = links + 1;
    inode_bytes[26..28].copy_from_slice(&new_links.to_le_bytes());
    
    // Recompute checksum if metadata_csum is enabled
    let seed = luks_core::fs::ext4::csum::Seed::for_writing(fs.superblock()).expect("seed");
    if let Some(csum) = seed.inode(ino, &inode_bytes) {
        inode_bytes[0x7C..0x7E].copy_from_slice(&(csum as u16).to_le_bytes());
        if seed.inode_has_csum_hi(&inode_bytes) {
            inode_bytes[0x82..0x84].copy_from_slice(&((csum >> 16) as u16).to_le_bytes());
        }
    }
    
    fs.device_mut().write_at(offset, &inode_bytes).expect("write inode");
    fs.flush().expect("flush");

    // Reopen and try to delete
    let mut fs = open(&path);
    let res = fs.delete_file("/hl.txt");
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), luks_core::error::LuksError::UnsupportedFsFeature(_)));
}

#[test]
fn break_verification_missing_unlink_leaves_unattached_inode() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "break-unlink");
    let content = b"temporary contents\n";

    // 1. Create a file
    {
        let mut fs = open(&path);
        fs.create_file(2, "broken.txt", content, FileType::Regular).expect("create");
        fs.flush().expect("flush");
    }

    // 2. Perform partial delete: free blocks & free inode, but skip unlink_file.
    {
        let mut fs = open(&path);
        let target_inode = fs.resolve_no_follow("/broken.txt").expect("resolve");
        let (data_extents, index_extents) = fs.collect_extents(&target_inode).expect("collect");

        // Skip unlink_file.
        fs.free_inode(target_inode.number, false).expect("free inode");
        fs.free_blocks(&data_extents).expect("free blocks");
        if !index_extents.is_empty() {
            fs.free_blocks(&index_extents).expect("free index blocks");
        }
        fs.flush().expect("flush");
    }

    // 3. Run e2fsck and check output
    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run the verifier");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // e2fsck must complain that a directory entry points to an unused/deleted inode
    assert!(
        text.contains("deleted inode") || text.contains("deleted/unused") || text.contains("unused inode") || text.contains("points to") || text.contains("not in use") || text.contains("invalid"),
        "e2fsck did not complain about unlinked inode reference:\n{text}"
    );
}

#[test]
fn break_verification_missing_free_blocks_leaves_orphan_blocks() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "break-blocks");
    let content = b"temporary contents\n";

    // 1. Create a file
    {
        let mut fs = open(&path);
        fs.create_file(2, "broken.txt", content, FileType::Regular).expect("create");
        fs.flush().expect("flush");
    }

    // 2. Perform partial delete: unlink & free inode, but skip free_blocks.
    {
        let mut fs = open(&path);
        let target_inode = fs.resolve_no_follow("/broken.txt").expect("resolve");
        
        fs.unlink_file(2, "broken.txt").expect("unlink");
        fs.free_inode(target_inode.number, false).expect("free inode");
        // Skip free_blocks.
        fs.flush().expect("flush");
    }

    // 3. Run e2fsck and check output
    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run the verifier");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // e2fsck must complain about block bitmap mismatch
    assert!(
        text.contains("bitmap differences") || text.contains("Free blocks count"),
        "e2fsck did not complain about block leak:\n{text}"
    );
}

#[test]
fn break_verification_missing_free_inode_leaves_orphan_inode() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "break-inode");
    let content = b"temporary contents\n";

    // 1. Create a file
    {
        let mut fs = open(&path);
        fs.create_file(2, "broken.txt", content, FileType::Regular).expect("create");
        fs.flush().expect("flush");
    }

    // 2. Perform partial delete: unlink & free blocks, but skip free_inode.
    {
        let mut fs = open(&path);
        let target_inode = fs.resolve_no_follow("/broken.txt").expect("resolve");
        let (data_extents, index_extents) = fs.collect_extents(&target_inode).expect("collect");
        
        fs.unlink_file(2, "broken.txt").expect("unlink");
        // Skip free_inode.
        fs.free_blocks(&data_extents).expect("free blocks");
        if !index_extents.is_empty() {
            fs.free_blocks(&index_extents).expect("free index blocks");
        }
        fs.flush().expect("flush");
    }

    // 3. Run e2fsck and check output
    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run the verifier");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // e2fsck must complain about unattached or orphan inode
    assert!(
        text.contains("unattached") || text.contains("Free inodes count") || text.contains("bitmap differences"),
        "e2fsck did not complain about unattached/leaked inode:\n{text}"
    );
}
