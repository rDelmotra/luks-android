//! End-to-end Btrfs file deletion and oracle verification test (Phase 2).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_delete
//! ```
//!
//! # The Oracle
//!
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly` (verifying all extent items, backrefs, csums, and tree roots)
//! 2. Real kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all data sector checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

#[path = "../common/mod.rs"]
mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::Btrfs;
use common::accounting::AccountingOracle;
use common::csum_pack::{get_file_disk_bytenr, pack_adjacent_csums};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-delete-{src_name}-{}-{}-{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::copy(&src, &dst).expect("copy fixture to temp");
    dst
}

fn run_verify_script(image_path: &PathBuf) -> bool {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !script.exists() {
        return false;
    }
    if !common::oracle::gate() {
        return true;
    }

    let output = Command::new(&script).arg(image_path).output();

    match output {
        Ok(out) => {
            if out.status.success() {
                println!("ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
                true
            } else {
                eprintln!(
                    "verify-btrfs.sh stdout:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                );
                eprintln!(
                    "verify-btrfs.sh stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("could not execute verify-btrfs.sh: {e}");
            false
        }
    }
}

#[test]
fn delete_empty_file_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Create an empty file
    fs.create_file("/", "empty_to_delete.txt").expect("create file");

    let entries = fs.list_dir("/").expect("list dir");
    assert!(entries.iter().any(|e| e.name == "empty_to_delete.txt"));

    // 2. Delete the empty file
    fs.delete_file("/empty_to_delete.txt").expect("delete file");

    // 3. Verify it is gone
    let entries_after = fs.list_dir("/").expect("list dir after delete");
    assert!(!entries_after.iter().any(|e| e.name == "empty_to_delete.txt"));
    assert!(matches!(fs.read_file("/empty_to_delete.txt"), Err(LuksError::NotFound(_))));

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_file_with_data_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let test_data = b"Btrfs file deletion with extent freeing and checksum cleanup test!";
    fs.create_file_with_data("/", "data_to_delete.txt", test_data)
        .expect("create file with data");

    let read_back = fs.read_file("/data_to_delete.txt").expect("read file");
    assert_eq!(read_back, test_data);

    // Delete the file
    fs.delete_file("/data_to_delete.txt").expect("delete file");

    // Verify it is gone
    let entries = fs.list_dir("/").expect("list dir");
    assert!(!entries.iter().any(|e| e.name == "data_to_delete.txt"));
    assert!(matches!(fs.read_file("/data_to_delete.txt"), Err(LuksError::NotFound(_))));

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_reclaims_space_and_allows_reallocation() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_used = fs.superblock().bytes_used;

    // Create 64 KiB file
    let large_data = vec![0x42u8; 64 * 1024];
    fs.create_file_with_data("/", "reclaim_test.bin", &large_data)
        .expect("create file");

    let used_after_create = fs.superblock().bytes_used;
    assert!(used_after_create > initial_used, "used space should have increased");
    AccountingOracle::assert_clean(&fs);

    // Delete the file
    fs.delete_file("/reclaim_test.bin").expect("delete file");

    let used_after_delete = fs.superblock().bytes_used;
    assert!(
        used_after_delete < used_after_create,
        "used space should have decreased after deletion: before={used_after_create}, after={used_after_delete}"
    );
    AccountingOracle::assert_clean(&fs);

    // Create a new file allocating reclaimed space
    let new_data = vec![0x77u8; 64 * 1024];
    fs.create_file_with_data("/", "reallocated.bin", &new_data)
        .expect("create new file in reclaimed space");

    let read_back = fs.read_file("/reallocated.bin").expect("read back");
    assert_eq!(read_back, new_data);

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_multiple_files_sequentially() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file_with_data("/", "file1.txt", b"content 1").expect("create file1");
    fs.create_file_with_data("/", "file2.txt", b"content 2").expect("create file2");
    fs.create_file_with_data("/", "file3.txt", b"content 3").expect("create file3");

    // Delete file1 and file3, keep file2
    fs.delete_file("/file1.txt").expect("delete file1");
    fs.delete_file("/file3.txt").expect("delete file3");

    let entries = fs.list_dir("/").expect("list dir");
    assert!(!entries.iter().any(|e| e.name == "file1.txt"));
    assert!(entries.iter().any(|e| e.name == "file2.txt"));
    assert!(!entries.iter().any(|e| e.name == "file3.txt"));

    assert_eq!(fs.read_file("/file2.txt").expect("read file2"), b"content 2");

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn delete_file_across_fixtures() {
    for fixture_name in ["mixed-4k.img", "compress.img", "subvol.img"] {
        let temp_img = copy_to_temp(fixture_name);
        let file_len = fs::metadata(&temp_img).unwrap().len();

        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        let payload = format!("test delete on {fixture_name}").into_bytes();
        fs.create_file_with_data("/", "fixture_del.txt", &payload)
            .expect("create file");

        assert_eq!(fs.read_file("/fixture_del.txt").expect("read"), payload);

        fs.delete_file("/fixture_del.txt").expect("delete file");
        assert!(matches!(fs.read_file("/fixture_del.txt"), Err(LuksError::NotFound(_))));

        AccountingOracle::assert_clean(&fs);
        drop(fs);
        assert!(
            run_verify_script(&temp_img),
            "oracle check failed on {fixture_name}"
        );
    }
}

#[test]
fn delete_refusal_gates() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // Deleting root "/" should fail with IsADirectory
    assert!(matches!(fs.delete_file("/"), Err(LuksError::IsADirectory(_))));

    // Deleting non-existent file should fail with NotFound
    assert!(matches!(fs.delete_file("/nonexistent.txt"), Err(LuksError::NotFound(_))));
}

#[test]
fn a_dot_component_is_refused_rather_than_silently_resolving_to_an_ancestor() {
    // `resolve_no_follow` drops `.` components entirely, so without an
    // explicit guard "/tree/." resolves to "/tree" itself and this function
    // would recurse into and delete every child of "/tree" before the
    // low-level transaction failed trying to remove an item literally named
    // "." — reporting failure *after* having already deleted everything
    // inside. This proves the guard fires before any of that happens: the
    // tree survives completely intact.
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_directory("/", "tree").expect("mkdir tree");
    fs.create_file_with_data("/tree", "a.txt", b"hello").expect("create a.txt");
    fs.create_directory("/tree", "nested").expect("mkdir nested");
    fs.create_file_with_data("/tree/nested", "b.txt", b"world")
        .expect("create b.txt");
    // A name that merely *starts* with a dot is a real, ordinary name and
    // must not be caught by the same guard.
    fs.create_file_with_data("/tree", ".hidden", b"x").expect("create .hidden");

    for bad in ["/.", "/tree/.", "/tree/..", "..", "/tree/nested/.."] {
        assert!(
            matches!(fs.delete_file(bad), Err(LuksError::UnsupportedFsFeature(_))),
            "expected {bad:?} to be refused"
        );
    }

    // Nothing was touched: the whole tree, and the rest of the root, is
    // exactly as it was.
    assert!(fs.list_dir("/").unwrap().iter().any(|e| e.name == "tree"));
    assert_eq!(fs.list_dir("/tree").unwrap().len(), 3);
    assert_eq!(fs.list_dir("/tree/nested").unwrap().len(), 1);
    assert_eq!(fs.read_file("/tree/a.txt").unwrap(), b"hello");

    // And an ordinary dotfile deletes normally.
    fs.delete_file("/tree/.hidden").expect("delete .hidden");
    assert!(!fs.list_dir("/tree").unwrap().iter().any(|e| e.name == ".hidden"));

    AccountingOracle::assert_clean(&fs);
    drop(fs);
}

#[test]
fn deleting_an_empty_directory_succeeds() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_directory("/", "empty").expect("mkdir");
    assert!(fs.list_dir("/").unwrap().iter().any(|e| e.name == "empty"));

    fs.delete_file("/empty").expect("delete empty dir");
    assert!(!fs.list_dir("/").unwrap().iter().any(|e| e.name == "empty"));

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn deleting_a_directory_recursively_removes_files_and_nested_subdirectories() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_directory("/", "tree").expect("mkdir tree");
    fs.create_file_with_data("/tree", "a.txt", b"hello").expect("create a.txt");
    fs.create_directory("/tree", "nested").expect("mkdir nested");
    fs.create_file_with_data("/tree/nested", "b.txt", b"world")
        .expect("create b.txt");

    // Sanity: the tree is really there before it's deleted.
    assert_eq!(fs.list_dir("/tree").unwrap().len(), 2);
    assert_eq!(fs.list_dir("/tree/nested").unwrap().len(), 1);

    fs.delete_file("/tree").expect("recursive delete");

    assert!(!fs.list_dir("/").unwrap().iter().any(|e| e.name == "tree"));
    assert!(matches!(fs.read_file("/tree/a.txt"), Err(LuksError::NotFound(_))));

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn the_low_level_transaction_refuses_a_directory_that_still_has_children() {
    // Defense in depth: `Btrfs::delete_file` empties a directory before it
    // ever reaches `Transaction::delete_file`, so this guard should be
    // unreachable in practice — proving it fires anyway is what makes that
    // "should be" load-bearing rather than assumed.
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_directory("/", "has_stuff").expect("mkdir");
    fs.create_file_with_data("/has_stuff", "inside.txt", b"x")
        .expect("create file inside");

    let res = luks_core::fs::btrfs::write::Transaction::delete_file(&fs, "/has_stuff", 0, 0);
    assert!(matches!(res, Err(LuksError::DirectoryNotEmpty(_))));
}

#[test]
fn deleting_deep_tree_collapses_root_and_allows_subsequent_creation() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Create many files to force an interior split (tree level >= 1)
    let payload = vec![0xAB; 2048];
    for i in 0..40 {
        fs.create_file_with_data("/", &format!("split_file_{i:03}.bin"), &payload)
            .expect("create file to induce split");
    }

    let entries_before = fs.list_dir("/").expect("list dir");
    assert!(entries_before.len() >= 40);

    // 2. Delete all created files — this empties leaves and shrinks interior nodes
    for entry in entries_before {
        if entry.name != "." && entry.name != ".." && entry.name != "lost+found" {
            let path = format!("/{}", entry.name);
            fs.delete_file(&path).expect("delete file");
        }
    }

    // 3. Now create a new file in the emptied / collapsed tree
    let new_file_data = b"fresh file in collapsed root";
    fs.create_file_with_data("/", "after_delete.txt", new_file_data)
        .expect("create file in collapsed tree must succeed");

    let read_back = fs.read_file("/after_delete.txt").expect("read back file");
    assert_eq!(read_back, new_file_data);

    AccountingOracle::assert_clean(&fs);
    drop(fs);
    assert!(run_verify_script(&temp_img), "oracle check failed");
}

#[test]
fn test_delete_file_sharing_csum_item_with_adjacent_file() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let data1 = vec![0x11u8; 4096];
    let data2 = vec![0x22u8; 4096];
    let data3 = vec![0x33u8; 4096];

    let b1;
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        fs.create_file_with_data("/", "f1.bin", &data1).expect("create f1");
        fs.create_file_with_data("/", "f2.bin", &data2).expect("create f2");
        fs.create_file_with_data("/", "f3.bin", &data3).expect("create f3");

        b1 = get_file_disk_bytenr(&fs, "/f1.bin");
        let b2 = get_file_disk_bytenr(&fs, "/f2.bin");
        let b3 = get_file_disk_bytenr(&fs, "/f3.bin");

        assert_eq!(b2, b1 + 4096, "f2 extent must immediately follow f1");
        assert_eq!(b3, b2 + 4096, "f3 extent must immediately follow f2");
    }

    // Pack the 3 adjacent single-sector csum items into one 12-byte item at b1
    pack_adjacent_csums(&temp_img, b1, 3);

    // Verify initial packed state passes AccountingOracle (Invariant A-8)
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let fs = Btrfs::mount(dev).expect("mount btrfs");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check on packed initial state failed");

    // Phase 1: Tail truncation — delete f3.bin
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount btrfs");
        fs.delete_file("/f3.bin").expect("delete f3 (tail truncation)");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check after tail truncation failed");

    // Phase 2: Head truncation — delete f1.bin
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount btrfs");
        fs.delete_file("/f1.bin").expect("delete f1 (head truncation)");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check after head truncation failed");

    // Phase 3: Full removal — delete remaining f2.bin
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount btrfs");
        fs.delete_file("/f2.bin").expect("delete f2 (full removal)");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check after full removal failed");
}

#[test]
fn test_delete_file_csum_middle_hole_punch() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let data1 = vec![0x44u8; 4096];
    let data2 = vec![0x55u8; 4096];
    let data3 = vec![0x66u8; 4096];

    let b1;
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

        fs.create_file_with_data("/", "f1.bin", &data1).expect("create f1");
        fs.create_file_with_data("/", "f2.bin", &data2).expect("create f2");
        fs.create_file_with_data("/", "f3.bin", &data3).expect("create f3");

        b1 = get_file_disk_bytenr(&fs, "/f1.bin");
        let b2 = get_file_disk_bytenr(&fs, "/f2.bin");
        let b3 = get_file_disk_bytenr(&fs, "/f3.bin");

        assert_eq!(b2, b1 + 4096, "f2 extent must immediately follow f1");
        assert_eq!(b3, b2 + 4096, "f3 extent must immediately follow f2");
    }

    // Pack the 3 adjacent single-sector csum items into one 12-byte item at b1
    pack_adjacent_csums(&temp_img, b1, 3);

    // Verify initial packed state
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let fs = Btrfs::mount(dev).expect("mount btrfs");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check on packed initial state failed");

    // Middle hole punch: delete middle file f2.bin
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount btrfs");
        fs.delete_file("/f2.bin").expect("delete f2 (middle hole punch)");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check after middle hole punch failed");

    // Verify f1.bin and f3.bin are still intact and readable with correct data
    {
        let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
        let mut fs = Btrfs::mount(dev).expect("mount btrfs");
        assert_eq!(fs.read_file("/f1.bin").expect("read f1"), data1);
        assert_eq!(fs.read_file("/f3.bin").expect("read f3"), data3);

        // Delete remaining files
        fs.delete_file("/f1.bin").expect("delete f1");
        fs.delete_file("/f3.bin").expect("delete f3");
        AccountingOracle::assert_clean(&fs);
    }
    assert!(run_verify_script(&temp_img), "oracle check after clean up failed");
}



/// The exact defect found on the physical 61.5 GB stick, in fixture form.
///
/// On that drive `mkfs.btrfs` had packed the checksums of `/existing/one-block.bin`
/// (FS_TREE, logical 13631488) and `/home/user/docs/one-block.bin` (subvolume 256,
/// logical 13635584) into a single 8-byte `EXTENT_CSUM` item keyed at 13631488.
/// Deleting the subvolume file left an orphan checksum for 13635584..13639680,
/// which `btrfs check` reported as "there are no extents for csum range".
///
/// CSUM_TREE is global, so the freed extent belongs to a subvolume tree while the
/// checksum item is keyed under a neighbour in FS_TREE. This test reproduces that
/// straddle in both directions and asserts the surviving neighbour still reads back
/// intact — an over-trim here would silently strip a live file's checksums.
#[test]
fn test_delete_subvolume_file_sharing_packed_csum_with_root_tree_file() {
    for delete_subvol_side in [true, false] {
        let temp_img = copy_to_temp("subvol.img");
        let file_len = fs::metadata(&temp_img).unwrap().len();

        let root_data = vec![0x5Au8; 4096];
        let subvol_data = vec![0xA5u8; 4096];

        let b_root;
        let b_subvol;
        {
            let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
            let mut fs = Btrfs::mount(dev).expect("mount subvol.img");

            fs.create_file_with_data("/", "root_neighbour.bin", &root_data)
                .expect("create file in FS_TREE");
            fs.create_file_with_data("/home", "subvol_neighbour.bin", &subvol_data)
                .expect("create file in /home subvolume");

            b_root = get_file_disk_bytenr(&fs, "/root_neighbour.bin");
            b_subvol = get_file_disk_bytenr(&fs, "/home/subvol_neighbour.bin");
            assert_eq!(
                b_subvol,
                b_root + 4096,
                "vacuity: subvolume file extent must immediately follow the FS_TREE file extent \
                 for the packed-checksum straddle to be reproducible"
            );
        }

        // Fuse the two single-sector checksum items into one packed item, exactly as
        // the Linux kernel's allocator would have written it.
        pack_adjacent_csums(&temp_img, b_root, 2);

        {
            let dev = FileDevice::open(&temp_img).expect("open packed");
            let fs = Btrfs::mount(dev).expect("mount packed");
            AccountingOracle::assert_clean(&fs);
        }
        assert!(
            run_verify_script(&temp_img),
            "kernel check on packed cross-tree initial state failed"
        );

        // Delete one side; the checksums of the other must survive untouched.
        let (victim, survivor, survivor_data) = if delete_subvol_side {
            ("/home/subvol_neighbour.bin", "/root_neighbour.bin", &root_data)
        } else {
            ("/root_neighbour.bin", "/home/subvol_neighbour.bin", &subvol_data)
        };

        {
            let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
            let mut fs = Btrfs::mount(dev).expect("mount for delete");
            fs.delete_file(victim).unwrap_or_else(|e| panic!("delete {victim}: {e}"));
            assert!(matches!(fs.read_file(victim), Err(LuksError::NotFound(_))));
            assert_eq!(
                fs.read_file(survivor).unwrap_or_else(|e| panic!("read {survivor}: {e}")),
                *survivor_data,
                "surviving neighbour must read back intact after the packed item was trimmed"
            );
            // A-8 catches an orphan checksum left behind; A-9 catches the converse,
            // a surviving extent whose checksums were trimmed away with the victim's.
            AccountingOracle::assert_clean(&fs);
        }
        assert!(
            run_verify_script(&temp_img),
            "kernel check after deleting {victim} from packed cross-tree item failed"
        );
    }
}
