//! End-to-end file creation and oracle verification test (Pass E).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_create_file
//! ```
//!
//! # The Oracle
//!
//! Ground truth is `tools/verify-btrfs.sh`:
//! 1. `btrfs check --readonly`
//! 2. Real kernel mount
//! 3. `btrfs scrub start -Bdr` (verifying all checksums and DUP mirrors)
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::error::LuksError;
use luks_core::fs::btrfs::tree::{Key, Node};
use luks_core::fs::btrfs::write::node::Leaf;
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

/// Distinguishes two scratch images made in the same microsecond.
///
/// A timestamp alone is not unique here, and that is measured rather than
/// assumed: `SystemTime::now()` on this host advances in **1 µs** steps (every
/// sample is a multiple of 1000 ns, and 97% of back-to-back calls return the
/// identical value). `cargo` starts a binary's tests as threads at effectively
/// the same instant, so two of them calling `copy_to_temp("plain.img")` land in
/// the same microsecond often enough to matter — 8 threads racing collided in
/// 1 run out of 5.
///
/// Two tests that agree on a path both `fs::copy` to it, and the second copy
/// **truncates the first's image while the first is using it**. That is the
/// whole of issue #25: the "flaky" failures were `WrongWriteTarget { expected:
/// 0 }`, `... it is smaller than that`, and `NotBtrfs([0, 0, ...])` — three
/// faces of one file being re-copied underneath a running test, which is also
/// why it always passed in isolation. `btrfs_data_write.rs` already had this
/// counter and was the one btrfs suite never reported flaky.
static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-create-{src_name}-{}-{}-{}",
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
fn create_file_in_root_directory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    // 1. Open writable device and mount
    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // 2. Create a new empty file in root directory
    fs.create_file("/", "newfile.txt").expect("create newfile.txt in /");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    // Verify reader sees the new file
    let entries = fs.list_dir("/").expect("list root dir");
    assert!(entries.iter().any(|e| e.name == "newfile.txt"));
    assert!(entries.iter().any(|e| e.name == "hello.txt"));
    assert!(entries.iter().any(|e| e.name == "docs"));

    let info = fs.file_info("/newfile.txt").expect("file info newfile.txt");
    assert_eq!(info.size, 0);
    assert_eq!(info.links, 1);
    assert!(info.file_type.is_file());

    drop(fs);

    // 3. Re-open read-only from disk to verify persistence across mounts
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");

    assert_eq!(fs_ro.superblock().generation, original_sb_gen + 1);
    let entries_ro = fs_ro.list_dir("/").expect("list root dir on remount");
    assert!(entries_ro.iter().any(|e| e.name == "newfile.txt"));

    let info_ro = fs_ro
        .file_info("/newfile.txt")
        .expect("file info on remount");
    assert_eq!(info_ro.size, 0);
    assert_eq!(info_ro.links, 1);
    assert!(info_ro.file_type.is_file());

    drop(fs_ro);

    // 4. Grade with kernel oracle (btrfs check, mount, scrub)
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on plain.img root create"
    );
}

#[test]
fn create_file_in_subdirectory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Create a new empty file in subdirectory /docs
    fs.create_file("/docs", "note.txt")
        .expect("create note.txt in /docs");

    assert_eq!(fs.superblock().generation, original_sb_gen + 1);

    let entries = fs.list_dir("/docs").expect("list /docs");
    assert!(entries.iter().any(|e| e.name == "note.txt"));
    assert!(entries.iter().any(|e| e.name == "readme.md"));

    let info = fs.file_info("/docs/note.txt").expect("file info note.txt");
    assert_eq!(info.size, 0);
    assert_eq!(info.links, 1);

    drop(fs);

    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount btrfs");
    let entries_ro = fs_ro.list_dir("/docs").expect("list /docs on remount");
    assert!(entries_ro.iter().any(|e| e.name == "note.txt"));

    drop(fs_ro);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on plain.img subdir create"
    );
}

#[test]
fn create_file_on_compress_img() {
    let temp_img = copy_to_temp("compress.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "extra.txt")
        .expect("create extra.txt in / on compress.img");

    let entries = fs.list_dir("/").expect("list / on compress.img");
    assert!(entries.iter().any(|e| e.name == "extra.txt"));
    assert!(entries.iter().any(|e| e.name == "zstd.txt"));

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on compress.img"
    );
}

#[test]
fn create_file_on_mixed_4k_img() {
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    fs.create_file("/", "mixed_new.txt")
        .expect("create mixed_new.txt on mixed-4k.img");

    let entries = fs.list_dir("/").expect("list / on mixed-4k.img");
    assert!(entries.iter().any(|e| e.name == "mixed_new.txt"));

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on mixed-4k.img"
    );
}

#[test]
fn duplicate_file_creation_is_refused() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Attempting to create an existing file must fail with AlreadyExists
    let res = fs.create_file("/", "hello.txt");
    match res {
        Err(LuksError::AlreadyExists(_)) => {}
        other => panic!("expected AlreadyExists error, got: {other:?}"),
    }

    // Superblock generation should be untouched
    assert_eq!(fs.superblock().generation, original_sb_gen);

    drop(fs);
    let _ = fs::remove_file(&temp_img);
}

#[test]
fn create_multiple_files_consecutively_and_verify() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let original_sb_gen = fs.superblock().generation;

    // Create 5 files consecutively
    for i in 0..5 {
        let name = format!("batch_file_{i}.txt");
        fs.create_file("/", &name).expect("create batch file");
    }

    assert_eq!(fs.superblock().generation, original_sb_gen + 5);

    let entries = fs.list_dir("/").expect("list root dir");
    for i in 0..5 {
        let name = format!("batch_file_{i}.txt");
        assert!(entries.iter().any(|e| e.name == name));
    }

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle verification failed on multiple files creation"
    );
}

// --- Fix 2 (E.1): find_max_inode must not be fooled by reserved objectids ---
//
// `ORPHAN_OBJECTID` (kernel `BTRFS_ORPHAN_OBJECTID` = -5, i.e.
// `0xFFFF_FFFF_FFFF_FFFB` as u64) is one of btrfs's reserved objectids that
// count down from `u64::MAX`. Reserved objectids sort after every real
// inode, so an `ORPHAN_ITEM` (kernel `BTRFS_ORPHAN_ITEM_KEY` = 48) — left
// behind when a still-open file is deleted — can end up as the only item in
// the FS tree's rightmost leaf: the real files that used to live there are
// gone, and the orphan item outsorts everything else, so it inherits their
// spot as the last leaf. `find_max_inode` must still return the true
// maximum real inode from earlier in the tree, not fall back to 256 just
// because the rightmost leaf itself has nothing but reserved objectids.
//
// Reproducing this precisely (rather than just appending an orphan item next
// to real ones, which leaves the real max reachable in the same leaf and
// doesn't exercise the bug) means the rightmost leaf's real items have to be
// gone. This test wipes plain.img's actual rightmost FS-tree leaf and
// replaces it with a single ORPHAN_ITEM, using this project's own writer
// (`Leaf::insert_item` / `Leaf::emit`, from `write/node.rs`) — the same
// pattern `btrfs_node_surgery.rs` uses for Pass C.
const ORPHAN_OBJECTID: u64 = 0xFFFF_FFFF_FFFF_FFFB;
const ORPHAN_ITEM_KEY: u8 = 48;
const FS_TREE_OBJECTID: u64 = 5;

/// Highest real-inode objectid across every leaf under `root` *except*
/// `exclude_bytenr`, by direct enumeration rather than any tree-descent
/// heuristic. This is the independent ground truth the test checks
/// `find_max_inode` against, so it deliberately does not share any code path
/// with `find_max_inode` itself (production or buggy).
///
/// plain.img's FS tree is exactly two levels (one interior root, leaves
/// below), which this asserts rather than assumes — a fixture change that
/// added another level would otherwise make this silently check the wrong
/// thing.
fn true_max_inode_excluding<D: ReadAt>(fs: &Btrfs<D>, exclude_bytenr: u64) -> u64 {
    let root = fs.read_node(fs.fs_tree().bytenr).expect("read fs tree root");
    assert_eq!(root.level, 1, "fixture is no longer a 2-level tree; update this test");

    let mut max_ino = 256u64;
    for i in 0..root.nr_items {
        let bytenr = root.key_ptr(i).expect("key_ptr").blockptr;
        if bytenr == exclude_bytenr {
            continue;
        }
        let leaf = fs.read_node(bytenr).expect("read leaf");
        for j in 0..leaf.nr_items {
            let objectid = leaf.key(j).expect("key").objectid;
            if objectid >= 256 && objectid < 0xFFFF_FFFF_FFFF_FF00 {
                max_ino = max_ino.max(objectid);
            }
        }
    }
    max_ino
}

#[test]
fn find_max_inode_survives_a_rightmost_leaf_full_of_orphan_items() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let metadata_uuid = sb.metadata_uuid;

    // 1. Locate the FS tree's actual rightmost leaf (last child of the root).
    let root = fs.read_node(fs.fs_tree().bytenr).expect("read fs tree root");
    assert_eq!(root.level, 1, "fixture is no longer a 2-level tree; update this test");
    let last_idx = root.nr_items - 1;
    let leaf_ptr = root.key_ptr(last_idx).expect("key_ptr");
    let leaf_bytenr = leaf_ptr.blockptr;
    let leaf_node = fs.read_node(leaf_bytenr).expect("read rightmost leaf");
    let leaf_generation = leaf_node.generation;

    // Sanity: plain.img's rightmost leaf really does hold real inode items
    // before we touch it — otherwise this fixture no longer represents the
    // "rightmost leaf = real inodes" case the old code assumed always held.
    let real_items_in_leaf = (0..leaf_node.nr_items)
        .filter(|&i| {
            let o = leaf_node.key(i).unwrap().objectid;
            o >= 256 && o < 0xFFFF_FFFF_FFFF_FF00
        })
        .count();
    assert!(
        real_items_in_leaf > 0,
        "fixture assumption violated: rightmost leaf holds no real inode items to begin with"
    );

    // 2. Ground truth: the true max real inode once this leaf is wiped.
    let expected_max_ino = true_max_inode_excluding(&fs, leaf_bytenr);
    assert!(expected_max_ino > 256, "plain.img should have real files besides root");

    // 3. Replace the leaf's contents outright with a single ORPHAN_ITEM —
    //    modeling every file that used to live here having been deleted
    //    while still open. The reserved objectid sorts after everything
    //    else, so this leaf, still the rightmost, now holds nothing a
    //    real-inode filter would accept.
    let mut leaf = Leaf::new(leaf_bytenr, leaf_generation, FS_TREE_OBJECTID, metadata_uuid, csum_type);
    leaf.insert_item(Key::new(ORPHAN_OBJECTID, ORPHAN_ITEM_KEY, 0), Vec::new(), node_size)
        .expect("insert orphan item");

    let emitted = leaf.emit(node_size).expect("emit corrupted leaf");
    // Confirm the reader accepts it before trusting it back onto disk — same
    // acceptance bar as btrfs_node_surgery.rs.
    Node::parse(emitted.clone(), leaf_bytenr, csum_type, &metadata_uuid)
        .expect("reader must accept the re-emitted leaf");

    // 4. Write the corrupted leaf back to every physical stripe (DUP
    //    metadata profile writes two copies; see write/commit.rs for the
    //    same pattern).
    let stripes = fs.chunk_map().map_all_stripes(leaf_bytenr).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush");
    drop(fs);

    // 5. Remount fresh (clears the node cache) and exercise the fix through
    //    the public create_file path: the new file's inode must be
    //    expected_max_ino + 1, not 256 and not a collision with any
    //    existing inode.
    let dev2 = FileDevice::open_writable(&temp_img, file_len).expect("reopen writable");
    let mut fs2 = Btrfs::mount(dev2).expect("remount writable btrfs");

    fs2.create_file("/", "after_orphan.txt")
        .expect("create_file after orphan injection");

    let new_ino = fs2
        .resolve_no_follow(fs2.fs_tree(), "/after_orphan.txt")
        .expect("resolve new file")
        .inode
        .objectid;

    assert_ne!(
        new_ino, 256,
        "find_max_inode fell back to 256 — the orphan-only leaf was not skipped"
    );
    assert_eq!(
        new_ino,
        expected_max_ino + 1,
        "new inode collides with or skips past an existing inode"
    );

    let _ = fs::remove_file(&temp_img);
}

#[test]
fn create_file_with_data_in_root_directory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_gen = fs.superblock().generation;
    let payload = b"Atomic single-transaction file creation with data payload!";

    let ino = fs
        .create_file_with_data("/", "atomic_root.txt", payload)
        .expect("create file with data in root");

    assert!(ino >= 256);
    assert_eq!(fs.superblock().generation, initial_gen + 1);

    // Verify content and metadata in single mount
    let readback = fs.read_file("/atomic_root.txt").expect("read file");
    assert_eq!(readback, payload);
    let info = fs.file_info("/atomic_root.txt").expect("file info");
    assert_eq!(info.size, payload.len() as u64);
    assert_eq!(info.links, 1);

    drop(fs);

    // Verify persistence across remount
    let dev_ro = FileDevice::open(&temp_img).expect("open ro");
    let fs_ro = Btrfs::mount(dev_ro).expect("remount ro");
    assert_eq!(fs_ro.superblock().generation, initial_gen + 1);
    let readback_ro = fs_ro.read_file("/atomic_root.txt").expect("read file ro");
    assert_eq!(readback_ro, payload);
    drop(fs_ro);

    // Grade with kernel oracle
    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle failed on atomic create_file_with_data in root"
    );
}

#[test]
fn create_file_with_data_in_subdirectory_on_plain_img() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_gen = fs.superblock().generation;
    let payload = b"Subdirectory atomic file write";

    let ino = fs
        .create_file_with_data("/docs", "atomic_sub.txt", payload)
        .expect("create file with data in /docs");

    assert!(ino >= 256);
    assert_eq!(fs.superblock().generation, initial_gen + 1);

    let readback = fs.read_file("/docs/atomic_sub.txt").expect("read file in /docs");
    assert_eq!(readback, payload);

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle failed on atomic create_file_with_data in subdir"
    );
}

#[test]
fn create_file_with_data_failure_leaves_no_orphan_file() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let initial_gen = fs.superblock().generation;

    // 1. First write succeeds
    fs.create_file_with_data("/", "taken.txt", b"original content")
        .expect("first create");
    assert_eq!(fs.superblock().generation, initial_gen + 1);

    // 2. Second write with same name fails with AlreadyExists
    let res = fs.create_file_with_data("/", "taken.txt", b"duplicate content");
    match res {
        Err(LuksError::AlreadyExists(_)) => {}
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }

    // Generation must NOT advance on failed transaction
    assert_eq!(fs.superblock().generation, initial_gen + 1);

    // Content must still be the original content
    let readback = fs.read_file("/taken.txt").expect("read taken.txt");
    assert_eq!(readback, b"original content");

    drop(fs);

    let oracle_clean = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(
        oracle_clean,
        "kernel oracle failed on create_file_with_data collision rollback"
    );
}

