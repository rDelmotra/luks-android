//! Deliberate-break chunk allocation control tests (Passes I.1, I.2, I.3).
//!
//! ```text
//! cargo test -p luks_core --features dangerous-write-support --test btrfs_chunk_alloc_controls
//! ```
//!
//! # Purpose
//!
//! RULES.md: "A verifier that cannot fail on a known-bad input is not verifying."
//!
//! This suite implements deliberate-break controls from notes/feature-btrfs-chunk-alloc.md §10
//! and notes/feature-write-hardening.md §6:
//!
//! - **Pass I.1: Exclusion control**:
//!   1. Overwrite Superblock mirror 1 at logical `58720256` (physical `67108864`), simulating an
//!      allocation with exclusions disabled. Assert that `tools/verify-btrfs.sh` / `btrfs scrub`
//!      fails with `"Error summary: super=1"`.
//!   2. With exclusions enabled, verify `58720256..58785792` is excluded and the image is clean.
//!   3. Run 684-file stress allocation test and record the highest logical metadata address reached
//!      (answering Gate I -> J).
//!
//! - **Pass I.2: On-disk item controls**:
//!   Intentionally corrupt or omit each item on test image copies and run `btrfs check --readonly`:
//!   1. Omit DEV_EXTENT: Assert `btrfs check` fails with `"is not found in dev extent"`.
//!   2. Overlapping DEV_EXTENT: Assert `btrfs check` fails with `"overlap with previous dev extent end"`.
//!   3. Bad DEV_ITEM.bytes_used: Assert `btrfs check` fails with `"total-byte"` `"byte-used"` mismatch.
//!   4. Chunk length mismatch: Assert `btrfs check` fails with `"mismatch with block group"`.
//!   5. Overlapping chunk range: Assert `btrfs check` fails with `"existed"`.
//!
//! - **Pass I.3: ChunkMap refresh control**:
//!   Simulate skipping `chunks.insert(new_chunk)` before commit; assert commit fails to map
//!   logical to physical blocks.
#![cfg(feature = "dangerous-write-support")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use luks_core::device::{FileDevice, WriteAt};
use luks_core::fs::btrfs::chunk::{
    Chunk, DevExtent, BLOCK_GROUP_DATA,
};
use luks_core::fs::btrfs::tree::{
    Key, DEV_EXTENT_KEY, DEV_ITEMS_OBJECTID, DEV_ITEM_KEY,
    DEV_TREE_OBJECTID,
};
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::commit::commit_transaction;
use luks_core::fs::btrfs::write::exclude::{compute_sb_exclusions, SB_PROTECT_LEN};
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::write::node::Leaf;
use luks_core::fs::btrfs::write::txn::Transaction;
use luks_core::fs::btrfs::Btrfs;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("btrfs")
        .join(name)
}

fn copy_to_temp(src_name: &str) -> PathBuf {
    let src = fixture(src_name);
    let temp_dir = std::env::temp_dir();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dst = temp_dir.join(format!(
        "btrfs-ctrl-{src_name}-{}-{}-{}",
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

fn run_verify_script(image_path: &Path) -> (bool, String) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !common::oracle::gate() {
        return (true, String::new());
    }

    let output = Command::new(&script)
        .arg(image_path)
        .output()
        .expect("execute verify-btrfs.sh");

    if output.status.success() {
        println!("ORACLE VERIFIED: verify-btrfs.sh passed for {}", image_path.display());
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

fn run_btrfs_check(image_path: &Path) -> (bool, String) {
    if !common::oracle::gate() {
        return (true, String::new());
    }

    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let remote = format!(
        "/tmp/check-ctrl-{}-{}-{}.img",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let cp_status = Command::new("colima")
        .args(["ssh", "--", "tee", &remote])
        .stdin(fs::File::open(image_path).expect("open image for colima"))
        .stdout(std::process::Stdio::null())
        .status()
        .expect("copy image to colima");
    assert!(cp_status.success(), "failed to copy image to colima");

    let cmd = format!(
        "btrfs check --readonly {remote}; ret=$?; rm -f {remote}; exit $ret"
    );
    let output = Command::new("colima")
        .args(["ssh", "--", "sudo", "bash", "-c", &cmd])
        .output()
        .expect("execute btrfs check in colima");

    if output.status.success() {
        println!("ORACLE VERIFIED: btrfs check passed for {}", image_path.display());
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

// ============================================================================
// Pass I.1: Exclusion control
// ============================================================================

#[test]
fn test_pass_i1_disabled_exclusions_fails_scrub() {
    // 1. On plain.img (4 GiB equivalent layout), METADATA|DUP chunk starts at
    //    logical 30408704 with stripe 0 at physical 38797312.
    //    Superblock mirror 1 is at physical 67108864.
    //    Reverse-mapped logical address = 30408704 + (67108864 - 38797312) = 58720256.
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // Verify logical mapping
    let (phys, _len) = fs.chunk_map().map(58_720_256).expect("map 58720256");
    assert_eq!(phys, 67_108_864, "logical 58720256 must map to physical 67108864");

    // Simulate an allocation with exclusions disabled that overwrites Superblock mirror 1
    // by writing dummy non-superblock data directly to that mapped physical location.
    let dummy_block = vec![0xEEu8; 4096];
    fs.device().write_at(phys, &dummy_block).expect("overwrite mirror 1");
    fs.device().flush().expect("flush device");
    drop(fs);

    // Run Oracle verification script (btrfs check -> mount -> btrfs scrub)
    let (clean, output) = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "verify-btrfs.sh MUST fail when superblock mirror 1 is overwritten");
    assert!(
        output.contains("Error summary:    super=1") || output.contains("Error summary: super=1"),
        "scrub output must report 'Error summary: super=1', got:\n{output}"
    );
}

#[test]
fn test_pass_i1_enabled_exclusions_keeps_image_clean() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Verify computed exclusions include 58720256..58785792
    let exclusions = compute_sb_exclusions(fs.chunk_map());
    assert!(
        exclusions.contains(&(58_720_256..58_720_256 + SB_PROTECT_LEN)),
        "exclusions must contain mirror 1 at 58720256..58785792, got: {exclusions:?}"
    );

    // 2. Derive FreeSpaceMap with exclusions applied
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())
        .expect("derive allocator");

    for bg in &allocator.block_groups {
        for range in &bg.free_ranges {
            let r_start = range.start;
            let r_end = range.start + range.length;
            // Free ranges must not overlap with 58720256..58785792
            assert!(
                r_end <= 58_720_256 || r_start >= 58_720_256 + SB_PROTECT_LEN,
                "free range {r_start}..{r_end} must not overlap excluded mirror 1"
            );
        }
    }

    // Allocate metadata and perform normal operations
    let allocated = allocator.allocate_metadata(16384).expect("allocate metadata");
    assert!(
        allocated < 58_720_256 || allocated >= 58_720_256 + SB_PROTECT_LEN,
        "allocated metadata block {allocated} must not land in excluded mirror 1"
    );

    // Dynamic chunk allocation
    let _new_log = fs.allocate_data_chunk().expect("allocate data chunk");

    drop(fs);

    let (clean, output) = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(clean, "verify-btrfs.sh must pass clean with exclusions enabled. Output:\n{output}");
}

#[test]
fn test_pass_i1_stress_allocation_records_highest_logical_metadata() {
    // Run 684-file stress allocation test on mixed-4k.img and plain.img to determine
    // whether logical address 58720256 is reached in practice (Gate I -> J).
    let temp_img = copy_to_temp("mixed-4k.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let mut highest_metadata_bytenr: u64 = 0;

    for i in 0..684 {
        let name = format!("stress_{i:05}.txt");
        fs.create_file("/", &name)
            .unwrap_or_else(|e| panic!("create_file #{i} failed: {e:?}"));
    }

    // Inspect all tree roots and nodes to find highest metadata address
    let mut roots = vec![
        fs.superblock().root,
        fs.superblock().chunk_root,
        fs.fs_tree().bytenr,
    ];
    if let Ok(ext_root) = fs.tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID) {
        roots.push(ext_root.bytenr);
    }

    for root in roots {
        let mut stack = vec![root];
        while let Some(bytenr) = stack.pop() {
            highest_metadata_bytenr = highest_metadata_bytenr.max(bytenr);
            if let Ok(node) = fs.read_node(bytenr) {
                if !node.is_leaf() {
                    for j in 0..node.nr_items {
                        if let Ok(ptr) = node.key_ptr(j) {
                            stack.push(ptr.blockptr);
                        }
                    }
                }
            }
        }
    }

    println!(
        "Pass I.1 Gate I -> J evidence: 684 files created on mixed-4k.img. Highest metadata bytenr = {} (0x{:X})",
        highest_metadata_bytenr, highest_metadata_bytenr
    );
    assert!(
        highest_metadata_bytenr < 58_720_256,
        "Highest metadata bytenr ({highest_metadata_bytenr}) did not reach 58720256"
    );

    drop(fs);

    let (clean, output) = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(clean, "verify-btrfs.sh must pass clean after 684 files stress test. Output:\n{output}");
}

// ============================================================================
// Pass I.2: On-disk item controls
// ============================================================================

#[test]
fn test_pass_i2_omit_dev_extent() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;

    // 1. Read DEV_TREE root
    let dev_root = fs.tree_root(DEV_TREE_OBJECTID).expect("read dev tree root");
    let node = fs.read_node(dev_root.bytenr).expect("read dev tree node");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("leaf from node");

    // 2. Find and delete the DEV_EXTENT at physical 13631488
    let target_key = Key::new(1, DEV_EXTENT_KEY, 13_631_488);
    leaf.delete_item(&target_key).expect("delete dev extent item");

    // 3. Emit leaf and write to all stripes
    let emitted = leaf.emit(node_size).expect("emit leaf");
    let stripes = fs.chunk_map().map_all_stripes(node.bytenr()).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush device");
    drop(fs);

    // 4. Run btrfs check --readonly
    let (clean, output) = run_btrfs_check(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "btrfs check MUST fail when DEV_EXTENT is omitted");
    assert!(
        output.contains("is not found in dev extent"),
        "btrfs check output must contain 'is not found in dev extent', got:\n{output}"
    );
}

#[test]
fn test_pass_i2_overlapping_dev_extent() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let chunk_tree_uuid = fs.chunk_tree_uuid().expect("chunk tree uuid");

    // 1. Read DEV_TREE root
    let dev_root = fs.tree_root(DEV_TREE_OBJECTID).expect("read dev tree root");
    let node = fs.read_node(dev_root.bytenr).expect("read dev tree node");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("leaf from node");

    // 2. Insert overlapping DEV_EXTENT at physical 14000000 (overlaps with 13631488..22020096)
    let overlap_extent = DevExtent::new(1, 14_000_000, 13_631_488, 8_388_608, chunk_tree_uuid);
    let (key, payload) = overlap_extent.emit();
    leaf.insert_item(key, payload, node_size).expect("insert overlapping dev extent");

    // 3. Emit leaf and write to all stripes
    let emitted = leaf.emit(node_size).expect("emit leaf");
    let stripes = fs.chunk_map().map_all_stripes(node.bytenr()).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush device");
    drop(fs);

    // 4. Run btrfs check --readonly
    let (clean, output) = run_btrfs_check(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "btrfs check MUST fail when DEV_EXTENTs overlap");
    assert!(
        output.contains("overlap with previous dev extent end"),
        "btrfs check output must contain 'overlap with previous dev extent end', got:\n{output}"
    );
}

#[test]
fn test_pass_i2_bad_dev_item_bytes_used() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;

    // 1. Read CHUNK_TREE root
    let node = fs.read_node(sb.chunk_root).expect("read chunk root");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("leaf from node");

    // 2. Corrupt DEV_ITEM.bytes_used at offset 0x10..0x18
    let dev_item_key = Key::new(DEV_ITEMS_OBJECTID, DEV_ITEM_KEY, 1);
    let idx = leaf.find_item(&dev_item_key).expect("find dev item");
    let cur_used = u64::from_le_bytes(leaf.items[idx].data[0x10..0x18].try_into().unwrap());
    let corrupted_used = cur_used + 1024 * 1024; // Mismatch
    leaf.items[idx].data[0x10..0x18].copy_from_slice(&corrupted_used.to_le_bytes());

    // 3. Emit leaf and write to all stripes
    let emitted = leaf.emit(node_size).expect("emit leaf");
    let stripes = fs.chunk_map().map_all_stripes(node.bytenr()).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush device");
    drop(fs);

    // 4. Run btrfs check --readonly
    let (clean, output) = run_btrfs_check(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "btrfs check MUST fail when DEV_ITEM.bytes_used does not match sum of DEV_EXTENTs");
    assert!(
        output.contains("total-byte") && output.contains("byte-used"),
        "btrfs check output must contain 'total-byte' and 'byte-used' mismatch, got:\n{output}"
    );
}

#[test]
fn test_pass_i2_chunk_length_mismatch() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;

    // 1. Read EXTENT_TREE root
    let ext_root = fs.tree_root(luks_core::fs::btrfs::tree::EXTENT_TREE_OBJECTID)
        .expect("read extent tree root");
    let node = fs.read_node(ext_root.bytenr).expect("read extent root");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("leaf from node");

    // 2. Corrupt BLOCK_GROUP_ITEM key offset (length: 8 MiB -> 4 MiB) to mismatch CHUNK_ITEM length
    let bg_key = Key::new(13_631_488, luks_core::fs::btrfs::tree::BLOCK_GROUP_ITEM_KEY, 8_388_608);
    let idx = leaf.find_item(&bg_key).expect("find block group item");
    leaf.items[idx].key.offset = 4_194_304; // Length mismatch with chunk item (8 MiB vs 4 MiB)

    // 3. Emit leaf and write to all stripes
    let emitted = leaf.emit(node_size).expect("emit leaf");
    let stripes = fs.chunk_map().map_all_stripes(node.bytenr()).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush device");
    drop(fs);

    // 4. Run btrfs check --readonly
    let (clean, output) = run_btrfs_check(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "btrfs check MUST fail when CHUNK_ITEM length != block group length");
    assert!(
        output.contains("mismatch with block group"),
        "btrfs check output must contain 'mismatch with block group', got:\n{output}"
    );
}

#[test]
fn test_pass_i2_overlapping_chunk_range() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let fs = Btrfs::mount(dev).expect("mount writable btrfs");

    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;

    // 1. Read CHUNK_TREE root
    let node = fs.read_node(sb.chunk_root).expect("read chunk root");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("leaf from node");

    // 2. Insert two chunks with overlapping ranges past existing chunks:
    //    Chunk A: 100_663_296 (96 MiB), length 8 MiB -> spans 96 MiB..104 MiB (100_663_296..109_051_904)
    //    Chunk B: 104_857_600 (100 MiB), length 8 MiB -> spans 100 MiB..108 MiB (104_857_600..113_246_208)
    //    Chunk B overlaps Chunk A by 4 MiB!
    let chunk_a = Chunk::new_single(
        100_663_296,
        8_388_608,
        BLOCK_GROUP_DATA,
        1,
        13_631_488,
        [0u8; 16],
    );
    let (key_a, payload_a) = chunk_a.emit();
    leaf.insert_item(key_a, payload_a, node_size).expect("insert chunk A");

    let chunk_b = Chunk::new_single(
        104_857_600,
        8_388_608,
        BLOCK_GROUP_DATA,
        1,
        13_631_488,
        [0u8; 16],
    );
    let (key_b, payload_b) = chunk_b.emit();
    leaf.insert_item(key_b, payload_b, node_size).expect("insert chunk B");

    // 3. Emit leaf and write to all stripes
    let emitted = leaf.emit(node_size).expect("emit leaf");
    let stripes = fs.chunk_map().map_all_stripes(node.bytenr()).expect("map stripes");
    for phys in &stripes {
        fs.device().write_at(*phys, &emitted).expect("write leaf");
    }
    fs.device().flush().expect("flush device");
    drop(fs);

    // 4. Run btrfs check --readonly
    let (clean, output) = run_btrfs_check(&temp_img);
    let _ = fs::remove_file(&temp_img);

    assert!(!clean, "btrfs check MUST fail when chunk logical ranges overlap");
    assert!(
        output.contains("existed"),
        "btrfs check output must contain 'existed', got:\n{output}"
    );
}

// ============================================================================
// Pass I.3: ChunkMap refresh control
// ============================================================================

#[test]
fn test_pass_i3_chunk_map_refresh_omission_fails_commit() {
    let temp_img = copy_to_temp("plain.img");
    let file_len = fs::metadata(&temp_img).unwrap().len();

    let dev = FileDevice::open_writable(&temp_img, file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount writable btrfs");

    // 1. Prepare chunk allocation transaction
    let (mut txn, new_chunk) = Transaction::allocate_data_chunk(&fs)
        .expect("allocate data chunk transaction");

    // Add pending data in the newly allocated chunk's logical address range
    let new_chunk_logical = new_chunk.logical;
    let dummy_data = vec![0x42u8; 4096];
    txn.pending_data.push((new_chunk_logical, dummy_data));

    // 2. Control: Skipping chunks.insert(new_chunk) MUST fail to map and fail commit_transaction
    let commit_res = commit_transaction(&mut fs, txn.clone());
    assert!(
        commit_res.is_err(),
        "commit_transaction MUST fail when ChunkMap refresh was skipped"
    );

    // 3. Now perform the ChunkMap refresh and commit successfully
    fs.chunk_map_mut().insert(new_chunk);
    let commit_success = commit_transaction(&mut fs, txn);
    assert!(
        commit_success.is_ok(),
        "commit_transaction must succeed once ChunkMap is properly refreshed: {:?}",
        commit_success.err()
    );

    drop(fs);

    let (clean, output) = run_verify_script(&temp_img);
    let _ = fs::remove_file(&temp_img);
    assert!(clean, "verify-btrfs.sh must pass clean after properly refreshed chunk commit. Output:\n{output}");
}
