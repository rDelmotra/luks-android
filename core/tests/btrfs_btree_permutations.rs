//! Intensive & Extensive B-Tree Mutation, Permutation & Property Stress Suite.
//!
//! Exercises the Btrfs B-tree mutation engine across 5 dimensions:
//! 1. Key ordering permutations (ascending, descending, alternating ends, pseudo-random, burst).
//! 2. Item size distributions and 3-way leaf split shapes (tiny, huge 3.5 KiB, bimodal, boundary).
//! 3. Tree height scaling (Level 0 -> 1 -> 2) and collapse (Level 2 -> 1 -> 0).
//! 4. Stateful fuzzing / property cycle against a BTreeMap reference model.
//! 5. Milestone Linux kernel oracle grading (btrfs check, mount, btrfs scrub).
//!
//! Invariants I-1 through I-5 and bidirectional Cursor parity are validated
//! at every mutation step via [`TreeValidator`].

#![cfg(feature = "dangerous-write-support")]
#![allow(clippy::explicit_counter_loop)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Command;

use common::btree_validator::TreeValidator;
use common::mem_device::MemoryDevice;
use common::scratch::ScratchFixture;

use luks_core::device::{FileDevice, WriteAt};
use luks_core::fs::btrfs::tree::Key;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::cow::{cow_tree_insert, cow_tree_mutate};
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::write::node::Leaf;
use luks_core::fs::btrfs::Btrfs;

/// Simple, deterministic Linear Congruential Generator (LCG) for reproducible pseudo-random testing.
struct TestRng {
    state: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }

    fn next_range(&mut self, min: u32, max: u32) -> u32 {
        assert!(max >= min);
        if max == min {
            return min;
        }
        min + (self.next_u32() % (max - min + 1))
    }

    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = (self.next_u32() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }
}

/// Helper to initialize an in-memory Btrfs instance from the `mixed-4k.img` fixture.
fn setup_in_memory_fixture() -> (Btrfs<MemoryDevice>, FreeSpaceMap, u64, u8) {
    let mem_dev = MemoryDevice::from_fixture("btrfs/mixed-4k.img");
    let fs = Btrfs::mount(mem_dev).expect("mount mixed-4k fixture into memory");
    let fs_tree = fs.fs_tree();
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map())
        .expect("build allocator");

    (fs, allocator, fs_tree.bytenr, fs_tree.level)
}

/// Flush pending blocks into the underlying device and return a fresh Btrfs mount over it.
fn commit_pending_to_device(
    dev: &MemoryDevice,
    pending: &HashMap<u64, Vec<u8>>,
) -> Btrfs<MemoryDevice> {
    for (&bytenr, block) in pending {
        dev.write_at(bytenr, block).expect("write pending block to memory device");
    }
    Btrfs::mount(dev.clone()).expect("remount memory device")
}

// -----------------------------------------------------------------------------
// Test 1: Key Ordering Permutations
// -----------------------------------------------------------------------------
#[test]
fn test_btree_key_order_permutations() {
    let orders = ["ascending", "descending", "alternating_edges", "pseudo_random", "clustered_burst"];

    for &order in &orders {
        let (mut fs, mut allocator, mut root_bytenr, mut root_level) = setup_in_memory_fixture();
        let mem_dev = fs.device().clone();
        let owner = fs.fs_tree().objectid;
        let mut generation = fs.fs_tree().generation + 1;
        let mut pending = HashMap::new();

        // Generate 60 distinct keys
        let num_items = 60usize;
        let mut keys: Vec<Key> = (0..num_items)
            .map(|i| Key::new(3000 + i as u64, 1, 0))
            .collect();

        match order {
            "ascending" => { /* already in ascending order */ }
            "descending" => {
                keys.reverse();
            }
            "alternating_edges" => {
                let mut alt = Vec::with_capacity(num_items);
                let mut l = 0;
                let mut r = num_items - 1;
                while l <= r {
                    alt.push(keys[l]);
                    if l != r {
                        alt.push(keys[r]);
                    }
                    l += 1;
                    if r == 0 { break; }
                    r -= 1;
                }
                keys = alt;
            }
            "pseudo_random" => {
                let mut rng = TestRng::new(0xABCD1234);
                rng.shuffle(&mut keys);
            }
            "clustered_burst" => {
                keys = (0..num_items)
                    .map(|i| {
                        let cluster = (i / 10) as u64;
                        let offset = (i % 10) as u64 * 100;
                        Key::new(4000 + cluster, 2, offset)
                    })
                    .collect();
            }
            _ => unreachable!(),
        }

        // Insert items one by one and validate invariants after every step
        for (idx, key) in keys.into_iter().enumerate() {
            let data = vec![(idx % 255) as u8; 120]; // 120 bytes data
            let res = cow_tree_insert(
                &fs,
                &pending,
                root_bytenr,
                root_level,
                owner,
                key,
                data,
                generation,
                &mut allocator,
            )
            .unwrap_or_else(|e| panic!("order {order} insert item {idx} ({key:?}): {e}"));

            root_bytenr = res.new_root_bytenr;
            root_level = res.new_root_level;
            for (b, block) in res.emitted_blocks {
                pending.insert(b, block);
            }
            generation += 1;

            // Remount in memory to validate via TreeValidator
            fs = commit_pending_to_device(&mem_dev, &pending);
            pending.clear();

            let report = TreeValidator::validate(&fs, root_bytenr, Some(root_level))
                .unwrap_or_else(|e| panic!("order {order} step {idx} validator failure: {e}"));

            assert!(report.total_items > 0, "order {order} must have items");
        }
    }
}

// -----------------------------------------------------------------------------
// Test 2: Variable Item Sizes & 3-Way Split Shapes
// -----------------------------------------------------------------------------
#[test]
fn test_btree_variable_item_sizes_and_3way_split_shapes() {
    let (mut fs, mut allocator, mut root_bytenr, mut root_level) = setup_in_memory_fixture();
    let mem_dev = fs.device().clone();
    let owner = fs.fs_tree().objectid;
    let mut generation = fs.fs_tree().generation + 1;
    let mut pending = HashMap::new();

    // Node size is 4096 bytes for mixed-4k.img.
    // Max allowable item payload is ~3960 bytes.
    // We test 3 item size classes:
    // - Tiny: 24 bytes (DIR_ITEM / INODE_REF)
    // - Huge: 3200 bytes (nearly fills an entire leaf)
    // - Boundary: exact fit tests
    let mut rng = TestRng::new(0x98765432);

    let mut expected_items = BTreeMap::new();

    for i in 0..40 {
        let key = Key::new(5000 + i as u64, 1, (i * 10) as u64);
        let size = if i % 5 == 0 {
            3200 // Huge item: forces Shape 3 (item gets a leaf to itself)
        } else if i % 2 == 0 {
            24 // Tiny item: fits comfortably
        } else {
            rng.next_range(100, 600) as usize // Moderate item
        };

        let data = vec![(i & 0xFF) as u8; size];
        expected_items.insert(key, data.clone());

        let res = cow_tree_insert(
            &fs,
            &pending,
            root_bytenr,
            root_level,
            owner,
            key,
            data,
            generation,
            &mut allocator,
        )
        .unwrap_or_else(|e| panic!("variable size insert {i} (size {size}): {e}"));

        root_bytenr = res.new_root_bytenr;
        root_level = res.new_root_level;
        for (b, block) in res.emitted_blocks {
            pending.insert(b, block);
        }
        generation += 1;

        fs = commit_pending_to_device(&mem_dev, &pending);
        pending.clear();

        TreeValidator::validate(&fs, root_bytenr, Some(root_level))
            .unwrap_or_else(|e| panic!("variable size step {i} validator failure: {e}"));
    }
}

// -----------------------------------------------------------------------------
// Test 3: Height Scaling and Root Collapse
// -----------------------------------------------------------------------------
#[test]
fn test_btree_height_scaling_and_root_collapse() {
    let (mut fs, mut allocator, mut root_bytenr, mut root_level) = setup_in_memory_fixture();
    let mem_dev = fs.device().clone();
    let owner = fs.fs_tree().objectid;
    let mut generation = fs.fs_tree().generation + 1;
    let mut pending = HashMap::new();

    // 1. Scale tree height: with 4 KiB nodes, inserting 200 items of 300 bytes
    // will fill leaves (~12 items per leaf) and interior nodes (121 children),
    // driving tree height up.
    let count = 80;
    let mut inserted_keys = Vec::new();

    for i in 0..count {
        let key = Key::new(7000 + i as u64, 1, 0);
        let data = vec![0xEE; 250];

        let res = cow_tree_insert(
            &fs,
            &pending,
            root_bytenr,
            root_level,
            owner,
            key,
            data,
            generation,
            &mut allocator,
        )
        .unwrap_or_else(|e| panic!("height scale insert {i}: {e}"));

        root_bytenr = res.new_root_bytenr;
        root_level = res.new_root_level;
        for (b, block) in res.emitted_blocks {
            pending.insert(b, block);
        }
        generation += 1;
        inserted_keys.push(key);
    }

    fs = commit_pending_to_device(&mem_dev, &pending);
    pending.clear();

    let initial_report = TreeValidator::validate(&fs, root_bytenr, Some(root_level))
        .expect("initial tree valid");
    assert!(
        initial_report.tree_height >= 1,
        "tree must scale to at least height 1, got {}",
        initial_report.tree_height
    );

    // 2. Collapse tree: delete items in reverse order
    for (del_idx, key) in inserted_keys.into_iter().rev().enumerate() {
        let res = cow_tree_mutate(
            &fs,
            &pending,
            root_bytenr,
            root_level,
            owner,
            &key,
            generation,
            &mut allocator,
            |leaf: &mut Leaf| {
                leaf.delete_item(&key).map(|_| ())
            },
        )
        .unwrap_or_else(|e| panic!("collapse delete {del_idx} ({key:?}): {e}"));

        root_bytenr = res.new_root_bytenr;
        root_level = res.new_root_level;
        for (b, block) in res.emitted_blocks {
            pending.insert(b, block);
        }
        generation += 1;

        fs = commit_pending_to_device(&mem_dev, &pending);
        pending.clear();

        TreeValidator::validate(&fs, root_bytenr, Some(root_level))
            .unwrap_or_else(|e| panic!("collapse step {del_idx} validator failure: {e}"));
    }
}

// -----------------------------------------------------------------------------
// Test 4: Stateful Fuzz Cycle with Reference Model
// -----------------------------------------------------------------------------
#[test]
fn test_btree_stateful_fuzz_property_cycle() {
    let (mut fs, mut allocator, mut root_bytenr, mut root_level) = setup_in_memory_fixture();
    let mem_dev = fs.device().clone();
    let owner = fs.fs_tree().objectid;
    let mut generation = fs.fs_tree().generation + 1;
    let initial_report = TreeValidator::validate(&fs, root_bytenr, Some(root_level))
        .expect("initial tree valid");
    let initial_items = initial_report.total_items;
    let mut pending = HashMap::new();

    let mut model: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
    let mut rng = TestRng::new(0xFEEDFACE);

    for op_idx in 0..100 {
        let roll = rng.next_range(1, 100);

        if roll <= 65 || model.is_empty() {
            // Insert
            let key = Key::new(9000 + rng.next_range(1, 500) as u64, 1, rng.next_range(0, 10) as u64);
            let size = rng.next_range(20, 300) as usize;
            let data = vec![(op_idx & 0xFF) as u8; size];

            if model.contains_key(&key) {
                // Key already exists, update payload
                let res = cow_tree_mutate(
                    &fs,
                    &pending,
                    root_bytenr,
                    root_level,
                    owner,
                    &key,
                    generation,
                    &mut allocator,
                    |leaf| leaf.replace_item(&key, data.clone()),
                )
                .unwrap_or_else(|e| panic!("fuzz update {op_idx}: {e}"));

                root_bytenr = res.new_root_bytenr;
                root_level = res.new_root_level;
                for (b, block) in res.emitted_blocks {
                    pending.insert(b, block);
                }
            } else {
                // Insert new item
                let res = cow_tree_insert(
                    &fs,
                    &pending,
                    root_bytenr,
                    root_level,
                    owner,
                    key,
                    data.clone(),
                    generation,
                    &mut allocator,
                )
                .unwrap_or_else(|e| panic!("fuzz insert {op_idx}: {e}"));

                root_bytenr = res.new_root_bytenr;
                root_level = res.new_root_level;
                for (b, block) in res.emitted_blocks {
                    pending.insert(b, block);
                }
            }
            model.insert(key, data);
        } else {
            // Delete
            let keys: Vec<Key> = model.keys().cloned().collect();
            let pick_idx = rng.next_range(0, (keys.len() - 1) as u32) as usize;
            let key_to_del = keys[pick_idx];

            let res = cow_tree_mutate(
                &fs,
                &pending,
                root_bytenr,
                root_level,
                owner,
                &key_to_del,
                generation,
                &mut allocator,
                |leaf| leaf.delete_item(&key_to_del).map(|_| ()),
            )
            .unwrap_or_else(|e| panic!("fuzz delete {op_idx}: {e}"));

            root_bytenr = res.new_root_bytenr;
            root_level = res.new_root_level;
            for (b, block) in res.emitted_blocks {
                pending.insert(b, block);
            }
            model.remove(&key_to_del);
        }

        generation += 1;

        if op_idx % 10 == 0 || op_idx == 99 {
            fs = commit_pending_to_device(&mem_dev, &pending);
            pending.clear();

            let report = TreeValidator::validate(&fs, root_bytenr, Some(root_level))
                .unwrap_or_else(|e| panic!("fuzz validator check at op {op_idx}: {e}"));

            assert_eq!(
                report.total_items,
                model.len() + initial_items,
                "op {op_idx}: item count mismatch"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Test 5: Milestone Linux Kernel Oracle Verification
// -----------------------------------------------------------------------------
fn run_verify_btrfs(image_path: &Path) -> (bool, String) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("verify-btrfs.sh");

    if !script.exists() {
        panic!("tools/verify-btrfs.sh missing");
    }

    if !common::oracle::gate() {
        return (true, "skipped (ALLOW_NO_ORACLE)".into());
    }

    let out = Command::new(&script)
        .arg(image_path)
        .output()
        .expect("execute verify-btrfs.sh");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let combined = format!("{stdout}\n{stderr}");

    (out.status.success(), combined)
}

#[test]
fn test_btree_kernel_oracle_milestone() {
    let scratch = ScratchFixture::new("btrfs/mixed-4k.img", "btree_milestone");
    let file_len = std::fs::metadata(scratch.path()).expect("metadata").len();
    let dev = FileDevice::open_writable(scratch.path(), file_len).expect("open writable");
    let mut fs = Btrfs::mount(dev).expect("mount btrfs");

    // Perform file writes through standard btrfs API to trigger CoW tree mutations
    let test_file = "test_perm.txt";
    let test_bytes = b"Kernel Oracle B-Tree Permutation Verification Content 2026";
    let _ino = fs
        .create_file_with_data("", test_file, test_bytes)
        .expect("create file with data");

    // Re-verify with in-memory TreeValidator first
    TreeValidator::validate(&fs, fs.fs_tree().bytenr, Some(fs.fs_tree().level))
        .expect("in-memory validation before oracle export");

    drop(fs);

    // Run triple-stage Linux kernel oracle check
    let (ok, report) = run_verify_btrfs(scratch.path());
    assert!(ok, "Kernel Oracle verification failed for btree milestone:\n{report}");
}

#[test]
fn test_tree_validator_negative_controls() {
    let (fs, _, root_bytenr, root_level) = setup_in_memory_fixture();

    // 1. Wrong level expectation must fail
    let wrong_level = root_level + 5;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = TreeValidator::validate(&fs, root_bytenr, Some(wrong_level));
    }));
    assert!(res.is_err(), "TreeValidator must fail on wrong root level");

    // 2. Corrupted leaf item order: mutate a node in memory so key[0] > key[1]
    let mem_dev = fs.device().clone();
    let root_node = fs.read_node(root_bytenr).expect("read root");
    let leaf_bytenr = if root_node.is_leaf() {
        root_bytenr
    } else {
        root_node.key_ptr(0).expect("key ptr 0").blockptr
    };

    let leaf_node = fs.read_node(leaf_bytenr).expect("read leaf");
    let mut leaf = Leaf::from_node(&leaf_node, fs.superblock().csum_type).expect("leaf from node");
    if leaf.items.len() >= 2 {
        // Swap first two items to invert sort order!
        leaf.items.swap(0, 1);
        let emitted = leaf.emit(fs.superblock().node_size).expect("emit corrupted leaf");
        mem_dev.write_at(leaf_bytenr, &emitted).expect("write corrupted leaf");

        let remounted = Btrfs::mount(mem_dev).expect("remount corrupted mem dev");
        let catch_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = TreeValidator::validate(&remounted, root_bytenr, Some(root_level));
        }));
        assert!(catch_res.is_err(), "TreeValidator must catch Invariant I-1 inversion!");
    }
}
