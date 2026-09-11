//! In-memory B-tree node surgery tests (Pass C).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_node_surgery
//! ```
//!
//! # The Oracle
//!
//! Ground truth for this pass is the existing reader's [`Node::parse`].
//!
//! This test suite proves:
//! 1. `Leaf::emit` and `InteriorNode::emit` reproduce the on-disk format so
//!    accurately that [`Node::parse`] accepts the emitted blocks with valid
//!    checksums across all 4 fixtures.
//! 2. Mutating, inserting, deleting, and splitting leaves preserves full key
//!    ordering, correct data offsets, and valid checksums.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::superblock::CsumType;
use luks_core::fs::btrfs::tree::{
    Key, Node, EXTENT_TREE_OBJECTID, FS_TREE_OBJECTID, HEADER_SIZE, INODE_ITEM_KEY, ITEM_SIZE,
};
use luks_core::fs::btrfs::write::node::{InteriorNode, Leaf};
use luks_core::fs::btrfs::Btrfs;

const IMAGES: [&str; 4] = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    let dev = FileDevice::open(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    Btrfs::mount(dev).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn round_trip_re_emits_all_leaves_identically_across_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let sb = fs.superblock();
        let node_size = sb.node_size;
        let csum_type = sb.csum_type;
        let metadata_uuid = sb.metadata_uuid;

        // Collect tree roots to visit
        let mut roots = vec![sb.root, sb.chunk_root];
        if let Ok(extent_root) = fs.tree_root(EXTENT_TREE_OBJECTID) {
            roots.push(extent_root.bytenr);
        }
        if let Ok(fs_root) = fs.tree_root(FS_TREE_OBJECTID) {
            roots.push(fs_root.bytenr);
        }

        let mut leaves_tested = 0;

        for root in roots {
            let mut stack = vec![root];
            while let Some(bytenr) = stack.pop() {
                let node = fs.read_node(bytenr).expect("read node");
                if node.is_leaf() {
                    // Test leaf round-trip
                    let leaf = Leaf::from_node(&node, csum_type).expect("from_node");
                    let emitted = leaf.emit(node_size).expect("leaf emit");

                    // Verify reader can parse the emitted bytes directly
                    let parsed = Node::parse(emitted, node.bytenr(), csum_type, &metadata_uuid)
                        .expect("parse emitted leaf");

                    assert_eq!(parsed.nr_items, node.nr_items, "{name} leaf {bytenr}");
                    assert_eq!(parsed.owner, node.owner, "{name} leaf {bytenr}");
                    assert_eq!(parsed.generation, node.generation, "{name} leaf {bytenr}");

                    for i in 0..node.nr_items {
                        assert_eq!(
                            parsed.key(i).unwrap(),
                            node.key(i).unwrap(),
                            "{name} leaf {bytenr} key {i}"
                        );
                        assert_eq!(
                            parsed.item_data(i).unwrap(),
                            node.item_data(i).unwrap(),
                            "{name} leaf {bytenr} item data {i}"
                        );
                    }
                    leaves_tested += 1;
                } else {
                    for i in 0..node.nr_items {
                        let ptr = node.key_ptr(i).expect("key_ptr");
                        stack.push(ptr.blockptr);
                    }
                }
            }
        }

        assert!(leaves_tested > 0, "{name}: should test at least 1 leaf");
    }
}

#[test]
fn round_trip_re_emits_interior_nodes() {
    let fs = mount("plain.img");
    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let metadata_uuid = sb.metadata_uuid;

    // plain.img has an interior node at 30605312 in the fs tree
    let node = fs.read_node(30605312).expect("read interior node");
    assert!(!node.is_leaf());
    assert_eq!(node.level, 1);

    let interior = InteriorNode::from_node(&node, csum_type).expect("from_node");
    let emitted = interior.emit(node_size).expect("interior emit");

    let parsed = Node::parse(emitted, node.bytenr(), csum_type, &metadata_uuid)
        .expect("parse emitted interior node");

    assert_eq!(parsed.level, 1);
    assert_eq!(parsed.nr_items, node.nr_items);

    for i in 0..node.nr_items {
        let want_ptr = node.key_ptr(i).unwrap();
        let got_ptr = parsed.key_ptr(i).unwrap();
        assert_eq!(got_ptr.key, want_ptr.key);
        assert_eq!(got_ptr.blockptr, want_ptr.blockptr);
        assert_eq!(got_ptr.generation, want_ptr.generation);
    }
}

#[test]
fn replace_item_mutates_inode_timestamp_cleanly() {
    let fs = mount("plain.img");
    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let metadata_uuid = sb.metadata_uuid;

    // Read the fs tree root leaf at 30441472
    let node = fs.read_node(30441472).expect("read fs root node");
    let mut leaf = Leaf::from_node(&node, csum_type).expect("from_node");

    // Find the first INODE_ITEM
    let (target_key, mut original_data) = leaf
        .items
        .iter()
        .find(|it| it.key.item_type == INODE_ITEM_KEY)
        .map(|it| (it.key, it.data.clone()))
        .expect("find INODE_ITEM");

    // Mutate the timestamp (mtime is at offset 80..92 in btrfs_inode_item)
    // and generation (transid at offset 0..8)
    assert!(original_data.len() >= 160);
    let new_generation = 9999u64;
    let new_mtime_sec = 1_700_000_000u64;
    original_data[0..8].copy_from_slice(&new_generation.to_le_bytes());
    original_data[80..88].copy_from_slice(&new_mtime_sec.to_le_bytes());

    leaf.replace_item(&target_key, original_data.clone())
        .expect("replace_item");

    // Emit and re-parse with reader
    let emitted = leaf.emit(node_size).expect("emit");
    let parsed = Node::parse(emitted, node.bytenr(), csum_type, &metadata_uuid)
        .expect("parse mutated leaf");

    // Verify the modified item has the new bytes
    let idx = parsed.lower_bound(&target_key).expect("find target");
    assert_eq!(parsed.key(idx).unwrap(), target_key);
    let data = parsed.item_data(idx).unwrap();
    assert_eq!(data, &original_data);

    // Verify all other items are untouched
    for i in 0..node.nr_items {
        if i != idx {
            assert_eq!(parsed.key(i).unwrap(), node.key(i).unwrap());
            assert_eq!(parsed.item_data(i).unwrap(), node.item_data(i).unwrap());
        }
    }
}

#[test]
fn insert_and_delete_items_maintains_sorted_order_and_free_space() {
    let node_size = 16384u32;
    let metadata_uuid = [0x42u8; 16];
    let csum_type = CsumType::Crc32c;

    let mut leaf = Leaf::new(1048576, 1, 5, metadata_uuid, csum_type);
    let initial_free = leaf.free_space(node_size);
    assert_eq!(initial_free, node_size as usize - HEADER_SIZE);

    // Insert keys in unsorted order: 30, 10, 50, 20, 40
    let keys = [30u64, 10, 50, 20, 40];
    for &k in &keys {
        let key = Key::new(k, 1, 0);
        let payload = vec![k as u8; 32];
        leaf.insert_item(key, payload, node_size).expect("insert");
    }

    // Verify sorted order
    let expected_keys = [10u64, 20, 30, 40, 50];
    for (i, &expected) in expected_keys.iter().enumerate() {
        assert_eq!(leaf.items[i].key.objectid, expected);
    }

    let expected_free = initial_free - (5 * (ITEM_SIZE + 32));
    assert_eq!(leaf.free_space(node_size), expected_free);

    // Emit and verify reader parses correctly
    let emitted = leaf.emit(node_size).expect("emit");
    let parsed = Node::parse(emitted, 1048576, csum_type, &metadata_uuid).expect("parse");
    assert_eq!(parsed.nr_items, 5);

    for (i, &expected) in expected_keys.iter().enumerate() {
        assert_eq!(parsed.key(i).unwrap().objectid, expected);
        assert_eq!(parsed.item_data(i).unwrap(), vec![expected as u8; 32]);
    }

    // Delete item 30
    let deleted = leaf.delete_item(&Key::new(30, 1, 0)).expect("delete");
    assert_eq!(deleted, vec![30u8; 32]);
    assert_eq!(leaf.items.len(), 4);
    assert_eq!(leaf.free_space(node_size), expected_free + ITEM_SIZE + 32);

    // Re-emit and verify
    let emitted2 = leaf.emit(node_size).expect("emit after delete");
    let parsed2 = Node::parse(emitted2, 1048576, csum_type, &metadata_uuid).expect("parse2");
    assert_eq!(parsed2.nr_items, 4);
    assert_eq!(parsed2.key(0).unwrap().objectid, 10);
    assert_eq!(parsed2.key(1).unwrap().objectid, 20);
    assert_eq!(parsed2.key(2).unwrap().objectid, 40);
    assert_eq!(parsed2.key(3).unwrap().objectid, 50);
}

#[test]
fn leaf_splitting_preserves_all_items_across_two_halves() {
    let node_size = 4096u32;
    let metadata_uuid = [0x55u8; 16];
    let csum_type = CsumType::Crc32c;

    let mut leaf = Leaf::new(1048576, 1, 5, metadata_uuid, csum_type);

    // Insert 20 items
    for i in 0..20 {
        let key = Key::new(100 + i as u64, 1, 0);
        let payload = vec![i as u8; 64];
        leaf.insert_item(key, payload, node_size).expect("insert");
    }

    // Split leaf
    let (left, right, pivot_key) = leaf.split(2097152).expect("split");

    assert_eq!(left.items.len() + right.items.len(), 20);
    assert_eq!(pivot_key, right.items[0].key);

    for item in &left.items {
        assert!(item.key < pivot_key);
    }
    for item in &right.items {
        assert!(item.key >= pivot_key);
    }

    // Emit both halves and check with reader
    let left_raw = left.emit(node_size).expect("emit left");
    let right_raw = right.emit(node_size).expect("emit right");

    let left_node =
        Node::parse(left_raw, 1048576, csum_type, &metadata_uuid).expect("parse left");
    let right_node =
        Node::parse(right_raw, 2097152, csum_type, &metadata_uuid).expect("parse right");

    assert_eq!(left_node.nr_items, left.items.len());
    assert_eq!(right_node.nr_items, right.items.len());
}

#[test]
fn corrupted_emitted_node_is_rejected_by_checksum_check() {
    let node_size = 16384u32;
    let metadata_uuid = [0x77u8; 16];
    let csum_type = CsumType::Crc32c;

    let mut leaf = Leaf::new(1048576, 1, 5, metadata_uuid, csum_type);
    leaf.insert_item(Key::new(1, 1, 0), vec![1, 2, 3, 4], node_size)
        .expect("insert");

    let mut raw = leaf.emit(node_size).expect("emit");

    // Unmodified parses clean
    assert!(Node::parse(raw.clone(), 1048576, csum_type, &metadata_uuid).is_ok());

    // Corrupt 1 byte in the data area
    raw[16380] ^= 0xff;

    // Must fail checksum verification
    let err = Node::parse(raw, 1048576, csum_type, &metadata_uuid).unwrap_err();
    match err {
        LuksError::FsChecksumMismatch(_) => {}
        other => panic!("expected FsChecksumMismatch, got {other:?}"),
    }
}
