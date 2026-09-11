//! Direct test of the CoW insert path's parent-key fixup (Fix 3 / E.2).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_cow_fixup
//! ```
//!
//! # Background
//!
//! `cow_descend_insert` and `cow_descend` (in `write/cow.rs`) update an
//! interior node's key pointer after CoW-ing a child. Both used to guard the
//! key update with `if child_idx > 0`, which is backwards: `tree.rs`
//! documents that a `KeyPtr` holds "where a subtree lives and the lowest key
//! in it," so the one case that *must* propagate is exactly `child_idx == 0`
//! — a change to the leftmost child's minimum. Real btrfs has
//! `fixup_low_keys()` for precisely this and calls it when the slot is 0.
//!
//! This bug is dormant behind the public API (`create_file` / `write_file` /
//! `set_mtime`) because nothing those paths insert can become a new tree
//! minimum: new inodes are always `max + 1`, and dirents sort after their
//! parent directory's own `INODE_ITEM` (item type 1 < 84/96). So this test
//! drives `cow_tree_insert` directly — it is `pub` and reachable from an
//! integration test — with a synthetic key manually chosen to be below the
//! fixture's current minimum, on a tree with a real interior root.

#![cfg(feature = "dangerous-write-support")]

use std::collections::HashMap;

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::tree::Key;
use luks_core::fs::btrfs::write::cow::{cow_tree_insert, read_node};
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::Btrfs;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    let dev = FileDevice::open(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    Btrfs::mount(dev).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Walk the leftmost path from `bytenr` down to the leaf and return its
/// first key — i.e. the current minimum key of the subtree rooted here.
fn leftmost_key(fs: &Btrfs<FileDevice>, bytenr: u64) -> Key {
    let node = fs.read_node(bytenr).expect("read node");
    if node.is_leaf() {
        node.key(0).expect("leaf has at least one item")
    } else {
        let ptr = node.key_ptr(0).expect("interior node has at least one child");
        leftmost_key(fs, ptr.blockptr)
    }
}

#[test]
fn leftmost_insert_fixes_up_parent_key() {
    let fs = mount("plain.img");
    let fs_tree = fs.fs_tree();

    // The fix only matters on a tree deep enough to have an interior root;
    // plain.img's FS_TREE is documented (feature-btrfs-write.md, Fix 3) as a
    // 2-level tree. Assert it rather than assume it, so this test fails loudly
    // instead of silently proving nothing if the fixture ever changes.
    assert!(
        fs_tree.level >= 1,
        "fixture FS_TREE root must be an interior node for this test to mean anything, got level {}",
        fs_tree.level
    );

    let current_min = leftmost_key(&fs, fs_tree.bytenr);
    assert!(
        current_min.objectid > 0,
        "need room below the current minimum objectid to construct a lower key"
    );

    // A key strictly below every key currently in the tree. child_for()
    // documents that a key below everything in a node descends into child 0
    // at every level, so this reliably drives child_idx == 0 all the way down
    // to the leftmost leaf.
    let below_min_key = Key::new(current_min.objectid - 1, 0, 0);
    assert!(below_min_key < current_min);

    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let mut allocator = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map()).expect("build allocator");

    let pending: HashMap<u64, Vec<u8>> = HashMap::new();
    let res = cow_tree_insert(
        &fs,
        &pending,
        fs_tree.bytenr,
        fs_tree.level,
        fs_tree.objectid,
        below_min_key,
        vec![0u8; 8],
        fs_tree.generation + 1,
        &mut allocator,
    )
    .expect("cow_tree_insert of a new tree minimum must succeed");

    // The new root must still be an interior node (inserting one small item
    // into a fixture-sized tree should not force a root split), and its
    // leftmost key pointer (entries[0]/child_idx 0) must reflect the new
    // minimum — that is exactly the propagation the `child_idx > 0` guard
    // used to suppress.
    let new_pending: HashMap<u64, Vec<u8>> = res.emitted_blocks.into_iter().collect();
    let new_root = read_node(&fs, &new_pending, res.new_root_bytenr).expect("read new root");
    assert!(
        !new_root.is_leaf(),
        "expected the FS_TREE root to remain an interior node after a single small insert"
    );

    let root_child0 = new_root.key_ptr(0).expect("new root has a child 0");
    assert_eq!(
        root_child0.key, below_min_key,
        "parent's entries[0].key must be fixed up to the leftmost child's new lowest key \
         after CoW-ing child_idx == 0; a stale key here is exactly the bug Fix 3 (E.2) closes"
    );
}
