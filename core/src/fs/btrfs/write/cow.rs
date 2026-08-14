//! Copy-on-Write (CoW) path copying for btrfs trees.
//!
//! When any item in a btrfs B-tree is modified, the leaf holding it cannot be
//! edited in place. It is copied to a newly allocated metadata block, and its
//! ancestors up to the tree root are likewise copied with updated child pointers.

use std::collections::HashMap;

use crate::device::ReadAt;
use crate::error::Result;
use crate::fs::btrfs::tree::{Key, Node};
use crate::fs::btrfs::write::alloc::FreeSpaceMap;
use crate::fs::btrfs::write::node::{InteriorNode, Leaf};
use crate::fs::btrfs::Btrfs;

/// Outcome of a CoW tree mutation.
#[derive(Debug)]
pub struct CowResult {
    pub new_root_bytenr: u64,
    pub new_root_level: u8,
    pub emitted_blocks: Vec<(u64, Vec<u8>)>,
    pub allocated: Vec<(u64, u8)>,
    pub freed: Vec<(u64, u8)>,
}

/// Read a node from pending in-memory blocks if it was emitted earlier in this
/// transaction, or from the underlying device.
pub fn read_node<D: ReadAt>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    bytenr: u64,
) -> Result<Node> {
    let sb = fs.superblock();
    if let Some(raw) = pending.get(&bytenr) {
        Node::parse(raw.clone(), bytenr, sb.csum_type, &sb.metadata_uuid)
    } else {
        fs.read_node(bytenr)
    }
}

/// Perform a Copy-on-Write descent from `root_bytenr` down to the leaf containing
/// `target_key`, apply `mutate_fn` on the leaf, and allocate new blocks along
/// the path back to a new tree root.
pub fn cow_tree_mutate<D: ReadAt, F>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    root_bytenr: u64,
    root_level: u8,
    owner: u64,
    target_key: &Key,
    generation: u64,
    allocator: &mut FreeSpaceMap,
    mutate_fn: F,
) -> Result<CowResult>
where
    F: FnOnce(&mut Leaf) -> Result<()>,
{
    let mut allocated = Vec::new();
    let mut freed = Vec::new();

    let (new_root_bytenr, _, emitted) = cow_descend(
        fs,
        pending,
        root_bytenr,
        root_level,
        owner,
        target_key,
        generation,
        allocator,
        &mut allocated,
        &mut freed,
        mutate_fn,
    )?;

    Ok(CowResult {
        new_root_bytenr,
        new_root_level: root_level,
        emitted_blocks: emitted,
        allocated,
        freed,
    })
}

fn cow_descend<D: ReadAt, F>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    bytenr: u64,
    level: u8,
    owner: u64,
    target_key: &Key,
    generation: u64,
    allocator: &mut FreeSpaceMap,
    allocated: &mut Vec<(u64, u8)>,
    freed: &mut Vec<(u64, u8)>,
    mutate_fn: F,
) -> Result<(u64, Key, Vec<(u64, Vec<u8>)>)>
where
    F: FnOnce(&mut Leaf) -> Result<()>,
{
    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let node = read_node(fs, pending, bytenr)?;

    let is_already_new = node.generation == generation && pending.contains_key(&bytenr);

    if level == 0 {
        // Leaf node
        let mut leaf = Leaf::from_node(&node, csum_type)?;
        mutate_fn(&mut leaf)?;

        let target_bytenr = if is_already_new {
            bytenr
        } else {
            let b = allocator.allocate_metadata(node_size)?;
            allocated.push((b, 0));
            freed.push((bytenr, 0));
            b
        };

        leaf.bytenr = target_bytenr;
        leaf.generation = generation;
        leaf.owner = owner;

        let emitted = leaf.emit(node_size)?;
        let first_key = leaf.items.first().map(|it| it.key).unwrap_or(*target_key);
        Ok((target_bytenr, first_key, vec![(target_bytenr, emitted)]))
    } else {
        // Interior node
        let mut interior = InteriorNode::from_node(&node, csum_type)?;
        let child_idx = node.child_for(target_key)?;
        let child_ptr = node.key_ptr(child_idx)?;

        let (new_child_bytenr, new_child_key, mut emitted_blocks) = cow_descend(
            fs,
            pending,
            child_ptr.blockptr,
            level - 1,
            owner,
            target_key,
            generation,
            allocator,
            allocated,
            freed,
            mutate_fn,
        )?;

        // Update child pointer in interior node
        interior.entries[child_idx].blockptr = new_child_bytenr;
        interior.entries[child_idx].generation = generation;
        if child_idx > 0 {
            interior.entries[child_idx].key = new_child_key;
        }

        let target_bytenr = if is_already_new {
            bytenr
        } else {
            let b = allocator.allocate_metadata(node_size)?;
            allocated.push((b, level));
            freed.push((bytenr, level));
            b
        };

        interior.bytenr = target_bytenr;
        interior.generation = generation;
        interior.owner = owner;

        let emitted = interior.emit(node_size)?;
        let first_key = interior.entries.first().map(|e| e.key).unwrap_or(*target_key);
        emitted_blocks.push((target_bytenr, emitted));

        Ok((target_bytenr, first_key, emitted_blocks))
    }
}
