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

/// Insert a `(key, data)` item into the tree starting at `root_bytenr`.
///
/// If the target leaf overflows, the leaf is split into two halves and the
/// pivot key is inserted into its parent interior node. If the root node
/// itself splits, the tree height increases (`new_root_level = root_level + 1`).
pub fn cow_tree_insert<D: ReadAt>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    root_bytenr: u64,
    root_level: u8,
    owner: u64,
    key: Key,
    data: Vec<u8>,
    generation: u64,
    allocator: &mut FreeSpaceMap,
) -> Result<CowResult> {
    let mut allocated = Vec::new();
    let mut freed = Vec::new();

    let (left_bytenr, left_first_key, split_opt, mut emitted) = cow_descend_insert(
        fs,
        pending,
        root_bytenr,
        root_level,
        owner,
        &key,
        data,
        generation,
        allocator,
        &mut allocated,
        &mut freed,
    )?;

    if let Some((split_key, split_bytenr)) = split_opt {
        // The root itself split! We must create a new interior root node at level root_level + 1
        let sb = fs.superblock();
        let new_root_level = root_level + 1;
        let new_root_bytenr = allocator.allocate_metadata(sb.node_size)?;
        allocated.push((new_root_bytenr, new_root_level));

        let root_node = read_node(fs, pending, root_bytenr)?;
        let chunk_tree_uuid = root_node.chunk_tree_uuid();

        let new_root = InteriorNode {
            bytenr: new_root_bytenr,
            generation,
            owner,
            level: new_root_level,
            flags: root_node.flags(),
            metadata_uuid: sb.metadata_uuid,
            chunk_tree_uuid,
            csum_type: sb.csum_type,
            entries: vec![
                crate::fs::btrfs::write::node::InteriorEntry {
                    key: left_first_key,
                    blockptr: left_bytenr,
                    generation,
                },
                crate::fs::btrfs::write::node::InteriorEntry {
                    key: split_key,
                    blockptr: split_bytenr,
                    generation,
                },
            ],
        };

        let raw = new_root.emit(sb.node_size)?;
        emitted.push((new_root_bytenr, raw));

        Ok(CowResult {
            new_root_bytenr,
            new_root_level,
            emitted_blocks: emitted,
            allocated,
            freed,
        })
    } else {
        Ok(CowResult {
            new_root_bytenr: left_bytenr,
            new_root_level: root_level,
            emitted_blocks: emitted,
            allocated,
            freed,
        })
    }
}

fn cow_descend_insert<D: ReadAt>(
    fs: &Btrfs<D>,
    pending: &HashMap<u64, Vec<u8>>,
    bytenr: u64,
    level: u8,
    owner: u64,
    target_key: &Key,
    target_data: Vec<u8>,
    generation: u64,
    allocator: &mut FreeSpaceMap,
    allocated: &mut Vec<(u64, u8)>,
    freed: &mut Vec<(u64, u8)>,
) -> Result<(u64, Key, Option<(Key, u64)>, Vec<(u64, Vec<u8>)>)> {
    let sb = fs.superblock();
    let node_size = sb.node_size;
    let csum_type = sb.csum_type;
    let node = read_node(fs, pending, bytenr)?;

    let is_already_new = node.generation == generation && pending.contains_key(&bytenr);

    if level == 0 {
        // Leaf node
        let mut leaf = Leaf::from_node(&node, csum_type)?;
        let needed = crate::fs::btrfs::tree::ITEM_SIZE + target_data.len();

        if needed <= leaf.free_space(node_size) {
            // Leaf has space: insert directly
            leaf.insert_item(*target_key, target_data, node_size)?;

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
            Ok((target_bytenr, first_key, None, vec![(target_bytenr, emitted)]))
        } else {
            // Leaf is full: split into left and right
            let right_bytenr = allocator.allocate_metadata(node_size)?;
            allocated.push((right_bytenr, 0));

            let (mut left, mut right, pivot_key) = leaf.split(right_bytenr)?;

            if *target_key < pivot_key {
                left.insert_item(*target_key, target_data, node_size)?;
            } else {
                right.insert_item(*target_key, target_data, node_size)?;
            }

            let left_target_bytenr = if is_already_new {
                bytenr
            } else {
                let b = allocator.allocate_metadata(node_size)?;
                allocated.push((b, 0));
                freed.push((bytenr, 0));
                b
            };

            left.bytenr = left_target_bytenr;
            left.generation = generation;
            left.owner = owner;

            right.bytenr = right_bytenr;
            right.generation = generation;
            right.owner = owner;

            let left_raw = left.emit(node_size)?;
            let right_raw = right.emit(node_size)?;

            let left_first_key = left.items[0].key;
            let right_first_key = right.items[0].key;

            let mut emitted = Vec::with_capacity(2);
            emitted.push((left_target_bytenr, left_raw));
            emitted.push((right_bytenr, right_raw));

            Ok((
                left_target_bytenr,
                left_first_key,
                Some((right_first_key, right_bytenr)),
                emitted,
            ))
        }
    } else {
        // Interior node
        let mut interior = InteriorNode::from_node(&node, csum_type)?;
        let child_idx = node.child_for(target_key)?;
        let child_ptr = node.key_ptr(child_idx)?;

        let (new_child_bytenr, new_child_key, split_opt, mut emitted_blocks) = cow_descend_insert(
            fs,
            pending,
            child_ptr.blockptr,
            level - 1,
            owner,
            target_key,
            target_data,
            generation,
            allocator,
            allocated,
            freed,
        )?;

        // Update child pointer in interior node
        interior.entries[child_idx].blockptr = new_child_bytenr;
        interior.entries[child_idx].generation = generation;
        if child_idx > 0 {
            interior.entries[child_idx].key = new_child_key;
        }

        if let Some((split_key, split_bytenr)) = split_opt {
            let needed = crate::fs::btrfs::tree::HEADER_SIZE
                + (interior.entries.len() + 1) * crate::fs::btrfs::tree::KEY_PTR_SIZE;

            if needed <= node_size as usize {
                interior.entries.push(crate::fs::btrfs::write::node::InteriorEntry {
                    key: split_key,
                    blockptr: split_bytenr,
                    generation,
                });
                interior.entries.sort_by_key(|e| e.key);

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

                Ok((target_bytenr, first_key, None, emitted_blocks))
            } else {
                // Interior node is full: split interior node
                let right_int_bytenr = allocator.allocate_metadata(node_size)?;
                allocated.push((right_int_bytenr, level));

                interior.entries.push(crate::fs::btrfs::write::node::InteriorEntry {
                    key: split_key,
                    blockptr: split_bytenr,
                    generation,
                });
                interior.entries.sort_by_key(|e| e.key);

                let (mut left_int, mut right_int, _) = interior.split(right_int_bytenr)?;

                let left_target_bytenr = if is_already_new {
                    bytenr
                } else {
                    let b = allocator.allocate_metadata(node_size)?;
                    allocated.push((b, level));
                    freed.push((bytenr, level));
                    b
                };

                left_int.bytenr = left_target_bytenr;
                left_int.generation = generation;
                left_int.owner = owner;

                right_int.bytenr = right_int_bytenr;
                right_int.generation = generation;
                right_int.owner = owner;

                let left_raw = left_int.emit(node_size)?;
                let right_raw = right_int.emit(node_size)?;

                let left_first_key = left_int.entries[0].key;
                let right_first_key = right_int.entries[0].key;

                emitted_blocks.push((left_target_bytenr, left_raw));
                emitted_blocks.push((right_int_bytenr, right_raw));

                Ok((
                    left_target_bytenr,
                    left_first_key,
                    Some((right_first_key, right_int_bytenr)),
                    emitted_blocks,
                ))
            }
        } else {
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

            Ok((target_bytenr, first_key, None, emitted_blocks))
        }
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
