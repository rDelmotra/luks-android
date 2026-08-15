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
use crate::fs::btrfs::write::node::{InteriorNode, Leaf, LeafItem};
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

    let (left_bytenr, left_first_key, extra_siblings, mut emitted) = cow_descend_insert(
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

    if !extra_siblings.is_empty() {
        // The root itself split! We must create a new interior root node at level root_level + 1
        let sb = fs.superblock();
        let new_root_level = root_level + 1;
        let new_root_bytenr = allocator.allocate_metadata(sb.node_size)?;
        allocated.push((new_root_bytenr, new_root_level));

        let root_node = read_node(fs, pending, root_bytenr)?;
        let chunk_tree_uuid = root_node.chunk_tree_uuid();

        let mut entries = vec![crate::fs::btrfs::write::node::InteriorEntry {
            key: left_first_key,
            blockptr: left_bytenr,
            generation,
        }];
        for (split_key, split_bytenr) in extra_siblings {
            entries.push(crate::fs::btrfs::write::node::InteriorEntry {
                key: split_key,
                blockptr: split_bytenr,
                generation,
            });
        }

        let new_root = InteriorNode {
            bytenr: new_root_bytenr,
            generation,
            owner,
            level: new_root_level,
            flags: root_node.flags(),
            metadata_uuid: sb.metadata_uuid,
            chunk_tree_uuid,
            csum_type: sb.csum_type,
            entries,
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

/// Would these items fit in one leaf of `node_size` bytes?
fn leaf_fits(items: &[LeafItem], node_size: u32) -> bool {
    let data_bytes: usize = items.iter().map(|it| it.data.len()).sum();
    crate::fs::btrfs::tree::HEADER_SIZE
        + items.len() * crate::fs::btrfs::tree::ITEM_SIZE
        + data_bytes
        <= node_size as usize
}

/// Decide how to lay a new item into a leaf that has no room for it, returning
/// one group of items per resulting leaf, left to right.
///
/// # Why this is not a midpoint split
///
/// The original code split the full leaf 50/50 and then inserted the new item
/// into whichever half its key belonged to. That works for small items and
/// **cannot** work for a large one: each half of a 50/50 split still carries
/// roughly half a node of data, so an item needing almost a whole node fits in
/// neither, and the insert failed with `FilesystemFull` — on a drive with
/// hundreds of megabytes free. Splitting checksums into ~16 KiB items
/// (`build_extent_csum_items`) makes that the *normal* case rather than an
/// exotic one, so it had to be fixed here before any large write could land.
///
/// Real btrfs splits at the insertion slot for the same reason, which is why a
/// kernel-written checksum tree is full of leaves holding exactly one item with
/// 30 bytes spare (measured 2026-08-15).
///
/// The three shapes, tried in order:
///
/// 1. `[..pos] + item` | `[pos..]` — the new item ends the left leaf.
/// 2. `[..pos]` | `item + [pos..]` — the new item starts the right leaf.
/// 3. `[..pos]` | `item` | `[pos..]` — the item gets a leaf to itself.
///
/// This is total, and never produces an empty leaf: if `pos == 0` shape 1 gives
/// a left leaf holding only the new item, and if `pos == items.len()` shape 2
/// gives a right leaf holding only it. Either always fits, because the caller
/// has already rejected an item too large for any leaf at all. So shape 3 is
/// only reached with `0 < pos < len`, where both outer groups are non-empty.
fn plan_leaf_split(
    items: &[LeafItem],
    pos: usize,
    new_item: LeafItem,
    node_size: u32,
) -> Vec<Vec<LeafItem>> {
    let left = &items[..pos];
    let right = &items[pos..];

    let mut shape_1: Vec<LeafItem> = left.to_vec();
    shape_1.push(new_item.clone());
    if leaf_fits(&shape_1, node_size) {
        return vec![shape_1, right.to_vec()]
            .into_iter()
            .filter(|g| !g.is_empty())
            .collect();
    }

    let mut shape_2: Vec<LeafItem> = vec![new_item.clone()];
    shape_2.extend_from_slice(right);
    if leaf_fits(&shape_2, node_size) {
        return vec![left.to_vec(), shape_2]
            .into_iter()
            .filter(|g| !g.is_empty())
            .collect();
    }

    vec![left.to_vec(), vec![new_item], right.to_vec()]
        .into_iter()
        .filter(|g| !g.is_empty())
        .collect()
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
) -> Result<(u64, Key, Vec<(Key, u64)>, Vec<(u64, Vec<u8>)>)> {
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
            Ok((target_bytenr, first_key, Vec::new(), vec![(target_bytenr, emitted)]))
        } else {
            // Leaf is full: plan a multi-way split
            use crate::error::LuksError;
            use crate::fs::btrfs::write::node::max_item_payload_bytes;

            if target_data.len() > max_item_payload_bytes(node_size) {
                return Err(LuksError::BtrfsItemTooLarge {
                    what: crate::fs::btrfs::tree::item_type_name(target_key.item_type),
                    item_bytes: target_data.len(),
                    node_size,
                });
            }

            let pos = match leaf.items.binary_search_by(|it| it.key.cmp(target_key)) {
                Ok(_) => return Err(LuksError::AlreadyExists("duplicate key in leaf".into())),
                Err(p) => p,
            };

            let new_item = crate::fs::btrfs::write::node::LeafItem {
                key: *target_key,
                data: target_data,
            };

            let groups = plan_leaf_split(&leaf.items, pos, new_item, node_size);

            let mut extra_siblings = Vec::new();
            let mut emitted = Vec::new();

            let mut left_target_bytenr = 0;
            let mut left_first_key = *target_key;

            for (i, group) in groups.into_iter().enumerate() {
                let target_bytenr = if i == 0 {
                    if is_already_new {
                        bytenr
                    } else {
                        let b = allocator.allocate_metadata(node_size)?;
                        allocated.push((b, 0));
                        freed.push((bytenr, 0));
                        b
                    }
                } else {
                    let b = allocator.allocate_metadata(node_size)?;
                    allocated.push((b, 0));
                    b
                };

                let new_leaf = Leaf {
                    bytenr: target_bytenr,
                    generation,
                    owner,
                    flags: leaf.flags,
                    metadata_uuid: leaf.metadata_uuid,
                    chunk_tree_uuid: leaf.chunk_tree_uuid,
                    csum_type: leaf.csum_type,
                    items: group,
                };

                let raw = new_leaf.emit(node_size)?;
                emitted.push((target_bytenr, raw));

                let first_key = new_leaf.items[0].key;

                if i == 0 {
                    left_target_bytenr = target_bytenr;
                    left_first_key = first_key;
                } else {
                    extra_siblings.push((first_key, target_bytenr));
                }
            }

            Ok((
                left_target_bytenr,
                left_first_key,
                extra_siblings,
                emitted,
            ))
        }
    } else {
        // Interior node
        let mut interior = InteriorNode::from_node(&node, csum_type)?;
        let child_idx = node.child_for(target_key)?;
        let child_ptr = node.key_ptr(child_idx)?;

        let (new_child_bytenr, new_child_key, extra_siblings, mut emitted_blocks) = cow_descend_insert(
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

        // Update child pointer in interior node. The key must always be
        // propagated, including at child_idx == 0: a KeyPtr holds "where a
        // subtree lives and the lowest key in it" (tree.rs), so when the
        // leftmost child's minimum key changes, the parent's own reported
        // minimum is stale until this runs. Real btrfs calls this case
        // fixup_low_keys(); skipping child_idx == 0 was doing the opposite.
        interior.entries[child_idx].blockptr = new_child_bytenr;
        interior.entries[child_idx].generation = generation;
        interior.entries[child_idx].key = new_child_key;

        if !extra_siblings.is_empty() {
            for (split_key, split_bytenr) in extra_siblings {
                interior.entries.push(crate::fs::btrfs::write::node::InteriorEntry {
                    key: split_key,
                    blockptr: split_bytenr,
                    generation,
                });
            }
            interior.entries.sort_by_key(|e| e.key);

            let needed = crate::fs::btrfs::tree::HEADER_SIZE
                + interior.entries.len() * crate::fs::btrfs::tree::KEY_PTR_SIZE;

            if needed <= node_size as usize {
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

                Ok((target_bytenr, first_key, Vec::new(), emitted_blocks))
            } else {
                // Interior node is full: split interior node
                let right_int_bytenr = allocator.allocate_metadata(node_size)?;
                allocated.push((right_int_bytenr, level));

                let (mut left_int, mut right_int, pivot_key) = interior.split(right_int_bytenr)?;

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

                emitted_blocks.push((left_target_bytenr, left_raw));
                emitted_blocks.push((right_int_bytenr, right_raw));

                Ok((
                    left_target_bytenr,
                    left_first_key,
                    vec![(pivot_key, right_int_bytenr)],
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

            Ok((target_bytenr, first_key, Vec::new(), emitted_blocks))
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

        // Update child pointer in interior node. See the matching comment in
        // cow_descend_insert above: the key must always be propagated, even
        // for child_idx == 0, or the parent's minimum goes stale.
        interior.entries[child_idx].blockptr = new_child_bytenr;
        interior.entries[child_idx].generation = generation;
        interior.entries[child_idx].key = new_child_key;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::btrfs::write::node::LeafItem;

    #[test]
    fn test_plan_leaf_split_shape_1_item_at_end_of_left() {
        let node_size = 4096;
        let mut items = Vec::new();
        // Create 2 small items
        items.push(LeafItem {
            key: Key::new(256, 1, 0),
            data: vec![0u8; 100],
        });
        items.push(LeafItem {
            key: Key::new(257, 1, 0),
            data: vec![0u8; 100],
        });

        let new_item = LeafItem {
            key: Key::new(256, 1, 50),
            data: vec![0u8; 100],
        };

        // pos = 1 (inserted between item 0 and item 1)
        let groups = plan_leaf_split(&items, 1, new_item, node_size);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2); // item 0 + new_item
        assert_eq!(groups[1].len(), 1); // item 1
        assert_eq!(groups[0][0].key, Key::new(256, 1, 0));
        assert_eq!(groups[0][1].key, Key::new(256, 1, 50));
        assert_eq!(groups[1][0].key, Key::new(257, 1, 0));
    }

    #[test]
    fn test_plan_leaf_split_shape_2_item_at_start_of_right() {
        let node_size = 1024; // smaller node size to force shape 2
        // Left already has large item
        let _items = vec![
            LeafItem {
                key: Key::new(256, 1, 0),
                data: vec![0u8; 700], // fits in 1024 (header 101 + item 25 + 700 = 826 <= 1024)
            },
            LeafItem {
                key: Key::new(258, 1, 0),
                data: vec![0u8; 50],
            },
        ];

        let new_item = LeafItem {
            key: Key::new(257, 1, 0),
            data: vec![0u8; 50],
        };

        // pos = 1. Left (700) + new_item (50) would be 826 + 75 = 901 <= 1024, so shape 1 fits.
        // Let's make left + new_item exceed node_size, but new_item + right fit.
        let large_left = vec![
            LeafItem {
                key: Key::new(256, 1, 0),
                data: vec![0u8; 850],
            },
            LeafItem {
                key: Key::new(258, 1, 0),
                data: vec![0u8; 50],
            },
        ];
        let groups = plan_leaf_split(&large_left, 1, new_item.clone(), node_size);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 1); // item 0 (850 bytes)
        assert_eq!(groups[1].len(), 2); // new_item (50) + item 1 (50)
        assert_eq!(groups[0][0].key, Key::new(256, 1, 0));
        assert_eq!(groups[1][0].key, Key::new(257, 1, 0));
        assert_eq!(groups[1][1].key, Key::new(258, 1, 0));
    }

    #[test]
    fn test_plan_leaf_split_shape_3_near_max_item_isolated() {
        let node_size = 4096;
        let items = vec![
            LeafItem {
                key: Key::new(256, 1, 0),
                data: vec![0u8; 1500],
            },
            LeafItem {
                key: Key::new(258, 1, 0),
                data: vec![0u8; 1500],
            },
        ];

        // New item is near max node size (e.g. 3500 bytes)
        let near_max_item = LeafItem {
            key: Key::new(257, 1, 0),
            data: vec![0u8; 3500],
        };

        // pos = 1 (between 256 and 258).
        // shape 1: left (1500) + near_max (3500) = 5000 > 4096 (overflows)
        // shape 2: near_max (3500) + right (1500) = 5000 > 4096 (overflows)
        // shape 3: left (1500) | near_max (3500) | right (1500) -> 3 leaves!
        let groups = plan_leaf_split(&items, 1, near_max_item, node_size);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 1);
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[0][0].key, Key::new(256, 1, 0));
        assert_eq!(groups[1][0].key, Key::new(257, 1, 0));
        assert_eq!(groups[2][0].key, Key::new(258, 1, 0));
    }
}
