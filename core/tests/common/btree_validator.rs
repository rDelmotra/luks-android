//! In-Memory B-Tree Structural Invariant Validator.
//!
//! Validates the 6 fundamental structural invariants of Btrfs B-trees:
//! 1. **I-1 (Strict Key Ordering)**: All items in leaves and all entries in
//!    interior nodes are strictly monotonically increasing. Across leaf
//!    boundaries, `max_key(leaf[k]) < min_key(leaf[k+1])`.
//! 2. **I-2 (Parent Key Accuracy / `fixup_low_keys`)**: For every interior
//!    node entry `(key, blockptr)`, `key` MUST strictly equal the minimum key
//!    present in the child node at `blockptr`.
//! 3. **I-3 (Non-Empty Nodes)**: No interior node or non-root leaf has 0 items.
//!    If the root has 0 items, its level must be 0.
//! 4. **I-4 (Generation Matching)**: Child node header `generation` equals parent
//!    interior entry `generation`.
//! 5. **I-5 (Height Uniformity & Level Stamping)**: An interior node at level $L$
//!    only points to children with level $L - 1$. All leaves are at level 0.
//! 6. **I-6 (Root Collapse Invariant)**: The root must NOT be an interior node
//!    with exactly one child (`cow.rs:739`). If an interior root collapses to
//!    1 child, the tree height must shrink by adopting the child as root.
//!    Non-root interior nodes with 1 child are permitted (sparsity is legal in
//!    Btrfs; see `cow.rs:682`) and counted in `total_single_child_interior_nodes`.
//!
//! In addition to recursive tree validation, this module validates:
//! 7. **Bidirectional Cursor Parity**: Traversal forward with `Cursor::advance`
//!    yields the exact reverse sequence of traversal backward with
//!    `Cursor::retreat`, and both match the keys collected from leaf inspection.
//! 8. **Search-vs-Walk Parity**: Every key discovered during the recursive
//!    structural walk is asserted to be findable via `Cursor::search`, catching
//!    gross misrouting and exercising `child_for` / `lower_bound`. (Note: I-2
//!    remains the only guard on exact parent-key accuracy, as `advance_leaf`
//!    can mask a separator key too high by one key).
//!
//! Multi-tree validation across all five standard trees (`FS_TREE`, `ROOT_TREE`,
//! `EXTENT_TREE`, `CSUM_TREE`, and `DEV_TREE`) is provided by `TreeValidator::validate_all`.

#![allow(dead_code)]

use luks_core::device::ReadAt;
use luks_core::error::Result;
use luks_core::fs::btrfs::cursor::Cursor;
use luks_core::fs::btrfs::tree::{
    Key, Node, CSUM_TREE_OBJECTID, DEV_TREE_OBJECTID, EXTENT_TREE_OBJECTID,
    FREE_SPACE_TREE_OBJECTID,
};
use luks_core::fs::btrfs::Btrfs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeValidationReport {
    pub root_bytenr: u64,
    pub tree_height: u8,
    pub total_nodes: usize,
    pub total_leaves: usize,
    pub total_interior_nodes: usize,
    pub total_single_child_interior_nodes: usize,
    pub total_items: usize,
    pub min_key: Option<Key>,
    pub max_key: Option<Key>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllTreesValidationReport {
    pub fs_tree: TreeValidationReport,
    pub root_tree: TreeValidationReport,
    pub extent_tree: TreeValidationReport,
    pub csum_tree: Option<TreeValidationReport>,
    pub dev_tree: TreeValidationReport,
    pub free_space_tree: Option<TreeValidationReport>,
}

impl AllTreesValidationReport {
    pub fn total_nodes(&self) -> usize {
        let mut total = self.fs_tree.total_nodes
            + self.root_tree.total_nodes
            + self.extent_tree.total_nodes
            + self.dev_tree.total_nodes;
        if let Some(ref csum) = self.csum_tree {
            total += csum.total_nodes;
        }
        if let Some(ref fst) = self.free_space_tree {
            total += fst.total_nodes;
        }
        total
    }

    pub fn total_items(&self) -> usize {
        let mut total = self.fs_tree.total_items
            + self.root_tree.total_items
            + self.extent_tree.total_items
            + self.dev_tree.total_items;
        if let Some(ref csum) = self.csum_tree {
            total += csum.total_items;
        }
        if let Some(ref fst) = self.free_space_tree {
            total += fst.total_items;
        }
        total
    }

    pub fn total_single_child_interior_nodes(&self) -> usize {
        let mut total = self.fs_tree.total_single_child_interior_nodes
            + self.root_tree.total_single_child_interior_nodes
            + self.extent_tree.total_single_child_interior_nodes
            + self.dev_tree.total_single_child_interior_nodes;
        if let Some(ref csum) = self.csum_tree {
            total += csum.total_single_child_interior_nodes;
        }
        if let Some(ref fst) = self.free_space_tree {
            total += fst.total_single_child_interior_nodes;
        }
        total
    }

    pub fn all_reports(&self) -> Vec<&TreeValidationReport> {
        let mut reports = vec![&self.fs_tree, &self.root_tree, &self.extent_tree, &self.dev_tree];
        if let Some(ref csum) = self.csum_tree {
            reports.push(csum);
        }
        if let Some(ref fst) = self.free_space_tree {
            reports.push(fst);
        }
        reports
    }
}

pub struct TreeValidator;

impl TreeValidator {
    /// Recursively validates all structural invariants on the tree starting at `root_bytenr`.
    ///
    /// If `expected_level` is provided, asserts that the root matches that level.
    pub fn validate<D: ReadAt>(
        fs: &Btrfs<D>,
        root_bytenr: u64,
        expected_level: Option<u8>,
    ) -> Result<TreeValidationReport> {
        let root_node = fs.read_node(root_bytenr)?;
        if let Some(level) = expected_level {
            assert_eq!(
                root_node.level, level,
                "root at {root_bytenr} level mismatch: expected {level}, got {}",
                root_node.level
            );
        }

        // Empty root check
        if root_node.nr_items == 0 {
            assert_eq!(
                root_node.level, 0,
                "Invariant I-3 violation: empty root node at {root_bytenr} must be level 0 leaf, got level {}",
                root_node.level
            );
            return Ok(TreeValidationReport {
                root_bytenr,
                tree_height: 0,
                total_nodes: 1,
                total_leaves: 1,
                total_interior_nodes: 0,
                total_single_child_interior_nodes: 0,
                total_items: 0,
                min_key: None,
                max_key: None,
            });
        }

        // Invariant I-6: Root Collapse Invariant
        // The root must not be an interior node with exactly one child (cow.rs:739).
        // If an interior root has collapsed to 1 child, it must be collapsed to that child.
        if root_node.level > 0 {
            assert!(
                root_node.nr_items > 1,
                "Invariant I-6 violation: root interior node at {root_bytenr} has {} child pointer(s); interior root must have at least 2 children or collapse to child (cow.rs:739)",
                root_node.nr_items
            );
        }

        let mut prev_leaf_max: Option<Key> = None;
        let mut leaf_keys = Vec::new();
        let mut total_leaves = 0;
        let mut total_interior = 0;
        let mut total_single_child_interior = 0;

        let (min_key, max_key) = Self::walk_node(
            fs,
            &root_node,
            root_node.level,
            None,
            &mut prev_leaf_max,
            &mut leaf_keys,
            &mut total_leaves,
            &mut total_interior,
            &mut total_single_child_interior,
        )?;

        // Parity Checks
        if !leaf_keys.is_empty() {
            Self::verify_bidirectional_cursor(fs, root_bytenr, &leaf_keys)?;
            Self::verify_search_walk_parity(fs, root_bytenr, &leaf_keys)?;
        }

        Ok(TreeValidationReport {
            root_bytenr,
            tree_height: root_node.level,
            total_nodes: total_leaves + total_interior,
            total_leaves,
            total_interior_nodes: total_interior,
            total_single_child_interior_nodes: total_single_child_interior,
            total_items: leaf_keys.len(),
            min_key: Some(min_key),
            max_key: Some(max_key),
        })
    }

    /// Validates all standard Btrfs trees (FS_TREE, ROOT_TREE, EXTENT_TREE, CSUM_TREE, DEV_TREE,
    /// and FREE_SPACE_TREE if present) across all structural invariants (I-1 through I-6),
    /// bidirectional cursor parity, and search-vs-walk parity.
    pub fn validate_all<D: ReadAt>(fs: &Btrfs<D>) -> Result<AllTreesValidationReport> {
        let sb = fs.superblock();

        // 1. ROOT_TREE (from superblock root)
        let root_tree = Self::validate(fs, sb.root, Some(sb.root_level))?;

        // 2. FS_TREE
        let fs_root = fs.fs_tree();
        let fs_tree = Self::validate(fs, fs_root.bytenr, Some(fs_root.level))?;

        // 3. EXTENT_TREE
        let extent_root = fs.tree_root(EXTENT_TREE_OBJECTID)?;
        let extent_tree = Self::validate(fs, extent_root.bytenr, Some(extent_root.level))?;

        // 4. CSUM_TREE (if present)
        let csum_tree = match fs.tree_root(CSUM_TREE_OBJECTID) {
            Ok(csum_root) => Some(Self::validate(fs, csum_root.bytenr, Some(csum_root.level))?),
            Err(_) => None,
        };

        // 5. DEV_TREE
        let dev_root = fs.tree_root(DEV_TREE_OBJECTID)?;
        let dev_tree = Self::validate(fs, dev_root.bytenr, Some(dev_root.level))?;

        // 6. FREE_SPACE_TREE (if present)
        let free_space_tree = match fs.tree_root(FREE_SPACE_TREE_OBJECTID) {
            Ok(fst_root) => Some(Self::validate(fs, fst_root.bytenr, Some(fst_root.level))?),
            Err(_) => None,
        };

        Ok(AllTreesValidationReport {
            fs_tree,
            root_tree,
            extent_tree,
            csum_tree,
            dev_tree,
            free_space_tree,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_node<D: ReadAt>(
        fs: &Btrfs<D>,
        node: &Node,
        expected_level: u8,
        expected_parent_gen: Option<u64>,
        prev_leaf_max: &mut Option<Key>,
        leaf_keys: &mut Vec<Key>,
        total_leaves: &mut usize,
        total_interior: &mut usize,
        total_single_child_interior: &mut usize,
    ) -> Result<(Key, Key)> {
        // Invariant I-5: Height Uniformity
        assert_eq!(
            node.level, expected_level,
            "Invariant I-5 violation at node {}: expected level {}, got {}",
            node.bytenr(),
            expected_level,
            node.level
        );

        // Invariant I-4: Generation Matching
        if let Some(parent_gen) = expected_parent_gen {
            assert_eq!(
                node.generation, parent_gen,
                "Invariant I-4 violation at node {}: parent expected generation {}, node has {}",
                node.bytenr(),
                parent_gen,
                node.generation
            );
        }

        // Invariant I-3: Non-Empty Children
        assert!(
            node.nr_items > 0,
            "Invariant I-3 violation: non-root child node at {} has 0 items",
            node.bytenr()
        );

        if node.is_leaf() {
            *total_leaves += 1;
            let mut prev_key: Option<Key> = None;
            let mut leaf_min_key = None;
            let mut leaf_max_key = None;

            for i in 0..node.nr_items {
                let key = node.key(i)?;
                if leaf_min_key.is_none() {
                    leaf_min_key = Some(key);
                }
                leaf_max_key = Some(key);

                // Invariant I-1: Strict intra-leaf key ordering
                if let Some(prev) = prev_key {
                    assert!(
                        prev < key,
                        "Invariant I-1 violation within leaf {}: key[{}] ({:?}) >= key[{}] ({:?})",
                        node.bytenr(),
                        i - 1,
                        prev,
                        i,
                        key
                    );
                }
                prev_key = Some(key);
                leaf_keys.push(key);
            }

            let min_k = leaf_min_key.expect("non-empty leaf");
            let max_k = leaf_max_key.expect("non-empty leaf");

            // Invariant I-1: Strict inter-leaf key ordering
            if let Some(prev_max) = *prev_leaf_max {
                assert!(
                    prev_max < min_k,
                    "Invariant I-1 violation across leaf boundary: previous leaf max ({:?}) >= current leaf min ({:?})",
                    prev_max,
                    min_k
                );
            }
            *prev_leaf_max = Some(max_k);

            Ok((min_k, max_k))
        } else {
            *total_interior += 1;
            if node.nr_items == 1 {
                *total_single_child_interior += 1;
            }
            let mut prev_entry_key: Option<Key> = None;
            let mut interior_min_key = None;
            let mut interior_max_key = None;

            for i in 0..node.nr_items {
                let ptr = node.key_ptr(i)?;
                if interior_min_key.is_none() {
                    interior_min_key = Some(ptr.key);
                }

                // Invariant I-1: Strict interior entry key ordering
                if let Some(prev) = prev_entry_key {
                    assert!(
                        prev < ptr.key,
                        "Invariant I-1 violation within interior node {}: entry[{}] ({:?}) >= entry[{}] ({:?})",
                        node.bytenr(),
                        i - 1,
                        prev,
                        i,
                        ptr.key
                    );
                }
                prev_entry_key = Some(ptr.key);

                // Recurse into child
                let child_node = fs.read_node(ptr.blockptr)?;
                let (child_min, child_max) = Self::walk_node(
                    fs,
                    &child_node,
                    node.level - 1,
                    Some(ptr.generation),
                    prev_leaf_max,
                    leaf_keys,
                    total_leaves,
                    total_interior,
                    total_single_child_interior,
                )?;

                // Invariant I-2: Parent Key Accuracy (fixup_low_keys)
                assert_eq!(
                    ptr.key, child_min,
                    "Invariant I-2 violation at interior node {} entry {}: pointer key ({:?}) != child's actual min key ({:?}) at blockptr {}",
                    node.bytenr(),
                    i,
                    ptr.key,
                    child_min,
                    ptr.blockptr
                );

                interior_max_key = Some(child_max);
            }

            Ok((
                interior_min_key.expect("non-empty interior"),
                interior_max_key.expect("non-empty interior"),
            ))
        }
    }

    /// Verifies that forward cursor traversal matches backward cursor traversal,
    /// and both match the exact expected leaf keys.
    fn verify_bidirectional_cursor<D: ReadAt>(
        fs: &Btrfs<D>,
        root_bytenr: u64,
        expected_keys: &[Key],
    ) -> Result<()> {
        let first_key = expected_keys.first().expect("non-empty");
        let last_key = expected_keys.last().expect("non-empty");

        // Forward traversal from beginning
        let mut forward_keys = Vec::with_capacity(expected_keys.len());
        let mut fwd_cursor = Cursor::search(fs, root_bytenr, first_key)?;
        while fwd_cursor.valid() {
            forward_keys.push(fwd_cursor.key()?);
            fwd_cursor.advance()?;
        }

        assert_eq!(
            forward_keys.len(),
            expected_keys.len(),
            "Forward Cursor traversal collected {} keys, expected {}",
            forward_keys.len(),
            expected_keys.len()
        );
        assert_eq!(
            forward_keys, expected_keys,
            "Forward Cursor keys diverged from leaf ground truth"
        );

        // Backward traversal from end
        let mut backward_keys = Vec::with_capacity(expected_keys.len());
        let mut rev_cursor = Cursor::search_le(fs, root_bytenr, last_key)?;
        while rev_cursor.valid() {
            backward_keys.push(rev_cursor.key()?);
            rev_cursor.retreat()?;
        }

        backward_keys.reverse();
        assert_eq!(
            backward_keys.len(),
            expected_keys.len(),
            "Backward Cursor traversal collected {} keys, expected {}",
            backward_keys.len(),
            expected_keys.len()
        );
        assert_eq!(
            backward_keys, expected_keys,
            "Backward Cursor keys diverged from forward keys / leaf ground truth"
        );

        Ok(())
    }

    /// Verifies that every key discovered during the recursive structural walk
    /// can be located via standard B-tree search from the root.
    ///
    /// This proves search-vs-walk parity: every item reachable via pointer-following
    /// traversal is also correctly indexable and reachable via logarithmic binary-search
    /// routing from the root, catching gross misrouting and exercising `child_for` / `lower_bound`.
    /// Note: I-2 remains the only guard on exact parent-key accuracy, since `Cursor::search`
    /// calls `advance_leaf` when landing past a leaf's end which masks a parent key too high by 1.
    pub fn verify_search_walk_parity<D: ReadAt>(
        fs: &Btrfs<D>,
        root_bytenr: u64,
        expected_keys: &[Key],
    ) -> Result<()> {
        for (idx, &k) in expected_keys.iter().enumerate() {
            let cursor = Cursor::search(fs, root_bytenr, &k)?;
            assert!(
                cursor.valid(),
                "Search-vs-walk parity violation at item {idx} in tree root {root_bytenr}: key {k:?} was found during walk, but Cursor::search returned an invalid cursor (past end)"
            );
            let found_key = cursor.key()?;
            assert_eq!(
                found_key, k,
                "Search-vs-walk parity violation at item {idx} in tree root {root_bytenr}: expected key {k:?} from walk, but Cursor::search landed on key {found_key:?}"
            );
        }
        Ok(())
    }
}
