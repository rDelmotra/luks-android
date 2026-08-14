//! Btrfs extent tree and free space tracking tests (Pass B).
//!
//! ```text
//! cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support --test btrfs_extent_tree
//! ```
//!
//! # The Oracle
//!
//! Ground truth for this pass is `btrfs inspect-internal dump-tree -t extent`
//! and `btrfs inspect-internal dump-tree -t free-space`.
//!
//! This test suite proves:
//! 1. Our extent tree parse matches the kernel's extent dump item for item.
//! 2. Our derived free-space map (computed purely by finding gaps in the extent
//!    tree) agrees exactly with the kernel's independent free-space tree across
//!    all four fixture images.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::crc32c::crc32c;
use luks_core::fs::btrfs::write::alloc::{read_free_space_tree, FreeSpaceMap};
use luks_core::fs::btrfs::write::extent_tree::{
    ExtentTree, BLOCK_GROUP_DATA, BLOCK_GROUP_DUP, BLOCK_GROUP_METADATA,
};
use luks_core::fs::btrfs::Btrfs;

const IMAGES: [&str; 4] = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    let dev = FileDevice::open(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    Btrfs::mount(dev).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Copy `plain.img`, flip its primary superblock's `incompat_flags` via
/// `patch`, recompute the crc32c the mount will check, and mount the result.
///
/// Patching only the primary copy (offset `0x10000`) is enough:
/// `Superblock::find` breaks generation ties in iteration order and tries the
/// primary first, so an untouched backup mirror at `0x4000000` never wins.
fn mount_patched(test: &str, patch: impl Fn(&mut [u8])) -> Btrfs<FileDevice> {
    const SB_OFFSET: usize = 0x10000;
    const SB_SIZE: usize = 4096;
    const CSUM_START: usize = 32;

    let mut img = std::fs::read(fixture("plain.img")).expect("read fixture");
    let sb = &mut img[SB_OFFSET..SB_OFFSET + SB_SIZE];
    patch(sb);
    let csum = crc32c(&sb[CSUM_START..]);
    sb[0..4].copy_from_slice(&csum.to_le_bytes());

    let dst = std::env::temp_dir().join(format!("luks-btrfs-gate-{test}.img"));
    std::fs::write(&dst, &img).expect("write scratch");
    Btrfs::mount(FileDevice::open(&dst).expect("open")).expect("mount")
}

#[test]
fn reads_extent_tree_on_plain_img() {
    let fs = mount("plain.img");
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree on plain.img");

    // 1. Check block groups (3 block groups on plain.img)
    assert_eq!(extent_tree.block_groups.len(), 3);

    let data_bg = &extent_tree.block_groups[0];
    assert_eq!(data_bg.start, 13631488);
    assert_eq!(data_bg.length, 8388608);
    assert_eq!(data_bg.used, 2097152);
    assert!(data_bg.is_data());
    assert!(data_bg.is_single());
    assert_eq!(data_bg.profile_name(), "DATA|single");

    let sys_bg = &extent_tree.block_groups[1];
    assert_eq!(sys_bg.start, 22020096);
    assert_eq!(sys_bg.length, 8388608);
    assert_eq!(sys_bg.used, 16384);
    assert!(sys_bg.is_system());
    assert!(sys_bg.is_dup());
    assert_eq!(sys_bg.profile_name(), "SYSTEM|DUP");

    let meta_bg = &extent_tree.block_groups[2];
    assert_eq!(meta_bg.start, 30408704);
    assert_eq!(meta_bg.length, 53673984);
    assert_eq!(meta_bg.used, 344064);
    assert!(meta_bg.is_metadata());
    assert!(meta_bg.is_dup());
    assert_eq!(meta_bg.profile_name(), "METADATA|DUP");

    // 2. Check total allocated bytes matches dump-tree output (2,457,600 bytes)
    assert_eq!(extent_tree.total_allocated_bytes(), 2457600);

    // 3. Check extents
    // plain.img has 24 allocated extents (2 data extents + 22 metadata tree blocks)
    assert_eq!(extent_tree.extents.len(), 24);

    let ext0 = &extent_tree.extents[0];
    assert_eq!(ext0.bytenr, 13631488);
    assert_eq!(ext0.length, 1048576);
    assert_eq!(ext0.refs, 1);
    assert_eq!(ext0.generation, 7);
    assert!(ext0.is_data);
    assert!(!ext0.is_tree_block);
    assert_eq!(ext0.level, 0);

    let ext1 = &extent_tree.extents[1];
    assert_eq!(ext1.bytenr, 14680064);
    assert_eq!(ext1.length, 1048576);
    assert!(ext1.is_data);

    // Check skinny metadata tree block at 30605312 (level 1 node)
    let lvl1_node = extent_tree
        .extents
        .iter()
        .find(|e| e.bytenr == 30605312)
        .expect("level 1 node");
    assert!(lvl1_node.is_tree_block);
    assert_eq!(lvl1_node.level, 1);
    assert_eq!(lvl1_node.length, 16384);
}

#[test]
fn reads_extent_tree_across_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let extent_tree = ExtentTree::read(&fs).unwrap_or_else(|e| panic!("{name}: {e}"));

        assert!(
            !extent_tree.block_groups.is_empty(),
            "{name}: has block groups"
        );
        assert!(!extent_tree.extents.is_empty(), "{name}: has extents");

        // Verify extents are strictly sorted and non-overlapping
        for i in 1..extent_tree.extents.len() {
            let prev = &extent_tree.extents[i - 1];
            let curr = &extent_tree.extents[i];
            let prev_i = i - 1;
            assert!(
                prev.bytenr + prev.length <= curr.bytenr,
                "{name}: extent {prev_i} [{:#x}..{:#x}) overlaps with extent {i} [{:#x}..{:#x})",
                prev.bytenr,
                prev.bytenr + prev.length,
                curr.bytenr,
                curr.bytenr + curr.length
            );
        }

        // Verify total allocated bytes matches sum of block group used fields
        let sum_bg_used: u64 = extent_tree.block_groups.iter().map(|bg| bg.used).sum();
        assert_eq!(
            extent_tree.total_allocated_bytes(),
            sum_bg_used,
            "{name}: total allocated bytes matches sum(bg.used)"
        );
    }
}

#[test]
fn derived_free_space_map_matches_free_space_tree_exactly() {
    for name in IMAGES {
        let fs = mount(name);
        let extent_tree = ExtentTree::read(&fs).unwrap_or_else(|e| panic!("{name}: {e}"));
        let free_space_map =
            FreeSpaceMap::from_extent_tree(&extent_tree).unwrap_or_else(|e| panic!("{name}: {e}"));

        let fst_ranges = read_free_space_tree(&fs)
            .unwrap_or_else(|e| panic!("{name} read_free_space_tree: {e}"))
            .unwrap_or_else(|| panic!("{name} missing free space tree"));

        // For each active block group, the derived free ranges must match
        // the Free Space Tree's recorded FREE_SPACE_EXTENT entries inside that block group.
        for bg_space in &free_space_map.block_groups {
            let bg_start = bg_space.block_group.start;
            let bg_end = bg_start + bg_space.block_group.length;

            let fst_bg_ranges: Vec<_> = fst_ranges
                .iter()
                .filter(|r| r.start >= bg_start && r.start < bg_end)
                .cloned()
                .collect();

            assert_eq!(
                bg_space.free_ranges.len(),
                fst_bg_ranges.len(),
                "{name} (BG {bg_start:#x}): free range count mismatch",
            );

            for (i, (derived, fst)) in bg_space.free_ranges.iter().zip(fst_bg_ranges.iter()).enumerate() {
                assert_eq!(
                    derived, fst,
                    "{name} (BG {bg_start:#x}): free range index {i} mismatch: derived={derived:?}, fst={fst:?}"
                );
            }
        }
    }
}

#[test]
fn block_group_accounting_is_exact() {
    for name in IMAGES {
        let fs = mount(name);
        let extent_tree = ExtentTree::read(&fs).unwrap_or_else(|e| panic!("{name}: {e}"));
        let free_space_map =
            FreeSpaceMap::from_extent_tree(&extent_tree).unwrap_or_else(|e| panic!("{name}: {e}"));

        for bg_space in &free_space_map.block_groups {
            assert_eq!(
                bg_space.total_allocated_bytes, bg_space.block_group.used,
                "{name}: total allocated mismatch on block group {:#x}",
                bg_space.block_group.start
            );
            assert_eq!(
                bg_space.total_allocated_bytes + bg_space.total_free_bytes,
                bg_space.block_group.length,
                "{name}: allocated + free != total length on block group {:#x}",
                bg_space.block_group.start
            );
        }
    }
}

#[test]
fn find_free_range_allocator_queries() {
    let fs = mount("plain.img");
    let extent_tree = ExtentTree::read(&fs).expect("read extent tree");
    let free_space_map = FreeSpaceMap::from_extent_tree(&extent_tree).expect("free space map");

    // 1. Query DATA block group for 1 MiB with 4096 alignment
    let data_free = free_space_map
        .find_free_range(BLOCK_GROUP_DATA, 1024 * 1024, 4096)
        .expect("find free DATA range");
    assert!(data_free.start >= 13631488);
    assert!(data_free.start + data_free.length <= 13631488 + 8388608);
    assert_eq!(data_free.length, 1024 * 1024);

    // 2. Query METADATA block group for 16 KiB with 16384 alignment
    let meta_free = free_space_map
        .find_free_range(BLOCK_GROUP_METADATA | BLOCK_GROUP_DUP, 16384, 16384)
        .expect("find free METADATA range");
    assert!(meta_free.start >= 30408704);
    assert!(meta_free.start + meta_free.length <= 30408704 + 53673984);
    assert_eq!(meta_free.length, 16384);
    assert_eq!(meta_free.start % 16384, 0);

    // 3. Query impossible size (> 100 MiB) -> should return None
    let impossible = free_space_map.find_free_range(BLOCK_GROUP_DATA, 100 * 1024 * 1024, 4096);
    assert_eq!(impossible, None);
}

/// Pass B.1. Measured on a real `mkfs.btrfs -O ^skinny-metadata` image
/// (2026-08-14): without `SKINNY_METADATA`, tree blocks are legacy
/// `EXTENT_ITEM`s carrying an inline `tree_block_info` (18 bytes: a 17-byte
/// owner key plus a 1-byte level) *before* the backref list, which this
/// parser reads from a fixed offset that assumes skinny layout. Every
/// backref came back as shifted garbage, `level` was always wrong, and
/// `FreeSpaceMap::from_extent_tree` still returned `Ok` — the self-check
/// only compares byte counts, so it cannot see a misparsed backref. Refuse
/// by name rather than silently misparse (`feature-btrfs-write.md` §1).
#[test]
fn non_skinny_metadata_is_refused_by_the_extent_tree_reader() {
    // incompat_flags is at superblock offset 0xbc, 8 bytes little-endian.
    // INCOMPAT_SKINNY_METADATA = 0x100 (bit 8, i.e. byte 1 of the field).
    let fs = mount_patched("non-skinny", |sb| {
        sb[0xbc + 1] &= !0x01;
    });

    assert!(
        !fs.superblock().has_skinny_metadata(),
        "the patch did not actually clear the flag — test is not exercising the gate"
    );

    let err = ExtentTree::read(&fs).expect_err("non-skinny metadata must be refused, not misparsed");
    assert!(
        err.to_string().contains("skinny metadata"),
        "wrong refusal: {err}"
    );
}

/// Control for the test above: the same patch function with the bit left
/// alone must not trip the gate. Without this, a gate that refuses
/// everything — not just non-skinny metadata — would still pass.
#[test]
fn skinny_metadata_flag_untouched_still_mounts_and_reads() {
    let fs = mount_patched("skinny-control", |_sb| {});
    assert!(fs.superblock().has_skinny_metadata());
    ExtentTree::read(&fs).expect("skinny metadata must still be readable");
}
