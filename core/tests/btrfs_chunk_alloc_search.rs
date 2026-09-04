//! Tests for btrfs chunk allocation search algorithms (Pass H.2).
//!
//! Validates the three read-only searches against:
//! 1. Kernel stripe sizing rules and the 9 verified device sizes (§2.1).
//! 2. First-fit physical hole searching and fallback behavior (§2.5).
//! 3. Real btrfs fixture images (`plain.img`, `compress.img`, `mixed-4k.img`, `subvol.img`).

#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::btrfs::chunk::{Chunk, ChunkMap, Stripe};
use luks_core::fs::btrfs::write::chunk_alloc::{
    decide_data_chunk_size, find_free_dev_extent, next_logical, read_dev_extents,
    BTRFS_BLOCK_RESERVED_1M_FOR_SUPER, MIN_DATA_CHUNK_SIZE, MIN_STRIPE_SIZE_FLOOR, SZ_16M, SZ_1G,
    SZ_64K,
};
use luks_core::fs::btrfs::Btrfs;

const IMAGES: [&str; 4] = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];

fn fixture_path(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    let dev = FileDevice::open(fixture_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    Btrfs::mount(dev).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// ---------------------------------------------------------------------------
// Search 1: next_logical
// ---------------------------------------------------------------------------

#[test]
fn next_logical_on_empty_and_mock_chunk_maps() {
    let empty = ChunkMap::default();
    assert_eq!(next_logical(&empty), 0);

    let mut map = ChunkMap::default();
    map.insert(Chunk {
        logical: 10_000_000,
        length: 2_000_000,
        owner: 2,
        stripe_len: 65536,
        chunk_type: 1,
        io_align: 65536,
        io_width: 65536,
        sector_size: 4096,
        sub_stripes: 1,
        stripes: vec![Stripe::new(1, 1_048_576, [0u8; 16])],
    });
    assert_eq!(next_logical(&map), 12_000_000);

    // Insert another chunk at a higher logical address
    map.insert(Chunk {
        logical: 50_000_000,
        length: 10_000_000,
        owner: 2,
        stripe_len: 65536,
        chunk_type: 1,
        io_align: 65536,
        io_width: 65536,
        sector_size: 4096,
        sub_stripes: 1,
        stripes: vec![Stripe::new(1, 20_000_000, [0u8; 16])],
    });
    assert_eq!(next_logical(&map), 60_000_000);

    // Insert an earlier chunk - max should remain 60_000_000
    map.insert(Chunk {
        logical: 20_000_000,
        length: 5_000_000,
        owner: 2,
        stripe_len: 65536,
        chunk_type: 1,
        io_align: 65536,
        io_width: 65536,
        sector_size: 4096,
        sub_stripes: 1,
        stripes: vec![Stripe::new(1, 15_000_000, [0u8; 16])],
    });
    assert_eq!(next_logical(&map), 60_000_000);
}

#[test]
fn next_logical_on_all_real_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let next = next_logical(fs.chunk_map());

        assert!(next > 0, "{name}: next_logical must be > 0");

        let chunks = fs.chunk_map().chunks();
        assert!(!chunks.is_empty(), "{name}: chunk map cannot be empty");

        for chunk in chunks {
            assert!(
                chunk.logical + chunk.length <= next,
                "{name}: chunk [{:#x}..{:#x}) exceeds next_logical {:#x}",
                chunk.logical,
                chunk.logical + chunk.length,
                next
            );
        }

        // At least one chunk must end exactly at next_logical
        let max_end = chunks.iter().map(|c| c.logical + c.length).max().unwrap();
        assert_eq!(
            next, max_end,
            "{name}: next_logical must match highest chunk end"
        );
    }
}

// ---------------------------------------------------------------------------
// Search 2: decide_data_chunk_size
// ---------------------------------------------------------------------------

#[test]
fn decide_data_chunk_size_nine_verified_kernel_measurements() {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    // The 9 exact verified kernel sizes from §2.1
    let table: [(u64, u64, u64); 11] = [
        (3 * GIB, 320 * MIB, 335_544_320),
        (4 * GIB, 416 * MIB, 436_207_616),
        (5 * GIB, 512 * MIB, 536_870_912),
        (6 * GIB, 624 * MIB, 654_311_424),
        (7 * GIB, 720 * MIB, 754_974_720),
        (8 * GIB, 832 * MIB, 872_415_232),
        (9 * GIB, 928 * MIB, 973_078_528),
        (12 * GIB, 1024 * MIB, 1_073_741_824),
        (16 * GIB, 1024 * MIB, 1_073_741_824),
        (32 * GIB, 1024 * MIB, 1_073_741_824),
        (64 * GIB, 1024 * MIB, 1_073_741_824),
    ];

    for (dev_size, expected_mib, expected_exact_bytes) in table {
        let size = decide_data_chunk_size(dev_size);
        assert_eq!(
            size, expected_mib,
            "dev_size {dev_size} bytes: expected {expected_mib} bytes, got {size}"
        );
        assert_eq!(size, expected_exact_bytes);
        assert_eq!(size % SZ_64K, 0, "must be 64 KiB aligned");
        assert_eq!(size % SZ_16M, 0, "must be 16 MiB aligned for regular sizes");
    }
}

#[test]
fn decide_data_chunk_size_edge_cases() {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    // 0 device size -> 0
    assert_eq!(decide_data_chunk_size(0), 0);

    // Sub-160MB devices: max_chunk < 16MB, rounds up to 16MB
    assert_eq!(decide_data_chunk_size(100 * MIB), 16 * MIB);
    assert_eq!(decide_data_chunk_size(1 * GIB), 112 * MIB); // 10% = 102.4 MB -> ceil to 16MB = 112 MB (7 * 16MB)
    assert_eq!(decide_data_chunk_size(2 * GIB), 208 * MIB); // 10% = 204.8 MB -> ceil to 16MB = 208 MB (13 * 16MB)

    // Very large drives (large multi-terabyte drives) -> always capped at 1 GiB per stripe
    assert_eq!(decide_data_chunk_size(1000 * GIB), SZ_1G);
    assert_eq!(decide_data_chunk_size(2000 * GIB), SZ_1G);
    assert_eq!(decide_data_chunk_size(10000 * GIB), SZ_1G);
}

// ---------------------------------------------------------------------------
// Search 3: find_free_dev_extent & read_dev_extents
// ---------------------------------------------------------------------------

#[test]
fn find_free_dev_extent_first_fit_and_shrink() {
    const MIB: u64 = 1024 * 1024;

    // Case 1: Brand new device with no DEV_EXTENTs
    let total_bytes = 4096 * MIB;
    let (off, len) = find_free_dev_extent(&[], total_bytes, 416 * MIB, MIN_DATA_CHUNK_SIZE).unwrap();
    assert_eq!(off, BTRFS_BLOCK_RESERVED_1M_FOR_SUPER);
    assert_eq!(len, 416 * MIB);

    // Case 2: Extents already start at 1 MiB
    let existing = vec![(1 * MIB, 100 * MIB)];
    let (off, len) = find_free_dev_extent(&existing, total_bytes, 416 * MIB, MIN_DATA_CHUNK_SIZE).unwrap();
    assert_eq!(off, 101 * MIB);
    assert_eq!(len, 416 * MIB);

    // Case 3: First-fit behavior:
    // Gap 1: 1MB..21MB (20MB) -> smaller than 100MB
    // Gap 2: 71MB..201MB (130MB) -> >= 100MB (FIRST FIT)
    // Gap 3: 301MB..801MB (500MB) -> larger, but later
    let multi_gaps = vec![
        (21 * MIB, 50 * MIB),
        (201 * MIB, 100 * MIB),
    ];
    let (off, len) = find_free_dev_extent(&multi_gaps, 1000 * MIB, 100 * MIB, MIN_DATA_CHUNK_SIZE).unwrap();
    assert_eq!(off, 71 * MIB, "First-fit must choose the first eligible hole");
    assert_eq!(len, 100 * MIB);

    // Case 4: No hole fits full requested size, shrink to largest hole >= min_stripe_size
    // Holes available:
    // 1MB..21MB = 20MB
    // 71MB..151MB = 80MB (LARGEST)
    // 191MB..251MB = 60MB
    let multi_gaps_shrink = vec![
        (21 * MIB, 50 * MIB),
        (151 * MIB, 40 * MIB),
        (251 * MIB, 50 * MIB), // total_dev = 300MB -> trailing hole is 299..300 = 1MB
    ];
    let (off, len) = find_free_dev_extent(&multi_gaps_shrink, 301 * MIB, 200 * MIB, 64 * MIB).unwrap();
    assert_eq!(off, 71 * MIB, "Fallback must pick largest available hole");
    assert_eq!(len, 80 * MIB);

    // Case 5: Filesystem full when largest hole is below min_stripe_size
    let err = find_free_dev_extent(&multi_gaps_shrink, 301 * MIB, 200 * MIB, 100 * MIB);
    assert!(matches!(err, Err(LuksError::FilesystemFull)));

    // Case 6: Unsorted input is handled identically
    let mut unsorted = multi_gaps.clone();
    unsorted.reverse();
    let (off2, len2) = find_free_dev_extent(&unsorted, 1000 * MIB, 100 * MIB, MIN_DATA_CHUNK_SIZE).unwrap();
    assert_eq!(off2, 71 * MIB);
    assert_eq!(len2, 100 * MIB);

    // Case 7: Total device size too small (< 1 MiB reserved)
    let tiny_err = find_free_dev_extent(&[], 512 * 1024, 64 * 1024, 64 * 1024);
    assert!(matches!(tiny_err, Err(LuksError::FilesystemFull)));
}

#[test]
fn dev_extents_and_free_extent_search_on_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let devid = fs.superblock().dev_id;
        let total_dev_bytes = fs.superblock().total_bytes;

        // 1. Read DEV_EXTENT items via read_dev_extents
        let extents = read_dev_extents(&fs, devid)
            .unwrap_or_else(|e| panic!("{name}: read_dev_extents failed: {e}"));
        assert!(!extents.is_empty(), "{name}: fixture must have dev extents");

        // Verify read_dev_extents via Btrfs method produces identical result
        let extents_method = fs.read_dev_extents(devid).unwrap();
        assert_eq!(extents, extents_method, "{name}: Btrfs::read_dev_extents mismatch");

        // Verify extents are sorted and non-overlapping
        for (i, &(off, len)) in extents.iter().enumerate() {
            assert!(off >= BTRFS_BLOCK_RESERVED_1M_FOR_SUPER, "{name}: extent {i} below 1MB reserved");
            assert_eq!(off % SZ_64K, 0, "{name}: extent {i} offset not 64K aligned");
            assert_eq!(len % SZ_64K, 0, "{name}: extent {i} length not 64K aligned");
            assert!(off + len <= total_dev_bytes, "{name}: extent {i} exceeds device");

            if i > 0 {
                let (prev_off, prev_len) = extents[i - 1];
                assert!(
                    prev_off + prev_len <= off,
                    "{name}: extent {i} overlaps with previous extent ({prev_off}+{prev_len} > {off})"
                );
            }
        }

        // 2. Decide chunk size for this device
        let chunk_size = decide_data_chunk_size(total_dev_bytes);
        assert!(chunk_size > 0, "{name}: chunk_size must be > 0");

        // 3. Find free physical hole for a new chunk
        // On small fixtures (~64MB - 160MB), chunk_size might exceed the single largest hole,
        // so we use MIN_STRIPE_SIZE_FLOOR (64 KiB) as min stripe size.
        let (phys_off, phys_len) = find_free_dev_extent(&extents, total_dev_bytes, chunk_size, MIN_STRIPE_SIZE_FLOOR)
            .unwrap_or_else(|e| panic!("{name}: find_free_dev_extent failed: {e}"));

        // 4. Verify candidate allocation properties:
        assert!(
            phys_off >= BTRFS_BLOCK_RESERVED_1M_FOR_SUPER,
            "{name}: allocated physical offset {phys_off} must be >= 1 MiB"
        );
        assert_eq!(
            phys_off % SZ_64K,
            0,
            "{name}: allocated physical offset {phys_off} must be 64 KiB aligned"
        );
        assert_eq!(
            phys_len % SZ_64K,
            0,
            "{name}: allocated physical length {phys_len} must be 64 KiB aligned"
        );
        assert!(
            phys_off + phys_len <= total_dev_bytes,
            "{name}: allocated extent [{:#x}..{:#x}) exceeds device total {:#x}",
            phys_off,
            phys_off + phys_len,
            total_dev_bytes
        );

        // Crucial invariant: candidate range MUST NOT overlap with ANY existing dev extent
        for &(ext_off, ext_len) in &extents {
            let overlaps = phys_off < ext_off + ext_len && phys_off + phys_len > ext_off;
            assert!(
                !overlaps,
                "{name}: candidate physical [{phys_off}..{}) overlaps with existing extent [{ext_off}..{})",
                phys_off + phys_len,
                ext_off + ext_len
            );
        }

        // 5. Verify next_logical range does not overlap with ANY existing chunk
        let next_log = next_logical(fs.chunk_map());
        for chunk in fs.chunk_map().chunks() {
            let overlaps = next_log < chunk.logical + chunk.length && next_log + phys_len > chunk.logical;
            assert!(
                !overlaps,
                "{name}: candidate logical [{next_log}..{}) overlaps with existing chunk [{:#x}..{:#x})",
                next_log + phys_len,
                chunk.logical,
                chunk.logical + chunk.length
            );
        }
    }
}
