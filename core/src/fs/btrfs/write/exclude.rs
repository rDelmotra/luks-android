//! Superblock mirror exclusion calculation (§3.3).
//!
//! btrfs does not avoid placing chunks over superblock mirrors on disk.
//! Instead, the kernel computes an in-memory exclusion set at mount time from the
//! chunk tree geometry and fixed superblock physical offsets, ensuring the allocator
//! never hands out logical addresses that would overwrite a superblock mirror.
//!
//! This module computes those logical exclusion ranges from the [`ChunkMap`].

use std::ops::Range;
use crate::fs::btrfs::chunk::ChunkMap;

/// Physical offset of the primary superblock (Mirror 0).
pub const SB_MIRROR_0: u64 = 65536; // 64 KiB

/// Physical offset of Superblock Mirror 1 (16384 << 12 = 64 MiB).
pub const SB_MIRROR_1: u64 = 67108864; // 64 MiB

/// Physical offset of Superblock Mirror 2 (16384 << 24 = 256 GiB).
pub const SB_MIRROR_2: u64 = 274877906944; // 256 GiB

/// All superblock mirror physical offsets.
pub const SB_OFFSETS: [u64; 3] = [SB_MIRROR_0, SB_MIRROR_1, SB_MIRROR_2];

/// Size of the region protected per superblock mirror (64 KiB).
pub const SB_PROTECT_LEN: u64 = 65536;

/// Compute all logical ranges that must be excluded from allocation to protect
/// superblock mirrors and the reserved leading region (< 64 KiB).
///
/// Returns a sorted, merged list of non-overlapping logical `Range<u64>` exclusions.
pub fn compute_sb_exclusions(chunk_map: &ChunkMap) -> Vec<Range<u64>> {
    let mut exclusions = Vec::new();

    for chunk in chunk_map.chunks() {
        let chunk_start = chunk.logical;
        let chunk_end = match chunk.logical.checked_add(chunk.length) {
            Some(end) => end,
            None => continue,
        };

        // Leading case: if chunk.logical < 65536, exclude [chunk.logical, min(65536, chunk.logical_end))
        if chunk_start < SB_MIRROR_0 {
            let excl_end = SB_MIRROR_0.min(chunk_end);
            if chunk_start < excl_end {
                exclusions.push(chunk_start..excl_end);
            }
        }

        // Check each superblock mirror against each stripe
        for &sb_offset in &SB_OFFSETS {
            for stripe in &chunk.stripes {
                let stripe_start = stripe.offset;
                let stripe_end = match stripe.offset.checked_add(chunk.length) {
                    Some(end) => end,
                    None => continue,
                };

                if stripe_start <= sb_offset && sb_offset < stripe_end {
                    let offset_in_stripe = sb_offset - stripe_start;
                    let logical_start = chunk_start + offset_in_stripe;
                    let logical_end = (logical_start + SB_PROTECT_LEN).min(chunk_end);
                    if logical_start < logical_end {
                        exclusions.push(logical_start..logical_end);
                    }
                }
            }
        }
    }

    merge_ranges(exclusions)
}

/// Helper to sort and merge overlapping or adjacent ranges.
pub fn merge_ranges(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if r.start >= r.end {
            continue;
        }
        if let Some(last) = merged.last_mut() {
            if r.start <= last.end {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        merged.push(r);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::btrfs::chunk::{Chunk, Stripe, BLOCK_GROUP_DATA, BLOCK_GROUP_DUP, BLOCK_GROUP_METADATA};

    #[test]
    fn test_4gib_metadata_mirror1_exclusion() {
        // §3.1 measured case on a fresh 4 GiB filesystem:
        // METADATA|DUP chunk at logical 30408704, length 268435456 (256 MiB)
        // Stripe 0: physical 38797312
        // Stripe 1: physical 307232768
        // Mirror 1 is at physical 67108864.
        // Reverse-mapped: logical 30408704 + (67108864 - 38797312) = 58720256.
        // Excluded range: 58720256..58785792 (64 KiB).
        let chunk = Chunk {
            logical: 30_408_704,
            length: 268_435_456,
            chunk_type: BLOCK_GROUP_METADATA | BLOCK_GROUP_DUP,
            stripes: vec![
                Stripe {
                    devid: 1,
                    offset: 38_797_312,
                },
                Stripe {
                    devid: 1,
                    offset: 307_232_768,
                },
            ],
        };

        let mut map = ChunkMap::default();
        map.insert(chunk);

        let exclusions = compute_sb_exclusions(&map);
        assert_eq!(exclusions.len(), 1);
        assert_eq!(exclusions[0], 58_720_256..58_785_792);
        assert_eq!(exclusions[0].end - exclusions[0].start, SB_PROTECT_LEN);
    }

    #[test]
    fn test_leading_case_below_64k_and_mirror0() {
        // Chunk starting at logical 0, length 8 MiB, stripe 0 at physical 0.
        // Leading case excludes [0, 65536).
        // Mirror 0 (65536) falls at offset 65536 in stripe 0 -> logical 65536..131072.
        // Merged exclusion: 0..131072.
        let chunk = Chunk {
            logical: 0,
            length: 8_388_608,
            chunk_type: BLOCK_GROUP_DATA,
            stripes: vec![Stripe {
                devid: 1,
                offset: 0,
            }],
        };

        let mut map = ChunkMap::default();
        map.insert(chunk);

        let exclusions = compute_sb_exclusions(&map);
        assert_eq!(exclusions.len(), 1);
        assert_eq!(exclusions[0], 0..131_072);
    }

    #[test]
    fn test_mirror2_256gib_exclusion() {
        // Chunk covering physical 274877906944 (256 GiB).
        // Logical start: 1_000_000_000, length: 1 GiB.
        // Stripe physical: 274_877_000_000.
        // Offset in stripe: 274877906944 - 274877000000 = 906944.
        // Excluded logical: (1_000_000_000 + 906944)..(1_000_000_000 + 906944 + 65536).
        let chunk = Chunk {
            logical: 1_000_000_000,
            length: 1_073_741_824,
            chunk_type: BLOCK_GROUP_DATA,
            stripes: vec![Stripe {
                devid: 1,
                offset: 274_877_000_000,
            }],
        };

        let mut map = ChunkMap::default();
        map.insert(chunk);

        let exclusions = compute_sb_exclusions(&map);
        assert_eq!(exclusions.len(), 1);
        assert_eq!(exclusions[0], 1_000_906_944..(1_000_906_944 + 65_536));
    }

    #[test]
    fn test_clamping_to_chunk_end() {
        // Chunk where mirror 1 lands 32 KiB before the end of the chunk.
        // Length is 65536. Stripe start is 67108864 - 32768 = 67076096.
        // Mirror 1 is at 67108864 -> offset in stripe is 32768.
        // Chunk logical: 10_000_000, chunk end: 10_065_536.
        // Logical start: 10_032_768. Logical start + 65536 = 10_098_304 > chunk end.
        // Clamped excluded range: 10_032_768..10_065_536 (32 KiB).
        let chunk = Chunk {
            logical: 10_000_000,
            length: 65_536,
            chunk_type: BLOCK_GROUP_DATA,
            stripes: vec![Stripe {
                devid: 1,
                offset: 67_076_096,
            }],
        };

        let mut map = ChunkMap::default();
        map.insert(chunk);

        let exclusions = compute_sb_exclusions(&map);
        assert_eq!(exclusions.len(), 1);
        assert_eq!(exclusions[0], 10_032_768..10_065_536);
        assert_eq!(exclusions[0].end - exclusions[0].start, 32_768);
    }

    #[test]
    fn test_no_mirrors_in_stripes() {
        // Chunk far away from any mirror (e.g. physical 10_000_000..18_388_608, logical 500_000_000).
        let chunk = Chunk {
            logical: 500_000_000,
            length: 8_388_608,
            chunk_type: BLOCK_GROUP_DATA,
            stripes: vec![Stripe {
                devid: 1,
                offset: 10_000_000,
            }],
        };

        let mut map = ChunkMap::default();
        map.insert(chunk);

        let exclusions = compute_sb_exclusions(&map);
        assert!(exclusions.is_empty());
    }

    #[test]
    fn test_exclusions_on_all_fixture_images() {
        use crate::device::FileDevice;
        use crate::fs::btrfs::Btrfs;

        let images = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];
        for name in images {
            let path = format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"));
            let dev = FileDevice::open(&path).expect("open fixture");
            let fs = Btrfs::mount(dev).expect("mount fixture");

            let exclusions = compute_sb_exclusions(fs.chunk_map());
            // For all fixtures, ensure exclusions are within chunk boundaries and valid ranges
            for excl in &exclusions {
                assert!(excl.start < excl.end);
                // Translate through chunk map to verify logical address is mapped
                let res = fs.chunk_map().map(excl.start);
                assert!(res.is_ok(), "{name}: exclusion start {:#x} must map to physical", excl.start);
            }
        }
    }
}
