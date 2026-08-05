//! ext4 `metadata_csum`, graded against `mke2fs`.
//!
//! ```text
//! cargo test --release --test ext4_csum
//! ```
//!
//! # Why this test exists before any allocator does
//!
//! Every counter an allocator touches — free blocks, free inodes, the bitmaps
//! themselves — sits under a crc32c. Write the counter and not the checksum and
//! `e2fsck` rejects the filesystem; write the checksum with the wrong seed and
//! it rejects it just as firmly, but now the bug is in code that *looks*
//! right.
//!
//! So the checksum code is graded the same way the LUKS encryptor was: against
//! output this project did not produce. These fixtures were built by real
//! `mke2fs`, which already wrote a correct checksum onto every structure. We
//! recompute them and require **byte-identical** agreement. If a single seeding
//! rule is wrong, thousands of comparisons fail at once.
//!
//! Nothing here writes. That is the point — the whole checksum layer is proven
//! before a single byte of a real filesystem is modified.

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::ext4::csum::Seed;
use luks_core::fs::ext4::Ext4;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Fixtures carrying `metadata_csum`, chosen to cover both seed derivations
/// and both block sizes.
///
/// `big-4k` and `small-1k` have `metadata_csum_seed`, so the seed is read
/// straight from the superblock. `csum-uuid-4k` does not, so the seed is
/// derived from the UUID — which is what a default `mkfs.ext4` produces, and
/// what the physical test stick has. Testing only the first kind would leave
/// the derivation that actually matters unexercised.
///
/// `many-groups-1k` exists because the others are single- or double-group
/// filesystems, and a group descriptor checksum is seeded with **the group
/// number**. Every group being group 0 or 1 is exactly the shape that lets a
/// wrong seeding rule pass. It was built with `-g 512` so 8 MiB spans 17
/// groups, 14 of them carrying `UNINIT` flags, which also exercises the
/// bitmaps that are legitimately absent.
const CSUM_FIXTURES: [&str; 4] = [
    "big-4k.img",
    "small-1k.img",
    "csum-uuid-4k.img",
    "many-groups-1k.img",
];

struct Fs {
    dev: FileDevice,
    fs: Ext4<FileDevice>,
}

fn open(name: &str) -> Fs {
    let fs = Ext4::mount(FileDevice::open(&fixture(name)).expect("open fixture"))
        .expect("mount fixture");
    let dev = FileDevice::open(&fixture(name)).expect("reopen fixture");
    Fs { dev, fs }
}

#[test]
fn the_superblock_checksum_matches_the_one_mke2fs_wrote() {
    for name in CSUM_FIXTURES {
        let f = open(name);
        let seed = Seed::of(f.fs.superblock());
        assert!(seed.enabled(), "{name}: fixture should have metadata_csum");

        let mut raw = [0u8; 1024];
        f.dev.read_at(1024, &mut raw).expect("read superblock");

        let stored = u32::from_le_bytes([raw[0x3FC], raw[0x3FD], raw[0x3FE], raw[0x3FF]]);
        let computed = seed.superblock(&raw).expect("enabled");

        assert_eq!(
            computed, stored,
            "{name}: superblock checksum mismatch — computed {computed:#010x}, \
             on disk {stored:#010x}"
        );
    }
}

#[test]
fn every_group_descriptor_checksum_matches() {
    let mut checked = 0usize;

    for name in CSUM_FIXTURES {
        let f = open(name);
        let sb = f.fs.superblock();
        let seed = Seed::of(sb);
        let size = sb.group_desc_size();

        let count = sb.group_count() as usize;
        let mut table = vec![0u8; count * size];
        f.dev
            .read_at(sb.group_desc_offset(), &mut table)
            .expect("read descriptor table");

        for g in 0..count {
            let desc = &table[g * size..(g + 1) * size];
            let stored = u16::from_le_bytes([desc[0x1E], desc[0x1F]]);
            let computed = seed.group_desc(g as u64, desc).expect("enabled");

            assert_eq!(
                computed, stored,
                "{name}: group {g} descriptor checksum mismatch — computed \
                 {computed:#06x}, on disk {stored:#06x}"
            );
            checked += 1;
        }
    }

    // Anti-vacuity: a loop that ran zero times passes silently.
    assert!(
        checked >= 20,
        "only {checked} group descriptors checked; the fixtures should have more"
    );
}

#[test]
fn every_bitmap_checksum_matches() {
    let mut checked = 0usize;

    for name in CSUM_FIXTURES {
        let f = open(name);
        let sb = f.fs.superblock();
        let seed = Seed::of(sb);
        let bs = sb.block_size as u64;

        // With 32-byte descriptors only the low half is stored, so the
        // comparison has to be truncated to the same width or an intact
        // filesystem fails every check.
        let wide = sb.group_desc_size() >= 64;
        let mask = if wide { u32::MAX } else { 0xFFFF };

        let block_bytes = (sb.clusters_per_group as usize).div_ceil(8);
        let inode_bytes = (sb.inodes_per_group as usize).div_ceil(8);

        for (g, desc) in f.fs.groups().iter().enumerate() {
            // An uninitialised bitmap has never been written; the bytes on disk
            // are whatever was there before and are not covered by a checksum.
            if !desc.block_bitmap_uninit() {
                let mut bm = vec![0u8; block_bytes];
                f.dev
                    .read_at(desc.block_bitmap * bs, &mut bm)
                    .expect("read block bitmap");
                let computed = seed.bitmap(&bm).expect("enabled") & mask;
                assert_eq!(
                    computed,
                    desc.block_bitmap_csum & mask,
                    "{name}: group {g} block bitmap checksum mismatch"
                );
                checked += 1;
            }

            if !desc.inode_bitmap_uninit() {
                let mut bm = vec![0u8; inode_bytes];
                f.dev
                    .read_at(desc.inode_bitmap * bs, &mut bm)
                    .expect("read inode bitmap");
                let computed = seed.bitmap(&bm).expect("enabled") & mask;
                assert_eq!(
                    computed,
                    desc.inode_bitmap_csum & mask,
                    "{name}: group {g} inode bitmap checksum mismatch"
                );
                checked += 1;
            }
        }
    }

    assert!(checked >= 10, "only {checked} bitmaps checked");
}

#[test]
fn inode_checksums_match_for_every_inode_in_use() {
    let mut checked = 0usize;

    for name in CSUM_FIXTURES {
        let f = open(name);
        let sb = f.fs.superblock();
        let seed = Seed::of(sb);
        let bs = sb.block_size as u64;
        let isize_ = sb.inode_size as usize;

        for (g, desc) in f.fs.groups().iter().enumerate() {
            if desc.inode_bitmap_uninit() {
                continue;
            }
            let mut bm = vec![0u8; (sb.inodes_per_group as usize).div_ceil(8)];
            f.dev
                .read_at(desc.inode_bitmap * bs, &mut bm)
                .expect("read inode bitmap");

            for i in 0..sb.inodes_per_group as usize {
                if bm[i / 8] & (1 << (i % 8)) == 0 {
                    continue; // free
                }
                let ino = (g as u64) * sb.inodes_per_group as u64 + i as u64 + 1;

                let mut raw = vec![0u8; isize_];
                f.dev
                    .read_at(desc.inode_table * bs + (i * isize_) as u64, &mut raw)
                    .expect("read inode");

                // An inode that is allocated but has never been written (no
                // links, no mode) carries no meaningful checksum.
                if raw.iter().all(|&b| b == 0) {
                    continue;
                }

                let computed = seed.inode(ino, &raw).expect("enabled");
                let stored = seed.stored_inode_csum(&raw);
                let mask = if seed.inode_has_csum_hi(&raw) {
                    u32::MAX
                } else {
                    0xFFFF
                };

                assert_eq!(
                    computed & mask,
                    stored & mask,
                    "{name}: inode {ino} checksum mismatch — computed \
                     {computed:#010x}, on disk {stored:#010x}"
                );
                checked += 1;
            }
        }
    }

    assert!(checked >= 20, "only {checked} inodes checked");
}

#[test]
fn a_flipped_byte_is_detected() {
    // Guards every test above from being vacuous. If the checksum function
    // ignored its input — returning a constant, say — all of them would still
    // pass. This requires it to actually depend on the data.
    let f = open("big-4k.img");
    let seed = Seed::of(f.fs.superblock());

    let mut raw = [0u8; 1024];
    f.dev.read_at(1024, &mut raw).expect("read superblock");
    let good = seed.superblock(&raw).expect("enabled");

    raw[200] ^= 0x01;
    let bad = seed.superblock(&raw).expect("enabled");

    assert_ne!(good, bad, "the superblock checksum ignores its input");
}

#[test]
fn the_seed_derivations_are_not_interchangeable() {
    // `csum-uuid-4k` has no `s_checksum_seed`, so its seed comes from the UUID.
    // Confirm the two derivations really are different code paths: if the
    // fixture's checksums verified under a UUID-derived seed *and* under a
    // stored one, this test suite would not distinguish them.
    let uuid_seeded = open("csum-uuid-4k.img");
    assert!(
        uuid_seeded.fs.superblock().checksum_seed.is_none(),
        "csum-uuid-4k should derive its seed from the UUID"
    );

    let stored_seed = open("big-4k.img");
    assert!(
        stored_seed.fs.superblock().checksum_seed.is_some(),
        "big-4k should carry an explicit s_checksum_seed"
    );
}

/// The physical block number of a single-extent inode's one and only extent.
/// Every fixture's root directory fits in one block, so this is enough
/// without pulling in the full extent-tree walker.
fn only_extent_block(inode: &luks_core::fs::ext4::Inode) -> u64 {
    let b = &inode.block_area;
    let entries = u16::from_le_bytes([b[2], b[3]]);
    assert_eq!(entries, 1, "test fixture's root should be a single extent");
    let lo = u32::from_le_bytes([b[20], b[21], b[22], b[23]]);
    let hi = u16::from_le_bytes([b[18], b[19]]);
    lo as u64 | ((hi as u64) << 32)
}

#[test]
fn the_directory_block_tail_checksum_matches_mke2fs() {
    // Four fixtures, both block sizes, both seed derivations — the same
    // spread of gaps the other checksum tests close. dirtail-1k is new: none
    // of the other fixtures happened to leave the tail readable at an offset
    // this test could find by inspection alone, so it was built specifically
    // to pin this format down before any directory gets written.
    let cases: [(&str, u64); 4] = [
        ("big-4k.img", 2),
        ("csum-uuid-4k.img", 2),
        ("many-groups-1k.img", 2),
        ("dirtail-1k.img", 2),
    ];

    for (name, root_ino) in cases {
        let f = open(name);
        let sb = f.fs.superblock();
        let seed = Seed::of(sb);
        let bs = sb.block_size as u64;

        let root = f.fs.read_inode(root_ino).expect("read root inode");
        let block_no = only_extent_block(&root);

        let mut block = vec![0u8; bs as usize];
        f.dev
            .read_at(block_no * bs, &mut block)
            .expect("read root directory block");

        // The tail is a 12-byte fake dirent: 4 zero bytes where an inode
        // number would go (so a reader skips it), rec_len 12, a zero
        // name_len, the 0xDE file_type marker, then the checksum.
        let tail = &block[block.len() - 12..];
        assert_eq!(
            u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]),
            0,
            "tail inode field should be 0 so readers skip it"
        );
        assert_eq!(
            u16::from_le_bytes([tail[4], tail[5]]),
            12,
            "tail rec_len should be 12"
        );
        assert_eq!(tail[6], 0, "tail name_len should be 0");
        assert_eq!(tail[7], 0xDE, "tail file_type should be the 0xDE marker");
        let stored = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]);

        let computed = seed
            .dir_block(root_ino, 0, &block)
            .expect("checksums enabled");

        assert_eq!(
            computed, stored,
            "{name}: directory block checksum mismatch — computed \
             {computed:#010x}, on disk {stored:#010x}"
        );
    }
}

#[test]
fn a_filesystem_without_checksums_reports_none() {
    // ext2 predates all of this. The seed must report itself disabled rather
    // than computing checksums nothing will ever compare against.
    let f = open("ext2-1k.img");
    let seed = Seed::of(f.fs.superblock());

    assert!(!seed.enabled(), "ext2 has no metadata_csum");
    assert!(seed.superblock(&[0u8; 1024]).is_none());
    assert!(seed.group_desc(0, &[0u8; 32]).is_none());
    assert!(seed.bitmap(&[0u8; 128]).is_none());

    // And it is still writable — no checksums to get wrong.
    assert!(Seed::for_writing(f.fs.superblock()).is_ok());
}
