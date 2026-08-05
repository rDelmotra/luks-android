//! Allocating and freeing ext4 blocks and inodes.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_alloc
//! ```
//!
//! # The oracle
//!
//! An allocator keeps five things in step — the bitmap bit, the group's free
//! counter, the superblock's free counter, the bitmap checksum and the
//! descriptor checksum. Update four and the filesystem is wrong in a way that
//! reading it back through our own code cannot see, because our reader would
//! be consulting the same four fields we just wrote.
//!
//! So the strongest available check is used for each case:
//!
//! * **blocks** — allocate then free must leave the image **byte-for-byte
//!   identical**. Any field updated on the way down but not on the way back up
//!   shows as a differing byte, including both checksums. Nothing self-
//!   referential about it: the comparison is against the bytes `mke2fs` wrote.
//! * **inodes** — the same, except `itable_unused`, which by design shrinks and
//!   is not restored (growing it again would tell `e2fsck` to skip live
//!   inodes). So that case is graded by `e2fsck` instead, via
//!   `tools/verify-image.sh`, which is the kernel's opinion rather than ours.
//!
//! `verify_clean` is skipped automatically when the VM is not running, so this
//! file stays useful on a machine without colima — but the byte-identity tests
//! run everywhere and are the ones that catch a mis-seeded checksum.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A private copy, so a failing test cannot damage a committed fixture.
fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-alloc-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> Ext4<FileDevice> {
    // The test made this copy itself, so it genuinely knows the size — this
    // is a real confirmation, not a number read back from the thing being
    // checked against it.
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Ext4::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

fn bytes(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("read image")
}

/// Indices of every differing byte, capped so a total mismatch stays readable.
fn diff(a: &[u8], b: &[u8]) -> Vec<usize> {
    a.iter()
        .zip(b)
        .enumerate()
        .filter(|(_, (x, y))| x != y)
        .map(|(i, _)| i)
        .take(64)
        .collect()
}

/// Fixtures with `metadata_csum`, so the checksum paths run. `many-groups-1k`
/// matters most: with 17 groups the allocator's group-to-group search actually
/// moves, and descriptor checksums are seeded with the group number.
const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

#[test]
fn allocating_then_freeing_a_block_restores_every_byte() {
    for name in FIXTURES {
        let path = scratch(name, "block-roundtrip");
        let before = bytes(&path);

        let block = {
            let mut fs = open(&path);
            let b = fs.alloc_block(0).expect("allocate a block");
            fs.flush().expect("flush");
            b
        };

        // A separate mount, so the free path reads the state from disk rather
        // than from an in-memory copy that might be masking a missing write.
        {
            let mut fs = open(&path);
            fs.free_block(block).expect("free the block");
            fs.flush().expect("flush");
        }

        let after = bytes(&path);
        let d = diff(&before, &after);
        assert!(
            d.is_empty(),
            "{name}: allocating block {block} and freeing it left {} bytes \
             changed, at offsets {d:?} — some field is updated on the way down \
             but not on the way back up",
            d.len()
        );
    }
}

#[test]
fn an_allocated_block_is_actually_marked_in_use() {
    // Guards the test above from passing vacuously: an allocator that did
    // nothing at all would round-trip perfectly.
    let path = scratch("many-groups-1k.img", "block-marked");
    let before = bytes(&path);

    let mut fs = open(&path);
    let block = fs.alloc_block(0).expect("allocate");
    fs.flush().expect("flush");

    let after = bytes(&path);
    assert!(
        !diff(&before, &after).is_empty(),
        "allocating block {block} changed nothing on disk"
    );

    // And the same block must not come back a second time.
    let second = fs.alloc_block(0).expect("allocate again");
    assert_ne!(block, second, "the allocator handed out the same block twice");
}

#[test]
fn the_free_counters_move_together() {
    // The group counter and the superblock counter are separate fields in
    // separate structures. Decrementing one and not the other is invisible
    // until e2fsck runs, and is exactly the bug this asserts against.
    let path = scratch("many-groups-1k.img", "counters");
    let mut fs = open(&path);

    let sb_before = fs.superblock().free_blocks_count;
    let group_before: u32 = fs.groups().iter().map(|g| g.free_blocks_count).sum();

    let mut allocated = Vec::new();
    for _ in 0..40 {
        allocated.push(fs.alloc_block(0).expect("allocate"));
    }

    let sb_after = fs.superblock().free_blocks_count;
    let group_after: u32 = fs.groups().iter().map(|g| g.free_blocks_count).sum();

    assert_eq!(sb_before - sb_after, 40, "superblock free count");
    assert_eq!(group_before - group_after, 40, "summed group free counts");

    // No duplicates: 40 allocations must be 40 distinct blocks.
    allocated.sort_unstable();
    let unique = allocated.windows(2).filter(|w| w[0] != w[1]).count() + 1;
    assert_eq!(unique, 40, "the allocator returned a block more than once");
}

#[test]
fn a_double_free_is_refused() {
    // Accepting one would let two files come to share a block, which is how a
    // filesystem loses data without anything looking wrong at the time.
    let path = scratch("big-4k.img", "double-free");
    let mut fs = open(&path);

    let block = fs.alloc_block(0).expect("allocate");
    fs.free_block(block).expect("first free");
    assert!(
        fs.free_block(block).is_err(),
        "freeing an already-free block was accepted"
    );
}

#[test]
fn uninitialised_groups_are_left_alone() {
    // 14 of many-groups-1k's 17 groups are UNINIT. Their bitmaps on disk are
    // whatever bytes preceded them, so allocating from one would hand out
    // blocks based on a bitmap that was never written.
    let path = scratch("many-groups-1k.img", "uninit");
    let mut fs = open(&path);

    let uninit: Vec<usize> = (0..fs.groups().len())
        .filter(|&g| fs.groups()[g].block_bitmap_uninit())
        .collect();
    assert!(!uninit.is_empty(), "fixture should have UNINIT groups");

    let per = fs.superblock().blocks_per_group as u64;
    let first = fs.superblock().first_data_block as u64;

    for _ in 0..30 {
        let b = fs.alloc_block(0).expect("allocate");
        let g = ((b - first) / per) as usize;
        assert!(
            !uninit.contains(&g),
            "allocated block {b} from group {g}, whose bitmap was never written"
        );
    }
}

#[test]
fn reserved_inodes_are_never_handed_out() {
    // Inode 2 is the root and 8 is the journal. An allocator that returns one
    // does not corrupt a file — it corrupts the filesystem's own structure.
    let path = scratch("many-groups-1k.img", "reserved");
    let mut fs = open(&path);
    let first_ino = fs.superblock().first_ino as u64;

    for _ in 0..20 {
        let ino = fs.alloc_inode(false).expect("allocate inode");
        assert!(
            ino >= first_ino,
            "handed out reserved inode {ino} (s_first_ino is {first_ino})"
        );
    }
}

#[test]
fn a_directory_inode_is_counted_as_one() {
    let path = scratch("big-4k.img", "dircount");
    let mut fs = open(&path);

    let before: u32 = fs.groups().iter().map(|g| g.used_dirs_count).sum();
    let ino = fs.alloc_inode(true).expect("allocate a directory inode");
    let after: u32 = fs.groups().iter().map(|g| g.used_dirs_count).sum();
    assert_eq!(after - before, 1, "used_dirs_count did not rise");

    fs.free_inode(ino, true).expect("free");
    let restored: u32 = fs.groups().iter().map(|g| g.used_dirs_count).sum();
    assert_eq!(restored, before, "used_dirs_count did not come back down");
}

#[test]
fn e2fsck_stays_clean_across_allocate_and_free() {
    // The kernel's opinion, not ours. This is the check that covers the inode
    // path, where byte-identity is not available because `itable_unused`
    // legitimately shrinks and is not restored.
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "e2fsck");
    {
        let mut fs = open(&path);
        let mut blocks = Vec::new();
        for _ in 0..25 {
            blocks.push(fs.alloc_block(0).expect("allocate block"));
        }
        let ino = fs.alloc_inode(false).expect("allocate inode");
        let dir = fs.alloc_inode(true).expect("allocate directory inode");

        for b in blocks {
            fs.free_block(b).expect("free block");
        }
        fs.free_inode(ino, false).expect("free inode");
        fs.free_inode(dir, true).expect("free directory inode");
        fs.flush().expect("flush");
    }

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run the verifier");

    assert!(
        out.status.success(),
        "e2fsck rejected the filesystem after allocate/free:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn every_checksum_on_disk_still_verifies_after_a_net_allocation() {
    // The round-trip test above cannot see a broken checksum writer: if the
    // checksums are never updated at all, allocating and then freeing restores
    // the original bitmap, so the original checksum becomes correct again and
    // the bytes match. Neither can the e2fsck test, for the same reason.
    //
    // So this one allocates and *keeps* what it allocated, then re-derives
    // every checksum on the disk from the bytes now there. The checksum
    // functions themselves were graded against mke2fs in `ext4_csum.rs`, so a
    // match here is not self-referential: it says the writer produced what the
    // kernel would have produced for this state.
    use luks_core::device::ReadAt;
    use luks_core::fs::ext4::csum::Seed;

    for name in FIXTURES {
        let path = scratch(name, "net-csum");
        {
            let mut fs = open(&path);
            for _ in 0..30 {
                fs.alloc_block(0).expect("allocate block");
            }
            for _ in 0..5 {
                fs.alloc_inode(false).expect("allocate inode");
            }
            fs.alloc_inode(true).expect("allocate directory inode");
            fs.flush().expect("flush");
        }

        let fs = open(&path);
        let dev = FileDevice::open(&path).expect("reopen read-only");
        let sb = fs.superblock();
        let seed = Seed::of(sb);
        let bs = sb.block_size as u64;
        let wide = sb.group_desc_size() >= 64;
        let mask = if wide { u32::MAX } else { 0xFFFF };

        let mut raw_sb = [0u8; 1024];
        dev.read_at(1024, &mut raw_sb).expect("read superblock");
        let stored = u32::from_le_bytes([
            raw_sb[0x3FC],
            raw_sb[0x3FD],
            raw_sb[0x3FE],
            raw_sb[0x3FF],
        ]);
        assert_eq!(
            seed.superblock(&raw_sb).expect("enabled"),
            stored,
            "{name}: superblock checksum is stale after allocating"
        );

        let size = sb.group_desc_size();
        let count = sb.group_count() as usize;
        let mut table = vec![0u8; count * size];
        dev.read_at(sb.group_desc_offset(), &mut table)
            .expect("read descriptors");

        for g in 0..count {
            let d = &table[g * size..(g + 1) * size];
            assert_eq!(
                seed.group_desc(g as u64, d).expect("enabled"),
                u16::from_le_bytes([d[0x1E], d[0x1F]]),
                "{name}: group {g} descriptor checksum is stale after allocating"
            );

            let desc = &fs.groups()[g];
            if !desc.block_bitmap_uninit() {
                let mut bm = vec![0u8; (sb.clusters_per_group as usize).div_ceil(8)];
                dev.read_at(desc.block_bitmap * bs, &mut bm)
                    .expect("read block bitmap");
                assert_eq!(
                    seed.bitmap(&bm).expect("enabled") & mask,
                    desc.block_bitmap_csum & mask,
                    "{name}: group {g} block bitmap checksum is stale"
                );
            }
            if !desc.inode_bitmap_uninit() {
                let mut bm = vec![0u8; (sb.inodes_per_group as usize).div_ceil(8)];
                dev.read_at(desc.inode_bitmap * bs, &mut bm)
                    .expect("read inode bitmap");
                assert_eq!(
                    seed.bitmap(&bm).expect("enabled") & mask,
                    desc.inode_bitmap_csum & mask,
                    "{name}: group {g} inode bitmap checksum is stale"
                );
            }
        }
    }
}

#[test]
fn e2fsck_complains_only_about_the_leak_after_a_net_allocation() {
    // Blocks allocated and never attached to a file are a leak, and e2fsck
    // says so — that complaint is expected. What must *not* appear is any
    // complaint about a checksum or a corrupt structure, because those would
    // mean the writer produced bytes the kernel considers malformed rather
    // than merely orphaned.
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "net-e2fsck");
    {
        let mut fs = open(&path);
        for _ in 0..30 {
            fs.alloc_block(0).expect("allocate");
        }
        fs.alloc_inode(false).expect("allocate inode");
        fs.flush().expect("flush");
    }

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run the verifier");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    for bad in ["checksum", "Checksum", "corrupt", "Corrupt"] {
        assert!(
            !text.contains(bad),
            "e2fsck reported {bad:?} after a net allocation — the writer \
             produced malformed metadata, not just a leak:\n{text}"
        );
    }
    // And it must have run at all: a net allocation always leaks, so silence
    // here would mean the checker never looked.
    assert!(
        text.contains("bitmap differences") || text.contains("Free blocks count"),
        "e2fsck reported no leak after 30 unattached allocations, so it \
         probably did not inspect the image:\n{text}"
    );
}

/// Path to `tools/verify-ext4.sh`, or `None` if the VM it needs is not up.
fn verify_script() -> Option<String> {
    let script = format!("{}/../tools/verify-ext4.sh", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    let up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    up.then_some(script)
}
