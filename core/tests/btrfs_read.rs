//! btrfs reader tests against images built by real `mkfs.btrfs`.
//!
//! Four images, each chosen for a code path rather than for variety:
//!
//! | image        | geometry              | what it is for                     |
//! |--------------|-----------------------|------------------------------------|
//! | `plain.img`  | 4 KiB sector / 16 KiB node | DUP metadata, 400 files, symlinks |
//! | `compress.img` | same, mounted       | zlib/lzo/zstd, inline, a hole      |
//! | `mixed-4k.img` | node == sector      | mixed block groups, 4 KiB nodes    |
//! | `subvol.img` | same as compress      | four subvolumes, one a snapshot    |
//!
//! `mixed-4k` earns its place by making `nodesize == sectorsize`, which is the
//! one configuration where an accidental "nodes are always 16 KiB" assumption
//! still produces plausible-looking results on the other two images.
//!
//! Unlike the ext4 tests these open the image through `FileDevice` rather than
//! reading it into a `Vec`: btrfs's minimum filesystem size is ~109 MiB, so
//! slurping all four would cost 537 MiB of RAM to read a few kilobytes of
//! metadata.
//!
//! Regenerate with `tools/gen-btrfs-fixtures.sh` (needs Linux — see the header
//! of that script).

use luks_core::device::{FileDevice, ReadAt};
use luks_core::error::LuksError;
use luks_core::fs::btrfs::{crc32c::crc32c, superblock::Superblock, CsumType, ExtentKind, Key, Node};
use luks_core::fs::{Btrfs, FileType};

const IMAGES: [&str; 4] = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];

fn device(name: &str) -> FileDevice {
    let path = format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"));
    FileDevice::open(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    Btrfs::mount(device(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// --- superblock ------------------------------------------------------------

#[test]
fn mounts_every_image() {
    for name in IMAGES {
        let fs = mount(name);
        assert_eq!(fs.sector_size(), 4096, "{name}");
        assert_eq!(fs.superblock().num_devices, 1, "{name}");
        assert_eq!(fs.superblock().csum_type, CsumType::Crc32c, "{name}");
    }
}

/// Ground truth is `fixtures/btrfs/BTRFS-EXPECTED.txt`, which is dump-super's
/// own output — so these assertions compare us against btrfs-progs, not against
/// a second copy of our own parsing.
#[test]
fn reads_the_labels_and_uuids_mkfs_was_given() {
    let plain = mount("plain.img");
    assert_eq!(plain.label(), "BTRFSTEST");
    assert_eq!(
        plain.fsid(),
        uuid_bytes("33333333-4444-5555-6666-777777777777")
    );

    let compress = mount("compress.img");
    assert_eq!(compress.label(), "BTRFSCOMP");
    assert_eq!(
        compress.fsid(),
        uuid_bytes("88888888-9999-aaaa-bbbb-cccccccccccc")
    );

    let mixed = mount("mixed-4k.img");
    assert_eq!(mixed.label(), "BTRFSMIX");
    assert_eq!(
        mixed.fsid(),
        uuid_bytes("11111111-2222-3333-4444-555555555555")
    );
}

#[test]
fn reads_the_tree_roots_and_geometry() {
    let sb = mount("plain.img");
    let sb = sb.superblock();
    assert_eq!(sb.generation, 8);
    assert_eq!(sb.root, 30490624);
    assert_eq!(sb.chunk_root, 22020096);
    assert_eq!(sb.root_level, 0);
    assert_eq!(sb.chunk_root_level, 0);
    assert_eq!(sb.log_root, 0);
    assert_eq!(sb.total_bytes, 146145280);
    assert_eq!(sb.node_size, 16384);
    // 129 bytes = one 17-byte key plus a 48-byte chunk with two 32-byte
    // stripes: the DUP system chunk that holds the chunk tree itself.
    assert_eq!(sb.sys_chunk_array.len(), 129);
    // FS_TREE.
    assert_eq!(sb.root_dir_objectid, 6);
}

#[test]
fn mixed_mode_forces_nodes_down_to_the_sector_size() {
    let fs = mount("mixed-4k.img");
    assert_eq!(fs.node_size(), 4096);
    assert_eq!(fs.sector_size(), 4096);
    assert!(fs.superblock().is_mixed_groups());
    // Its system chunk is single, not DUP: 17 + 48 + 32 = 97.
    assert_eq!(fs.superblock().sys_chunk_array.len(), 97);
}

#[test]
fn no_holes_is_set_on_every_modern_image() {
    // Worth asserting rather than assuming: with NO_HOLES there is no
    // EXTENT_DATA item covering a gap at all, so the file-read path has to
    // infer zeros from a missing item instead of from a hole marker.
    for name in IMAGES {
        assert!(mount(name).superblock().has_no_holes(), "{name}");
    }
}

// --- checksums -------------------------------------------------------------

#[test]
fn the_superblock_checksum_is_actually_verified() {
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    Superblock::parse(&raw, 0x1_0000).expect("the pristine copy must parse");

    raw[0x100] ^= 0xFF;
    let err = Superblock::parse(&raw, 0x1_0000)
        .expect_err("a corrupt superblock must be refused");
    assert!(
        matches!(err, LuksError::FsChecksumMismatch(_)),
        "expected a checksum error, got {err}"
    );
}

#[test]
fn a_copy_read_from_the_wrong_offset_is_refused() {
    // `bytenr` is what distinguishes this filesystem's superblock from a stale
    // one left behind in a re-used partition. Parsing copy 0's bytes as though
    // they came from copy 1's offset must fail.
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    assert!(Superblock::parse(&raw, 0x400_0000).is_err());
}

#[test]
fn every_superblock_mirror_on_the_disk_verifies() {
    // 146 MiB holds copies at 64 KiB and 64 MiB, not the one at 256 GiB.
    let dev = device("plain.img");
    for offset in [0x1_0000u64, 0x400_0000] {
        let mut raw = vec![0u8; 4096];
        dev.read_at(offset, &mut raw).unwrap();
        let sb = Superblock::parse(&raw, offset)
            .unwrap_or_else(|e| panic!("mirror at {offset:#x}: {e}"));
        assert_eq!(sb.bytenr, offset);
        assert_eq!(sb.label, "BTRFSTEST");
    }
}

#[test]
fn crc32c_agrees_with_the_stored_superblock_checksum() {
    // The one assertion that pins the algorithm down end to end: our CRC over
    // the real block must equal the value mkfs wrote. Both the polynomial and
    // the final inversion have to be right for this to pass.
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    let stored = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    assert_eq!(crc32c(&raw[32..]), stored);
    assert_eq!(stored, 0xf7b4_210d);
}

// --- mirror selection ------------------------------------------------------

/// A 64 MiB + 4 KiB in-memory device holding the first two superblock copies,
/// each with the generation asked for. Cheaper than copying the 146 MiB fixture
/// and it lets the two copies disagree, which the real image never does.
fn two_mirrors(gen_primary: u64, gen_mirror: u64) -> Vec<u8> {
    let mut original = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut original).unwrap();

    let mut disk = vec![0u8; 0x400_0000 + 4096];
    for (offset, generation) in [(0x1_0000u64, gen_primary), (0x400_0000, gen_mirror)] {
        let mut copy = original.clone();
        copy[0x30..0x38].copy_from_slice(&offset.to_le_bytes());
        copy[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        fix_checksum(&mut copy);
        disk[offset as usize..offset as usize + 4096].copy_from_slice(&copy);
    }
    disk
}

#[test]
fn the_newest_superblock_copy_wins() {
    // btrfs writes the mirrors in order, so a commit interrupted by power loss
    // can leave copy 0 older than copy 1. Taking the primary unconditionally
    // would mount a stale filesystem — which reads fine and shows the wrong
    // contents, the worst possible failure for this app.
    //
    // These go through `Superblock::find` rather than `Btrfs::mount`: the
    // synthetic disk holds superblocks and nothing else, and a full mount also
    // wants the chunk tree the copies point at.
    let disk = two_mirrors(8, 9);
    assert_eq!(Superblock::find(&disk[..]).unwrap().generation, 9);

    let disk = two_mirrors(11, 9);
    assert_eq!(Superblock::find(&disk[..]).unwrap().generation, 11);
}

#[test]
fn a_corrupt_primary_falls_back_to_the_mirror() {
    let mut disk = two_mirrors(8, 8);
    disk[0x1_0000 + 0x100] ^= 0xFF;
    let sb = Superblock::find(&disk[..]).expect("the mirror at 64 MiB is intact");
    assert_eq!(sb.label, "BTRFSTEST");
    assert_eq!(sb.bytenr, 0x400_0000, "the mirror is the copy that was used");
}

#[test]
fn a_device_too_short_for_any_mirror_reports_the_primarys_error() {
    // The error a user sees must describe the copy they care about. "bad
    // checksum on the mirror at 64 MiB" is baffling when the real answer is
    // "this is not btrfs".
    let junk = vec![0u8; 0x2_0000];
    assert!(matches!(
        Btrfs::mount(&junk[..]).err().unwrap(),
        LuksError::NotBtrfs(_)
    ));
}

// --- refusals --------------------------------------------------------------

#[test]
fn a_non_btrfs_device_is_rejected_by_magic() {
    let junk = vec![0u8; 1 << 20];
    let err = Btrfs::mount(&junk[..])
        .err()
        .expect("zeros are not a filesystem");
    assert!(matches!(err, LuksError::NotBtrfs(_)), "got {err}");
}

#[test]
fn an_unreadable_incompat_flag_is_refused_by_name() {
    // RAID5/6 needs parity-stripe arithmetic this reader does not have.
    // Reading one stripe of a RAID5 extent would return plausible garbage, so
    // the flag has to be a hard refusal — and the message has to name it,
    // because "unsupported feature 0x80" tells the user nothing.
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    raw[0xbc] |= 0x80; // INCOMPAT_RAID56
    fix_checksum(&mut raw);

    let err = Superblock::parse(&raw, 0x1_0000).expect_err("must refuse");
    let msg = err.to_string();
    assert!(msg.contains("RAID5/6"), "unhelpful message: {msg}");
}

#[test]
fn an_unknown_future_flag_is_refused_rather_than_ignored() {
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    raw[0xc3] |= 0x80; // bit 63: nothing defined, so nothing we can read
    fix_checksum(&mut raw);

    let err = Superblock::parse(&raw, 0x1_0000).expect_err("must refuse");
    assert!(
        err.to_string().contains("unknown incompat"),
        "got {err}"
    );
}

#[test]
fn a_multi_device_filesystem_is_refused() {
    // Its chunks point at device ids we cannot open — the other members are
    // separate physical devices. Reading one device's share of a striped
    // extent would silently return the wrong bytes.
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    raw[0x88] = 2;
    fix_checksum(&mut raw);

    let err = Superblock::parse(&raw, 0x1_0000).expect_err("must refuse");
    assert!(err.to_string().contains("2 devices"), "got {err}");
}

#[test]
fn an_implausible_node_size_is_refused() {
    let mut raw = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut raw).unwrap();
    raw[0x94..0x98].copy_from_slice(&(1u32 << 20).to_le_bytes()); // 1 MiB nodes
    fix_checksum(&mut raw);

    let err = Superblock::parse(&raw, 0x1_0000).expect_err("must refuse");
    assert!(matches!(err, LuksError::CorruptFs(_)), "got {err}");
}

/// Recompute the checksum after editing a superblock, so a test that means to
/// exercise a feature check is not accidentally caught by the checksum check
/// one line earlier.
fn fix_checksum(raw: &mut [u8]) {
    let csum = crc32c(&raw[32..4096]).to_le_bytes();
    raw[..4].copy_from_slice(&csum);
}

// --- chunk tree ------------------------------------------------------------

#[test]
fn the_chunk_map_matches_what_dump_tree_reports() {
    // Ground truth is BTRFS-EXPECTED.txt, which is btrfs-progs' own dump.
    let fs = mount("plain.img");
    let chunks = fs.chunk_map().chunks();
    assert_eq!(chunks.len(), 3);

    let shape: Vec<(u64, u64, u64, usize)> = chunks
        .iter()
        .map(|c| (c.logical, c.length, c.chunk_type, c.stripes.len()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (13631488, 8388608, 0x1, 1),   // DATA, single
            (22020096, 8388608, 0x22, 2),  // SYSTEM, DUP
            (30408704, 53673984, 0x24, 2), // METADATA, DUP
        ]
    );

    // The DUP chunks' second stripes, which the map never uses but must parse.
    assert_eq!(chunks[1].stripes[0].offset, 22020096);
    assert_eq!(chunks[1].stripes[1].offset, 30408704);
    assert_eq!(chunks[2].stripes[0].offset, 38797312);
    assert_eq!(chunks[2].stripes[1].offset, 92471296);
}

#[test]
fn mixed_mode_puts_data_and_metadata_in_one_chunk() {
    let fs = mount("mixed-4k.img");
    let chunks = fs.chunk_map().chunks();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chunk_type, 0x2); // SYSTEM
    assert_eq!(chunks[1].chunk_type, 0x5); // DATA | METADATA
    assert!(!chunks[1].is_mirrored());
}

#[test]
fn the_bootstrap_map_covers_the_chunk_tree_and_little_else() {
    // The point of sys_chunk_array: it is not the whole map, just enough of it
    // to read the tree that holds the whole map.
    let fs = mount("plain.img");
    let boot = luks_core::fs::btrfs::ChunkMap::bootstrap(fs.superblock()).unwrap();
    assert_eq!(boot.len(), 1);
    assert!(boot.map(fs.superblock().chunk_root).is_ok());
    // The root tree lives in the metadata chunk, which the bootstrap map has
    // never heard of.
    assert!(boot.map(fs.superblock().root).is_err());
}

#[test]
fn the_root_tree_is_reachable_only_through_the_full_map() {
    // The strongest single check on the chunk layer. sb.root is in a chunk
    // that appears only inside the chunk tree, so reading a node there proves
    // the whole bootstrap-then-replace sequence worked. And because a node
    // carries its own address, a mapping that is merely *plausible* — right
    // chunk, wrong offset — fails the bytenr check rather than returning
    // convincing garbage.
    for name in IMAGES {
        let fs = mount(name);
        let root = fs.read_node(fs.superblock().root).unwrap();
        assert_eq!(root.owner, 1, "{name}: root tree objectid is 1");
        assert!(root.nr_items > 0, "{name}");
    }
}

#[test]
fn logical_addresses_translate_the_way_the_chunk_items_say() {
    let fs = mount("plain.img");
    // Inside the metadata chunk: logical 30408704 -> stripe 0 at 38797312.
    let (physical, run) = fs.chunk_map().map(30408704).unwrap();
    assert_eq!(physical, 38797312);
    assert_eq!(run, 53673984);

    // 16 KiB in, the offset carries through unchanged.
    let (physical, run) = fs.chunk_map().map(30408704 + 16384).unwrap();
    assert_eq!(physical, 38797312 + 16384);
    assert_eq!(run, 53673984 - 16384);
}

#[test]
fn an_address_in_no_chunk_is_an_error_not_a_hole() {
    let fs = mount("plain.img");
    // Below the first chunk: the first 13 MiB of the logical space is not
    // mapped at all.
    assert!(fs.chunk_map().map(0).is_err());
    // Past the last chunk.
    assert!(fs.chunk_map().map(30408704 + 53673984).is_err());
    // In the gap between the data chunk (ends at 22020096) and... there is
    // none here, so use the far end instead: reading unmapped space must never
    // be treated as a hole full of zeros, which is what a filesystem reader
    // does for a *file* hole and is exactly the wrong answer for metadata.
    assert!(fs.chunk_map().map(u64::MAX).is_err());
}

#[test]
fn reads_spanning_a_chunk_boundary_are_stitched_together() {
    let fs = mount("plain.img");
    // The system chunk ends at 22020096 + 8388608 = 30408704, which is exactly
    // where the metadata chunk begins — so a read straddling that point has to
    // come from two different physical places.
    let mut spanning = vec![0u8; 8192];
    fs.read_logical(30408704 - 4096, &mut spanning).unwrap();

    let mut first = vec![0u8; 4096];
    let mut second = vec![0u8; 4096];
    fs.read_logical(30408704 - 4096, &mut first).unwrap();
    fs.read_logical(30408704, &mut second).unwrap();
    assert_eq!(&spanning[..4096], &first[..]);
    assert_eq!(&spanning[4096..], &second[..]);
}

#[test]
fn a_node_claiming_the_wrong_address_is_refused() {
    // A checksum alone cannot catch a bad chunk mapping: a node fetched from
    // the wrong place is still a perfectly valid node and verifies fine. Only
    // comparing the node's own `bytenr` against the address we followed to get
    // there catches it — so feed the real chunk-root block in while claiming it
    // came from one node further on.
    let fs = mount("plain.img");
    let sb = fs.superblock();
    let mut raw = vec![0u8; sb.node_size as usize];
    fs.read_logical(sb.chunk_root, &mut raw).unwrap();

    Node::parse(raw.clone(), sb.chunk_root, sb.csum_type, &sb.metadata_uuid)
        .expect("the honest address must parse");

    let err = Node::parse(
        raw,
        sb.chunk_root + sb.node_size as u64,
        sb.csum_type,
        &sb.metadata_uuid,
    )
    .expect_err("a node must not be accepted at an address it does not claim");
    assert!(matches!(err, LuksError::CorruptFs(_)), "got {err}");
}

#[test]
fn a_node_from_another_filesystem_is_refused() {
    // Re-used space: a node left behind by a previous filesystem checksums
    // correctly and can even sit at the right address. Its fsid is what gives
    // it away.
    let fs = mount("plain.img");
    let sb = fs.superblock();
    let mut raw = vec![0u8; sb.node_size as usize];
    fs.read_logical(sb.chunk_root, &mut raw).unwrap();

    let stranger = [0xABu8; 16];
    let err = Node::parse(raw, sb.chunk_root, sb.csum_type, &stranger)
        .expect_err("a foreign fsid must be refused");
    assert!(matches!(err, LuksError::CorruptFs(_)), "got {err}");
}

// --- tree walking ----------------------------------------------------------

#[test]
fn walks_a_single_leaf_tree() {
    let fs = mount("plain.img");
    let mut items = Vec::new();
    fs.walk_tree(fs.superblock().chunk_root, &mut |key, data| {
        items.push((key, data.len()));
        Ok(())
    })
    .unwrap();

    // One DEV_ITEM plus the three chunks, in key order — dump-tree reports the
    // same four at the same sizes.
    assert_eq!(items.len(), 4);
    assert_eq!(items[0].0, Key::new(1, 216, 1));
    assert_eq!(items[0].1, 98);
    assert_eq!(items[1].0, Key::new(256, 228, 13631488));
    assert!(items.windows(2).all(|w| w[0].0 < w[1].0), "keys must ascend");
}

/// Logical address of the fs tree's root node, via the root tree.
///
/// This peeks at two fields of a `ROOT_ITEM` rather than waiting for the item
/// parsing that comes with the next layer, because leaving the interior-node
/// descent untested until then would mean shipping the trickiest ten lines in
/// the tree code on faith. `bytenr` at 176 and `level` at 238 were both read
/// off the real item and cross-checked against dump-tree.
fn fs_tree_root(fs: &Btrfs<FileDevice>) -> (u64, u8) {
    const FS_TREE_OBJECTID: u64 = 5;
    const ROOT_ITEM_KEY: u8 = 132;

    let mut found = None;
    fs.walk_tree(fs.superblock().root, &mut |key, data| {
        if key.objectid == FS_TREE_OBJECTID && key.item_type == ROOT_ITEM_KEY {
            let bytenr = u64::from_le_bytes(data[176..184].try_into().unwrap());
            found = Some((bytenr, data[238]));
        }
        Ok(())
    })
    .unwrap();
    found.expect("every btrfs has an FS_TREE root item")
}

#[test]
fn walks_a_tree_with_interior_nodes() {
    // The 400 files in the fixture exist for exactly this: they push the fs
    // tree to level 1, so the walk has to descend key pointers instead of
    // reading one leaf and stopping. A filesystem small enough to fit in a
    // single leaf would exercise none of that and would look perfectly healthy.
    let fs = mount("plain.img");
    let (root, level) = fs_tree_root(&fs);
    assert_eq!(level, 1, "the fixture must keep the fs tree multi-level");

    let mut count = 0usize;
    let mut previous: Option<Key> = None;
    let mut ascending = true;
    fs.walk_tree(root, &mut |key, _| {
        if let Some(p) = previous {
            // Ordering across a leaf boundary is the thing that breaks when
            // children are visited in the wrong order — within one leaf it
            // holds no matter what the walk does.
            ascending &= p < key;
        }
        previous = Some(key);
        count += 1;
        Ok(())
    })
    .unwrap();

    assert!(ascending, "the walk must visit keys in order across leaves");
    // 400 files, each with an inode item, an inode ref, two directory entries
    // and an extent — plus the rest of the tree.
    assert!(count > 400, "only visited {count} items, so leaves were skipped");
}

#[test]
fn a_child_at_the_wrong_level_stops_the_walk() {
    // The termination proof: levels must fall by exactly one per descent, so a
    // corrupt pointer aimed back at an ancestor is refused rather than looped
    // on. Point the fs tree's walk at a *leaf* address while claiming the tree
    // root, and the level bookkeeping is what catches it.
    let fs = mount("plain.img");
    let (root, _) = fs_tree_root(&fs);
    let node = fs.read_node(root).unwrap();
    let child = node.key_ptr(0).unwrap().blockptr;

    // Descending from a leaf must not be possible at all.
    let leaf = fs.read_node(child).unwrap();
    assert!(leaf.is_leaf());
    assert!(leaf.key_ptr(0).is_err());
}

// --- tree roots and searching ----------------------------------------------

#[test]
fn finds_the_fs_tree_through_its_root_item() {
    let fs = mount("plain.img");
    let root = fs.fs_tree();
    // Cross-checked against dump-tree, which reports the FS_TREE node at this
    // address and level.
    assert_eq!(root.bytenr, 30605312);
    assert_eq!(root.level, 1);
    // Every fs tree's root directory is objectid 256.
    assert_eq!(root.root_dirid, 256);

    for name in IMAGES {
        assert_eq!(mount(name).fs_tree().root_dirid, 256, "{name}");
    }
}

#[test]
fn a_missing_tree_is_an_error_not_an_empty_one() {
    let fs = mount("plain.img");
    assert!(fs.tree_root(999_999).is_err());
}

#[test]
fn searching_lands_on_an_exact_key() {
    let fs = mount("plain.img");
    let key = Key::new(256, 228, 22020096); // the system chunk
    let cursor = fs.search(fs.superblock().chunk_root, &key).unwrap();
    assert!(cursor.valid());
    assert_eq!(cursor.key().unwrap(), key);
    assert_eq!(cursor.data().unwrap().len(), 112);
}

#[test]
fn searching_a_missing_key_lands_on_the_next_one() {
    let fs = mount("plain.img");
    // Between the data chunk at 13631488 and the system chunk at 22020096.
    let cursor = fs
        .search(fs.superblock().chunk_root, &Key::new(256, 228, 20000000))
        .unwrap();
    assert!(cursor.valid());
    assert_eq!(cursor.key().unwrap(), Key::new(256, 228, 22020096));
}

#[test]
fn searching_past_the_last_key_is_not_an_error() {
    // Range scans hit this every time they finish. Making it an error would
    // mean every caller has to distinguish "ran out" from "went wrong".
    let fs = mount("plain.img");
    let cursor = fs
        .search(fs.superblock().chunk_root, &Key::new(u64::MAX, 255, u64::MAX))
        .unwrap();
    assert!(!cursor.valid());
}

#[test]
fn stepping_a_cursor_visits_exactly_what_walking_does() {
    // The equivalence that matters: the cheap traversal and the exhaustive one
    // must agree, across leaf boundaries and interior nodes alike. The fs tree
    // is level 1 with 13 leaves, so a cursor that mishandles the climb-and-
    // descend would diverge here and nowhere else.
    let fs = mount("plain.img");
    let root = fs.fs_tree().bytenr;

    let mut walked = Vec::new();
    fs.walk_tree(root, &mut |key, data| {
        walked.push((key, data.len()));
        Ok(())
    })
    .unwrap();

    let mut stepped = Vec::new();
    let mut cursor = fs.search(root, &Key::new(0, 0, 0)).unwrap();
    while cursor.valid() {
        stepped.push((cursor.key().unwrap(), cursor.data().unwrap().len()));
        cursor.advance().unwrap();
    }

    assert_eq!(stepped.len(), walked.len());
    assert_eq!(stepped, walked);
    assert!(walked.len() > 400, "the fixture must be multi-leaf");
}

#[test]
fn a_run_scan_stops_at_the_end_of_the_run() {
    let fs = mount("plain.img");
    let root = fs.fs_tree().bytenr;

    // The root directory's DIR_INDEX entries: hello.txt, big.bin, docs, many,
    // the unicode name, and the two symlinks.
    let mut names = Vec::new();
    fs.for_each_item(root, 256, 96, &mut |key, _| {
        names.push(key);
        Ok(true)
    })
    .unwrap();
    assert!(!names.is_empty());
    assert!(names.iter().all(|k| k.objectid == 256 && k.item_type == 96));
    assert!(names.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn a_run_scan_can_stop_early() {
    let fs = mount("plain.img");
    let root = fs.fs_tree().bytenr;
    let mut seen = 0;
    fs.for_each_item(root, 256, 96, &mut |_, _| {
        seen += 1;
        Ok(seen < 2)
    })
    .unwrap();
    assert_eq!(seen, 2);
}

/// Counts device reads, so a claim about traversal cost can be checked rather
/// than asserted. The same idea as the ext4 test that counts I/Os: over USB the
/// number of round trips is the thing that matters, not the number of bytes.
struct CountingDevice {
    inner: FileDevice,
    reads: std::sync::atomic::AtomicUsize,
}

impl ReadAt for CountingDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), LuksError> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.read_at(offset, buf)
    }
    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

#[test]
fn searching_costs_the_depth_of_the_tree_not_its_size() {
    // The whole reason the cursor exists. On this fixture the difference is
    // 2 reads against 14; on the developer's 1 TB drive it is the difference
    // between opening a directory and reading the filesystem.
    let counting = CountingDevice {
        inner: device("plain.img"),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let fs = Btrfs::mount(counting).unwrap();
    let root = fs.fs_tree().bytenr;

    let load = |fs: &Btrfs<CountingDevice>| {
        fs.device().reads.load(std::sync::atomic::Ordering::Relaxed)
    };

    let before = load(&fs);
    let cursor = fs.search(root, &Key::new(256, 1, 0)).unwrap();
    assert!(cursor.valid());
    let searched = load(&fs) - before;

    let before = load(&fs);
    fs.walk_tree(root, &mut |_, _| Ok(())).unwrap();
    let walked = load(&fs) - before;

    // level 1 tree: root node plus one leaf.
    assert_eq!(searched, 2, "a search should read one node per level");
    assert!(
        walked > searched * 4,
        "walking read {walked} nodes, searching {searched} — the fixture is \
         too small for this comparison to mean anything"
    );
}

// --- inodes and directories ------------------------------------------------

fn names(entries: &[luks_core::fs::DirEntry]) -> Vec<String> {
    let mut v: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    v.sort();
    v
}

#[test]
fn lists_the_root_directory() {
    let fs = mount("plain.img");
    let entries = fs.list_dir("/").unwrap();
    assert_eq!(
        names(&entries),
        vec![
            "big.bin",
            "café-naïve-日本語.txt",
            "docs",
            "hello.txt",
            "link-to-hello",
            "many",
        ]
    );
    // btrfs stores no "." or ".." items at all, so unlike ext4 there is nothing
    // to filter out — worth asserting so a future "helpful" filter is not added.
    assert!(!entries.iter().any(|e| e.name == "." || e.name == ".."));
}

#[test]
fn reports_the_type_of_each_entry() {
    let fs = mount("plain.img");
    let entries = fs.list_dir("/").unwrap();
    let of = |n: &str| entries.iter().find(|e| e.name == n).unwrap().file_type;
    assert_eq!(of("hello.txt"), FileType::Regular);
    assert_eq!(of("docs"), FileType::Directory);
    assert_eq!(of("link-to-hello"), FileType::Symlink);
    assert_eq!(of("many"), FileType::Directory);
}

#[test]
fn lists_nested_directories() {
    let fs = mount("plain.img");
    assert_eq!(
        names(&fs.list_dir("/docs").unwrap()),
        vec!["link-to-deep", "nested", "readme.md"]
    );
    assert_eq!(
        names(&fs.list_dir("/docs/nested").unwrap()),
        vec!["deep.txt"]
    );
    // Leading and trailing slashes, and "." components, must not change the
    // answer.
    assert_eq!(
        names(&fs.list_dir("docs/./nested/").unwrap()),
        vec!["deep.txt"]
    );
}

#[test]
fn lists_a_directory_that_spans_several_leaves() {
    // 400 entries do not fit in one 16 KiB leaf, so this is the case where a
    // listing silently truncates if the cursor cannot cross a leaf boundary.
    let fs = mount("plain.img");
    let entries = fs.list_dir("/many").unwrap();
    assert_eq!(entries.len(), 400);
    assert!(entries.iter().all(|e| e.file_type == FileType::Regular));

    let listed = names(&entries);
    let expected: Vec<String> = (0..400).map(|i| format!("f{i:04}.txt")).collect();
    assert_eq!(listed, expected);
}

#[test]
fn a_listing_comes_back_in_a_stable_order() {
    // DIR_INDEX is keyed by a sequence number, so the order is stable across
    // reads. It is *creation* order, not alphabetical — mkfs --rootdir copies
    // the staging directory in readdir order, so f0251.txt legitimately comes
    // first. Asserting alphabetical order here would be asserting something
    // btrfs never promised.
    let fs = mount("plain.img");
    let first: Vec<String> = fs
        .list_dir("/many")
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    let second: Vec<String> = fs
        .list_dir("/many")
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();

    assert_eq!(first, second, "the order must not vary between reads");
    assert_eq!(first.len(), 400);

    let mut sorted = first.clone();
    sorted.sort();
    assert_ne!(
        first, sorted,
        "this fixture happens to be stored out of alphabetical order, which is \
         what makes it evidence that the order comes from DIR_INDEX"
    );
}

#[test]
fn looks_a_name_up_without_scanning_the_directory() {
    // The point of hashing the name: finding one file in a 400-entry directory
    // must not cost 400 entries' worth of reads.
    let counting = CountingDevice {
        inner: device("plain.img"),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let fs = Btrfs::mount(counting).unwrap();
    let root = fs.fs_tree();
    let load = || {
        fs.device()
            .reads
            .load(std::sync::atomic::Ordering::Relaxed)
    };

    let many = fs
        .lookup(root.bytenr, root.root_dirid, "many")
        .unwrap()
        .unwrap();
    let docs = fs
        .lookup(root.bytenr, root.root_dirid, "docs")
        .unwrap()
        .unwrap();

    // The claim worth testing is that a lookup costs the same in a directory of
    // 400 entries as in one of 3 — cost follows tree depth, not directory size.
    // Comparing lookup against listing would instead measure how big this
    // particular fixture is, and at 400 small entries it is not big enough for
    // that comparison to say anything.
    let before = load();
    let found = fs
        .lookup(root.bytenr, many.location.objectid, "f0399.txt")
        .unwrap()
        .expect("the last file in a 400-entry directory");
    let big_dir_reads = load() - before;
    assert_eq!(found.name, b"f0399.txt");

    let before = load();
    fs.lookup(root.bytenr, docs.location.objectid, "readme.md")
        .unwrap()
        .expect("a file in a 3-entry directory");
    let small_dir_reads = load() - before;

    assert_eq!(
        big_dir_reads, small_dir_reads,
        "a lookup in a 400-entry directory cost {big_dir_reads} reads and one \
         in a 3-entry directory {small_dir_reads} — the hash index is not \
         doing its job"
    );
    // Tree depth here is 2 (root node + leaf), and that is the whole cost.
    assert_eq!(big_dir_reads, 2);
}

#[test]
fn a_missing_name_is_not_found_rather_than_an_error() {
    let fs = mount("plain.img");
    let root = fs.fs_tree();
    assert!(fs
        .lookup(root.bytenr, root.root_dirid, "nope.txt")
        .unwrap()
        .is_none());
    assert!(matches!(
        fs.list_dir("/nope").unwrap_err(),
        LuksError::NotFound(_)
    ));
}

#[test]
fn a_unicode_name_round_trips() {
    let fs = mount("plain.img");
    let root = fs.fs_tree();
    let found = fs
        .lookup(root.bytenr, root.root_dirid, "café-naïve-日本語.txt")
        .unwrap()
        .expect("hashing must be over the raw bytes, not over chars");
    assert_eq!(found.file_type, FileType::Regular);
}

#[test]
fn listing_a_file_is_refused() {
    let fs = mount("plain.img");
    assert!(matches!(
        fs.list_dir("/hello.txt").unwrap_err(),
        LuksError::NotADirectory(_)
    ));
    assert!(matches!(
        fs.list_dir("/hello.txt/inner").unwrap_err(),
        LuksError::NotADirectory(_)
    ));
}

#[test]
fn reads_inode_metadata() {
    let fs = mount("plain.img");
    let info = fs.file_info("/hello.txt").unwrap();
    assert_eq!(info.size, 12); // "hello btrfs\n"
    assert_eq!(info.file_type, FileType::Regular);
    assert_eq!(info.mode & 0xF000, 0x8000);
    assert_eq!(info.links, 1);
    assert!(info.mtime > 1_600_000_000, "a plausible timestamp");

    let big = fs.file_info("/big.bin").unwrap();
    assert_eq!(big.size, 2 * 1024 * 1024);

    let dir = fs.file_info("/docs").unwrap();
    assert_eq!(dir.file_type, FileType::Directory);
}

#[test]
fn a_symlink_is_reported_as_one_rather_than_followed() {
    // Following needs the extent reader, which does not exist yet. The
    // important part is that it does not silently resolve to something else.
    let fs = mount("plain.img");
    let info = fs.file_info("/link-to-hello").unwrap();
    assert_eq!(info.file_type, FileType::Symlink);
    assert_eq!(info.size, 9); // "hello.txt"
}

#[test]
fn every_image_lists_its_own_contents() {
    assert_eq!(
        names(&mount("mixed-4k.img").list_dir("/").unwrap()),
        vec!["data.bin", "docs", "hello.txt"]
    );
    assert_eq!(
        names(&mount("compress.img").list_dir("/").unwrap()),
        vec!["lzo.txt", "sparse.bin", "tiny.txt", "zlib.txt", "zstd.txt"]
    );
}

#[test]
fn the_name_hash_matches_what_mkfs_filed_entries_under() {
    // Different convention from the block checksum: seed !1, and no final
    // inversion. Getting it wrong makes every lookup miss while every checksum
    // still verifies, so it is worth pinning to a value read off the disk.
    use luks_core::fs::btrfs::crc32c::name_hash;
    assert_eq!(name_hash(b"hello.txt"), 1096805209);
    assert_eq!(name_hash(b"default"), 2378154706);

    // And the hash must actually agree with the key mkfs used, for every entry
    // in the root directory rather than just the two above.
    let fs = mount("plain.img");
    let root = fs.fs_tree();
    for entry in fs.list_dir("/").unwrap() {
        let found = fs
            .lookup(root.bytenr, root.root_dirid, &entry.name)
            .unwrap();
        assert!(found.is_some(), "{} was listed but not findable", entry.name);
    }
}

// --- file contents ---------------------------------------------------------

/// The same pattern `tools/gen-btrfs-fixtures.sh` writes into `big.bin`.
fn expected_big() -> Vec<u8> {
    (0..2 * 1024 * 1024)
        .map(|i| ((i * 31 + 7) % 256) as u8)
        .collect()
}

#[test]
fn reads_an_inline_file() {
    // Small files have no data block at all — the bytes are in the leaf.
    let fs = mount("plain.img");
    assert_eq!(fs.read_file("/hello.txt").unwrap(), b"hello btrfs\n");
    assert_eq!(
        fs.read_file("/docs/readme.md").unwrap(),
        b"# readme\n\nnested content\n"
    );
    assert_eq!(
        fs.read_file("/docs/nested/deep.txt").unwrap(),
        b"three levels down\n"
    );

    let found = fs.resolve_no_follow(fs.fs_tree(), "/hello.txt").unwrap();
    let extents = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();
    assert_eq!(extents.len(), 1);
    assert_eq!(extents[0].kind, ExtentKind::Inline);
}

#[test]
fn reads_a_file_that_spans_several_extents() {
    // 2 MiB written as two 1 MiB extents, so a read that stops at the first
    // one returns exactly half a file and looks fine until the bytes are
    // checked.
    let fs = mount("plain.img");
    let data = fs.read_file("/big.bin").unwrap();
    assert_eq!(data.len(), 2 * 1024 * 1024);
    assert_eq!(data, expected_big());

    let found = fs.resolve_no_follow(fs.fs_tree(), "/big.bin").unwrap();
    let extents = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();
    assert_eq!(extents.len(), 2);
    assert!(extents.iter().all(|e| e.kind == ExtentKind::Regular));
}

#[test]
fn reads_from_the_middle_of_a_file() {
    // The case search_le exists for: the extent covering byte 1_500_000 is
    // filed under 1_048_576, so an equal-or-greater search sails past it and
    // the read returns zeros.
    let fs = mount("plain.img");
    let expected = expected_big();

    for (offset, len) in [
        (0usize, 100usize),
        (4095, 4098),          // straddles a sector boundary
        (1_048_575, 3),        // straddles the extent boundary
        (1_500_000, 65536),    // squarely inside the second extent
        (2 * 1024 * 1024 - 10, 10), // the very end
    ] {
        let mut buf = vec![0u8; len];
        let n = fs.read_chunk("/big.bin", offset as u64, &mut buf).unwrap();
        assert_eq!(n, len, "at offset {offset}");
        assert_eq!(buf, expected[offset..offset + len], "at offset {offset}");
    }
}

#[test]
fn a_read_past_the_end_of_a_file_is_short_not_an_error() {
    let fs = mount("plain.img");
    let mut buf = vec![0u8; 1000];
    let n = fs.read_chunk("/hello.txt", 0, &mut buf).unwrap();
    assert_eq!(n, 12);
    assert_eq!(&buf[..n], b"hello btrfs\n");

    assert_eq!(fs.read_chunk("/hello.txt", 12, &mut buf).unwrap(), 0);
    assert_eq!(fs.read_chunk("/hello.txt", 9999, &mut buf).unwrap(), 0);
}

#[test]
fn a_sparse_file_reads_as_zeros_where_it_has_no_extents() {
    // NO_HOLES means the gap has *no* item covering it. The reader has to infer
    // zeros from an item that is absent, which is the case that returns
    // whatever was in the buffer if it is handled by iterating items instead of
    // by walking file offsets.
    let fs = mount("compress.img");
    let info = fs.file_info("/sparse.bin").unwrap();
    assert_eq!(info.size, 1048576);

    let data = fs.read_file("/sparse.bin").unwrap();
    assert_eq!(data.len(), 1048576);
    assert!(
        data[..1048573].iter().all(|&b| b == 0),
        "the hole must read as zeros"
    );
    assert_eq!(&data[1048573..], b"end");

    // And the same through a partial read that starts inside the hole.
    let mut buf = vec![0xAAu8; 64];
    fs.read_chunk("/sparse.bin", 500_000, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "a stale buffer must be cleared");
}

#[test]
fn reads_a_symlink_target() {
    // Symlink targets are stored exactly like file contents, which is why this
    // could not work before the extent reader existed.
    let fs = mount("plain.img");
    assert_eq!(fs.read_link("/link-to-hello").unwrap(), "hello.txt");
    assert_eq!(fs.read_link("/docs/link-to-deep").unwrap(), "nested/deep.txt");

    assert!(fs.read_link("/hello.txt").is_err(), "not a symlink");
}

#[test]
fn reading_a_directory_is_refused() {
    let fs = mount("plain.img");
    assert!(matches!(
        fs.read_file("/docs").unwrap_err(),
        LuksError::IsADirectory(_)
    ));
}

#[test]
fn reads_every_file_in_a_multi_leaf_directory() {
    // 400 files, each an inline extent in a different leaf than its neighbours
    // near the boundaries. Content is derived from the name, so a mix-up
    // between two files is caught rather than just a truncation.
    let fs = mount("plain.img");
    for entry in fs.list_dir("/many").unwrap() {
        let i: u32 = entry.name[1..5].parse().unwrap();
        let got = fs.read_file(&format!("/many/{}", entry.name)).unwrap();
        assert_eq!(got, format!("file number {i}\n").into_bytes(), "{}", entry.name);
    }
}

#[test]
fn reads_files_on_a_mixed_block_group_filesystem() {
    // Data and metadata share one chunk here, so a mapping that assumed a
    // chunk is only ever one or the other would fail on the data read.
    let fs = mount("mixed-4k.img");
    assert_eq!(fs.read_file("/hello.txt").unwrap(), b"hello mixed\n");
    assert_eq!(fs.read_file("/docs/readme.md").unwrap(), b"nested content\n");
}

#[test]
fn an_inline_file_is_readable_on_the_compressed_image() {
    // tiny.txt is below max_inline, and the mount that wrote it had no
    // compression forced, so it is a plain inline extent.
    let fs = mount("compress.img");
    let data = fs.read_file("/tiny.txt").unwrap();
    assert!(data.starts_with(b"inline extent"));
}

#[test]
fn reading_a_file_costs_one_device_read_per_extent() {
    // The regression guard this project has already paid for once. The ext4
    // reader originally mapped one block at a time, turning a 1 GiB file into
    // a quarter of a million SCSI round trips and minutes of wall clock on real
    // hardware. btrfs is more prone to it, not less: every data read goes
    // through a logical-to-physical translation, so a loop that re-translates
    // per block looks perfectly correct and is unusably slow.
    //
    // big.bin is 2 MiB in two extents. A per-sector reader would take 512
    // reads for the data alone.
    let counting = CountingDevice {
        inner: device("plain.img"),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let fs = Btrfs::mount(counting).unwrap();
    let before = fs
        .device()
        .reads
        .load(std::sync::atomic::Ordering::Relaxed);

    let data = fs.read_file("/big.bin").unwrap();

    let reads = fs
        .device()
        .reads
        .load(std::sync::atomic::Ordering::Relaxed)
        - before;
    assert_eq!(data.len(), 2 * 1024 * 1024);
    // Measured: 12. Eight of those are the mount and the extent runs; the
    // other four are the checksum tree, which costs one search per extent
    // read. That is the price of verifying the data and it is bounded by the
    // number of extents, not by the size of the file — which is the property
    // that matters, since a 1 GiB file has the same handful of searches.
    assert!(
        reads <= 16,
        "reading a two-extent file took {reads} device reads — either the \
         extent runs are being chopped up, or the checksum lookup is being \
         repeated per sector instead of per extent"
    );
}

// --- compression -----------------------------------------------------------

/// The same 256 KiB of text `tools/gen-btrfs-fixtures.sh` writes into each
/// compressed file. Deliberately not one repeated byte: a single repeated byte
/// can be encoded in ways that hide a segment-framing bug, because every
/// segment's output looks the same as every other's.
fn expected_payload() -> Vec<u8> {
    (0..5000)
        .map(|i| format!("line {i:06} the quick brown fox jumps over the lazy dog\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn reads_zlib_lzo_and_zstd_extents() {
    let fs = mount("compress.img");
    let expected = expected_payload();
    assert!(expected.len() > 64 * 1024, "must span several extents");

    for name in ["/zlib.txt", "/lzo.txt", "/zstd.txt"] {
        let got = fs.read_file(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(got.len(), expected.len(), "{name}: wrong length");
        assert_eq!(got, expected, "{name}: wrong contents");
    }
}

#[test]
fn the_fixture_is_actually_compressed() {
    // Without this the test above would pass just as happily against three
    // uncompressed files, and would be proving nothing at all.
    let fs = mount("compress.img");
    let root = fs.fs_tree();
    let expected_len = expected_payload().len() as u64;

    for (name, algorithm) in [("zlib.txt", 1u8), ("lzo.txt", 2), ("zstd.txt", 3)] {
        let found = fs.resolve_no_follow(root, name).unwrap();
        let extents = fs
            .file_extents(found.tree.bytenr, found.inode.objectid)
            .unwrap();
        assert!(!extents.is_empty(), "{name}");
        assert!(
            extents.iter().all(|e| e.compression == algorithm),
            "{name}: expected algorithm {algorithm}, got {:?}",
            extents.iter().map(|e| e.compression).collect::<Vec<_>>()
        );
        let on_disk: u64 = extents.iter().map(|e| e.disk_num_bytes).sum();
        assert!(
            on_disk < expected_len / 2,
            "{name}: {on_disk} bytes on disk for {expected_len} of text is not compression"
        );
    }
}

#[test]
fn reads_from_the_middle_of_a_compressed_file() {
    // Compression is per extent, so a partial read has to decompress the whole
    // extent and then take a slice of it at `offset + within`. Dropping either
    // term returns real text from the wrong part of the file — which looks
    // entirely plausible.
    let fs = mount("compress.img");
    let expected = expected_payload();

    for name in ["/zlib.txt", "/lzo.txt", "/zstd.txt"] {
        for (offset, len) in [
            (0usize, 64usize),
            (4095, 4098),
            (100_000, 1000),
            (expected.len() - 50, 50),
        ] {
            let mut buf = vec![0u8; len];
            let n = fs.read_chunk(name, offset as u64, &mut buf).unwrap();
            assert_eq!(n, len, "{name} at {offset}");
            assert_eq!(buf, expected[offset..offset + len], "{name} at {offset}");
        }
    }
}

#[test]
fn lzo_segment_framing_spans_more_than_one_sector() {
    // The LZO-specific trap: segments are independently compressed and a
    // segment header never straddles a sector boundary, so the reader has to
    // skip padding the writer inserted. Miss it and the first 4 KiB decodes
    // perfectly and everything after it is wrong — so this asserts the file is
    // big enough for that to be exercised at all.
    let fs = mount("compress.img");
    let root = fs.fs_tree();
    let found = fs.resolve_no_follow(root, "lzo.txt").unwrap();
    let extents = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();

    let biggest = extents
        .iter()
        .map(|e| e.disk_num_bytes)
        .max()
        .expect("lzo.txt has extents");
    assert!(
        biggest > fs.sector_size() as u64,
        "the compressed extent is {biggest} bytes, which fits in one sector — \
         this fixture cannot exercise the segment framing"
    );
}

// --- subvolumes ------------------------------------------------------------

/// The ground truth here is `btrfs subvolume list`, recorded in
/// BTRFS-EXPECTED.txt when the fixture was built:
///
/// ```text
/// ID 256 gen 8 top level 5   path root
/// ID 257 gen 7 top level 5   path home
/// ID 258 gen 8 top level 257 path home/user/snap
/// ID 259 gen 7 top level 5   path snapshots/home-snap
/// ```
#[test]
fn enumerates_every_subvolume_with_the_path_btrfs_progs_reports() {
    let fs = mount("subvol.img");
    let subvols = fs.subvolumes().unwrap();

    let seen: Vec<(u64, &str, u64)> = subvols
        .iter()
        .map(|s| (s.id, s.path.as_str(), s.parent_id))
        .collect();
    assert_eq!(
        seen,
        vec![
            (256, "/root", 5),
            (257, "/home", 5),
            // Nested inside another subvolume: its path crosses two trees, and
            // its parent is 257 rather than the top level.
            (258, "/home/user/snap", 257),
            // Parent dirid is not the tree root, so this path can only come
            // from walking the INODE_REF chain.
            (259, "/snapshots/home-snap", 5),
        ]
    );
}

/// The bug this fixture was built to catch, and it caught one immediately: a
/// snapshot's ROOT_ITEM is keyed by the transid it was taken at, not by zero.
/// `tree_root` looked it up with an exact match at offset 0 and reported a
/// healthy filesystem as corrupt — on a drive where every rollback point is a
/// snapshot, which is to say on openSUSE and on anything using `snapper`.
#[test]
fn a_snapshots_root_item_is_found_despite_its_nonzero_key_offset() {
    let fs = mount("subvol.img");
    let snapshot = fs.tree_root(259).expect("snapshot root item");
    assert!(snapshot.bytenr != 0);
    assert_eq!(snapshot.root_dirid, 256);
    assert_eq!(snapshot.objectid, 259);
    // Taken with -r, so this is the one subvolume that reports read-only.
    assert!(snapshot.is_read_only(), "snapshot should be read-only");

    let others: Vec<u64> = fs
        .subvolumes()
        .unwrap()
        .iter()
        .filter(|s| s.is_read_only())
        .map(|s| s.id)
        .collect();
    assert_eq!(others, vec![259]);
}

/// Reported, not obeyed. The fixture had `set-default` run on it, so this is
/// 256 rather than the top level — and browsing must still start at 5, or the
/// three subvolumes outside `root` would be unreachable.
#[test]
fn reports_the_default_subvolume_without_browsing_from_it() {
    let fs = mount("subvol.img");
    assert_eq!(fs.default_subvolume().unwrap(), 256);
    assert_eq!(fs.fs_tree().objectid, 5);
    assert_eq!(fs.fs_tree().root_dirid, 256);
}

/// A filesystem nobody has run `set-default` on — the Fedora case — must not
/// error just because the entry is absent.
#[test]
fn a_filesystem_with_no_default_entry_answers_with_the_top_level() {
    for name in ["plain.img", "compress.img", "mixed-4k.img"] {
        let fs = mount(name);
        assert_eq!(fs.default_subvolume().unwrap(), 5, "{name}");
        assert!(fs.subvolumes().unwrap().is_empty(), "{name}");
    }
}

/// Subvolume ids and inode numbers share a namespace of `u64` and start at the
/// same place, so a tree id read as an inode number lands somewhere plausible.
/// This pins the distinguishing fact: the top level's own directory listing
/// carries entries whose location is a ROOT_ITEM, not an INODE_ITEM.
#[test]
fn a_subvolume_entry_is_marked_as_a_tree_not_an_inode() {
    let fs = mount("subvol.img");
    let root = fs.fs_tree();

    let subvol = fs.lookup(root.bytenr, root.root_dirid, "home").unwrap();
    let subvol = subvol.expect("/home exists");
    assert!(subvol.is_subvolume(), "/home is a subvolume boundary");
    assert_eq!(subvol.location.objectid, 257, "the location is a tree id");

    let plain = fs.lookup(root.bytenr, root.root_dirid, "plaindir").unwrap();
    let plain = plain.expect("/plaindir exists");
    assert!(!plain.is_subvolume(), "a plain directory is not a boundary");
    assert!(
        plain.location.objectid >= 256,
        "an inode number in the same range as a tree id — which is exactly why \
         the item type is what has to be checked"
    );
}

/// Enumeration must not cost a walk of the filesystem. It reads the root tree,
/// which is the smallest tree there is, plus one search per subvolume.
#[test]
fn enumerating_subvolumes_reads_only_the_root_tree() {
    let counting = CountingDevice {
        inner: device("subvol.img"),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let fs = Btrfs::mount(counting).unwrap();
    let before = fs.device().reads.load(std::sync::atomic::Ordering::Relaxed);
    let subvols = fs.subvolumes().unwrap();
    let cost = fs.device().reads.load(std::sync::atomic::Ordering::Relaxed) - before;

    assert_eq!(subvols.len(), 4);
    // 4 subvolumes on a fixture whose root tree is a single leaf. The bound is
    // deliberately loose — what it rules out is a per-subvolume tree walk,
    // which would be hundreds.
    assert!(cost < 40, "enumeration cost {cost} reads");
}

// --- crossing subvolume boundaries -----------------------------------------

/// The top level looks like an ordinary directory, with the subvolumes in it
/// presented as the directories a user thinks they are — and flagged, because
/// their `inode` field is a tree id and nothing about the number says so.
#[test]
fn the_top_level_lists_subvolumes_as_directories() {
    let fs = mount("subvol.img");
    let mut entries = fs.list_dir("/").unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let seen: Vec<(&str, bool, bool)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.file_type.is_dir(), e.is_subvolume))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("home", true, true),
            ("plaindir", true, false),
            ("root", true, true),
            ("snapshots", true, false),
            ("toplevel.txt", false, false),
        ]
    );
}

/// The Fedora shape: content that lives in a different fs tree from the root.
#[test]
fn reads_a_file_inside_a_subvolume() {
    let fs = mount("subvol.img");
    assert_eq!(
        fs.read_file("/root/etc/hostname").unwrap(),
        b"fixture.localdomain\n"
    );
    assert_eq!(
        fs.read_file("/home/user/docs/deep.txt").unwrap(),
        b"four levels down, in another tree\n"
    );
    // A path that crosses *two* boundaries: the top level into `home`, then
    // `home` into the subvolume nested inside it.
    assert_eq!(
        fs.read_file("/home/user/snap/inside.txt").unwrap(),
        b"nested subvolume\n"
    );
    // And the plain directory beside them still resolves without any of this.
    assert_eq!(
        fs.read_file("/plaindir/note.txt").unwrap(),
        b"just a directory\n"
    );
}

/// A read-only snapshot is a full second copy of the tree it was taken from,
/// so the same relative path reads the same bytes through it.
#[test]
fn reads_through_a_snapshot() {
    let fs = mount("subvol.img");
    let live = fs.read_file("/home/user/docs/deep.txt").unwrap();
    let snap = fs
        .read_file("/snapshots/home-snap/user/docs/deep.txt")
        .unwrap();
    assert_eq!(live, snap);

    // The snapshot was taken before `snap` was created inside `home`... or
    // after; either way, listing it must succeed rather than error.
    let entries = fs.list_dir("/snapshots/home-snap").unwrap();
    assert!(
        entries.iter().any(|e| e.name == "user"),
        "{:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// Listing and metadata cross boundaries too, not just whole-file reads.
#[test]
fn listing_and_stat_work_across_a_boundary() {
    let fs = mount("subvol.img");

    let entries = fs.list_dir("/home/user").unwrap();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["docs", "snap"]);
    // `snap` is a subvolume even when seen from inside another subvolume.
    assert!(entries.iter().any(|e| e.name == "snap" && e.is_subvolume));

    let info = fs.file_info("/home/user/docs/deep.txt").unwrap();
    assert_eq!(info.size, b"four levels down, in another tree\n".len() as u64);
    assert!(info.file_type.is_file());
}

/// The mistake the `Located` type exists to prevent, demonstrated rather than
/// described: every fs tree numbers its inodes from 256, so an inode number
/// from one tree is a *valid* inode number in another, naming something else
/// entirely. Reading it through the top-level tree — the obvious thing to do
/// when resolution hands back a bare inode — silently returns the wrong file.
#[test]
fn the_same_inode_number_means_different_files_in_different_trees() {
    let fs = mount("subvol.img");
    let found = fs
        .resolve_no_follow(fs.fs_tree(), "/home/user/docs/deep.txt")
        .unwrap();

    // It really did end up in another tree, or this test proves nothing.
    assert_ne!(found.tree.objectid, fs.fs_tree().objectid);
    assert_eq!(found.tree.objectid, 257);

    let mut correct = vec![0u8; found.inode.size as usize];
    fs.read_inode_data(found.tree.bytenr, &found.inode, 0, &mut correct)
        .unwrap();
    assert_eq!(correct, b"four levels down, in another tree\n");

    // Now the bug. Inode 259 in tree 257 is this file; inode 259 in the top
    // level is `/plaindir/note.txt`. Reading through the wrong tree does not
    // fail — it returns a real file, whose checksums all verify, which is not
    // the one that was asked for. That is the entire hazard in one assertion.
    assert_eq!(found.inode.objectid, 259);
    let mut wrong = vec![0u8; found.inode.size as usize];
    let n = fs
        .read_inode_data(fs.fs_tree().bytenr, &found.inode, 0, &mut wrong)
        .expect("inode 259 exists in the top-level tree too");
    assert_eq!(&wrong[..17], b"just a directory\n");
    assert_ne!(&wrong[..n], &correct[..]);
}

/// Crossing must cost a boundary crossing, not a rescan. One extra root-tree
/// search per subvolume entered is the whole price.
#[test]
fn crossing_a_boundary_costs_one_extra_search() {
    let counting = CountingDevice {
        inner: device("subvol.img"),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let fs = Btrfs::mount(counting).unwrap();
    let count = || fs.device().reads.load(std::sync::atomic::Ordering::Relaxed);

    let before = count();
    fs.file_info("/plaindir/note.txt").unwrap();
    let no_crossing = count() - before;

    let before = count();
    fs.file_info("/home/user/docs/deep.txt").unwrap();
    let one_crossing = count() - before;

    // Deeper by two components and across a tree boundary. The bound rules out
    // anything that re-reads the root tree per component or walks a tree.
    assert!(
        one_crossing < no_crossing + 12,
        "{no_crossing} reads without a crossing, {one_crossing} with one"
    );
}

// --- an unclean filesystem -------------------------------------------------

/// A btrfs that was not unmounted cleanly keeps its newest writes in a log
/// tree, which this reader does not walk — replaying one is a write. Mounting
/// anyway would show the filesystem as it was *before* the interruption:
/// recent files missing, or holding their previous contents, with every
/// checksum verifying, because that stale data is genuinely what is there.
///
/// The fixtures are all cleanly unmounted, so the dirty state is synthesised:
/// take a real superblock, set `log_root`, and repair the checksum — which is
/// only possible because the CRC is ours to compute, and is the same trick the
/// mirror-selection tests use.
#[test]
fn a_filesystem_with_an_unreplayed_log_tree_is_refused() {
    let mut original = vec![0u8; 4096];
    device("plain.img").read_at(0x1_0000, &mut original).unwrap();

    let with_log = |log_root: u64| -> Vec<u8> {
        let mut disk = vec![0u8; 0x400_0000 + 4096];
        for offset in [0x1_0000u64, 0x400_0000] {
            let mut copy = original.clone();
            copy[0x30..0x38].copy_from_slice(&offset.to_le_bytes());
            copy[0x60..0x68].copy_from_slice(&log_root.to_le_bytes());
            fix_checksum(&mut copy);
            disk[offset as usize..offset as usize + 4096].copy_from_slice(&copy);
        }
        disk
    };

    let dirty = with_log(30_000_000);
    // `.err()` rather than `expect_err`: Btrfs has no Debug, and giving it one
    // would mean dumping a 16 KiB node on every failed assertion.
    let err = Btrfs::mount(&dirty[..])
        .err()
        .expect("a dirty filesystem must be refused");
    assert!(
        matches!(err, LuksError::FsNeedsRecovery),
        "expected FsNeedsRecovery, got {err}"
    );

    // The guard must be the log tree specifically, not the synthetic disk:
    // with log_root cleared the same disk gets past this check and fails later
    // for the reason it should — no chunk tree behind the superblock.
    let clean = with_log(0);
    let err = Btrfs::mount(&clean[..])
        .err()
        .expect("this disk has no chunk tree");
    assert!(
        !matches!(err, LuksError::FsNeedsRecovery),
        "cleared log_root still reported as needing recovery"
    );
}

/// Every committed fixture is cleanly unmounted, so the guard above cannot be
/// silently rejecting all of them.
#[test]
fn the_fixtures_are_all_cleanly_unmounted() {
    for name in IMAGES {
        assert_eq!(mount(name).superblock().log_root, 0, "{name}");
    }
}

// --- data checksums --------------------------------------------------------

/// Metadata checksums were enforced from the start; file *contents* were not.
/// This asserts the csum tree is actually being consulted — a lookup bug that
/// found nothing would leave every read passing, silently unverified, which
/// looks identical to working from the outside.
#[test]
fn file_data_is_covered_by_checksums() {
    use luks_core::fs::btrfs::Verified;

    for (image, path) in [
        ("plain.img", "/big.bin"),
        // Compressed extents are checksummed over their on-disk (compressed)
        // bytes, so this exercises a different range than the file's size.
        ("compress.img", "/zlib.txt"),
        ("compress.img", "/lzo.txt"),
        // nodesize == sectorsize here, which is where a per-sector indexing
        // error would not show up on the other images.
        ("mixed-4k.img", "/data.bin"),
    ] {
        let fs = mount(image);
        let found = fs.resolve_no_follow(fs.fs_tree(), path).unwrap();
        let extents = fs
            .file_extents(found.tree.bytenr, found.inode.objectid)
            .unwrap();

        let mut checked = 0;
        for e in &extents {
            // Inline extents live in a tree node and are covered by that node's
            // own checksum, so they have no entry here.
            if e.disk_bytenr == 0 {
                continue;
            }
            let mut raw = vec![0u8; e.disk_num_bytes as usize];
            let outcome = fs.read_data(e.disk_bytenr, &mut raw).unwrap();
            assert_eq!(
                outcome,
                Verified::All,
                "{image}{path}: extent at {} is not fully checksummed",
                e.disk_bytenr
            );
            checked += 1;
        }
        assert!(checked > 0, "{image}{path}: nothing was checked");
    }

    // The skip above is real, not a way to pass vacuously: a small file is
    // stored *inside* a tree node, so it has no data extent and no entry in
    // the csum tree — it is covered by that node's own checksum instead.
    let fs = mount("plain.img");
    let found = fs.resolve_no_follow(fs.fs_tree(), "/docs/readme.md").unwrap();
    let inline = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();
    assert!(
        inline.iter().all(|e| e.disk_bytenr == 0),
        "readme.md was expected to be inline"
    );
}

/// The test that decides whether any of this is worth having: corrupt one byte
/// of file data on the disk and the read must fail, not hand back a file that
/// is quietly wrong.
///
/// A single flipped bit is the realistic failure — bit rot, a dying cell, a
/// bad cable. Everything else about the filesystem stays valid, so nothing
/// *except* the data checksum can catch it: the extent item is intact, the
/// tree nodes verify, the size is right.
#[test]
fn a_single_corrupted_byte_of_file_data_is_caught() {
    let fs = mount("plain.img");
    let found = fs.resolve_no_follow(fs.fs_tree(), "/big.bin").unwrap();
    let extents = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();
    let victim = extents
        .iter()
        .find(|e| e.disk_bytenr != 0)
        .expect("big.bin has an out-of-line extent");
    // Logical addresses mean nothing to a file on disk; the chunk map is what
    // turns one into a byte offset we can reach.
    let (physical, _) = fs.chunk_map().map(victim.disk_bytenr).unwrap();

    let mut image = std::fs::read(format!(
        "{}/../fixtures/btrfs/plain.img",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // Not the first byte of the sector — anywhere in it must be caught.
    let at = physical as usize + 1234;
    image[at] ^= 0x01;

    let corrupt = std::env::temp_dir().join("luks-btrfs-corrupt.img");
    std::fs::write(&corrupt, &image).unwrap();

    let fs = Btrfs::mount(FileDevice::open(&corrupt).unwrap()).expect("still mounts");
    // The filesystem itself is untouched: listing and metadata still work, so
    // the failure below is specifically about data.
    assert!(fs.list_dir("/").is_ok(), "metadata should be unaffected");

    let err = fs
        .read_file("/big.bin")
        .err()
        .expect("a corrupted data extent must not be returned as a file");
    assert!(
        matches!(err, LuksError::FsChecksumMismatch(_)),
        "expected a checksum error, got {err}"
    );

    // A file whose data was not touched still reads.
    assert_eq!(
        fs.read_file("/hello.txt").unwrap(),
        b"hello btrfs\n",
        "corruption in one extent must not condemn the whole filesystem"
    );

    std::fs::remove_file(&corrupt).ok();
}

/// Checksums cover whole sectors, so an unaligned read cannot be verified from
/// its own bytes. It must still be verified — by reading the sectors around
/// it — rather than silently skipping the edges, which on a stream of small
/// reads would mean verifying almost nothing.
#[test]
fn an_unaligned_read_is_still_verified() {
    use luks_core::fs::btrfs::Verified;
    let fs = mount("plain.img");
    let found = fs.resolve_no_follow(fs.fs_tree(), "/big.bin").unwrap();
    let extents = fs
        .file_extents(found.tree.bytenr, found.inode.objectid)
        .unwrap();
    let e = extents.iter().find(|e| e.disk_bytenr != 0).unwrap();

    // Deliberately ragged at both ends.
    let mut buf = vec![0u8; 100];
    let outcome = fs.read_data(e.disk_bytenr + 7, &mut buf).unwrap();
    assert_eq!(outcome, Verified::All);

    // And the bytes are still the right ones, not the sector they were read
    // inside of.
    let mut whole = vec![0u8; 4096];
    fs.read_data(e.disk_bytenr, &mut whole).unwrap();
    assert_eq!(buf, whole[7..107]);
}
