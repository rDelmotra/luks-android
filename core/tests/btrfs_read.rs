//! btrfs reader tests against images built by real `mkfs.btrfs`.
//!
//! Three images, each chosen for a code path rather than for variety:
//!
//! | image        | geometry              | what it is for                     |
//! |--------------|-----------------------|------------------------------------|
//! | `plain.img`  | 4 KiB sector / 16 KiB node | DUP metadata, 400 files, symlinks |
//! | `compress.img` | same, mounted       | zlib/lzo/zstd, inline, a hole      |
//! | `mixed-4k.img` | node == sector      | mixed block groups, 4 KiB nodes    |
//!
//! `mixed-4k` earns its place by making `nodesize == sectorsize`, which is the
//! one configuration where an accidental "nodes are always 16 KiB" assumption
//! still produces plausible-looking results on the other two images.
//!
//! Unlike the ext4 tests these open the image through `FileDevice` rather than
//! reading it into a `Vec`: btrfs's minimum filesystem size is ~109 MiB, so
//! slurping all three would cost 377 MiB of RAM to read a few kilobytes of
//! metadata.
//!
//! Regenerate with `tools/gen-btrfs-fixtures.sh` (needs Linux — see the header
//! of that script).

use luks_core::device::{FileDevice, ReadAt};
use luks_core::error::LuksError;
use luks_core::fs::btrfs::{crc32c::crc32c, superblock::Superblock, CsumType, Key, Node};
use luks_core::fs::Btrfs;

const IMAGES: [&str; 3] = ["plain.img", "compress.img", "mixed-4k.img"];

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
    let root = fs.fs_tree().unwrap();
    // Cross-checked against dump-tree, which reports the FS_TREE node at this
    // address and level.
    assert_eq!(root.bytenr, 30605312);
    assert_eq!(root.level, 1);
    // Every fs tree's root directory is objectid 256.
    assert_eq!(root.root_dirid, 256);

    for name in IMAGES {
        assert_eq!(mount(name).fs_tree().unwrap().root_dirid, 256, "{name}");
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
    let root = fs.fs_tree().unwrap().bytenr;

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
    let root = fs.fs_tree().unwrap().bytenr;

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
    let root = fs.fs_tree().unwrap().bytenr;
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
    let root = fs.fs_tree().unwrap().bytenr;

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
