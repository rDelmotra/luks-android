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
use luks_core::fs::btrfs::{crc32c::crc32c, superblock::Superblock, CsumType};
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
    let disk = two_mirrors(8, 9);
    assert_eq!(Btrfs::mount(&disk[..]).unwrap().superblock().generation, 9);

    let disk = two_mirrors(11, 9);
    assert_eq!(Btrfs::mount(&disk[..]).unwrap().superblock().generation, 11);
}

#[test]
fn a_corrupt_primary_falls_back_to_the_mirror() {
    let mut disk = two_mirrors(8, 8);
    disk[0x1_0000 + 0x100] ^= 0xFF;
    let fs = Btrfs::mount(&disk[..]).expect("the mirror at 64 MiB is intact");
    assert_eq!(fs.label(), "BTRFSTEST");
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
