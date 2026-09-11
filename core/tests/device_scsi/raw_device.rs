//! Reading through the alignment-widening path used for raw character devices.
//!
//! Why this exists: on macOS `/dev/rdiskN` is 5.4x faster than `/dev/diskN` for
//! large sequential reads (measured on the developer's storage device: 722 vs 132 MiB/s),
//! because the buffered node copies every byte through the page cache for data
//! that is read exactly once. The catch is that the raw node rejects any read
//! whose offset or length is not block-aligned — and the LUKS header parse does
//! several. So `FileDevice` widens reads to a 4 KiB boundary and slices the
//! result back down.
//!
//! That slicing is the part that can be wrong while looking right: an off-by-one
//! in the skip returns real bytes from the wrong place, which is exactly the
//! failure mode that produces "the header is corrupt" on a perfectly good drive.
//! These tests read known content at deliberately awkward offsets and compare
//! against the same bytes read the ordinary way.
//!
//! A character device cannot be created without root, so the alignment is forced
//! on an ordinary fixture with `open_with_alignment`. The arithmetic under test
//! is identical; only the reason for it differs.

use luks_core::device::{FileDevice, ReadAt};

/// A fixture with varied, position-dependent content — a compressed image, so
/// no long runs of identical bytes that a misplaced slice could hide in.
fn fixture() -> String {
    format!(
        "{}/../fixtures/disks/gpt-luks-btrfs.img",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn read(dev: &FileDevice, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    dev.read_at(offset, &mut buf)
        .unwrap_or_else(|e| panic!("read {len} at {offset}: {e}"));
    buf
}

#[test]
fn widened_reads_return_the_same_bytes_as_direct_reads() {
    let plain = FileDevice::open(fixture()).expect("fixture");
    let raw = FileDevice::open_with_alignment(fixture(), 4096).expect("fixture");

    assert!(!plain.is_raw(), "a regular file must not be widened");
    assert!(raw.is_raw());

    // Offsets and lengths chosen to hit every combination of aligned and not,
    // including reads that start and end inside the same 4 KiB block and reads
    // that straddle several.
    let cases = [
        (0u64, 512usize),    // aligned start, short
        (0, 4096),           // exactly one block
        (0, 8192),           // exactly two
        (1, 1),              // one byte, unaligned both ends
        (511, 2),            // straddles a 512 boundary
        (4095, 2),           // straddles a 4096 boundary
        (4096, 4096),        // aligned block, not the first
        (1024, 3072),        // inside one block, ends on its boundary
        (17, 9000),          // unaligned start, spans three blocks
        (65536, 4096),       // the btrfs superblock, aligned
        (65536 + 7, 100),    // just past it, unaligned
        (1_048_576 - 3, 10), // straddling a 1 MiB boundary
    ];

    for (offset, len) in cases {
        assert_eq!(
            read(&raw, offset, len),
            read(&plain, offset, len),
            "widened read of {len} bytes at {offset} does not match a direct read"
        );
    }
}

#[test]
fn widening_does_not_read_past_the_end_of_the_device() {
    let plain = FileDevice::open(fixture()).expect("fixture");
    let raw = FileDevice::open_with_alignment(fixture(), 4096).expect("fixture");
    let len = plain.len().expect("image has a length");

    // The last byte. Widening rounds the end up to the next 4 KiB boundary,
    // which for an image whose size is not a multiple of 4096 lands past EOF —
    // the read must still succeed, because the bytes the *caller* asked for are
    // all there. Treating the short tail as an error would make the final
    // sector of every raw device unreadable.
    assert_eq!(read(&raw, len - 1, 1), read(&plain, len - 1, 1));
    assert_eq!(read(&raw, len - 4096, 4096), read(&plain, len - 4096, 4096));

    // Genuinely past the end is still an error, not silently zero-filled.
    let mut buf = [0u8; 16];
    assert!(
        raw.read_at(len, &mut buf).is_err(),
        "reading beyond the end must fail rather than return zeros"
    );
}

#[test]
fn the_whole_stack_reads_through_a_widened_device() {
    // The point of the widening is that nothing above it needs to know. Mount
    // the LUKS+btrfs disk image through a device that widens every read and
    // check it produces the same filesystem — this is the path a raw
    // `/dev/rdiskN` takes, minus the device node.
    use luks_core::fs::MountedFs;
    use luks_core::luks::{self, LuksVolume};
    use luks_core::partition;

    let dev = FileDevice::open_with_alignment(fixture(), 4096).expect("fixture");
    let table = partition::scan(&dev, 512).expect("gpt");
    let part = table.luks_partitions().next().expect("a LUKS partition");
    let offset = part.offset_bytes();
    let part_len = Some(part.size_bytes());

    let header = luks::read_from(&dev, offset).expect("header parses through widened reads");
    let volume = LuksVolume::open(&dev, offset, part_len, &header, b"test").expect("unlock");
    let fs = MountedFs::mount(&volume).expect("mount");

    assert_eq!(fs.kind().name(), "btrfs");
    let entries = fs.list_dir("/").expect("list root");
    assert!(
        entries.iter().any(|e| e.name == "proof.txt"),
        "expected proof.txt in {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );

    // Reading a file's *contents* is the assertion that matters: listing a
    // directory only touches tree nodes, which are aligned anyway. File data
    // goes through the extent map and the csum tree at whatever offsets the
    // allocator chose, so this is where a misplaced slice would show up.
    let plain = FileDevice::open(fixture()).expect("fixture");
    let via_plain = {
        let v = LuksVolume::open(&plain, offset, part_len, &header, b"test").expect("unlock");
        let f = MountedFs::mount(&v).expect("mount");
        f.read_file("/proof.txt").expect("read")
    };
    assert_eq!(fs.read_file("/proof.txt").expect("read"), via_plain);
}
