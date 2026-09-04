//! The size confirmation on `FileDevice::open_writable`.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test write_target
//! ```
//!
//! Device numbering is assigned by plug order, not by identity. For instance,
//! a dynamic path like `/dev/diskN` can be an encrypted storage device in one session and
//! an unrelated secondary drive in the next. The check exists so that a path which
//! has come to mean a different drive fails loudly instead of being written to.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::{FileDevice, WriteAt};

fn scratch(name: &str, len: usize) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("write-target-{name}"));
    std::fs::write(&p, vec![0u8; len]).expect("create scratch");
    p
}

#[test]
fn a_matching_size_opens_and_writes() {
    let path = scratch("match", 4096);
    let dev = FileDevice::open_writable(&path, 4096).expect("open");
    dev.write_at(0, &[0xAB; 16]).expect("write");
    dev.flush().expect("flush");

    assert_eq!(&std::fs::read(&path).expect("read back")[..16], &[0xAB; 16]);
}

#[test]
fn the_path_meaning_a_different_drive_is_refused() {
    // The real failure: a size is confirmed, then the path comes to refer to
    // something else before it is opened.
    let path = scratch("renumbered", 40_000);
    let confirmed = 40_000u64;

    std::fs::write(&path, vec![0u8; 61_000]).expect("swap what the path means");

    let err = FileDevice::open_writable(&path, confirmed)
        .expect_err("a size mismatch must be refused");
    let msg = format!("{err}");
    assert!(msg.contains("40000") && msg.contains("larger"), "{msg}");
}

#[test]
fn a_size_that_cannot_be_determined_is_refused_not_assumed() {
    // Failing closed matters more than the check itself: an unreadable or
    // absent target must never fall through to "trust the caller".
    let err = FileDevice::open_writable("/no/such/path", 100)
        .expect_err("an unverifiable target must be refused");
    assert!(format!("{err}").contains("could not determine its size"));
}

#[test]
fn being_off_by_one_byte_is_still_refused() {
    // Two drives essentially never share an exact byte count, which is what
    // makes size a usable identity check — so the comparison must be exact
    // rather than approximate.
    let path = scratch("off-by-one", 8192);
    assert!(FileDevice::open_writable(&path, 8191).is_err());
    assert!(FileDevice::open_writable(&path, 8193).is_err());
    assert!(FileDevice::open_writable(&path, 8192).is_ok());
}

#[test]
fn the_probe_works_through_the_widened_raw_device_path() {
    // The whole check rests on two reads landing correctly on a device whose
    // reads must be block-aligned. On a raw character device every read is
    // widened to 4 KiB and sliced back down, so "read the last byte" is not
    // the simple operation it looks like — it reads the 4 KiB block
    // containing that byte and relies on the short-read check to notice when
    // the block runs past the end.
    //
    // A real raw device needs root, so alignment is forced here on an
    // ordinary file, which is exactly what open_writable_with_alignment
    // exists for. Without this the probe would be untested on the only kind
    // of device it actually matters for — and shipping an unverified
    // mechanism is the mistake that produced this rewrite.
    let path = scratch("widened", 4096 * 3);

    // Correct size, through the widening path.
    assert!(FileDevice::open_writable_with_alignment(&path, 4096, 4096 * 3).is_ok());

    // One block short and one block long must both be refused, which is what
    // proves the probe is reading where it thinks it is.
    assert!(FileDevice::open_writable_with_alignment(&path, 4096, 4096 * 2).is_err());
    assert!(FileDevice::open_writable_with_alignment(&path, 4096, 4096 * 4).is_err());

    // A size that is not a multiple of the alignment still resolves exactly,
    // since the last partial block is readable and the byte past it is not.
    let odd = scratch("widened-odd", 4096 * 2 + 17);
    assert!(FileDevice::open_writable_with_alignment(&odd, 4096, 4096 * 2 + 17).is_ok());
    assert!(FileDevice::open_writable_with_alignment(&odd, 4096, 4096 * 2 + 16).is_err());
    assert!(FileDevice::open_writable_with_alignment(&odd, 4096, 4096 * 2 + 18).is_err());
}

#[test]
fn the_read_only_open_needs_no_confirmation() {
    // Reading a wrong device is harmless, and requiring a size there would be
    // ceremony that makes the read path worse for no safety gain.
    let path = scratch("readonly", 512);
    assert!(FileDevice::open(&path).is_ok());
}
