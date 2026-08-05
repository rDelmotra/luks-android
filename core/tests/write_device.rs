//! The device write path, and the guarantee it must not break.
//!
//! Run with:
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test write_device
//! ```
//!
//! Without the feature this file compiles to nothing, which is the point being
//! tested as much as anything here: a default build has no way to obtain a
//! writable descriptor, so it cannot corrupt a drive by any code path at all.
//! That is what makes pointing the reader at the developer's real 1 TB SSD
//! safe as a *property* rather than as a promise, and it is the property most
//! at risk now that a writer exists.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::{FileDevice, ReadAt, WriteAt};

/// A private copy of a fixture, so a failing test cannot damage the original.
///
/// Named after the test rather than randomly: a leftover file from a crashed
/// run should be recognisable and overwritten by the next one, not accumulate.
fn scratch(name: &str) -> String {
    let src = format!(
        "{}/../fixtures/disks/gpt-luks-btrfs.img",
        env!("CARGO_MANIFEST_DIR")
    );
    let dst = std::env::temp_dir().join(format!("luks-write-test-{name}.img"));
    std::fs::copy(&src, &dst).expect("copy the fixture to scratch");
    dst.to_string_lossy().into_owned()
}

fn read(dev: &FileDevice, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    dev.read_at(offset, &mut buf).expect("read back");
    buf
}

#[test]
fn a_read_only_device_refuses_to_write() {
    // The guarantee. `open` gives an O_RDONLY descriptor, so the kernel would
    // refuse this even if every check in this crate were removed — but the
    // error should name the mistake rather than surfacing a bare errno.
    let path = scratch("readonly");
    let dev = FileDevice::open(&path).expect("open");
    assert!(!dev.is_writable());

    let err = dev.write_at(0, b"nope").err().expect("must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("read-only") || msg.contains("open_writable"),
        "unhelpful refusal: {msg}"
    );

    // And nothing was written despite the attempt.
    let dev2 = FileDevice::open(&path).expect("reopen");
    assert_ne!(&read(&dev2, 0, 4)[..], b"nope");
}

#[test]
fn what_was_written_is_what_comes_back() {
    let path = scratch("roundtrip");
    let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
    assert!(dev.is_writable());

    // Deliberately awkward offsets and lengths, including ones that straddle
    // sector and page boundaries. **Non-overlapping**, which is not a detail:
    // the first draft had (4095, 2) followed by (4096, 4096), so the second
    // write clobbered a byte of the first. The write-then-check-immediately
    // loop passed anyway and only the reopen pass caught it — which is the
    // argument for the reopen pass existing.
    let cases: [(u64, usize); 6] = [
        (0, 16),
        (511, 2),
        (4095, 2),
        (8192, 4096),
        (65536 + 7, 100),
        (1_048_576 - 3, 10),
    ];

    for (i, (offset, len)) in cases.into_iter().enumerate() {
        // Position-dependent content, so a write landing at the wrong offset
        // cannot coincidentally match.
        let payload: Vec<u8> = (0..len).map(|n| (n * 7 + i * 31 + 1) as u8).collect();
        dev.write_at(offset, &payload)
            .unwrap_or_else(|e| panic!("write {len} at {offset}: {e}"));
        assert_eq!(read(&dev, offset, len), payload, "at offset {offset}");
    }

    dev.flush().expect("flush");

    // Reopened from scratch: this is the assertion that the bytes reached the
    // file rather than a buffer that happened to still be in scope.
    let fresh = FileDevice::open(&path).expect("reopen");
    for (i, (offset, len)) in cases.into_iter().enumerate() {
        let payload: Vec<u8> = (0..len).map(|n| (n * 7 + i * 31 + 1) as u8).collect();
        assert_eq!(read(&fresh, offset, len), payload, "after reopen, at {offset}");
    }
}

#[test]
fn a_partial_write_does_not_disturb_its_neighbours() {
    // The read-modify-write path is where a device write can destroy data the
    // caller never asked to touch: it fetches the surrounding block, patches
    // the middle and writes the whole thing back. If the fetch or the patch is
    // off, the damage lands on bytes nobody mentioned — and that is invisible
    // to a test that only checks what it wrote.
    let path = scratch("neighbours");

    // Alignment forced to 4096, so every one of these writes goes through
    // read-modify-write rather than straight to the file. A character device
    // cannot be created without root; the arithmetic under test is identical.
    let before = {
        let dev = FileDevice::open(&path).expect("open");
        read(&dev, 0, 3 * 4096)
    };

    let dev = FileDevice::open_writable_with_alignment(&path, 4096, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
    let payload = [0xEEu8; 5];
    let at = 4096 + 17;
    dev.write_at(at, &payload).expect("write");

    let after = {
        let dev = FileDevice::open(&path).expect("reopen");
        read(&dev, 0, 3 * 4096)
    };

    let at = at as usize;
    assert_eq!(&after[at..at + 5], &payload, "the write itself");
    assert_eq!(&after[..at], &before[..at], "bytes before the write moved");
    assert_eq!(
        &after[at + 5..],
        &before[at + 5..],
        "bytes after the write moved"
    );
}

#[test]
fn writing_past_the_end_of_a_widened_device_is_refused() {
    // Read-modify-write past the end cannot fetch the surrounding block, so
    // there is nothing to patch. Writing the zero padding back would extend or
    // corrupt the device, so it must refuse rather than guess.
    let path = scratch("past-end");
    let len = FileDevice::open(&path).expect("open").len().expect("length");

    let dev = FileDevice::open_writable_with_alignment(&path, 4096, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
    assert!(
        dev.write_at(len + 8192, &[1u8; 16]).is_err(),
        "a widened write well past the end must fail"
    );
}
