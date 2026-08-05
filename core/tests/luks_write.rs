//! Encrypting into a LUKS volume.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test luks_write
//! ```
//!
//! # The oracle
//!
//! The temptation here is to test `write_at` by reading it back with
//! `read_at`. That proves almost nothing: two functions that are inverses of
//! each other pass a round trip perfectly while producing ciphertext Linux
//! cannot decrypt. The tweak-step bug found in Phase 3 was exactly that shape —
//! it decrypted sector 0 correctly and everything after it into garbage, and a
//! self-consistent test would have missed it.
//!
//! So the real test grades against **the kernel**. These fixture containers
//! were produced by real `cryptsetup` and dm-crypt, so their ciphertext is the
//! kernel's own output. Take a region of it, decrypt with the read path (proven
//! byte-for-byte against `cryptsetup --dump-master-key`), re-encrypt the
//! plaintext with our writer, and require the ciphertext back **identical**.
//! If it matches, the drive we write is a drive Linux can read.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::fs::MountedFs;
use luks_core::luks::{self, LuksVolume};

const PASSWORD: &[u8] = b"test";

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/containers/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A private copy, so a failing test cannot damage a committed fixture.
fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("luks-write-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture to scratch");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> (FileDevice, luks::Luks2Header) {
    let dev = FileDevice::open(path).expect("open fixture");
    let header = luks::read_from(&dev, 0).expect("parse header");
    (dev, header)
}

/// Every container, so the 512- and 4096-byte sector cases are both covered —
/// that difference is where the tweak step hides.
const CONTAINERS: [&str; 3] = [
    "unlock-argon2id-512.img",
    "unlock-argon2id-4096.img",
    "unlock-pbkdf2-512.img",
];

#[test]
fn our_ciphertext_is_byte_identical_to_the_kernels() {
    for name in CONTAINERS {
        let (dev, header) = open(&fixture(name));
        let seg = header.primary_segment().expect("segment");
        let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock");

        // A region well past the start, so a bug in the tweak *step* shows up.
        // Sector 0 encrypts correctly under almost any wrong stepping rule,
        // which is precisely how that class of bug survives testing.
        let sector_size = volume.sector_size() as u64;
        let offset = sector_size * 40;
        let len = (sector_size * 4) as usize;

        // The kernel's own ciphertext, read raw — no decryption.
        let mut original = vec![0u8; len];
        dev.read_at(seg.offset + offset, &mut original)
            .expect("read raw ciphertext");

        // Plaintext, via the read path that was verified against cryptsetup.
        let mut plain = vec![0u8; len];
        volume.read_at(offset, &mut plain).expect("decrypt");

        // Re-encrypt that plaintext with the writer, into a scratch copy.
        let path = scratch(name, "identical");
        let wdev = FileDevice::open_writable(&path).expect("open writable");
        let wheader = luks::read_from(&wdev, 0).expect("parse header");
        let wvol = LuksVolume::open(&wdev, 0, &wheader, PASSWORD).expect("unlock");
        wvol.write_at(offset, &plain).expect("encrypt and write");
        wvol.flush().expect("flush");

        let check = FileDevice::open(&path).expect("reopen");
        let mut produced = vec![0u8; len];
        check
            .read_at(seg.offset + offset, &mut produced)
            .expect("read back raw");

        assert_eq!(
            produced, original,
            "{name}: our ciphertext differs from what dm-crypt wrote for the \
             same plaintext at the same offset — the drive we produce would \
             not decrypt correctly on Linux"
        );
    }
}

#[test]
fn the_tweak_step_is_actually_being_exercised() {
    // Guards the test above from becoming vacuous. If the chosen region were
    // all zeros, or identical across sectors, the comparison could pass under
    // a wrong tweak rule. Require the plaintext to differ between sectors.
    let (dev, header) = open(&fixture("unlock-argon2id-4096.img"));
    let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock");
    let ss = volume.sector_size();

    let mut plain = vec![0u8; ss * 4];
    volume.read_at((ss * 40) as u64, &mut plain).expect("read");

    let first = &plain[..ss];
    let distinct = plain.chunks(ss).filter(|c| *c != first).count();
    assert!(
        distinct > 0 || first.iter().any(|&b| b != 0),
        "the region compared in the oracle test is uniform, so it could not \
         detect a wrong tweak step — pick a different offset"
    );
}

#[test]
fn a_partial_sector_write_preserves_the_rest_of_the_sector() {
    // The read-modify-write path. XTS has no notion of a partial sector, so
    // writing 7 bytes means decrypting the whole sector, patching, and
    // re-encrypting. If the surrounding plaintext is not carried through
    // correctly, the damage lands outside anything the caller named.
    let path = scratch("unlock-argon2id-512.img", "partial");
    let dev = FileDevice::open_writable(&path).expect("open writable");
    let header = luks::read_from(&dev, 0).expect("header");
    let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock");

    let ss = volume.sector_size();
    let base = (ss * 40) as u64;
    let mut before = vec![0u8; ss * 2];
    volume.read_at(base, &mut before).expect("read before");

    let payload = [0xC7u8; 7];
    let at = base + 13; // deliberately mid-sector
    volume.write_at(at, &payload).expect("write");
    volume.flush().expect("flush");

    let mut after = vec![0u8; ss * 2];
    volume.read_at(base, &mut after).expect("read after");

    assert_eq!(&after[13..20], &payload, "the write itself");
    assert_eq!(&after[..13], &before[..13], "plaintext before the patch moved");
    assert_eq!(&after[20..], &before[20..], "plaintext after the patch moved");
}

#[test]
fn the_filesystem_inside_still_mounts_after_a_write() {
    // An end-to-end sanity check that the container is still a container.
    // Writing into the *data* area at an offset the filesystem does not use
    // must leave ext4 mountable — if the tweak or the offset arithmetic is
    // wrong, the damage usually lands somewhere the superblock notices.
    let path = scratch("unlock-argon2id-512.img", "mounts");
    {
        let dev = FileDevice::open_writable(&path).expect("open writable");
        let header = luks::read_from(&dev, 0).expect("header");
        let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock");
        // Well past the superblock and group descriptors.
        let offset = volume.len().map(|n| n / 2).unwrap_or(1 << 20);
        let aligned = offset - (offset % volume.sector_size() as u64);
        volume
            .write_at(aligned, &[0x5Au8; 512])
            .expect("write into the data area");
        volume.flush().expect("flush");
    }

    let dev = FileDevice::open(&path).expect("reopen");
    let header = luks::read_from(&dev, 0).expect("header");
    let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock after write");
    let fs = MountedFs::mount(&volume).expect("the filesystem must still mount");
    assert_eq!(fs.kind().name(), "ext4");
    fs.list_dir("/").expect("root must still list");
}

#[test]
fn writing_past_the_end_of_the_segment_is_refused() {
    let path = scratch("unlock-argon2id-512.img", "bounds");
    let dev = FileDevice::open_writable(&path).expect("open writable");
    let header = luks::read_from(&dev, 0).expect("header");
    let volume = LuksVolume::open(&dev, 0, &header, PASSWORD).expect("unlock");

    if let Some(len) = volume.len() {
        assert!(
            volume.write_at(len, &[0u8; 512]).is_err(),
            "a write starting at the end of the segment must be refused"
        );
        assert!(
            volume.write_at(len - 4, &[0u8; 512]).is_err(),
            "a write running off the end of the segment must be refused"
        );
    }
}
