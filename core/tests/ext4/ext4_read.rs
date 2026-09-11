//! ext2/ext3/ext4 reader tests against images built by real `mke2fs`/`debugfs`.
//!
//! Three images, each exercising a different code path:
//!
//! | image        | block size | mapping           |
//! |--------------|-----------|--------------------|
//! | `small-1k`   | 1024      | extent tree        |
//! | `big-4k`     | 4096      | extent tree        |
//! | `ext2-1k`    | 1024      | indirect blocks    |
//!
//! `ext2-1k` matters most: with 1 KiB blocks a 2 MiB file needs double-indirect
//! blocks, so it walks all three levels of the legacy chain.
//!
//! Regenerate with `tools/gen-ext4-fixtures.sh`.

use luks_core::error::LuksError;
use luks_core::fs::{Ext4, FileType};

const IMAGES: [&str; 3] = ["small-1k.img", "big-4k.img", "ext2-1k.img"];

fn image(name: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}

/// The same pattern `tools/gen-ext4-fixtures.sh` writes into `big.bin`.
fn expected_big() -> Vec<u8> {
    (0..2 * 1024 * 1024).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

// --- superblock ------------------------------------------------------------

#[test]
fn mounts_every_image() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(fs.volume_name(), "EXT4TEST", "{name}");
        assert_eq!(
            fs.uuid(),
            [
                0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x77, 0x77,
                0x77, 0x77
            ],
            "{name}"
        );
    }
}

#[test]
fn reports_block_size() {
    assert_eq!(Ext4::mount(&image("small-1k.img")).unwrap().block_size(), 1024);
    assert_eq!(Ext4::mount(&image("big-4k.img")).unwrap().block_size(), 4096);
    assert_eq!(Ext4::mount(&image("ext2-1k.img")).unwrap().block_size(), 1024);
}

#[test]
fn rejects_non_ext4_data() {
    let junk = vec![0x5Au8; 65536];
    assert!(matches!(Ext4::mount(&junk), Err(LuksError::NotExt4(_))));
}

/// A dirty journal means the on-disk metadata is stale. Reading it would show a
/// filesystem state that never existed, so mount must refuse.
#[test]
fn refuses_a_filesystem_needing_journal_recovery() {
    let mut data = image("small-1k.img");
    // Set INCOMPAT_RECOVER (0x4) in s_feature_incompat at superblock +96.
    let off = 1024 + 96;
    let mut feat = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    feat |= 0x0004;
    data[off..off + 4].copy_from_slice(&feat.to_le_bytes());

    assert!(matches!(
        Ext4::mount(&data),
        Err(LuksError::FsNeedsRecovery)
    ));
}

#[test]
fn refuses_fscrypt_encrypted_filesystems() {
    let mut data = image("small-1k.img");
    let off = 1024 + 96;
    let mut feat = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    feat |= 0x1_0000; // INCOMPAT_ENCRYPT
    data[off..off + 4].copy_from_slice(&feat.to_le_bytes());

    assert!(matches!(
        Ext4::mount(&data),
        Err(LuksError::UnsupportedFsFeature(_))
    ));
}

// --- directories -----------------------------------------------------------

#[test]
fn lists_the_root_directory() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        let entries = fs.list_dir("/").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

        for expected in [
            "hello.txt",
            "big.bin",
            "café-naïve-日本語.txt",
            "docs",
            "link-to-hello",
        ] {
            assert!(names.contains(&expected), "{name}: missing {expected} in {names:?}");
        }
        // "." and ".." are deliberately filtered out.
        assert!(!names.contains(&"."), "{name}");
        assert!(!names.contains(&".."), "{name}");
    }
}

#[test]
fn reports_entry_types() {
    let data = image("small-1k.img");
    let fs = Ext4::mount(&data).unwrap();
    let entries = fs.list_dir("/").unwrap();
    let find = |n: &str| entries.iter().find(|e| e.name == n).unwrap().file_type;

    assert_eq!(find("hello.txt"), FileType::Regular);
    assert_eq!(find("docs"), FileType::Directory);
    assert_eq!(find("link-to-hello"), FileType::Symlink);
}

#[test]
fn lists_nested_directories() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();

        let docs: Vec<String> = fs
            .list_dir("/docs")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(docs.contains(&"readme.md".to_string()), "{name}: {docs:?}");
        assert!(docs.contains(&"nested".to_string()), "{name}: {docs:?}");

        let nested: Vec<String> = fs
            .list_dir("/docs/nested")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(nested, vec!["deep.txt".to_string()], "{name}");
    }
}

// --- file contents ---------------------------------------------------------

#[test]
fn reads_small_files() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        assert_eq!(fs.read_file("/hello.txt").unwrap(), b"hello ext4\n", "{name}");
        assert_eq!(
            fs.read_file("/docs/nested/deep.txt").unwrap(),
            b"three levels down\n",
            "{name}"
        );
    }
}

#[test]
fn reads_files_with_unicode_names() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        let content = fs.read_file("/café-naïve-日本語.txt").unwrap();
        assert_eq!(
            String::from_utf8(content).unwrap(),
            "café naïve 日本語\n",
            "{name}"
        );
    }
}

/// 2 MiB exercises multi-extent trees on ext4, and on 1 KiB-block ext2 it needs
/// double-indirect blocks — all three levels of the legacy chain.
#[test]
fn reads_a_large_file_byte_for_byte() {
    let expected = expected_big();
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        let got = fs.read_file("/big.bin").unwrap();
        assert_eq!(got.len(), expected.len(), "{name}: wrong length");
        assert!(got == expected, "{name}: contents differ");
    }
}

#[test]
fn partial_reads_match_the_whole_file() {
    let expected = expected_big();
    let data = image("big-4k.img");
    let fs = Ext4::mount(&data).unwrap();
    let inode = fs.resolve("/big.bin").unwrap();

    for (offset, len) in [
        (0u64, 10usize),
        (1, 4095),
        (4095, 2),        // straddles a block boundary
        (4096, 8192),
        (1_000_000, 1000),
        (2 * 1024 * 1024 - 10, 10), // last bytes
    ] {
        let mut got = vec![0u8; len];
        let n = fs.read_inode_data(&inode, offset, &mut got).unwrap();
        assert_eq!(n, len, "short read at {offset}");
        assert_eq!(
            got,
            &expected[offset as usize..offset as usize + len],
            "mismatch at offset={offset} len={len}"
        );
    }
}

#[test]
fn reading_past_the_end_returns_nothing() {
    let data = image("small-1k.img");
    let fs = Ext4::mount(&data).unwrap();
    let inode = fs.resolve("/hello.txt").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(fs.read_inode_data(&inode, 1000, &mut buf).unwrap(), 0);
}

// --- metadata --------------------------------------------------------------

#[test]
fn reports_file_metadata() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();

        let info = fs.file_info("/hello.txt").unwrap();
        assert_eq!(info.size, 11, "{name}");
        assert_eq!(info.file_type, FileType::Regular, "{name}");
        assert_eq!(info.mode & 0o777, 0o644, "{name}");

        let big = fs.file_info("/big.bin").unwrap();
        assert_eq!(big.size, 2 * 1024 * 1024, "{name}");

        let dir = fs.file_info("/docs").unwrap();
        assert_eq!(dir.file_type, FileType::Directory, "{name}");
        assert!(dir.mtime > 0, "{name}: no mtime");
    }
}

#[test]
fn a_directory_listing_reports_size_and_mtime_matching_file_info() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();

        let entries = fs.list_dir("/").unwrap();
        let entry = entries.iter().find(|e| e.name == "hello.txt").unwrap();
        let info = fs.file_info("/hello.txt").unwrap();

        assert_eq!(entry.size, info.size, "{name}");
        assert_eq!(entry.mtime, info.mtime, "{name}");
        assert_eq!(entry.size, 11, "{name}");
    }
}

// --- symlinks --------------------------------------------------------------

#[test]
fn reads_symlink_targets() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        assert_eq!(fs.read_link("/link-to-hello").unwrap(), "hello.txt", "{name}");
        assert_eq!(
            fs.read_link("/docs/link-to-deep").unwrap(),
            "nested/deep.txt",
            "{name}"
        );
    }
}

#[test]
fn follows_symlinks_when_resolving() {
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        // Absolute-ish target in the same directory.
        assert_eq!(
            fs.read_file("/link-to-hello").unwrap(),
            b"hello ext4\n",
            "{name}"
        );
        // Relative target resolved against the link's own directory.
        assert_eq!(
            fs.read_file("/docs/link-to-deep").unwrap(),
            b"three levels down\n",
            "{name}"
        );
    }
}

// --- path handling and errors ---------------------------------------------

#[test]
fn handles_awkward_paths() {
    let data = image("small-1k.img");
    let fs = Ext4::mount(&data).unwrap();

    for path in [
        "/hello.txt",
        "hello.txt",
        "//hello.txt",
        "/./hello.txt",
        "/docs/../hello.txt",
        "/docs/nested/../../hello.txt",
    ] {
        assert_eq!(
            fs.read_file(path).unwrap(),
            b"hello ext4\n",
            "failed for path {path:?}"
        );
    }
}

#[test]
fn error_cases() {
    let data = image("small-1k.img");
    let fs = Ext4::mount(&data).unwrap();

    assert!(matches!(
        fs.read_file("/nope.txt"),
        Err(LuksError::NotFound(_))
    ));
    assert!(matches!(
        fs.read_file("/docs"),
        Err(LuksError::IsADirectory(_))
    ));
    assert!(matches!(
        fs.list_dir("/hello.txt"),
        Err(LuksError::NotADirectory(_))
    ));
    assert!(matches!(
        fs.read_file("/hello.txt/impossible"),
        Err(LuksError::NotADirectory(_)) | Err(LuksError::NotFound(_))
    ));
}

/// Counts device reads, so a change in *how many* I/Os a read costs is visible.
struct Counting {
    inner: Vec<u8>,
    reads: std::cell::Cell<usize>,
}

impl luks_core::device::ReadAt for Counting {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), LuksError> {
        self.reads.set(self.reads.get() + 1);
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> Option<u64> {
        Some(self.inner.len() as u64)
    }
}

/// Regression guard for a bug found on real hardware, not by this suite.
///
/// `read_inode_data` used to map and read **one filesystem block at a time**,
/// re-walking the extent tree for each. Every test still passed — the bytes
/// were right — but reading a 1 GiB file over USB took minutes, because it
/// became ~262,000 SCSI command/data/status round trips instead of a few
/// thousand.
///
/// The bytes-correct tests above cannot catch this. Only counting I/Os can.
#[test]
fn a_sequential_read_does_not_cost_one_io_per_block() {
    for (name, block_size) in [("big-4k.img", 4096usize), ("small-1k.img", 1024)] {
        let dev = Counting {
            inner: image(name),
            reads: std::cell::Cell::new(0),
        };
        let fs = Ext4::mount(&dev).unwrap();

        let before = dev.reads.get();
        let got = fs.read_file("/big.bin").unwrap();
        let reads = dev.reads.get() - before;

        assert_eq!(got.len(), 2 * 1024 * 1024, "{name}");

        // The file is contiguous or nearly so, so a run-aware reader needs a
        // handful of I/Os. Block-at-a-time would need 2 MiB / block_size:
        // 512 reads at 4 KiB, 2048 at 1 KiB. Assert an order of magnitude
        // better than that, which passes comfortably for any sane extent
        // layout while failing loudly if per-block mapping returns.
        let per_block = (2 * 1024 * 1024) / block_size;
        println!("{name}: 2 MiB read cost {reads} device reads (was {per_block})");
        assert!(
            reads < per_block / 10,
            "{name}: {reads} device reads for a 2 MiB file \
             (block-at-a-time would be {per_block}) — run coalescing regressed",
        );
    }
}

/// The four fields at the tail of the 64-bit superblock, and why they need
/// sentinels rather than a fixture.
///
/// ```text
///   0x150 s_blocks_count_hi
///   0x154 s_r_blocks_count_hi   <- read by nobody, and that is the trap
///   0x158 s_free_blocks_count_hi
///   0x15C s_min_extra_isize (u16) | 0x15E s_want_extra_isize (u16)
/// ```
///
/// They are adjacent and three of them are `u32`, so dropping the reserved
/// count from a mental model shifts every field after it four bytes early.
/// That is exactly what happened: `s_free_blocks_count_hi` was read from
/// `s_r_blocks_count_hi`, and `s_min_extra_isize` from `s_free_blocks_count_hi`.
///
/// Nothing caught it, and nothing could have. Below 16 TiB every high word is
/// zero, so the wrong offset and the right one return the same `0` on every
/// fixture in this repo and on every drive this project has touched — and
/// `min_extra_isize` was rescued downstream by a `.max(32)`. A fixture-based
/// assertion agrees with a broken parser. Distinct values at each offset are
/// the only thing that can tell them apart.
#[test]
fn superblock_tail_fields_come_from_their_own_offsets() {
    const SB: usize = 1024; // the superblock starts 1024 bytes in
    let mut img = image("csum-uuid-4k.img");

    let put32 = |b: &mut [u8], off: usize, v: u32| {
        b[SB + off..SB + off + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put16 = |b: &mut [u8], off: usize, v: u16| {
        b[SB + off..SB + off + 2].copy_from_slice(&v.to_le_bytes());
    };

    // A value no correct parser may ever surface, in the field between the two
    // block counts.
    put32(&mut img, 0x154, 0xDEAD_BEEF);
    put32(&mut img, 0x158, 1); // s_free_blocks_count_hi
    put16(&mut img, 0x15C, 28); // s_min_extra_isize, deliberately not 32
    put16(&mut img, 0x15E, 44); // s_want_extra_isize — must not be mistaken for it

    let fs = Ext4::mount(&img).expect("mount the patched fixture");
    let sb = fs.superblock();

    assert_eq!(
        sb.min_extra_isize, 28,
        "s_min_extra_isize must come from 0x15C; 0 means it was read from \
         s_free_blocks_count_hi at 0x158, 44 means s_want_extra_isize at 0x15E",
    );

    let hi = sb.free_blocks_count >> 32;
    assert_ne!(
        hi, 0xDEAD_BEEF,
        "free_blocks_count picked up s_r_blocks_count_hi at 0x154",
    );
    assert_eq!(
        hi, 1,
        "s_free_blocks_count_hi must come from 0x158, not 0x154",
    );

    // The low half is still the fixture's own, so the two are genuinely being
    // combined rather than one of them being ignored.
    assert_eq!(
        sb.free_blocks_count & 0xFFFF_FFFF,
        2793,
        "s_free_blocks_count_lo (dumpe2fs: Free blocks: 2793) was disturbed",
    );
}

#[test]
fn superblock_parses_s_r_blocks_count() {
    const SB: usize = 1024;
    // Test on real fixtures
    for name in IMAGES {
        let data = image(name);
        let fs = Ext4::mount(&data).unwrap();
        let sb = fs.superblock();
        // Reserved block count in these fixtures is > 0 (standard 5% or minimum allocated)
        let expected_lo = u32::from_le_bytes(data[SB + 8..SB + 12].try_into().unwrap()) as u64;
        assert_eq!(sb.s_r_blocks_count & 0xFFFF_FFFF, expected_lo, "{name} s_r_blocks_count_lo");
    }

    // Test 64-bit high half parsing
    let mut img = image("csum-uuid-4k.img");
    let put32 = |b: &mut [u8], off: usize, v: u32| {
        b[SB + off..SB + off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put32(&mut img, 0x08, 0x1234_5678); // s_r_blocks_count_lo
    put32(&mut img, 0x154, 0x0000_0042); // s_r_blocks_count_hi

    let fs = Ext4::mount(&img).expect("mount patched fixture");
    let sb = fs.superblock();
    assert_eq!(
        sb.s_r_blocks_count,
        0x0000_0042_1234_5678,
        "s_r_blocks_count must combine low (0x08) and high (0x154) halves"
    );
}

