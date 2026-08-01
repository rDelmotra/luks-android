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
