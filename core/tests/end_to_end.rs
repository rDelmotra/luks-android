//! The whole stack: encrypted bytes in, files out.
//!
//! ```text
//!   container image  ->  LUKS2 header parse
//!                    ->  Argon2id / PBKDF2 key derivation
//!                    ->  keyslot unwrap + AF-merge + digest verify
//!                    ->  AES-XTS sector decryption   (LuksVolume: ReadAt)
//!                    ->  ext4 superblock, inodes, extents, dirents
//!                    ->  file contents
//! ```
//!
//! This is the shape of what the Android app will do once the USB/SCSI layer
//! replaces the in-memory image. Nothing here is aware of encryption below
//! `LuksVolume`, which is the point of the `ReadAt` seam.

use luks_core::fs::{Ext4, FileType};
use luks_core::luks::{self, LuksVolume};

const PASSWORD: &[u8] = b"test";

const CONTAINERS: [&str; 3] = [
    "unlock-argon2id-512.img",
    "unlock-argon2id-4096.img",
    "unlock-pbkdf2-512.img",
];

fn container(name: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/containers/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing container {path}: {e}"))
}

#[test]
fn browses_an_encrypted_ext4_volume() {
    for name in CONTAINERS {
        let data = container(name);

        let header = luks::parse(&data).unwrap_or_else(|e| panic!("{name}: header: {e}"));
        let volume = LuksVolume::open(&data, 0, None, &header, PASSWORD)
            .unwrap_or_else(|e| panic!("{name}: unlock: {e}"));
        let fs = Ext4::mount(&volume).unwrap_or_else(|e| panic!("{name}: mount: {e}"));

        assert_eq!(fs.volume_name(), "LUKSDATA", "{name}");
        assert_eq!(
            fs.uuid(),
            [
                0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66
            ],
            "{name}"
        );

        let names: Vec<String> = fs
            .list_dir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"marker.txt".to_string()), "{name}: {names:?}");
        assert!(names.contains(&"subdir".to_string()), "{name}: {names:?}");

        assert_eq!(
            fs.read_file("/marker.txt").unwrap(),
            b"decrypted successfully\n",
            "{name}"
        );
        assert_eq!(
            fs.read_file("/subdir/nested.txt").unwrap(),
            b"nested content\n",
            "{name}"
        );

        let info = fs.file_info("/marker.txt").unwrap();
        assert_eq!(info.size, 23, "{name}");
        assert_eq!(info.file_type, FileType::Regular, "{name}");
    }
}

/// A wrong password must fail at unlock, never produce a mountable filesystem.
#[test]
fn wrong_password_never_yields_a_filesystem() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    assert!(LuksVolume::open(&data, 0, None, &header, b"wrong").is_err());
}

/// Decrypting with the right key but the wrong tweak numbering would still
/// "work" structurally, so confirm the plaintext is genuinely correct rather
/// than merely well-formed.
#[test]
fn sector_size_4096_produces_identical_content_to_512() {
    let mut contents = Vec::new();
    for name in ["unlock-argon2id-512.img", "unlock-argon2id-4096.img"] {
        let data = container(name);
        let header = luks::parse(&data).unwrap();
        let volume = LuksVolume::open(&data, 0, None, &header, PASSWORD).unwrap();
        let fs = Ext4::mount(&volume).unwrap();
        contents.push(fs.read_file("/marker.txt").unwrap());
    }
    assert_eq!(contents[0], contents[1]);
    assert_eq!(contents[0], b"decrypted successfully\n");
}
