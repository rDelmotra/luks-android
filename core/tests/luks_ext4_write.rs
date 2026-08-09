//! Creating a file through the whole stack: ext4 on top of LUKS2.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test luks_ext4_write
//! ```
//!
//! Every layer below this has been graded on its own — the encryptor against
//! dm-crypt's own ciphertext, the allocator and the directory writer against
//! `e2fsck` and a real kernel mount. What none of that proves is that they
//! compose. Two specific things only appear when they are stacked:
//!
//! * **Read-modify-write at the cipher sector.** The ext4 writer emits a
//!   12-byte group descriptor and a 1024-byte superblock; the LUKS layer can
//!   only write whole cipher sectors. Every one of those small writes becomes
//!   read, decrypt, patch, re-encrypt, write. If that path is wrong, the damage
//!   lands on *neighbouring* bytes the filesystem never asked to change —
//!   which is why one fixture here has a 4096-byte cipher sector, where a
//!   single descriptor update touches a sector holding many other structures.
//!
//! * **Offset translation.** The filesystem addresses block 5; that is one
//!   offset inside the volume, another inside the partition, and a third on
//!   the disk. An error here writes structurally perfect ext4 metadata to the
//!   wrong place.
//!
//! The oracle is unchanged and external: real `cryptsetup` opens it, real
//! `e2fsck` checks it, and the real kernel mounts it and reads the file back
//! by name. Our own reader is never the judge.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use std::process::Command;

const PASSWORD: &[u8] = b"test";
const PASSWORD_STR: &str = "test";

fn fixture(rel: &str) -> String {
    format!("{}/../fixtures/{rel}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(rel: &str, test: &str) -> String {
    let leaf = rel.rsplit('/').next().unwrap();
    let dst = std::env::temp_dir().join(format!("luks-ext4-{test}-{leaf}"));
    std::fs::copy(fixture(rel), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

/// Bare LUKS containers. The 4096 one matters most: its cipher sector is
/// 4096 bytes, so a 12-byte group descriptor update rewrites a sector shared
/// with unrelated metadata.
const CONTAINERS: [&str; 3] = [
    "containers/unlock-argon2id-512.img",
    "containers/unlock-argon2id-4096.img",
    "containers/unlock-pbkdf2-512.img",
];

/// Open a bare LUKS container and mount the ext4 inside it for writing.
fn mount_container(dev: &FileDevice) -> Ext4<LuksVolume<&FileDevice>> {
    let header = luks::read_from(dev, 0).expect("parse LUKS header");
    let volume = LuksVolume::open(dev, 0, None, &header, PASSWORD).expect("unlock");
    Ext4::mount(volume).expect("mount ext4 inside the container")
}

#[test]
fn a_file_written_through_luks_is_readable_by_the_kernel() {
    let Some(script) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for rel in CONTAINERS {
        let path = scratch(rel, "kernel-read");
        let content = b"encrypted on the way in, plaintext on the way out\n";

        {
            let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
            let mut fs = mount_container(&dev);
            let ino = fs.write_new_file(content).expect("write file");
            fs.link_file(2, "through-luks.txt", ino, FileType::Regular)
                .expect("link into root");
            fs.flush().expect("flush");
        }

        let out = Command::new("bash")
            .arg(&script)
            .arg(&path)
            .arg("through-luks.txt")
            .arg(PASSWORD_STR)
            .output()
            .expect("run cat-in-image");

        assert!(
            out.status.success(),
            "{rel}: cryptsetup+kernel could not read the file back:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, content,
            "{rel}: the kernel returned different bytes than were written"
        );
    }
}

#[test]
fn e2fsck_is_clean_inside_the_container() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for rel in CONTAINERS {
        let path = scratch(rel, "e2fsck");
        {
            let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
            let mut fs = mount_container(&dev);
            let ino = fs.write_new_file(b"checked by e2fsck\n").expect("write");
            fs.link_file(2, "checked.txt", ino, FileType::Regular)
                .expect("link");
            fs.flush().expect("flush");
        }

        let out = Command::new("bash")
            .arg(&script)
            .arg(&path)
            .arg(PASSWORD_STR)
            .output()
            .expect("run verify-image");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert!(
            out.status.success() && text.contains("VERDICT: clean"),
            "{rel}: e2fsck was not clean after writing through LUKS:\n{text}"
        );
    }
}

#[test]
fn a_file_larger_than_the_luks_write_chunk_is_clean_and_kernel_readable() {
    // The write layer deliberately caps a single encrypt/write operation at
    // 128 KiB. Use the 4096-byte-sector fixture and cross that boundary with
    // unaligned file data: this exercises both the chunk loop and the final
    // cipher-sector read-modify-write in the full ext4-on-LUKS stack.
    let Some(verify) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };
    let Some(cat) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let rel = "containers/unlock-argon2id-4096.img";
    let path = scratch(rel, "chunked-kernel-read");
    let content: Vec<u8> = (0..(2 * 128 * 1024 + 17))
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();

    {
        let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
        let mut fs = mount_container(&dev);
        let ino = fs.write_new_file(&content).expect("write chunked file");
        fs.link_file(2, "chunked.bin", ino, FileType::Regular)
            .expect("link into root");
        fs.flush().expect("flush");
    }

    let verify_out = Command::new("bash")
        .arg(&verify)
        .arg(&path)
        .arg(PASSWORD_STR)
        .output()
        .expect("run verify-image");
    let verify_text = format!(
        "{}{}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr)
    );
    assert!(
        verify_out.status.success() && verify_text.contains("VERDICT: clean"),
        "{rel}: e2fsck or the kernel rejected the chunked write:\n{verify_text}"
    );

    let read_out = Command::new("bash")
        .arg(&cat)
        .arg(&path)
        .arg("chunked.bin")
        .arg(PASSWORD_STR)
        .output()
        .expect("run cat-in-image");
    assert!(
        read_out.status.success(),
        "{rel}: the kernel could not read the chunked file:\n{}",
        String::from_utf8_lossy(&read_out.stderr)
    );
    assert_eq!(read_out.stdout, content, "{rel}: kernel readback differed");
}

#[test]
fn the_files_that_were_already_in_the_container_survive() {
    // A read-modify-write bug at the cipher sector damages bytes the caller
    // never named, so the interesting question is not whether the new file
    // arrived but whether the old ones are still intact.
    for rel in CONTAINERS {
        let path = scratch(rel, "survivors");

        let before: Vec<(String, Vec<u8>)> = {
            let dev = FileDevice::open(&path).expect("open");
            let header = luks::read_from(&dev, 0).expect("header");
            let volume = LuksVolume::open(&dev, 0, None, &header, PASSWORD).expect("unlock");
            let fs = Ext4::mount(volume).expect("mount");
            fs.list_dir("/")
                .expect("list")
                .into_iter()
                .filter(|e| !e.file_type.is_dir())
                .map(|e| {
                    let data = fs.read_file(&format!("/{}", e.name)).unwrap_or_default();
                    (e.name, data)
                })
                .collect()
        };

        {
            let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
            let mut fs = mount_container(&dev);
            let ino = fs.write_new_file(b"newcomer\n").expect("write");
            fs.link_file(2, "newcomer.txt", ino, FileType::Regular)
                .expect("link");
            fs.flush().expect("flush");
        }

        let dev = FileDevice::open(&path).expect("reopen");
        let header = luks::read_from(&dev, 0).expect("header");
        let volume = LuksVolume::open(&dev, 0, None, &header, PASSWORD).expect("unlock");
        let fs = Ext4::mount(volume).expect("mount");

        for (name, data) in &before {
            let got = fs
                .read_file(&format!("/{name}"))
                .unwrap_or_else(|e| panic!("{rel}: pre-existing file /{name} unreadable: {e}"));
            assert_eq!(&got, data, "{rel}: pre-existing file /{name} was corrupted");
        }
    }
}

#[test]
fn the_luks_header_is_never_touched() {
    // The filesystem lives at a positive offset inside the volume, so no
    // filesystem write should ever reach the header. If offset translation is
    // wrong by the segment offset, the first metadata write lands on the
    // keyslots — and the drive stops unlocking at all, taking the data with it.
    for rel in CONTAINERS {
        let path = scratch(rel, "header");

        // The protected region is everything before the data segment, taken
        // from the header itself rather than guessed. These containers are
        // only 3 MiB, so their payload starts at 512 KiB — assuming the usual
        // 16 MiB would compare bytes the filesystem is *supposed* to own and
        // fail for the wrong reason.
        let guard_len = {
            let dev = FileDevice::open(&path).expect("open");
            let header = luks::read_from(&dev, 0).expect("header");
            header.primary_segment().expect("segment").offset as usize
        };
        assert!(guard_len > 0, "{rel}: segment offset should be positive");

        let read_guard = |p: &str| -> Vec<u8> {
            let mut buf = vec![0u8; guard_len];
            let mut f = std::fs::File::open(p).expect("open image");
            std::io::Read::read_exact(&mut f, &mut buf).expect("read guard region");
            buf
        };

        let before = read_guard(&path);

        {
            let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
            let mut fs = mount_container(&dev);
            let ino = fs.write_new_file(&vec![0x5Au8; 8192]).expect("write");
            fs.link_file(2, "big.bin", ino, FileType::Regular)
                .expect("link");
            fs.flush().expect("flush");
        }

        let after = read_guard(&path);

        // Report the offset, not the megabyte — a failure here should point at
        // the byte, and dumping two buffers buries it.
        let differing = before
            .iter()
            .zip(&after)
            .position(|(a, b)| a != b);
        assert!(
            differing.is_none(),
            "{rel}: writing a file changed byte {} of the {guard_len}-byte \
             region before the data segment — that is LUKS header and keyslot \
             territory, and corrupting it makes the drive permanently \
             unopenable",
            differing.unwrap()
        );
    }
}

#[test]
fn a_file_written_through_gpt_and_luks_is_readable_by_the_kernel() {
    // The full shape of a real drive: partition table, then LUKS, then ext4.
    // Two offset translations stacked instead of one.
    let Some(script) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("disks/gpt-luks.img", "gpt");
    let content = b"partition table, container, filesystem\n";

    {
        let dev = FileDevice::open_writable(&path, std::fs::metadata(&path).expect("stat").len()).expect("open writable");
        let table = partition::scan(&dev, 512).expect("scan GPT");
        let part = table
            .luks_partitions()
            .next()
            .expect("a LUKS partition");
        let offset = part.offset_bytes();
        let part_len = Some(part.size_bytes());

        let header = luks::read_from(&dev, offset).expect("header");
        let volume = LuksVolume::open(&dev, offset, part_len, &header, PASSWORD).expect("unlock");
        let mut fs = Ext4::mount(volume).expect("mount ext4");

        let ino = fs.write_new_file(content).expect("write file");
        fs.link_file(2, "on-a-disk.txt", ino, FileType::Regular)
            .expect("link");
        fs.flush().expect("flush");
    }

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .arg("on-a-disk.txt")
        .arg(PASSWORD_STR)
        .output()
        .expect("run cat-in-image");

    assert!(
        out.status.success(),
        "the kernel could not read the file through GPT+LUKS:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, content);
}

fn tool(which: &str) -> Option<String> {
    let script = format!("{}/../tools/{which}", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        .then_some(script)
}
