//! Testing ext4 in-place inode field patching (patch_inode_links_count).
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_inode_patch
//! ```
#![cfg(feature = "dangerous-write-support")]

mod common;

use luks_core::device::{FileDevice, ReadAt, WriteAt};
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-patch-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> Ext4<FileDevice> {
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Ext4::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

fn verify_script() -> Option<String> {
    let script = format!("{}/../tools/verify-ext4.sh", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    if !common::oracle::gate() {
        return None;
    }

    Some(script)
}

const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

#[test]
fn patch_inode_links_count_roundtrip_leaves_e2fsck_clean() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "links-roundtrip");

        // 1. Create a regular file in root
        let ino = {
            let mut fs = open(&path);
            let ino = fs
                .create_file(2, "patch_target.txt", b"patch test data\n", FileType::Regular)
                .expect("create file");
            fs.flush().expect("flush");
            ino as u32
        };

        // Initial link count should be 1
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let inode = fs.read_inode(ino as u64).expect("read inode");
            assert_eq!(inode.links, 1, "{name}: initial link count mismatch");
        }

        // 2. Patch link count +1 -> 2
        {
            let mut fs = open(&path);
            fs.patch_inode_links_count(ino, 1).expect("patch +1");
        }

        // Verify readback has 2
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let inode = fs.read_inode(ino as u64).expect("read inode");
            assert_eq!(inode.links, 2, "{name}: link count after +1 mismatch");
        }

        // 3. Patch link count -1 back to 1
        {
            let mut fs = open(&path);
            fs.patch_inode_links_count(ino, -1).expect("patch -1");
        }

        // Verify readback is back to 1
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let inode = fs.read_inode(ino as u64).expect("read inode");
            assert_eq!(inode.links, 1, "{name}: link count after -1 mismatch");
        }

        // 4. Run e2fsck: must be completely clean
        let out = Command::new("bash")
            .arg(&script)
            .arg(&path)
            .output()
            .expect("run verifier");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "{name}: e2fsck failed on patched image:\n{text}"
        );
        assert!(
            !text.contains("checksum") && !text.contains("Checksum"),
            "{name}: e2fsck reported checksum error:\n{text}"
        );
    }
}

#[test]
fn deliberate_break_omitted_checksum_detected_by_e2fsck() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    // Test on csum-uuid-4k.img (which has metadata_csum enabled)
    let path = scratch("csum-uuid-4k.img", "broken-csum");

    let ino = {
        let mut fs = open(&path);
        let ino = fs
            .create_file(2, "broken.txt", b"corrupt test\n", FileType::Regular)
            .expect("create file");
        fs.flush().expect("flush");
        ino as u32
    };

    // Deliberately modify i_links_count on disk directly without recomputing checksum
    {
        let fs = open(&path);
        let offset = fs.test_inode_offset(ino as u64).expect("get offset");
        let len = std::fs::metadata(&path).expect("stat").len();
        let dev = FileDevice::open_writable(&path, len).expect("open raw device");
        let mut raw_links = [0u8; 2];
        dev.read_at(offset + 0x1A, &mut raw_links).expect("read links");
        let new_links = u16::from_le_bytes(raw_links) + 1;
        dev.write_at(offset + 0x1A, &new_links.to_le_bytes()).expect("write corrupted links");
        dev.flush().expect("flush");
    }

    // Run e2fsck: must detect checksum mismatch
    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .output()
        .expect("run verifier");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success() || text.contains("checksum") || text.contains("Checksum"),
        "e2fsck failed to detect corrupted inode checksum:\n{text}"
    );
}
