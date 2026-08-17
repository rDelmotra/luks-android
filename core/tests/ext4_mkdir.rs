//! Testing ext4 directory creation (`create_directory`).
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_mkdir
//! ```
#![cfg(feature = "dangerous-write-support")]

mod common;

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-mkdir-{test}-{name}"));
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
fn mkdir_creates_valid_directories_and_passes_e2fsck() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "mkdir-e2fsck");

        let (_sub_ino, file_content) = {
            let mut fs = open(&path);

            let root_before = fs.read_inode(2).expect("read root");
            let root_links_before = root_before.links;

            // 1. Create a top-level directory "mydir" in root (ino 2)
            let sub_ino = fs.create_directory(2, "mydir").expect("mkdir mydir");
            assert!(sub_ino >= fs.superblock().first_ino);

            // Verify parent link count increased by 1
            let root_after = fs.read_inode(2).expect("read root after");
            assert_eq!(
                root_after.links,
                root_links_before + 1,
                "{name}: parent root link count not incremented"
            );

            // 2. Create a file inside "mydir"
            let content = b"hello inside created directory\n";
            fs.create_file(sub_ino as u64, "child.txt", content, FileType::Regular)
                .expect("create child.txt");

            // 3. Create a nested subdirectory inside "mydir"
            let nested_ino = fs
                .create_directory(sub_ino, "nested")
                .expect("mkdir nested");
            assert!(nested_ino >= fs.superblock().first_ino);

            fs.flush().expect("flush");
            (sub_ino, content.to_vec())
        };

        // Check via internal reader
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");

            // Root listing
            let root_entries = fs.list_dir("/").expect("list root");
            assert!(root_entries.iter().any(|e| e.name == "mydir" && e.file_type.is_dir()));

            // Subdir listing
            let sub_entries = fs.list_dir("/mydir").expect("list mydir");
            assert!(sub_entries.iter().any(|e| e.name == "child.txt" && e.file_type.is_file()));
            assert!(sub_entries.iter().any(|e| e.name == "nested" && e.file_type.is_dir()));

            // Read child file content
            let got = fs.read_file("/mydir/child.txt").expect("read child.txt");
            assert_eq!(got, file_content, "{name}: child file content mismatch");
        }

        // Verify with e2fsck
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
            "{name}: e2fsck rejected image after mkdir:\n{text}"
        );

        // Verify with kernel mount (cat-in-image)
        let cat = format!("{}/../tools/cat-in-image.sh", env!("CARGO_MANIFEST_DIR"));
        if std::path::Path::new(&cat).exists() {
            let got = Command::new("bash")
                .arg(&cat)
                .arg(&path)
                .arg("/mydir/child.txt")
                .output()
                .expect("run cat-in-image");
            assert!(
                got.status.success(),
                "kernel failed to read /mydir/child.txt:\n{}",
                String::from_utf8_lossy(&got.stderr)
            );
            assert_eq!(got.stdout, file_content);
        }
    }
}

#[test]
fn deliberate_break_omitted_parent_link_count_bump_detected_by_e2fsck() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "broken-mkdir-link");

    {
        let mut fs = open(&path);
        let _sub_ino = fs.create_directory(2, "bad_link_dir").expect("mkdir");
        // Deliberately decrement parent root link count to simulate missing bump
        fs.patch_inode_links_count(2, -1)
            .expect("patch parent link count back down");
        fs.flush().expect("flush");
    }

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
        !out.status.success() || text.contains("ref count") || text.contains("link count"),
        "e2fsck failed to report parent link count mismatch:\n{text}"
    );
}
