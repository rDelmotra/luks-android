//! Testing ext4 same-directory file rename (`rename_file`).
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_rename
//! ```
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::error::LuksError;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-rename-{test}-{name}"));
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
    let up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !up {
        if std::env::var("REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false) {
            panic!("REQUIRE_ORACLE=1 is set but colima/oracle is not running!");
        }
        eprintln!("⚠️  ORACLE SKIPPED: colima is not running");
        return None;
    }
    Some(script)
}

const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

#[test]
fn same_directory_rename_and_collision_replacement_leave_e2fsck_clean() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "rename-clean");
        let content_a = b"content of file a\n";
        let content_b = b"content of file b\n";

        // 1. Create file_a.txt and file_b.txt in root
        {
            let mut fs = open(&path);
            fs.create_file(2, "file_a.txt", content_a, FileType::Regular)
                .expect("create file_a");
            fs.create_file(2, "file_b.txt", content_b, FileType::Regular)
                .expect("create file_b");
            fs.flush().expect("flush");
        }

        // 2. Rename file_a.txt to file_c.txt (no collision)
        {
            let mut fs = open(&path);
            fs.rename_file(2, "file_a.txt", "file_c.txt")
                .expect("rename file_a to file_c");
            fs.flush().expect("flush");
        }

        // Verify file_a is gone and file_c has content_a
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let entries = fs.list_dir("/").expect("list root");
            assert!(!entries.iter().any(|e| e.name == "file_a.txt"));
            assert!(entries.iter().any(|e| e.name == "file_c.txt"));
            let got_c = fs.read_file("/file_c.txt").expect("read file_c");
            assert_eq!(got_c, content_a);
        }

        // 3. Rename file_c.txt to file_b.txt (collision replacement)
        {
            let mut fs = open(&path);
            fs.rename_file(2, "file_c.txt", "file_b.txt")
                .expect("overwrite file_b with file_c");
            fs.flush().expect("flush");
        }

        // Verify file_c is gone and file_b now has content_a
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let entries = fs.list_dir("/").expect("list root");
            assert!(!entries.iter().any(|e| e.name == "file_c.txt"));
            assert!(entries.iter().any(|e| e.name == "file_b.txt"));
            let got_b = fs.read_file("/file_b.txt").expect("read file_b");
            assert_eq!(got_b, content_a, "{name}: overwritten file content mismatch");
        }

        // 4. Verify e2fsck is completely clean
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
            "{name}: e2fsck failed after rename:\n{text}"
        );
    }
}

#[test]
fn rename_refusal_gates() {
    let path = scratch("csum-uuid-4k.img", "rename-gates");

    let _sub_ino = {
        let mut fs = open(&path);
        let sub = fs.create_directory(2, "some_dir").expect("mkdir");
        fs.create_file(2, "some_file.txt", b"data\n", FileType::Regular)
            .expect("create file");
        fs.flush().expect("flush");
        sub
    };

    let mut fs = open(&path);

    // Refusal 1: Directory rename by name
    let err_dir = fs.rename_file(2, "some_dir", "new_dir_name");
    assert!(
        matches!(err_dir, Err(LuksError::UnsupportedFsFeature(_))),
        "expected UnsupportedFsFeature on directory rename, got: {err_dir:?}"
    );

    // Refusal 2: Cross-directory move by name containing '/'
    let err_cross = fs.rename_file(2, "some_file.txt", "some_dir/moved.txt");
    assert!(
        matches!(err_cross, Err(LuksError::UnsupportedFsFeature(_)) | Err(LuksError::CorruptFs(_))),
        "expected refusal on cross-directory rename, got: {err_cross:?}"
    );

    // Refusal 3: Non-existent source
    let err_notfound = fs.rename_file(2, "nonexistent.txt", "target.txt");
    assert!(
        matches!(err_notfound, Err(LuksError::NotFound(_))),
        "expected NotFound on missing source, got: {err_notfound:?}"
    );

    // Refusal 4: Overwriting a directory with a regular file
    let err_overwrite_dir = fs.rename_file(2, "some_file.txt", "some_dir");
    assert!(
        matches!(err_overwrite_dir, Err(LuksError::UnsupportedFsFeature(_))),
        "expected UnsupportedFsFeature when overwriting a directory, got: {err_overwrite_dir:?}"
    );
}
