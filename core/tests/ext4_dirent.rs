//! Linking a file into a directory — the step that makes it a file.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_dirent
//! ```
//!
//! # The oracle
//!
//! Every earlier pass had to settle for "only the *expected* complaints",
//! because an unlinked inode is genuinely not a clean filesystem. This one
//! does not: after linking, `e2fsck` must be **completely clean**, and the
//! Linux kernel must mount the image and return the file's bytes by name.
//!
//! That last check is the one that matters. `e2fsck` validates structure; it
//! does not prove the kernel's own directory walk finds the record we wrote.
//! A `rec_len` chain can be internally consistent and still place an entry
//! where a lookup will not see it — so the final assertion is a real `mount`
//! and a real `cat`, compared byte-for-byte with what was written.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-dirent-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> Ext4<FileDevice> {
    Ext4::mount(FileDevice::open_writable(path).expect("open writable")).expect("mount")
}

const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

/// Write a file and link it into the root, returning its inode number.
fn create(fs: &mut Ext4<FileDevice>, name: &str, content: &[u8]) -> u64 {
    let ino = fs.write_new_file(content).expect("write file");
    fs.link_file(2, name, ino, FileType::Regular)
        .expect("link into root");
    ino
}

#[test]
fn a_linked_file_is_visible_to_our_own_reader() {
    for name in FIXTURES {
        let path = scratch(name, "visible");
        let content = b"linked and readable\n";
        {
            let mut fs = open(&path);
            create(&mut fs, "written.txt", content);
            fs.flush().expect("flush");
        }

        let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
        let entries = fs.list_dir("/").expect("list root");
        assert!(
            entries.iter().any(|e| e.name == "written.txt"),
            "{name}: new entry missing from root listing: {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        let got = fs.read_file("/written.txt").expect("read by path");
        assert_eq!(got, content, "{name}: content mismatch via path lookup");
    }
}

#[test]
fn the_entries_that_were_already_there_survive() {
    // Splitting a record means rewriting the rec_len of an existing entry. Get
    // that wrong and the chain walks into the middle of a name, which drops
    // every entry after the insertion point — while the new entry itself still
    // looks fine.
    let path = scratch("many-groups-1k.img", "survivors");

    let before: Vec<String> = {
        let fs = Ext4::mount(FileDevice::open(&path).expect("open")).expect("mount");
        fs.list_dir("/")
            .expect("list")
            .into_iter()
            .map(|e| e.name)
            .collect()
    };
    assert!(before.len() >= 5, "fixture root should have several entries");

    {
        let mut fs = open(&path);
        create(&mut fs, "newcomer.txt", b"x");
        fs.flush().expect("flush");
    }

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    let after: Vec<String> = fs
        .list_dir("/")
        .expect("list")
        .into_iter()
        .map(|e| e.name)
        .collect();

    for old in &before {
        assert!(
            after.contains(old),
            "entry {old:?} disappeared after inserting a new one; \
             before={before:?} after={after:?}"
        );
    }
    assert!(after.contains(&"newcomer.txt".to_string()));
}

#[test]
fn many_files_can_be_added_in_sequence() {
    // Each insertion consumes slack left by the previous one, so the arithmetic
    // has to stay right as the block fills rather than only on a fresh block.
    let path = scratch("big-4k.img", "many");
    let mut expected = Vec::new();
    {
        let mut fs = open(&path);
        for i in 0..40 {
            let name = format!("file-{i:03}.txt");
            let content = format!("contents of file {i}\n").into_bytes();
            create(&mut fs, &name, &content);
            expected.push((name, content));
        }
        fs.flush().expect("flush");
    }

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    for (name, content) in &expected {
        let got = fs
            .read_file(&format!("/{name}"))
            .unwrap_or_else(|e| panic!("reading /{name}: {e}"));
        assert_eq!(&got, content, "content mismatch for {name}");
    }
}

#[test]
fn a_duplicate_name_is_refused() {
    // Two records with one name is not a corruption e2fsck always catches, but
    // which one a lookup finds depends on scan order — so the filesystem would
    // behave differently depending on who reads it.
    let path = scratch("csum-uuid-4k.img", "duplicate");
    let mut fs = open(&path);

    create(&mut fs, "twice.txt", b"first");
    let second = fs.write_new_file(b"second").expect("write second file");
    assert!(
        fs.link_file(2, "twice.txt", second, FileType::Regular)
            .is_err(),
        "linking a name that already exists was accepted"
    );
}

#[test]
fn a_name_with_a_slash_or_nul_is_refused() {
    let path = scratch("csum-uuid-4k.img", "badname");
    let mut fs = open(&path);
    let ino = fs.write_new_file(b"x").expect("write");

    assert!(fs.link_file(2, "a/b", ino, FileType::Regular).is_err());
    assert!(fs.link_file(2, "a\0b", ino, FileType::Regular).is_err());
    assert!(fs.link_file(2, "", ino, FileType::Regular).is_err());
}

#[test]
fn e2fsck_is_completely_clean_after_linking() {
    let Some(script) = verify_script("verify-ext4.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "e2fsck-clean");
        {
            let mut fs = open(&path);
            create(&mut fs, "proof.txt", b"the kernel should accept this\n");
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

        // No carve-outs this time. A linked file leaves nothing for e2fsck to
        // report, so any complaint at all is a real defect.
        assert!(
            out.status.success(),
            "{name}: e2fsck rejected the filesystem after linking a file:\n{text}"
        );
        assert!(
            text.contains("VERDICT: clean"),
            "{name}: verifier did not reach a clean verdict:\n{text}"
        );
    }
}

#[test]
fn the_linux_kernel_can_mount_it_and_read_the_file_back() {
    // The claim the whole write path exists to support. e2fsck validates
    // structure; only a real mount proves the kernel's directory walk finds
    // what we wrote, at the name we wrote it under, with the bytes intact.
    let Some(script) = verify_script("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "kernel-cat");
        let content = b"written by luks-android, read by Linux\n";
        {
            let mut fs = open(&path);
            create(&mut fs, "hello-linux.txt", content);
            fs.flush().expect("flush");
        }

        let out = Command::new("bash")
            .arg(&script)
            .arg(&path)
            .arg("hello-linux.txt")
            .output()
            .expect("run cat-in-image");

        assert!(
            out.status.success(),
            "{name}: the kernel could not mount and read the file:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout,
            content,
            "{name}: the kernel returned different bytes than were written"
        );
    }
}

fn verify_script(which: &str) -> Option<String> {
    let script = format!("{}/../tools/{which}", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    let up = Command::new("colima")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    up.then_some(script)
}
