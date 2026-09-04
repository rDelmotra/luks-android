//! Testing ext4 unknown-size streaming writes (`begin_file_streaming`).
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_streaming_unknown
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
    let dst = std::env::temp_dir().join(format!("ext4-stream-{test}-{name}"));
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
fn streaming_unknown_size_arbitrary_chunks_reads_back_byte_identical() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    for name in FIXTURES {
        let path = scratch(name, "stream-chunks");
        let content: Vec<u8> = (0..(256 * 1024 + 37)).map(|i| ((i * 37 + 11) % 251) as u8).collect();

        let ino = {
            let mut fs = open(&path);
            let mut writer = fs.begin_file_streaming().expect("begin streaming file");

            let mut offset = 0;
            // Variable chunk sizes spanning sub-block, multi-block, odd lengths
            for chunk_sz in [3, 17, 4091, 1, 8192, 65537, 23, usize::MAX] {
                if offset == content.len() {
                    break;
                }
                let end = offset.saturating_add(chunk_sz).min(content.len());
                fs.write_chunk(&mut writer, &content[offset..end])
                    .expect("write chunk");
                offset = end;
            }
            assert_eq!(offset, content.len());

            let ino = fs
                .finish_file(writer, 2, "streamed_unknown.bin", FileType::Regular)
                .expect("finish streaming file");
            fs.flush().expect("flush");
            ino
        };

        // 1. Check via our reader
        {
            let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
            let inode = fs.read_inode(ino).expect("read inode");
            assert_eq!(inode.size, content.len() as u64);

            let mut back = vec![0u8; content.len()];
            fs.read_inode_data(&inode, 0, &mut back).expect("read data");
            assert_eq!(back, content, "{name}: streamed content mismatch");
        }

        // 2. Verify with e2fsck
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
            "{name}: e2fsck rejected image with streamed file:\n{text}"
        );

        // 3. Verify with kernel mount (cat-in-image)
        let cat = format!("{}/../tools/cat-in-image.sh", env!("CARGO_MANIFEST_DIR"));
        if std::path::Path::new(&cat).exists() {
            let got = Command::new("bash")
                .arg(&cat)
                .arg(&path)
                .arg("/streamed_unknown.bin")
                .output()
                .expect("run cat-in-image");
            assert!(
                got.status.success(),
                "kernel failed to read /streamed_unknown.bin:\n{}",
                String::from_utf8_lossy(&got.stderr)
            );
            assert_eq!(got.stdout, content, "{name}: kernel readback mismatch");
        }
    }
}

#[test]
fn streaming_empty_file_is_clean() {
    let path = scratch("big-4k.img", "stream-empty");

    let ino = {
        let mut fs = open(&path);
        let writer = fs.begin_file_streaming().expect("begin streaming");
        let ino = fs
            .finish_file(writer, 2, "empty_stream.txt", FileType::Regular)
            .expect("finish empty");
        fs.flush().expect("flush");
        ino
    };

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    let inode = fs.read_inode(ino).expect("read inode");
    assert_eq!(inode.size, 0);

    let got = fs.read_file("/empty_stream.txt").expect("read empty");
    assert!(got.is_empty());
}

#[test]
fn streaming_abandon_rolls_back_cleanly() {
    let path = scratch("csum-uuid-4k.img", "stream-abandon");

    let initial_free_blocks = {
        let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
        fs.superblock().free_blocks_count
    };

    {
        let mut fs = open(&path);
        let mut writer = fs.begin_file_streaming().expect("begin streaming");
        let data = vec![0xAB; 64 * 1024];
        fs.write_chunk(&mut writer, &data).expect("write chunk");
        fs.abandon_file(writer);
        fs.flush().expect("flush");
    }

    let final_free_blocks = {
        let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
        fs.superblock().free_blocks_count
    };

    assert_eq!(
        initial_free_blocks, final_free_blocks,
        "abandoning a stream must reclaim all allocated blocks"
    );
}
