//! Writing a file's inode, data blocks and extent tree — with no directory
//! entry yet.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test ext4_file
//! ```
//!
//! # The oracle
//!
//! There is no way to make this file *fully* correct on its own: without a
//! directory entry, nothing reaches it, so it is by definition an orphan.
//! `e2fsck` is expected to say exactly that — "Unattached inode", "ref count is
//! 1, should be 0" — and the strong claim these tests make is not "no
//! complaints" but **only those two, and nothing that names a checksum or a
//! corrupt structure**. The same technique that caught a broken checksum
//! writer and a wrong bitmap bit order in the allocator's tests (see
//! `ext4_alloc.rs`) is deliberately reused here: a message containing
//! "checksum" or "corrupt" in the checker's output fails the test outright.
//!
//! Content correctness is checked by reading the new inode back through the
//! proven read path (`Ext4::read_inode` / `read_inode_data`), which is
//! independent of everything this module writes except the extent tree and
//! the inode fields themselves.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/../fixtures/ext4/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("ext4-file-{test}-{name}"));
    std::fs::copy(fixture(name), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

fn open(path: &str) -> Ext4<FileDevice> {
    // The test made this copy itself, so it genuinely knows the size — this
    // is a real confirmation, not a number read back from the thing being
    // checked against it.
    let len = std::fs::metadata(path).expect("stat scratch").len();
    Ext4::mount(FileDevice::open_writable(path, len).expect("open writable")).expect("mount")
}

const FIXTURES: [&str; 3] = ["big-4k.img", "csum-uuid-4k.img", "many-groups-1k.img"];

#[test]
fn a_small_file_reads_back_byte_identical() {
    for name in FIXTURES {
        let path = scratch(name, "small-roundtrip");
        let content = b"hello from the ext4 writer\n".to_vec();

        let ino = {
            let mut fs = open(&path);
            let ino = fs.write_new_file(&content).expect("write file");
            fs.flush().expect("flush");
            ino
        };

        let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
        let inode = fs.read_inode(ino).expect("read new inode");
        assert_eq!(inode.size, content.len() as u64);

        let mut back = vec![0u8; content.len()];
        fs.read_inode_data(&inode, 0, &mut back).expect("read data");
        assert_eq!(back, content, "{name}: content did not read back identical");
    }
}

#[test]
fn a_streamed_file_accepts_arbitrary_chunks_and_reads_back_identical() {
    let path = scratch("big-4k.img", "streamed-roundtrip");
    let content: Vec<u8> = (0..(128 * 1024 + 17)).map(|i| (i % 251) as u8).collect();

    let ino = {
        let mut fs = open(&path);
        let mut writer = fs.begin_file(content.len() as u64).expect("begin file");
        let mut offset = 0;
        for want in [7, 4090, 1, 65_537, 17, 8192, usize::MAX] {
            if offset == content.len() {
                break;
            }
            let end = offset.saturating_add(want).min(content.len());
            fs.write_chunk(&mut writer, &content[offset..end])
                .expect("write chunk");
            offset = end;
        }
        assert_eq!(offset, content.len(), "all source bytes were supplied");
        fs.finish_file(writer, 2, "streamed.bin", FileType::Regular)
            .expect("finish file")
    };

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    let inode = fs.read_inode(ino).expect("read inode");
    let mut back = vec![0u8; content.len()];
    fs.read_inode_data(&inode, 0, &mut back).expect("read data");
    assert_eq!(back, content);
}

#[test]
fn a_multi_block_file_spans_extents_correctly() {
    // Large enough to need several blocks even at 4 KiB, and filled with
    // position-dependent bytes so a block landing at the wrong offset is
    // detectable rather than coincidentally matching.
    let path = scratch("big-4k.img", "multi-block");
    let content: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();

    let mut fs = open(&path);
    let ino = fs.write_new_file(&content).expect("write file");
    fs.flush().expect("flush");
    drop(fs);

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    let inode = fs.read_inode(ino).expect("read inode");
    let mut back = vec![0u8; content.len()];
    fs.read_inode_data(&inode, 0, &mut back).expect("read data");
    assert_eq!(back, content);
}

#[test]
fn an_empty_file_has_no_blocks_and_still_reads_back() {
    let path = scratch("csum-uuid-4k.img", "empty");
    let mut fs = open(&path);
    let ino = fs.write_new_file(&[]).expect("write empty file");
    fs.flush().expect("flush");
    drop(fs);

    let fs = Ext4::mount(FileDevice::open(&path).expect("reopen")).expect("mount");
    let inode = fs.read_inode(ino).expect("read inode");
    assert_eq!(inode.size, 0);
}

#[test]
fn a_file_needing_a_fifth_extent_is_refused_not_corrupted() {
    // Force fragmentation: pre-allocate every other block near the start of
    // group 0 so a subsequent multi-block write cannot find more than a
    // handful of blocks contiguous at a time, then ask for far more than 4
    // fragments' worth. Writing must fail cleanly — no partial inode, no
    // leaked blocks — rather than truncating the extent tree.
    let path = scratch("many-groups-1k.img", "fragmented");
    let mut fs = open(&path);

    // Checkerboard the first 64 blocks of group 0's free space so a run can
    // never exceed 1 block.
    let mut held = Vec::new();
    for _ in 0..64 {
        let b = fs.alloc_block(0).expect("checkerboard alloc");
        held.push(b);
    }
    for (i, b) in held.iter().enumerate() {
        if i % 2 == 0 {
            fs.free_block(*b).expect("free every other block");
        }
    }

    let free_before = fs.superblock().free_blocks_count;
    let ino_before_next = fs.superblock().free_inodes_count;

    // 30 single-byte-apart blocks against a checkerboard cannot land in fewer
    // than 5 runs.
    let content = vec![0xAAu8; 30 * fs.block_size() as usize];
    let result = fs.write_new_file(&content);
    assert!(
        result.is_err(),
        "a 30-block write into checkerboarded free space should need more than 4 extents"
    );

    fs.flush().expect("flush");
    assert_eq!(
        fs.superblock().free_blocks_count,
        free_before,
        "a refused write must not leak blocks"
    );
    assert_eq!(
        fs.superblock().free_inodes_count,
        ino_before_next,
        "a refused write must not leak the inode it allocated to hold it"
    );
}

#[test]
fn e2fsck_reports_only_the_expected_orphan_complaints() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("csum-uuid-4k.img", "e2fsck-orphan");
    {
        let mut fs = open(&path);
        fs.write_new_file(b"an orphan, on purpose")
            .expect("write file");
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

    for bad in ["checksum", "Checksum", "corrupt", "Corrupt", "Padding"] {
        assert!(
            !text.contains(bad),
            "e2fsck reported {bad:?} for a new orphan file — that is \
             malformed metadata, not just an expected orphan:\n{text}"
        );
    }
    assert!(
        text.contains("Unattached inode") || text.contains("ref count is"),
        "e2fsck did not report the orphan at all, which suggests it never \
         inspected the new inode:\n{text}"
    );
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
    up.then_some(script)
}

/// The check the batched allocator was written for: a file of a size where
/// per-block bookkeeping was the whole cost, graded by the kernel rather than
/// by us.
///
/// Two oracles, because they answer different questions. `e2fsck` says the
/// structures are well-formed — and unlike the orphan test above, a *named*
/// file must leave it completely clean, with no complaint of any kind. Then
/// the kernel mounts the image and hands the bytes back, which is the only
/// statement that actually matters: "e2fsck is happy" and "Linux can open your
/// file by name and read what you wrote" are not the same claim.
///
/// A megabyte is 256 blocks. Under the per-block allocator that was 256
/// bitmap-descriptor-superblock commits; it is now one.
#[test]
fn a_multi_megabyte_named_file_is_clean_and_reads_back_byte_for_byte() {
    let Some(script) = verify_script() else {
        eprintln!("skipping: colima is not running");
        return;
    };

    const SIZE: usize = 4 * 1024 * 1024;
    // A pattern, not zeros: a run of zeros would read back correctly even from
    // blocks that were never written.
    let content: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

    let path = scratch("big-4k.img", "e2fsck-bigfile");
    {
        let mut fs = open(&path);
        fs.create_file(2, "batched.bin", &content, luks_core::fs::FileType::Regular)
            .expect("create a multi-megabyte file");
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
        out.status.success(),
        "e2fsck rejected an image holding one 4 MB named file:\n{text}"
    );

    let cat = format!("{}/../tools/cat-in-image.sh", env!("CARGO_MANIFEST_DIR"));
    let got = Command::new("bash")
        .arg(&cat)
        .arg(&path)
        .arg("/batched.bin")
        .output()
        .expect("run cat-in-image");
    assert!(
        got.status.success(),
        "the kernel could not read /batched.bin back:\n{}",
        String::from_utf8_lossy(&got.stderr)
    );
    assert_eq!(
        got.stdout.len(),
        content.len(),
        "the kernel read back {} bytes, not {}",
        got.stdout.len(),
        content.len()
    );
    assert!(
        got.stdout == content,
        "the kernel read /batched.bin back with different contents — first \
         differing byte at {:?}",
        got.stdout.iter().zip(&content).position(|(a, b)| a != b)
    );
}

#[test]
fn an_abandoned_writer_rolls_back_its_allocations() {
    let path = scratch("csum-uuid-4k.img", "abandon");
    let content = vec![0xAAu8; 128 * 1024]; // 128 KiB
    let mut fs = open(&path);

    let free_blocks_before = fs.superblock().free_blocks_count;
    let free_inodes_before = fs.superblock().free_inodes_count;

    // Start a file and write a chunk
    let mut writer = fs.begin_file(content.len() as u64).expect("begin file");
    fs.write_chunk(&mut writer, &content).expect("write chunk");

    // Blocks and inodes should be consumed
    assert!(fs.superblock().free_blocks_count < free_blocks_before);
    assert!(fs.superblock().free_inodes_count < free_inodes_before);

    // Abandon it instead of finish
    fs.abandon_file(writer);
    fs.flush().expect("flush");

    // They should be back to original
    assert_eq!(
        fs.superblock().free_blocks_count,
        free_blocks_before,
        "an abandoned writer must not leak blocks"
    );
    assert_eq!(
        fs.superblock().free_inodes_count,
        free_inodes_before,
        "an abandoned writer must not leak its inode"
    );
}
