//! The write gate, proven to bite.
//!
//! `Seed::for_writing` is the single choke point every write operation passes
//! through, and `metadata_block_offset` is the bound every on-disk block
//! pointer must clear. Both exist to refuse things — so each refusal here is
//! exercised by *deliberately breaking* a scratch copy of a good fixture and
//! watching the specific refusal fire. A gate that has never been seen closed
//! is decoration (this repo has shipped exactly that once; see INCIDENTS.md).
//!
//! The superblock is patched raw. `Ext4::mount` does not verify the
//! superblock checksum, which is what makes this cheap; if it ever starts to,
//! these tests will fail loudly here rather than silently weaken.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;

const SB: usize = 1024; // superblock offset within the image

/// Copy the fixture, let the test damage it, mount it writable.
fn mount_patched(test: &str, patch: impl Fn(&mut Vec<u8>)) -> Ext4<FileDevice> {
    let src = format!(
        "{}/../fixtures/ext4/csum-uuid-4k.img",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut img = std::fs::read(&src).expect("read fixture");
    patch(&mut img);

    let dst = std::env::temp_dir().join(format!("luks-write-gate-{test}.img"));
    std::fs::write(&dst, &img).expect("write scratch");
    let len = img.len() as u64;
    Ext4::mount(FileDevice::open_writable(&dst, len).expect("open writable")).expect("mount")
}

fn expect_refusal(result: luks_core::error::Result<u64>, needle: &str) {
    match result {
        Ok(_) => panic!("the write gate let it through — refusal expected ({needle})"),
        Err(e) => assert!(
            e.to_string().contains(needle),
            "wrong refusal: wanted one mentioning {needle:?}, got: {e}"
        ),
    }
}

#[test]
fn bigalloc_is_refused_by_the_write_gate() {
    // ro_compat is at 0x64. The same bit value in *incompat* (0x60) is
    // flex_bg, which every fixture has — a check against the wrong field
    // refuses everything real and admits actual bigalloc. That exact mistake
    // was made while writing this gate and caught by the alloc suite, so the
    // distinction is load-bearing enough to pin here.
    let mut fs = mount_patched("bigalloc", |img| {
        // RO_COMPAT_BIGALLOC = 0x0200: that is bit 1 of the *second* byte of
        // the little-endian field. The first draft of this test set bit 1 of
        // the first byte — which is `large_file`, already set, a no-op — and
        // the gate "let it through". The test was wrong, not the gate; kept
        // spelled out because a vacuous pass here would hide a real hole.
        img[SB + 0x65] |= 0x02;
    });
    expect_refusal(fs.write_new_file(b"x"), "bigalloc");
}

#[test]
fn a_filesystem_with_recorded_errors_is_refused() {
    let mut fs = mount_patched("errors", |img| {
        img[SB + 0x3A] |= 0x02; // s_state: EXT4_ERROR_FS
    });
    expect_refusal(fs.write_new_file(b"x"), "errors");
}

#[test]
fn a_dirty_filesystem_is_refused() {
    let mut fs = mount_patched("dirty", |img| {
        img[SB + 0x3A] &= !0x01; // s_state: clear EXT4_VALID_FS — mounted or died mid-write
    });
    expect_refusal(fs.write_new_file(b"x"), "cleanly unmounted");
}

#[test]
fn inline_data_is_refused_by_the_write_gate() {
    let mut fs = mount_patched("inline", |img| {
        img[SB + 0x61] |= 0x80; // INCOMPAT_INLINE_DATA = 0x8000, byte 1 bit 7
    });
    expect_refusal(fs.write_new_file(b"x"), "inline_data");
}

#[test]
fn a_missing_filetype_feature_is_refused() {
    let mut fs = mount_patched("filetype", |img| {
        img[SB + 0x60] &= !0x02; // clear INCOMPAT_FILETYPE
    });
    expect_refusal(fs.write_new_file(b"x"), "filetype");
}

#[test]
fn a_block_pointer_outside_the_filesystem_is_refused() {
    // Shrink s_blocks_count so every real metadata block — the root
    // directory's inode table among them — lands past the end. This is the
    // cheap stand-in for the expensive scenario: a corrupt extent or
    // descriptor pointer aiming a write outside the filesystem (a single bit
    // flip in ee_start_hi moves a pointer 4 TiB). Same check, same refusal.
    let mut fs = mount_patched("bounds", |img| {
        img[SB + 0x4..SB + 0x8].copy_from_slice(&8u32.to_le_bytes()); // s_blocks_count_lo = 8
    });
    let err = fs
        .link_file(2, "x.txt", 12, FileType::Regular)
        .expect_err("a pointer past blocks_count must be refused");
    assert!(
        err.to_string().contains("outside the filesystem"),
        "wrong error: {err}"
    );
}
