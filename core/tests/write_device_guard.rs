//! The target allowlist gating `FileDevice::open_writable_confirmed`.
//!
//! ```text
//! cargo test --release --features dangerous-write-support --test write_device_guard
//! ```
//!
//! # Why this exists
//!
//! Every write test so far has opened a scratch file it created itself —
//! there is no renumbering risk in that, since the path and the file are the
//! same thing for the test's whole lifetime. Real hardware is different: this
//! session, `/dev/disk4` was the developer's Fedora SSD in the morning and an
//! unrelated SanDisk stick in the afternoon, same path, different drive. This
//! test reproduces exactly that shape — confirm a path while it is one file,
//! swap what the path points to, and require the swap to be caught — because
//! that is the actual failure this module exists to prevent, not a
//! hypothetical one.
#![cfg(feature = "dangerous-write-support")]

use luks_core::device::FileDevice;
use luks_core::device_guard::TargetConfirmation;

fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("guard-write-{name}"))
}

#[test]
fn a_confirmed_target_opens_for_writing() {
    let path = scratch("confirmed-ok");
    std::fs::write(&path, vec![0u8; 65536]).expect("create");

    let confirmation = TargetConfirmation {
        label: "65536-byte scratch file".into(),
        expected_len: 65536,
    };
    let dev = FileDevice::open_writable_confirmed(&path, &confirmation)
        .expect("a matching confirmation should open");
    assert!(dev.is_writable());
}

#[test]
fn a_renumbered_device_is_refused() {
    // The exact scenario this module exists for: the same path pointing at a
    // different drive than the one that was confirmed.
    let path = scratch("renumbered");
    std::fs::write(&path, vec![0u8; 40_000]).expect("create original");
    let original_len = std::fs::metadata(&path).unwrap().len();

    let confirmation = TargetConfirmation {
        label: "the drive the operator looked at".into(),
        expected_len: original_len,
    };

    // The path gets unplugged and replugged as a different, differently-sized
    // drive — simulated by truncating the same path to a new size, which is
    // exactly what device renumbering does from this crate's point of view:
    // the path is unchanged, the bytes behind it are not what was confirmed.
    std::fs::write(&path, vec![0u8; (original_len + 1) as usize]).expect("swap contents");

    let err = FileDevice::open_writable_confirmed(&path, &confirmation)
        .expect_err("a size mismatch must be refused, not silently opened");
    let msg = format!("{err}");
    assert!(
        msg.contains("renumbered") || msg.contains("bytes"),
        "error should explain the size mismatch: {msg}"
    );
}

#[test]
fn a_target_confirmed_without_a_label_is_refused() {
    let path = scratch("nolabel-write");
    std::fs::write(&path, vec![0u8; 1024]).expect("create");

    let confirmation = TargetConfirmation {
        label: String::new(),
        expected_len: 1024,
    };
    assert!(FileDevice::open_writable_confirmed(&path, &confirmation).is_err());
}

#[test]
fn a_writable_confirmed_handle_can_actually_write() {
    // The guard is a gate, not a replacement for the write path — once past
    // it, ordinary write_at must still work.
    use luks_core::device::WriteAt;

    let path = scratch("actually-writes");
    std::fs::write(&path, vec![0u8; 4096]).expect("create");

    let confirmation = TargetConfirmation {
        label: "4096-byte scratch file".into(),
        expected_len: 4096,
    };
    let dev = FileDevice::open_writable_confirmed(&path, &confirmation).expect("open");
    dev.write_at(0, &[0xAB; 16]).expect("write");
    dev.flush().expect("flush");

    let on_disk = std::fs::read(&path).expect("read back");
    assert_eq!(&on_disk[..16], &[0xAB; 16]);
}

#[test]
fn known_system_disk_paths_are_refused_even_with_a_correct_confirmation() {
    // No confirmation, correct or otherwise, should be able to talk this
    // module into opening a well-known boot-disk path. The path does not need
    // to exist on the test machine — the refusal must happen before the
    // filesystem is even asked about it.
    let confirmation = TargetConfirmation {
        label: "I am very sure about this".into(),
        expected_len: 123_456_789,
    };
    let err = FileDevice::open_writable_confirmed("/dev/disk0", &confirmation)
        .expect_err("disk0 must never be opened for writing by this crate");
    assert!(format!("{err}").contains("system/boot disk"));
}
