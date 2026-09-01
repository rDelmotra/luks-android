//! The write path as the phone will actually call it.
//!
//! ```text
//! cargo test -p luks_jni --features dangerous-write-support --test write_path
//! ```
//!
//! Everything below `VolumeHandle` has been graded already — the encryptor
//! against dm-crypt, the ext4 writer against `e2fsck` and a real kernel mount.
//! What has not been graded is the bridge itself: the handle that owns the
//! whole stack, the lock around the filesystem, the root-directory link, and
//! the flush. On the phone those sit behind JNI, a USB bridge and an Android
//! service, and a failure there could come from any of them.
//!
//! So they are exercised here instead, on the host, through the *same*
//! `bridge` functions `lib.rs` marshals into — with a `FileDevice` underneath
//! instead of a `ScsiBlockDevice`. `DeviceHandle::new` is generic over the
//! device, so this is not a parallel implementation of the phone's path; it is
//! that path, with one layer swapped. What remains untested after this is the
//! transport and nothing else.
//!
//! The oracle stays external: real `cryptsetup`, real `e2fsck`, a real kernel
//! mount. Our own reader never grades our own writer.
#![cfg(feature = "dangerous-write-support")]

// The oracle gate is a single implementation shared with `core/tests/`, not a
// second copy of the same logic — see `core/tests/common/oracle.rs` for why
// that duplication was the bug in the first place.
#[path = "../../core/tests/common/oracle.rs"]
mod oracle;

use luks_core::device::FileDevice;
use luks_jni::bridge::{
    cancel_operation, code, error_code, is_cancelled, register_cancel_token,
    unregister_cancel_token, DeviceHandle, VolumeHandle,
};
use std::process::Command;

const PASSWORD: &[u8] = b"test";
const PASSWORD_STR: &str = "test";

fn fixture(rel: &str) -> String {
    format!("{}/../fixtures/{rel}", env!("CARGO_MANIFEST_DIR"))
}

/// A private copy, so one test's writes cannot be another's starting state.
fn scratch(test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("luks-jni-write-{test}.img"));
    std::fs::copy(fixture("disks/gpt-luks.img"), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

/// The colima VM holds the only real kernel here. By default a down oracle
/// **fails the test** (see `oracle::gate`) rather than silently skipping —
/// set `ALLOW_NO_ORACLE=1` to explicitly run offline instead.
fn tool(which: &str) -> Option<String> {
    let script = format!("{}/../tools/{which}", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        return None;
    }
    if !oracle::gate() {
        return None;
    }
    Some(script)
}

/// Open a scratch image exactly as the JNI layer opens a phone's drive:
/// build a device handle over it, then unlock the LUKS partition it finds.
fn unlock(path: &str) -> VolumeHandle {
    let len = std::fs::metadata(path).expect("stat").len();
    let dev = FileDevice::open_writable(path, len).expect("open writable");
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();
    handle.unlock(offset, PASSWORD).expect("unlock")
}

#[test]
fn a_file_written_through_the_bridge_is_readable_by_the_kernel() {
    let Some(script) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("kernel-read");
    let content = b"written through the JNI bridge\n";

    let ino = {
        let vol = unlock(&path);
        vol.write_file("/", "from-the-bridge.txt", content)
            .expect("write through the bridge")
    };
    assert!(ino > 11, "inode {ino} is in the reserved range");

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .arg("from-the-bridge.txt")
        .arg(PASSWORD_STR)
        .output()
        .expect("run cat-in-image");

    assert!(
        out.status.success(),
        "the kernel could not read back what the bridge wrote:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, content,
        "the kernel returned different bytes than the bridge wrote"
    );
}

#[test]
fn the_filesystem_is_clean_after_the_bridge_writes() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("e2fsck");
    {
        let vol = unlock(&path);
        vol.write_file("/", "checked.txt", b"graded by e2fsck\n")
            .expect("write");
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
        "e2fsck was not clean after a write through the bridge:\n{text}"
    );
}

#[test]
fn the_files_that_were_already_there_survive() {
    // A bug in offset translation or in the read-modify-write at the cipher
    // sector damages bytes nobody named. The new file arriving proves nothing
    // about that; the old ones still being intact does.
    let path = scratch("survivors");

    let before = {
        let vol = unlock(&path);
        let json = vol.list_dir_json("/").expect("list");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["entries"].as_array().unwrap().len()
    };

    {
        let vol = unlock(&path);
        vol.write_file("/", "newcomer.txt", b"newcomer\n").expect("write");
    }

    let vol = unlock(&path);
    let json = vol.list_dir_json("/").expect("list");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let names: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();

    assert!(
        names.contains(&"newcomer.txt"),
        "the written file is missing: {names:?}"
    );
    assert_eq!(
        names.len(),
        before + 1,
        "the directory gained or lost something other than the new file: {names:?}"
    );
}

#[test]
fn a_duplicate_name_is_refused_as_a_conflict_not_as_corruption() {
    // Sending the same file twice is an ordinary thing to do, and the code the
    // UI sees decides whether it says "rename it" or "your drive is damaged".
    let path = scratch("duplicate");
    let vol = unlock(&path);

    vol.write_file("/", "once.txt", b"first\n").expect("first write");
    let err = vol
        .write_file("/", "once.txt", b"second\n")
        .expect_err("the second write must be refused");

    assert_eq!(
        error_code(&err),
        code::ALREADY_EXISTS,
        "a name collision reported code {} ({err})",
        error_code(&err)
    );
}

#[test]
fn a_refused_duplicate_leaves_no_orphan_behind() {
    // The regression this guards: `write_new_file` then `link_file` as two
    // calls writes the data *before* discovering the name is taken, and an
    // early version left that inode allocated and referenced by nothing.
    // e2fsck calls it an unattached inode. `create_file` undoes the write, so
    // the filesystem must be as clean after the failure as before it.
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("orphan");
    {
        let vol = unlock(&path);
        vol.write_file("/", "taken.txt", b"the first one\n")
            .expect("first write");
        vol.write_file("/", "taken.txt", b"the second one\n")
            .expect_err("the duplicate must fail");
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
        "a failed write left the filesystem unclean — an orphaned inode is the \
         expected shape of this failure:\n{text}"
    );
}

#[test]
fn an_unwritable_name_is_refused_before_anything_is_allocated() {
    // "Before anything is allocated" is the actual claim, and asserting only
    // `is_err()` would pass just as well if the whole file were written first
    // and then rejected. It matters because the write happens over USB: an
    // earlier version spent 27 seconds transferring a 40 MiB payload and then
    // failed for a slash in the name — reporting NO_SPACE, because the
    // transient allocation was what ran out.
    //
    // So the payload here is larger than the free space, which makes the two
    // orders give different answers: check-first refuses the name, and
    // write-first runs out of room and says so.
    let path = scratch("badname");
    let vol = unlock(&path);

    let free = {
        let v: serde_json::Value =
            serde_json::from_str(&vol.info_json()).expect("volume info");
        v["sizeBytes"].as_u64().expect("size")
    };
    let oversized = vec![0u8; free as usize];

    for bad in ["", "with/slash", "..", &"x".repeat(256)] {
        let err = vol
            .write_file("/", bad, &oversized)
            .expect_err("a file named {bad:?} should not be creatable");
        assert_ne!(
            error_code(&err),
            code::NO_SPACE,
            "a file named {bad:?} was refused for lack of space, which means \
             the name was only checked after the data was written: {err}"
        );
    }
}

#[test]
fn a_second_volume_on_one_device_cannot_also_write() {
    // Two `nativeUnlock` calls on one device each mount their own `Ext4`,
    // caching the superblock counters and group descriptors separately. Two of
    // those allocating against one disk do not see each other's bitmap
    // updates: before this was refused, one small file through each left
    // e2fsck reporting wrong free counts, and racing them produced two files
    // owning the same blocks — damage e2fsck can only repair by deleting.
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("two-writers");
    let len = std::fs::metadata(&path).expect("stat").len();
    let dev = FileDevice::open_writable(&path, len).expect("open writable");
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();

    // A second unlock stays allowed — reads through it are safe, and refusing
    // it would break a UI that re-prompts for a password without closing the
    // first volume.
    let first = handle.unlock(offset, PASSWORD).expect("first unlock");
    let second = handle.unlock(offset, PASSWORD).expect("second unlock");

    first.write_file("/", "from-first.txt", b"first\n").expect("first write");
    let err = second
        .write_file("/", "from-second.txt", b"second\n")
        .expect_err("the second volume must not be allowed to write");
    assert!(
        err.to_string().contains("already the writer"),
        "the refusal should say why: {err}"
    );
    // Its own code, not `UNSUPPORTED`. That is what the btrfs refusal below
    // returns, and the two arriving at the UI as the same number left it
    // unable to tell "close the other volume" from "this filesystem cannot be
    // written at all" — two remedies with nothing in common.
    assert_eq!(
        error_code(&err),
        code::WRITER_BUSY,
        "the writer refusal must be distinguishable from the btrfs one: {err}"
    );

    // The second volume can still read, which is the point of allowing it.
    second.list_dir_json("/").expect("the second volume must still read");

    drop(first);
    drop(second);
    drop(handle);

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
        "the filesystem is damaged after two volumes wrote to one device:\n{text}"
    );
}

#[test]
fn closing_the_writer_lets_another_volume_take_over() {
    // The claim must be released on drop, or a volume closed and reopened —
    // exactly what happens when a user backs out of a screen and returns —
    // would find itself permanently unable to write.
    let path = scratch("writer-handover");
    let len = std::fs::metadata(&path).expect("stat").len();
    let dev = FileDevice::open_writable(&path, len).expect("open writable");
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();

    let first = handle.unlock(offset, PASSWORD).expect("unlock");
    first.write_file("/", "one.txt", b"one\n").expect("first write");
    drop(first);

    let second = handle.unlock(offset, PASSWORD).expect("re-unlock");
    second
        .write_file("/", "two.txt", b"two\n")
        .expect("the claim should have been released when the first was dropped");
}

// `writing_to_btrfs_is_refused_by_name` retired here (Pass G): its entire
// premise — that the bridge refuses every btrfs write outright — is what
// this pass changed on purpose. What remains true and is still covered,
// by name, elsewhere in this file: a write into a subvolume is refused
// (`writing_into_a_btrfs_subvolume_is_refused_by_name_not_miswritten`), a
// duplicate name is refused as a conflict
// (`a_btrfs_duplicate_name_is_refused_as_a_conflict_not_as_corruption`),
// and the real 1 TB SSD stays refused by its own free-space-tree shape —
// see `feature-btrfs-write.md` Fix 1 — which this small fixture cannot
// exercise and is not this file's job to.

#[test]
fn two_threads_writing_through_one_volume_are_never_told_another_volume_has_it() {
    // The writer claim used to be a load followed by a compare_exchange, taken
    // *before* the filesystem lock. Two threads on the same handle could both
    // read `holds_writer == false`, both attempt the exchange, and the loser
    // was told "another unlocked volume on this device is already the writer" —
    // about itself. Not corrupting, since the `fs` mutex serialised the real
    // work either way, but a false statement, and the one a caller would act on
    // by hunting for a volume that does not exist.
    //
    // One-sided by nature: it can only ever catch the race by observing it, so
    // a pass is evidence rather than proof. What it does do reliably is fail if
    // the claim is ever moved back out from under the lock and the interleaving
    // happens to land, which is the regression worth guarding.
    let path = scratch("same-volume-threads");
    let vol = unlock(&path);

    let results = std::thread::scope(|s| {
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let vol = &vol;
                s.spawn(move || vol.write_file("/", &format!("thread-{i}.txt"), b"concurrent\n"))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("thread did not panic"))
            .collect::<Vec<_>>()
    });

    for (i, r) in results.iter().enumerate() {
        match r {
            Ok(_) => {}
            Err(e) => assert_ne!(
                error_code(e),
                code::WRITER_BUSY,
                "thread {i} was told another volume held the writer, but there \
                 is only one volume — it raced against itself: {e}"
            ),
        }
    }
    assert!(
        results.iter().all(|r| r.is_ok()),
        "both writes through one volume should succeed: {results:?}"
    );
}

#[test]
fn a_write_that_runs_out_of_room_leaves_the_filesystem_clean() {
    // The failure paths *inside* `write_new_file_runs` — a mid-loop allocation
    // failure, more than four extents, a failed data write, a failed inode
    // record — used to unwind through a local closure rather than through
    // `undo_new_file`, and that closure had the opposite ordering: blocks freed
    // before the inode that pointed at them, the inode's own free result
    // discarded, no flush. There is one rollback now, and this is the path that
    // used to reach the other one; nothing covered it before.
    //
    // What this can and cannot show: it proves the rollback frees everything it
    // took, because `e2fsck` counts. It cannot show the ordering matters — that
    // argument is about which of two states an *interruption* leaves behind,
    // and a host test that runs to completion never occupies either.
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("nospace-rollback");
    {
        let vol = unlock(&path);
        let free = {
            let v: serde_json::Value =
                serde_json::from_str(&vol.info_json()).expect("volume info");
            v["sizeBytes"].as_u64().expect("size")
        };
        // A perfectly good name, so the refusal comes from the allocator rather
        // than from validation — the closure's territory, not `create_file`'s.
        let err = vol
            .write_file("/", "too-big.txt", &vec![0u8; free as usize])
            .expect_err("a payload larger than the volume must be refused");
        assert_eq!(
            error_code(&err),
            code::NO_SPACE,
            "expected the allocator to run out, not something else: {err}"
        );
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
        "a rolled-back write left the filesystem dirty:\n{text}"
    );
}

#[test]
fn a_streaming_writer_closed_before_finish_leaves_no_orphan_behind() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("streaming-abandon");
    {
        let vol = unlock(&path);
        let mut writer = vol.begin_file(1024).expect("begin");
        vol.write_file_chunk(&mut writer, b"halfway there").expect("chunk");
        vol.abandon_file(writer); // explicitly abandon before finish
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
        "an abandoned stream left the filesystem unclean:\n{text}"
    );
}

#[test]
fn a_streaming_writer_that_collides_on_finish_rolls_back_cleanly() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("streaming-conflict");
    {
        let vol = unlock(&path);
        vol.write_file("/", "existing.txt", b"already here").expect("first");

        let mut writer = vol.begin_file(1024).expect("begin");
        vol.write_file_chunk(&mut writer, &vec![0u8; 1024]).expect("chunk");
        let err = vol.finish_file(writer, "/", "existing.txt").expect_err("finish duplicate");
        
        assert_eq!(
            error_code(&err),
            code::ALREADY_EXISTS,
            "collision must report ALREADY_EXISTS, not corruption: {err}"
        );
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
        "a failed finish left the filesystem unclean:\n{text}"
    );
}

// --- begin_file_streaming: the genuinely unknown-size path (Pass 2b JNI) ---
//
// The two tests above with "streaming" in the name drive the SIZED
// `begin_file(1024)` in chunks — they never call `begin_file_streaming`, so
// they say nothing about the unknown-size primitive. These do.

#[test]
fn a_streaming_write_of_unknown_size_is_readable_by_the_kernel() {
    let Some(script) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("streaming-unknown-size");
    let content = b"nobody told begin_file_streaming how big this was\n";

    let ino = {
        let vol = unlock(&path);
        let mut writer = vol.begin_file_streaming().expect("begin_file_streaming");
        // Write in pieces, as a transfer whose total length is not known
        // upfront would arrive.
        vol.write_file_chunk(&mut writer, &content[..10]).expect("chunk 1");
        vol.write_file_chunk(&mut writer, &content[10..]).expect("chunk 2");
        vol.finish_file(writer, "/", "unknown-size.txt").expect("finish")
    };
    assert!(ino > 0, "expected a real inode/objectid, got {ino}");

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .arg("unknown-size.txt")
        .arg(PASSWORD_STR)
        .output()
        .expect("run cat-in-image");

    assert!(
        out.status.success(),
        "the kernel could not read back the streamed write:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, content,
        "the kernel returned different bytes than the stream wrote"
    );
}

#[test]
fn a_second_writer_is_refused_while_a_streaming_writer_is_live() {
    // Same claim mechanism `a_second_volume_on_one_device_cannot_also_write`
    // exercises for the sized path — here the live writer is the unknown-size
    // one, so this is the actual regression this pass could introduce: a
    // begin_file_streaming that forgot to call claim_writer would let a
    // second volume in underneath it.
    let path = scratch("streaming-writer-busy");
    let len = std::fs::metadata(&path).expect("stat").len();
    let dev = FileDevice::open_writable(&path, len).expect("open writable");
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();

    let first = handle.unlock(offset, PASSWORD).expect("first unlock");
    let second = handle.unlock(offset, PASSWORD).expect("second unlock");

    let mut writer = first.begin_file_streaming().expect("begin_file_streaming");
    let err = second
        .begin_file_streaming()
        .err()
        .expect("a second streaming writer must be refused while the first is live");
    assert_eq!(
        error_code(&err),
        code::WRITER_BUSY,
        "the refusal should be WRITER_BUSY, not something else: {err}"
    );

    // The second volume can still read while the first holds the writer.
    second.list_dir_json("/").expect("the second volume must still read");

    first.write_file_chunk(&mut writer, b"still holding the claim").expect("chunk");
    first.abandon_file(writer);
}

#[test]
fn an_abandoned_streaming_writer_leaves_no_orphan_behind() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("streaming-unknown-abandon");
    {
        let vol = unlock(&path);
        let mut writer = vol.begin_file_streaming().expect("begin_file_streaming");
        vol.write_file_chunk(&mut writer, b"never finished").expect("chunk");
        vol.abandon_file(writer); // explicitly abandon before finish
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
        "an abandoned unknown-size stream left the filesystem unclean:\n{text}"
    );
}

#[test]
fn a_zero_byte_streaming_write_finishes_cleanly() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch("streaming-zero-byte");
    {
        let vol = unlock(&path);
        // Begin, then finish immediately — no chunk written at all, which is
        // the shape of a genuinely empty unknown-size transfer.
        let writer = vol.begin_file_streaming().expect("begin_file_streaming");
        let ino = vol
            .finish_file(writer, "/", "empty-stream.txt")
            .expect("finish a zero-byte stream");
        assert!(ino > 0, "expected a real inode/objectid, got {ino}");

        let content = vol.read_file("/empty-stream.txt", 1024).expect("read back");
        assert!(content.is_empty(), "a zero-byte stream produced {} bytes", content.len());
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
        "a zero-byte stream left the filesystem unclean:\n{text}"
    );
}

#[test]
fn a_file_deleted_through_the_bridge_is_gone_and_e2fsck_clean() {
    let path = scratch("bridge-delete");

    {
        let vol = unlock(&path);
        // Create a file through the bridge
        vol.write_file("/", "bridge_del.txt", b"temporary bridge file")
            .expect("write_file");
        // Verify it was created and delete it through the bridge
        vol.delete_file("/bridge_del.txt").expect("delete_file");
    }

    if let Some(script) = tool("verify-image.sh") {
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
            "delete_file through the bridge left the filesystem unclean:\n{text}"
        );
    }
}

// --- btrfs through the same bridge (Pass G) ---------------------------------

/// A private btrfs copy, mirroring `scratch` for the ext4 fixture above.
fn scratch_btrfs(test: &str) -> String {
    let dst = std::env::temp_dir().join(format!("luks-jni-write-btrfs-{test}.img"));
    std::fs::copy(fixture("disks/gpt-luks-btrfs.img"), &dst).expect("copy fixture");
    dst.to_string_lossy().into_owned()
}

#[test]
fn a_btrfs_file_written_through_the_bridge_is_readable_by_the_kernel() {
    let Some(script) = tool("cat-in-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch_btrfs("kernel-read");
    let content = b"written through the JNI bridge to btrfs\n";

    let ino = {
        let vol = unlock(&path);
        vol.write_file("/", "from-the-bridge.txt", content)
            .expect("write through the bridge")
    };
    // btrfs's own numbering starts well above the reserved range too — same
    // shape of assertion as the ext4 test above, different floor.
    assert!(ino >= 256, "objectid {ino} is in btrfs's reserved range");

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .arg("from-the-bridge.txt")
        .arg(PASSWORD_STR)
        .output()
        .expect("run cat-in-image");

    assert!(
        out.status.success(),
        "the kernel could not read back what the bridge wrote to btrfs:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, content,
        "the kernel returned different bytes than the bridge wrote"
    );
}

#[test]
fn the_btrfs_filesystem_is_clean_after_the_bridge_writes() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch_btrfs("check");
    {
        let vol = unlock(&path);
        vol.write_file("/", "checked.txt", b"graded by btrfs check + scrub\n")
            .expect("write");
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
        "btrfs check was not clean after a write through the bridge:\n{text}"
    );
}

#[test]
fn the_btrfs_files_that_were_already_there_survive() {
    let path = scratch_btrfs("survivors");

    let before = {
        let vol = unlock(&path);
        let json = vol.list_dir_json("/").expect("list");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["entries"].as_array().unwrap().len()
    };

    {
        let vol = unlock(&path);
        vol.write_file("/", "newcomer.txt", b"newcomer\n").expect("write");
    }

    let vol = unlock(&path);
    let json = vol.list_dir_json("/").expect("list");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let names: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();

    assert!(
        names.contains(&"newcomer.txt"),
        "the written file is missing: {names:?}"
    );
    assert_eq!(
        names.len(),
        before + 1,
        "the directory gained or lost something other than the new file: {names:?}"
    );
    // proof.txt and sub/ predate this test and must still be exactly what
    // they were — see bridge.rs's own read-side tests for their contents.
    assert!(names.contains(&"proof.txt"), "{names:?}");
    assert!(names.contains(&"sub"), "{names:?}");
}

#[test]
fn a_btrfs_duplicate_name_is_refused_as_a_conflict_not_as_corruption() {
    let path = scratch_btrfs("duplicate");
    let vol = unlock(&path);

    vol.write_file("/", "once.txt", b"first\n").expect("first write");
    let err = vol
        .write_file("/", "once.txt", b"second\n")
        .expect_err("the second write must be refused");

    assert_eq!(
        error_code(&err),
        code::ALREADY_EXISTS,
        "a name collision reported code {} ({err})",
        error_code(&err)
    );
}

#[test]
fn writing_into_a_btrfs_subvolume_is_refused_by_name_not_miswritten() {
    // The engine refuses anything outside the default subvolume's FS_TREE
    // (feature-btrfs-write.md) rather than writing into the wrong tree. `sub`
    // is a real subvolume in this fixture (see bridge.rs's own
    // `reads_across_a_subvolume_boundary_through_the_bridge`).
    let path = scratch_btrfs("subvolume-refused");
    let vol = unlock(&path);

    let err = vol
        .write_file("/sub", "should-not-land-here.txt", b"x")
        .expect_err("a subvolume write must be refused, not silently misplaced");
    assert_eq!(
        error_code(&err),
        code::UNSUPPORTED,
        "wrong error for a subvolume write: {err}"
    );
}

#[test]
fn a_btrfs_write_correctly_claims_the_device_writer() {
    // Same mechanism as the ext4 test above, proven fs-agnostic: the claim
    // lives on `SharedDevice`, not inside either filesystem implementation.
    let path = scratch_btrfs("writer-claim");
    let len = std::fs::metadata(&path).expect("stat").len();
    let dev = FileDevice::open_writable(&path, len).expect("open writable");
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();

    let first = handle.unlock(offset, PASSWORD).expect("first unlock");
    let second = handle.unlock(offset, PASSWORD).expect("second unlock");

    first.write_file("/", "from-first.txt", b"first\n").expect("first write");
    let err = second
        .write_file("/", "from-second.txt", b"second\n")
        .expect_err("the second volume must not be allowed to write");
    assert_eq!(error_code(&err), code::WRITER_BUSY);

    second.list_dir_json("/").expect("the second volume must still read");
}

#[test]
fn a_btrfs_refused_duplicate_leaves_no_orphan_behind() {
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch_btrfs("orphan");
    {
        let vol = unlock(&path);
        vol.write_file("/", "taken.txt", b"the first one\n")
            .expect("first write");
        let err = vol
            .write_file("/", "taken.txt", b"the second one\n")
            .expect_err("the duplicate must fail");
        assert_eq!(error_code(&err), code::ALREADY_EXISTS);
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
        "a failed btrfs write left the filesystem unclean:\n{text}"
    );
}

#[test]
fn writing_into_nonexistent_directory_on_btrfs_is_refused() {
    let path = scratch_btrfs("nonexistent-dir");
    let vol = unlock(&path);

    let err = vol
        .write_file("/docs", "guide.txt", b"content")
        .expect_err("writing into nonexistent directory must fail");
    assert_eq!(error_code(&err), code::NOT_FOUND);
}

#[test]
fn a_btrfs_file_deleted_through_the_bridge_is_gone_and_clean() {
    let path = scratch_btrfs("bridge-delete");

    {
        let vol = unlock(&path);
        // Create a file through the bridge
        vol.write_file("/", "btrfs_del.txt", b"temporary btrfs bridge file")
            .expect("write_file");
        // Verify it was created and delete it through the bridge
        vol.delete_file("/btrfs_del.txt").expect("delete_file");
    }

    if let Some(script) = tool("verify-image.sh") {
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
            "delete_file on btrfs through the bridge left the filesystem unclean:\n{text}"
        );
    }
}

#[test]
fn ext4_volume_handle_statfs_mkdir_rename_and_read_cap() {
    let path = scratch("bridge-ops");
    let vol = unlock(&path);

    // 1. statfs_json
    let stat_json = vol.statfs_json().expect("statfs_json");
    let stat: serde_json::Value = serde_json::from_str(&stat_json).expect("valid json");
    assert!(stat["totalBytes"].as_u64().unwrap() > 0);
    assert!(stat["freeBytes"].as_u64().unwrap() > 0);
    assert!(stat["availableBytes"].as_u64().unwrap() > 0);
    assert!(stat["blockSize"].as_u64().unwrap() > 0);

    // 2. create_directory
    let dir_ino = vol.create_directory("/", "subfolder").expect("create_directory");
    assert!(dir_ino > 0);

    // 3. write inside directory
    vol.write_file("/subfolder", "data.txt", b"ext4 bridge subfolder test content\n")
        .expect("write_file in subdir");

    // 4. rename inside directory
    vol.rename("/subfolder", "data.txt", "/subfolder", "renamed_data.txt")
        .expect("rename in subdir");

    // 5. read_file and max_bytes cap enforcement
    let content = vol.read_file("/subfolder/renamed_data.txt", 1000).expect("read_file");
    assert_eq!(content, b"ext4 bridge subfolder test content\n");

    let exact_len = content.len() as u64;
    assert!(vol.read_file("/subfolder/renamed_data.txt", exact_len).is_ok());
    let err_capped = vol.read_file("/subfolder/renamed_data.txt", exact_len - 1).unwrap_err();
    assert_eq!(error_code(&err_capped), code::UNSUPPORTED);
}

#[test]
fn btrfs_volume_handle_statfs_mkdir_rename_and_read_cap() {
    let path = scratch_btrfs("bridge-ops");
    let vol = unlock(&path);

    // 1. statfs_json
    let stat_json = vol.statfs_json().expect("statfs_json");
    let stat: serde_json::Value = serde_json::from_str(&stat_json).expect("valid json");
    assert!(stat["totalBytes"].as_u64().unwrap() > 0);
    assert!(stat["freeBytes"].as_u64().unwrap() > 0);
    assert!(stat["availableBytes"].as_u64().unwrap() > 0);
    assert_eq!(stat["blockSize"].as_u64().unwrap(), 4096);

    // 2. create_directory
    let dir_ino = vol.create_directory("/", "btrfs_sub").expect("create_directory");
    assert!(dir_ino >= 256);

    // 3. write inside directory
    vol.write_file("/btrfs_sub", "b_data.txt", b"btrfs bridge subfolder test content\n")
        .expect("write_file in subdir");

    // 4. rename inside directory
    vol.rename("/btrfs_sub", "b_data.txt", "/btrfs_sub", "renamed_b_data.txt")
        .expect("rename in subdir");

    // 5. read_file and max_bytes cap enforcement
    let content = vol.read_file("/btrfs_sub/renamed_b_data.txt", 1000).expect("read_file");
    assert_eq!(content, b"btrfs bridge subfolder test content\n");

    let exact_len = content.len() as u64;
    assert!(vol.read_file("/btrfs_sub/renamed_b_data.txt", exact_len).is_ok());
    let err_capped = vol.read_file("/btrfs_sub/renamed_b_data.txt", exact_len - 1).unwrap_err();
    assert_eq!(error_code(&err_capped), code::UNSUPPORTED);
}

#[test]
fn write_mutex_poison_fatal_to_writing_but_reads_survive_ext4() {
    let path = scratch("mutex-poison-ext4");
    let vol = unlock(&path);

    // Initial write succeeds
    vol.write_file("/", "before_poison.txt", b"safe data\n").expect("write_file");

    // Simulate a panicked write holding the write lock
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = vol.fs_for_writing().unwrap();
        panic!("simulated panic inside write transaction");
    }));
    assert!(panic_result.is_err(), "panic should have occurred");

    // Subsequent write operations on this handle MUST be refused with MUTEX_POISONED (18)
    let err_write = vol.write_file("/", "after_poison.txt", b"unsafe data\n").unwrap_err();
    assert_eq!(error_code(&err_write), code::MUTEX_POISONED);

    let err_mkdir = vol.create_directory("/", "poison_dir").unwrap_err();
    assert_eq!(error_code(&err_mkdir), code::MUTEX_POISONED);

    let err_rename = vol.rename("/", "before_poison.txt", "/", "renamed.txt").unwrap_err();
    assert_eq!(error_code(&err_rename), code::MUTEX_POISONED);

    let err_delete = vol.delete_file("/before_poison.txt").unwrap_err();
    assert_eq!(error_code(&err_delete), code::MUTEX_POISONED);

    let err_begin = vol.begin_file(1024).err().expect("begin_file should fail on poisoned handle");
    assert_eq!(error_code(&err_begin), code::MUTEX_POISONED);

    // BUT read operations survive because read lock recovers from poison!
    let info = vol.info_json();
    assert!(info.contains("DISKDATA"));

    let list_json = vol.list_dir_json("/").expect("list_dir_json must survive");
    let list_val: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    let entries = list_val["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["name"] == "before_poison.txt"));

    let data = vol.read_file("/before_poison.txt", 1024).expect("read_file must survive");
    assert_eq!(data, b"safe data\n");
}

#[test]
fn write_mutex_poison_fatal_to_writing_but_reads_survive_btrfs() {
    let path = scratch_btrfs("mutex-poison-btrfs");
    let vol = unlock(&path);

    vol.write_file("/", "btrfs_before.txt", b"btrfs safe data\n").expect("write_file");

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = vol.fs_for_writing().unwrap();
        panic!("simulated panic inside btrfs write transaction");
    }));
    assert!(panic_result.is_err());

    // Subsequent write operations MUST be refused with MUTEX_POISONED
    let err_write = vol.write_file("/", "btrfs_after.txt", b"bad\n").unwrap_err();
    assert_eq!(error_code(&err_write), code::MUTEX_POISONED);

    let err_mkdir = vol.create_directory("/", "b_dir").unwrap_err();
    assert_eq!(error_code(&err_mkdir), code::MUTEX_POISONED);

    let err_rename = vol.rename("/", "btrfs_before.txt", "/", "renamed.txt").unwrap_err();
    assert_eq!(error_code(&err_rename), code::MUTEX_POISONED);

    let err_delete = vol.delete_file("/btrfs_before.txt").unwrap_err();
    assert_eq!(error_code(&err_delete), code::MUTEX_POISONED);

    let err_begin = vol.begin_file(1024).err().expect("begin_file should fail on poisoned handle");
    assert_eq!(error_code(&err_begin), code::MUTEX_POISONED);

    // Read operations survive
    let list_json = vol.list_dir_json("/").expect("list_dir_json must survive");
    let list_val: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    let entries = list_val["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["name"] == "btrfs_before.txt"));

    let data = vol.read_file("/btrfs_before.txt", 1024).expect("read_file must survive");
    assert_eq!(data, b"btrfs safe data\n");
}

#[test]
fn cancellation_token_halts_streaming_sha256_and_chunk_writes() {
    let path = scratch("cancel-stream");
    let vol = unlock(&path);

    // 1. Test SHA256 cancellation
    let token = register_cancel_token();
    assert!(!is_cancelled(token));

    // Cancel before or during streaming
    cancel_operation(token);
    assert!(is_cancelled(token));

    let err_sha = vol.sha256_json_with_cancel("/proof.txt", 8, token).unwrap_err();
    assert_eq!(error_code(&err_sha), code::CANCELLED);

    // 2. Test streaming chunk write cancellation
    let mut writer = vol.begin_file(1024).expect("begin_file");
    let err_write = vol
        .write_file_chunk_with_cancel(&mut writer, &[0x42u8; 128], token)
        .unwrap_err();
    assert_eq!(error_code(&err_write), code::CANCELLED);
    vol.abandon_file(writer);

    // 3. Test read_file_stream cancellation
    let mut sink = Vec::new();
    let err_read_stream = vol.read_file_stream("/proof.txt", &mut sink, 8, token).unwrap_err();
    assert_eq!(error_code(&err_read_stream), code::CANCELLED);

    unregister_cancel_token(token);
    assert!(!is_cancelled(token));
}

#[test]
fn paged_directory_listing_on_ext4_and_btrfs() {
    // 1. ext4 paged listing
    let ext4_path = scratch("paged-dir-ext4");
    let ext4_vol = unlock(&ext4_path);

    let ext4_paged_all: serde_json::Value = serde_json::from_str(
        &ext4_vol.list_directory_paged("/", 0, 0).expect("list_directory_paged all")
    ).unwrap();
    let total_ext4 = ext4_paged_all["total_count"].as_u64().unwrap() as usize;
    assert!(total_ext4 >= 3);
    assert_eq!(ext4_paged_all["has_more"].as_bool().unwrap(), false);
    assert_eq!(ext4_paged_all["next_offset"].as_u64().unwrap() as usize, total_ext4);

    let ext4_p1: serde_json::Value = serde_json::from_str(
        &ext4_vol.list_directory_paged("/", 0, 2).expect("page 1")
    ).unwrap();
    assert_eq!(ext4_p1["entries"].as_array().unwrap().len(), 2);
    assert_eq!(ext4_p1["has_more"].as_bool().unwrap(), total_ext4 > 2);
    assert_eq!(ext4_p1["next_offset"].as_u64().unwrap(), 2);
    assert_eq!(ext4_p1["total_count"].as_u64().unwrap() as usize, total_ext4);

    let ext4_p2: serde_json::Value = serde_json::from_str(
        &ext4_vol.list_directory_paged("/", 2, 2).expect("page 2")
    ).unwrap();
    let p2_count = ext4_p2["entries"].as_array().unwrap().len();
    assert_eq!(p2_count, total_ext4 - 2);
    assert_eq!(ext4_p2["has_more"].as_bool().unwrap(), false);
    assert_eq!(ext4_p2["next_offset"].as_u64().unwrap() as usize, total_ext4);

    // 2. btrfs paged listing
    let btrfs_path = scratch_btrfs("paged-dir-btrfs");
    let btrfs_vol = unlock(&btrfs_path);

    let btrfs_p1: serde_json::Value = serde_json::from_str(
        &btrfs_vol.list_directory_paged("/", 0, 1).expect("btrfs page 1")
    ).unwrap();
    assert_eq!(btrfs_p1["entries"].as_array().unwrap().len(), 1);
    assert_eq!(btrfs_p1["has_more"].as_bool().unwrap(), true);
    assert_eq!(btrfs_p1["next_offset"].as_u64().unwrap(), 1);
    assert!(btrfs_p1["total_count"].as_u64().unwrap() >= 2);
}




// ---------------------------------------------------------------------
// Write-session fencing.
//
// A transport failure leaves the drive's state unknown. Continuing to write
// after one is what produced the 2026-09-01 field corruption: the failure was
// swallowed, the batch stayed live, and a later unrelated commit published a
// `BLOCK_GROUP_ITEM.used` the extent tree could not account for. These tests
// pin the policy that replaced that behaviour.
// ---------------------------------------------------------------------

/// The whole point: after fencing, writes are refused and reads are not.
///
/// Reads staying open is a deliberate product decision, not an oversight. The
/// drive holds the user's data; stranding it behind an error screen because a
/// cable glitched would be a worse outcome than the one being prevented.
#[test]
fn a_fenced_write_session_refuses_writes_and_still_serves_reads() {
    let path = scratch_btrfs("fence-refuses-writes");
    let vol = unlock(&path);

    vol.write_file("/", "before-fence.txt", b"written while healthy\n")
        .expect("baseline write must succeed");
    vol.commit_active_batch().expect("baseline commit");

    assert!(
        !vol.is_write_fenced(),
        "vacuity: the volume must start unfenced, or the assertions below prove nothing"
    );

    vol.fence_writes(luks_core::error::LuksError::ScsiProtocol("no CSW"));

    assert!(vol.is_write_fenced(), "fence_writes must latch");
    assert!(
        vol.fence_reason().is_some_and(|r| r.contains("no CSW")),
        "the fence must carry the original diagnosis, not a generic message"
    );

    let err = vol
        .write_file("/", "after-fence.txt", b"must not land\n")
        .expect_err("a fenced session must refuse writes");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED,
        "a fenced write must be distinguishable from a poisoned mutex, got {err:?}"
    );

    let err = vol
        .commit_active_batch()
        .expect_err("a fenced session must refuse to commit");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    // Reads survive.
    let json = vol
        .list_dir_json("/")
        .expect("list_dir_json must survive fencing");
    assert!(
        json.contains("before-fence.txt"),
        "the file written before the fence must still be listed: {json}"
    );
    let data = vol
        .read_file("/before-fence.txt", 4096)
        .expect("read_file must survive fencing");
    assert_eq!(data, b"written while healthy\n");

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// The control, and the assertion that keeps the fence from being useless.
///
/// If ordinary refusals fenced, an out-of-space drive or a typo'd path would
/// force the user to unlock again. A green fence test with no control here
/// would be satisfied by a classifier that returns `true` for everything.
#[test]
fn an_ordinary_refusal_does_not_fence_the_write_session() {
    let path = scratch_btrfs("fence-control-refusal");
    let vol = unlock(&path);

    let err = vol
        .write_file("/no-such-directory", "orphan.txt", b"nope\n")
        .expect_err("writing into a missing directory must fail");
    assert_ne!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED,
        "a path refusal must not be reported as a fenced session"
    );
    assert!(
        !vol.is_write_fenced(),
        "a self-generated refusal proves the write did not happen; it must not fence: {err:?}"
    );

    // And the session is genuinely still usable, not merely unfenced by flag.
    vol.write_file("/", "still-writable.txt", b"session survived\n")
        .expect("the session must still accept writes after an ordinary refusal");
    vol.commit_active_batch().expect("commit after refusal");

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// Fencing must *discard* the active batch, not commit it.
///
/// Committing a batch whose earlier writes may or may not have landed is
/// exactly the operation that publishes a `used` counter with no extent items
/// behind it. Graded by `btrfs check`, not by our own reader.
#[test]
fn fencing_discards_the_active_batch_and_leaves_a_valid_filesystem() {
    // `verify-image.sh`, not `verify-btrfs.sh`: `scratch_btrfs` is a LUKS
    // container, so the oracle has to unlock it before `btrfs check` sees a
    // filesystem at all. Same script the other btrfs bridge tests grade with.
    let Some(script) = tool("verify-image.sh") else {
        eprintln!("skipping: colima is not running");
        return;
    };

    let path = scratch_btrfs("fence-discards-batch");
    {
        let vol = unlock(&path);

        vol.write_file("/", "committed.txt", b"this one is committed\n")
            .expect("first write");
        vol.commit_active_batch().expect("commit the first file");

        // Leave a batch live and uncommitted, then fence.
        vol.write_file("/", "uncommitted.txt", b"this one is dropped\n")
            .expect("second write joins the active batch");
        vol.fence_writes(luks_core::error::LuksError::UsbTransfer("timed out".into()));

        assert!(vol.is_write_fenced());
    }

    let out = Command::new("bash")
        .arg(&script)
        .arg(&path)
        .arg(PASSWORD_STR)
        .output()
        .expect("run verify-image.sh");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && combined.contains("VERDICT: clean"),
        "discarding a batch on fence must leave a filesystem the kernel accepts:\n{combined}"
    );
    assert!(
        !combined.contains("but extent items used"),
        "the used counter must still match the extent tree:\n{combined}"
    );

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------
// Stage A0: fencing coverage for the mutators that previously called
// `fs_for_writing` directly, without going through `guarding_writes`. Being
// refused once fenced was never in question — `fs_for_writing` already
// refuses everything. What was untested is the other direction: a transport
// failure *inside* one of these four must be able to *trigger* the fence in
// the first place, the same way `begin_file` / `write_file_chunk` /
// `finish_file` / `commit_active_batch` already could.
// ---------------------------------------------------------------------

/// `write_file` refuses once the session is fenced.
#[test]
fn a_fenced_session_refuses_write_file() {
    let path = scratch_btrfs("fence-write-file");
    let vol = unlock(&path);

    vol.fence_writes(luks_core::error::LuksError::ScsiProtocol("no CSW"));
    assert!(vol.is_write_fenced());

    let err = vol
        .write_file("/", "must-not-land.txt", b"nope\n")
        .expect_err("write_file must refuse once fenced");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// `delete_file` refuses once the session is fenced.
#[test]
fn a_fenced_session_refuses_delete_file() {
    let path = scratch_btrfs("fence-delete-file");
    let vol = unlock(&path);

    vol.write_file("/", "to-delete.txt", b"present\n")
        .expect("baseline write");
    vol.commit_active_batch().expect("baseline commit");

    vol.fence_writes(luks_core::error::LuksError::UsbTransfer("timed out".into()));
    assert!(vol.is_write_fenced());

    let err = vol
        .delete_file("/to-delete.txt")
        .expect_err("delete_file must refuse once fenced");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// `create_directory` refuses once the session is fenced.
#[test]
fn a_fenced_session_refuses_create_directory() {
    let path = scratch_btrfs("fence-create-directory");
    let vol = unlock(&path);

    vol.fence_writes(luks_core::error::LuksError::ScsiCommandFailed {
        opcode: 0x2A,
        sense: None,
    });
    assert!(vol.is_write_fenced());

    let err = vol
        .create_directory("/", "must-not-exist")
        .expect_err("create_directory must refuse once fenced");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// `rename` refuses once the session is fenced.
#[test]
fn a_fenced_session_refuses_rename() {
    let path = scratch_btrfs("fence-rename");
    let vol = unlock(&path);

    vol.write_file("/", "old-name.txt", b"present\n")
        .expect("baseline write");
    vol.commit_active_batch().expect("baseline commit");

    vol.fence_writes(luks_core::error::LuksError::Io {
        path: "/dev/sda".into(),
        source: std::io::Error::new(std::io::ErrorKind::TimedOut, "etimedout"),
    });
    assert!(vol.is_write_fenced());

    let err = vol
        .rename("/", "old-name.txt", "/", "new-name.txt")
        .expect_err("rename must refuse once fenced");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// The mandatory control for the four tests above: an ordinary,
/// self-generated refusal from one of the newly-wrapped mutators
/// (`delete_file` on a path that was never there) must NOT fence the
/// session. Without this, a classifier that fenced on every `Err` would
/// satisfy the four tests above just as well as the correct one, and every
/// missing file on the drive would force a re-unlock.
#[test]
fn an_ordinary_refusal_from_delete_file_does_not_fence_the_write_session() {
    let path = scratch_btrfs("fence-control-delete");
    let vol = unlock(&path);

    let err = vol
        .delete_file("/no-such-file.txt")
        .expect_err("deleting a missing file must fail");
    assert_ne!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::WRITE_SESSION_FENCED,
        "a missing-file refusal must not be reported as a fenced session"
    );
    assert!(
        !vol.is_write_fenced(),
        "a self-generated refusal from delete_file proves nothing was written; \
         it must not fence: {err:?}"
    );

    // The session must still be genuinely usable afterwards, not merely
    // unfenced by flag: every mutator wrapped in this pass gets exercised
    // once more here.
    vol.write_file("/", "still-writable.txt", b"session survived\n")
        .expect("write_file must still work after an ordinary delete_file refusal");
    vol.create_directory("/", "still-usable-dir")
        .expect("create_directory must still work");
    vol.rename("/", "still-writable.txt", "/", "renamed-after-refusal.txt")
        .expect("rename must still work");
    vol.delete_file("/renamed-after-refusal.txt")
        .expect("delete_file must still work");
    vol.commit_active_batch().expect("commit after refusal");

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------
// The other half of coverage: a real transport failure *inside* one of the
// four newly-wrapped mutators must be able to *trigger* the fence, not just
// be refused by one already set. The tests above prove `fs_for_writing`
// refuses a pre-fenced session — true for every mutator, wrapped or not,
// since `fs_for_writing` itself never changed. What actually distinguishes
// "wrapped in `guarding_writes`" from "not" is whether the mutator's own
// failure sets the latch, and that needs a failure to originate inside the
// call, not be injected from outside it.
// ---------------------------------------------------------------------

/// A device wrapper that lets exactly `budget` `write_at`/`flush` calls
/// through, then answers every later one with a transport error — the same
/// shape as `FailAfterNWrites` in `core/tests/btrfs_crash_safety.rs`, kept
/// local here because these tests need to flip the budget with a live
/// `Arc` *after* `unlock`, which that copy has no reason to expose.
struct FailAfterNWrites {
    inner: luks_core::device::FileDevice,
    budget: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl luks_core::device::ReadAt for FailAfterNWrites {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> luks_core::error::Result<()> {
        self.inner.read_at(offset, buf)
    }
    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl luks_core::device::WriteAt for FailAfterNWrites {
    fn write_at(&self, offset: u64, buf: &[u8]) -> luks_core::error::Result<()> {
        use std::sync::atomic::Ordering;
        let prev = self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |b| {
                if b == 0 {
                    None
                } else {
                    Some(b - 1)
                }
            });
        if prev.is_err() {
            return Err(luks_core::error::LuksError::UsbTransfer(
                "simulated transport vanished (FailAfterNWrites budget exhausted)".into(),
            ));
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> luks_core::error::Result<()> {
        use std::sync::atomic::Ordering;
        if self.budget.load(Ordering::SeqCst) == 0 {
            return Err(luks_core::error::LuksError::UsbTransfer(
                "simulated transport vanished (FailAfterNWrites budget exhausted)".into(),
            ));
        }
        self.inner.flush()
    }
}

/// Open a scratch image through `FailAfterNWrites` instead of a plain
/// `FileDevice`, returning the volume and a live handle to the write budget
/// so the caller can exhaust it after setup (baseline writes, `unlock`
/// itself) has already happened.
fn unlock_with_budget(path: &str) -> (VolumeHandle, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let budget = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1_000));
    let len = std::fs::metadata(path).expect("stat").len();
    let inner = luks_core::device::FileDevice::open_writable(path, len).expect("open writable");
    let dev = FailAfterNWrites {
        inner,
        budget: budget.clone(),
    };
    let handle =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = handle
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();
    (handle.unlock(offset, PASSWORD).expect("unlock"), budget)
}

/// A transport failure inside `write_file` fences the session, not just
/// fails the one call.
#[test]
fn a_transport_failure_inside_write_file_triggers_the_fence() {
    let path = scratch_btrfs("fence-trigger-write-file");
    let (vol, budget) = unlock_with_budget(&path);

    // Unlock succeeded on plenty of budget; now cut the device off before
    // the write under test, exactly the way a cable pulled mid-transfer
    // would.
    budget.store(0, std::sync::atomic::Ordering::SeqCst);

    let err = vol
        .write_file("/", "vanishes-mid-write.txt", b"never lands\n")
        .expect_err("write_file must fail when the transport is gone");
    assert_eq!(
        luks_jni::bridge::error_code(&err),
        luks_jni::bridge::code::TRANSPORT,
        "the first failure must be reported as the transport error it is, got {err:?}"
    );
    assert!(
        vol.is_write_fenced(),
        "write_file's own transport failure must have latched the fence, not just failed the call"
    );

    let err2 = vol
        .write_file("/", "also-refused.txt", b"still refused\n")
        .expect_err("a later write must be refused by the fence write_file set");
    assert_eq!(
        luks_jni::bridge::error_code(&err2),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// A transport failure inside `delete_file` fences the session.
#[test]
fn a_transport_failure_inside_delete_file_triggers_the_fence() {
    let path = scratch_btrfs("fence-trigger-delete-file");
    let (vol, budget) = unlock_with_budget(&path);

    vol.write_file("/", "to-delete.txt", b"present\n")
        .expect("baseline write on a healthy budget");
    vol.commit_active_batch().expect("baseline commit");

    budget.store(0, std::sync::atomic::Ordering::SeqCst);

    let err = vol
        .delete_file("/to-delete.txt")
        .expect_err("delete_file must fail when the transport is gone");
    assert_eq!(luks_jni::bridge::error_code(&err), luks_jni::bridge::code::TRANSPORT);
    assert!(
        vol.is_write_fenced(),
        "delete_file's own transport failure must have latched the fence"
    );

    let err2 = vol
        .delete_file("/to-delete.txt")
        .expect_err("a later delete must be refused by the fence delete_file set");
    assert_eq!(
        luks_jni::bridge::error_code(&err2),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// A transport failure inside `create_directory` fences the session.
#[test]
fn a_transport_failure_inside_create_directory_triggers_the_fence() {
    let path = scratch_btrfs("fence-trigger-create-directory");
    let (vol, budget) = unlock_with_budget(&path);

    budget.store(0, std::sync::atomic::Ordering::SeqCst);

    let err = vol
        .create_directory("/", "vanishes-mid-mkdir")
        .expect_err("create_directory must fail when the transport is gone");
    assert_eq!(luks_jni::bridge::error_code(&err), luks_jni::bridge::code::TRANSPORT);
    assert!(
        vol.is_write_fenced(),
        "create_directory's own transport failure must have latched the fence"
    );

    let err2 = vol
        .create_directory("/", "also-refused")
        .expect_err("a later mkdir must be refused by the fence create_directory set");
    assert_eq!(
        luks_jni::bridge::error_code(&err2),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}

/// A transport failure inside `rename` fences the session.
#[test]
fn a_transport_failure_inside_rename_triggers_the_fence() {
    let path = scratch_btrfs("fence-trigger-rename");
    let (vol, budget) = unlock_with_budget(&path);

    vol.write_file("/", "old-name.txt", b"present\n")
        .expect("baseline write on a healthy budget");
    vol.commit_active_batch().expect("baseline commit");

    budget.store(0, std::sync::atomic::Ordering::SeqCst);

    let err = vol
        .rename("/", "old-name.txt", "/", "new-name.txt")
        .expect_err("rename must fail when the transport is gone");
    assert_eq!(luks_jni::bridge::error_code(&err), luks_jni::bridge::code::TRANSPORT);
    assert!(
        vol.is_write_fenced(),
        "rename's own transport failure must have latched the fence"
    );

    let err2 = vol
        .rename("/", "old-name.txt", "/", "another-name.txt")
        .expect_err("a later rename must be refused by the fence rename set");
    assert_eq!(
        luks_jni::bridge::error_code(&err2),
        luks_jni::bridge::code::WRITE_SESSION_FENCED
    );

    drop(vol);
    let _ = std::fs::remove_file(&path);
}
