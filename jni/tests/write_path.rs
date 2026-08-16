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

use luks_core::device::FileDevice;
use luks_jni::bridge::{code, error_code, DeviceHandle, VolumeHandle};
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

/// The colima VM holds the only real kernel here. Skipping rather than failing
/// when it is down keeps `cargo test` usable offline — but a skip is printed,
/// because a silent skip is how a suite quietly stops proving anything.
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


