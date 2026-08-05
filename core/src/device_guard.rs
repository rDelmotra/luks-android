//! The target allowlist: what stands between `dangerous-write-support` and a
//! wrong device.
//!
//! This is the gap flagged since the write path's first commit and never
//! closed until now: nothing stopped a write from reaching `/dev/disk0`
//! instead of the intended stick. It is not a hypothetical. This session,
//! `/dev/disk4` was the developer's real Fedora SSD in the morning and an
//! entirely different SanDisk stick in the afternoon — device numbering on
//! every OS this crate targets is reassigned by plug order, not fixed by
//! identity. A path typed once and reused later can silently mean a different
//! physical drive.
//!
//! # What this defends against, and what it cannot
//!
//! [`FileDevice::open_writable_confirmed`] refuses to open unless the caller
//! states, in advance, the exact byte length they believe the target to be,
//! **and** that length matches what the OS reports once the file is open. A
//! wrong device essentially never happens to share an exact size in bytes —
//! two different SSDs, or a partition versus its whole disk, differ by at
//! least a few sectors. A caller who states what they *meant* to open gets
//! refused the moment reality disagrees, which is exactly the renumbering
//! failure above.
//!
//! It is a defence against **mistake**, not against a caller who lies about
//! the size on purpose — nothing here can distinguish "the right stick, size
//! confirmed" from "the wrong stick that happens to be the same size", and it
//! is not trying to. The threat model is a stale path or a typo, which is what
//! actually happens in a terminal.
//!
//! It is *not* a defence against opening a partition of the same disk the OS
//! is running from — that check needs to identify "which physical disk backs
//! this path", which is OS-specific (`diskutil`'s APFS physical-store lookup
//! on macOS, block topology on Linux) and deliberately out of scope for this
//! pass. What this module gives up in exchange is staying pure, portable
//! Rust: no shelling out, no ioctls, nothing this crate's
//! `#![forbid(unsafe_code)]` would have to carve an exception for. The known
//! whole-disk-by-convention names below are a cheap net for the common case
//! this weaker check cannot see; a real system-disk lookup is future work, not
//! a silent gap — see `STATE.md`.
//!
//! # The length itself
//!
//! `Metadata::len()` reports 0 for most special device files rather than the
//! true device size — this crate already treats that as "unknown" for reads
//! (see [`crate::device::FileDevice`]'s length handling). For a write target
//! that is not good enough: "unknown" must not silently become "trust the
//! caller". So the actual size is obtained by seeking to the end of a
//! **separate read-only** handle, which is how every Unix character or block
//! device reports its true size — no ioctl required, and the confirmation
//! path never depends on the writable descriptor's own position.

use crate::error::{LuksError, Result};
use std::io::{Seek, SeekFrom};
use std::path::Path;

/// What the caller states, in advance, about the device they intend to open.
///
/// Both fields exist to force a deliberate call site rather than a bare path
/// string threaded through from somewhere else. `label` is never compared
/// against anything — its only job is to appear in an error message and in
/// whatever the caller logs, so a mistaken confirmation is legible after the
/// fact rather than just a bare device path.
#[derive(Debug, Clone)]
pub struct TargetConfirmation {
    /// What the caller believes they are about to open — for a human to read
    /// back, e.g. `"58GB SanDisk (disk4), confirmed via diskutil list"`.
    pub label: String,
    /// The exact byte length the caller believes the target to be. Must come
    /// from an independent source (a UI showing the drive's advertised size,
    /// or `diskutil`/`lsblk` output a person read) — not from probing the
    /// path this code is about to open, which would make the check compare a
    /// number against itself.
    pub expected_len: u64,
}

/// Devices that are the system/boot disk by near-universal OS convention:
/// index (or letter) zero, whole-disk form, no partition suffix.
///
/// This is a denylist, which is the wrong shape for a security boundary — a
/// system with an unconventional layout is not covered, and that is why it is
/// paired with the length check above rather than relied on alone. Its value
/// is catching the specific mistake of typing a number without thinking,
/// unconditionally, with no override: there is no legitimate reason for this
/// crate to write to a device matching one of these names.
const WHOLE_DISK_ZERO: &[&str] = &[
    "/dev/disk0",
    "/dev/rdisk0",
    "/dev/sda",
    "/dev/hda",
    "/dev/nvme0n1",
    "/dev/mmcblk0",
];

/// Checked before anything is opened, so a denied path never even reaches
/// `OpenOptions`.
fn reject_known_system_disk(path: &Path) -> Result<()> {
    let s = path.to_string_lossy();
    if WHOLE_DISK_ZERO.iter().any(|&d| s == d) {
        return Err(LuksError::UnconfirmedWriteTarget(format!(
            "{s} matches a well-known system/boot disk name and is refused \
             unconditionally — there is no legitimate reason for this crate \
             to write there"
        )));
    }
    Ok(())
}

/// The true size of whatever `path` refers to, via seek-to-end on a read-only
/// handle. `None` if the OS genuinely cannot say (a pipe, a path that does not
/// exist yet).
pub(crate) fn probe_len(path: &Path) -> Option<u64> {
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::End(0)).ok()
}

/// Refuse unless `confirmation` matches reality. Called before the writable
/// descriptor is handed back — see [`crate::device::FileDevice::open_writable_confirmed`].
pub(crate) fn check(path: &Path, confirmation: &TargetConfirmation) -> Result<()> {
    if confirmation.label.trim().is_empty() {
        return Err(LuksError::UnconfirmedWriteTarget(
            "confirmation label is empty — state what you believe you are \
             opening, not just a bare path"
                .into(),
        ));
    }

    reject_known_system_disk(path)?;

    let actual = probe_len(path).ok_or_else(|| {
        LuksError::UnconfirmedWriteTarget(format!(
            "could not determine the true size of {} to check against the \
             {} bytes claimed for {:?} — refusing rather than trusting an \
             unverified target",
            path.display(),
            confirmation.expected_len,
            confirmation.label
        ))
    })?;

    if actual != confirmation.expected_len {
        return Err(LuksError::UnconfirmedWriteTarget(format!(
            "{:?} was confirmed as {} bytes, but {} is actually {actual} \
             bytes — this is exactly the failure mode a device being \
             renumbered by the OS looks like, and the mismatch is refused \
             rather than guessed at",
            confirmation.label,
            confirmation.expected_len,
            path.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str, bytes: usize) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("guard-test-{name}"));
        std::fs::write(&p, vec![0u8; bytes]).expect("write scratch file");
        p
    }

    #[test]
    fn a_matching_length_is_accepted() {
        let p = scratch("match", 4096);
        let c = TargetConfirmation {
            label: "test file".into(),
            expected_len: 4096,
        };
        assert!(check(&p, &c).is_ok());
    }

    #[test]
    fn a_wrong_length_is_refused() {
        // The exact shape of a renumbered device: same path, different drive.
        let p = scratch("mismatch", 4096);
        let c = TargetConfirmation {
            label: "test file".into(),
            expected_len: 8192,
        };
        assert!(check(&p, &c).is_err());
    }

    #[test]
    fn an_empty_label_is_refused_even_with_a_correct_length() {
        let p = scratch("nolabel", 100);
        let c = TargetConfirmation {
            label: "  ".into(),
            expected_len: 100,
        };
        assert!(check(&p, &c).is_err());
    }

    #[test]
    fn known_system_disk_names_are_refused_regardless_of_length() {
        // These paths do not exist on the test machine, so probe_len would
        // fail anyway — the point is that the system-disk check runs and
        // rejects *before* that, with its own distinct reason.
        for name in WHOLE_DISK_ZERO {
            let c = TargetConfirmation {
                label: "definitely not the boot disk, honest".into(),
                expected_len: 999,
            };
            let err = check(Path::new(name), &c).unwrap_err();
            assert!(
                format!("{err}").contains("system/boot disk"),
                "{name} should be refused as a known system disk, got: {err}"
            );
        }
    }

    #[test]
    fn a_nonexistent_path_is_refused_as_unverifiable_not_as_a_length_mismatch() {
        let c = TargetConfirmation {
            label: "does not exist".into(),
            expected_len: 100,
        };
        let err = check(Path::new("/no/such/path/at/all"), &c).unwrap_err();
        assert!(format!("{err}").contains("could not determine"));
    }
}
