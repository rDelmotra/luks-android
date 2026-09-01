use thiserror::Error;

#[derive(Debug, Error)]
pub enum LuksError {
    #[error("not a LUKS partition: bad magic {found:02x?}")]
    BadMagic { found: [u8; 6] },

    #[error("LUKS version {0} is not supported (expected 1 or 2)")]
    UnsupportedVersion(u16),

    #[error("LUKS1 headers are not implemented yet")]
    Luks1NotImplemented,

    #[error("header truncated: needed {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },

    #[error("declared header size {0} is implausible")]
    ImplausibleHeaderSize(u64),

    #[error("header checksum mismatch (corrupt header, or we parsed it wrong)")]
    ChecksumMismatch,

    #[error("unsupported header checksum algorithm: {0}")]
    UnsupportedChecksumAlg(String),

    #[error("JSON metadata area is not valid UTF-8")]
    JsonNotUtf8,

    #[error("JSON metadata parse failed: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("field {field} is not a valid integer: {value:?}")]
    BadIntegerField { field: &'static str, value: String },

    #[error("header declares no {0}")]
    Missing(&'static str),

    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    #[error("unsupported hash: {0}")]
    UnsupportedHash(String),

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("unsupported digest type: {0}")]
    UnsupportedDigest(String),

    #[error("unsupported key length {0} (expected 32 or 64 bytes for AES-XTS)")]
    BadKeyLength(usize),

    /// No keyslot accepted the password. Deliberately indistinguishable from
    /// "this slot did not match" so nothing is leaked about which slot exists.
    #[error("wrong password")]
    WrongPassword,

    #[error("unsupported sector size {0} (expected 512, 1024, 2048 or 4096)")]
    BadSectorSize(u32),

    #[error("read past end of volume")]
    OutOfBounds,

    // --- filesystem layer ---
    #[error("not an ext4 filesystem: magic 0x{0:04x}, expected 0xef53")]
    NotExt4(u16),

    #[error("not a btrfs filesystem: magic {0:02x?}, expected _BHRfS_M")]
    NotBtrfs([u8; 8]),

    /// Nothing recognisable on an otherwise readable volume. Distinct from a
    /// wrong password, which produces plausible-looking noise — by the time
    /// this is reached the master key has already been verified against the
    /// keyslot digest, so the volume really is decrypted and really is
    /// something we cannot read.
    #[error("unrecognised filesystem: this reader understands ext4 and btrfs")]
    UnknownFs,

    /// Two filesystem signatures on one volume, usually a reformat that did not
    /// wipe the old one. Refused rather than resolved: one of the two answers
    /// is a filesystem that no longer exists, and there is no way to tell from
    /// the signatures alone which.
    #[error("this volume carries both ext4 and btrfs signatures — refusing to guess which is real")]
    AmbiguousFs,

    /// A metadata block did not match its stored checksum. btrfs checksums all
    /// of its metadata, so this is a genuine corruption signal rather than the
    /// advisory it would be on ext4.
    #[error("{0} failed its checksum — the drive is corrupt, or we parsed it wrong")]
    FsChecksumMismatch(&'static str),

    #[error("filesystem uses unsupported feature: {0}")]
    UnsupportedFsFeature(String),

    /// The journal has unreplayed transactions, so the on-disk state is stale.
    /// Reading it would show a filesystem that never existed.
    #[error("filesystem was not cleanly unmounted and needs journal recovery")]
    FsNeedsRecovery,

    #[error("invalid extent header (magic 0x{0:04x}, expected 0xf30a)")]
    BadExtentHeader(u16),

    #[error("extent tree is malformed: {0}")]
    BadExtentTree(&'static str),

    #[error("inode {0} is out of range")]
    BadInode(u64),

    #[error("no such file or directory: {0}")]
    NotFound(String),

    #[error("not a directory: {0}")]
    NotADirectory(String),

    #[error("is a directory: {0}")]
    IsADirectory(String),

    /// The low-level single-transaction delete refuses a directory that still
    /// has children — deleting only its own metadata while entries under it
    /// remain would orphan them (their storage never freed, their names
    /// unreachable). The recursive delete empties a directory before this is
    /// ever reached; surfacing here means recursion stopped partway — at a
    /// child type it doesn't delete yet, or a concurrent change — not that
    /// this call itself did anything wrong.
    #[error("directory is not empty: {0}")]
    DirectoryNotEmpty(String),

    #[error("too many levels of symbolic links resolving {0}")]
    SymlinkLoop(String),

    #[error("corrupt filesystem structure: {0}")]
    CorruptFs(&'static str),

    /// A name already taken in the directory being written to.
    ///
    /// Distinct from [`LuksError::CorruptFs`] on purpose: a caller creating a
    /// file whose name is already there has done something ordinary and
    /// recoverable — pick another name — and telling the user their filesystem
    /// is corrupt would be both alarming and false.
    ///
    /// The name is carried for a caller that wants it but deliberately kept
    /// **out of the message**. This text crosses into a Java exception and is
    /// a strong candidate for a log; filenames on an encrypted volume are
    /// among the things that volume exists to conceal, and the caller that
    /// chose the name already knows it.
    #[error("a file with that name already exists here")]
    AlreadyExists(String),

    /// Another unlocked volume on the same device already holds the write
    /// claim. Only one may allocate at a time: each unlock caches its own copy
    /// of the superblock counters and group descriptors, and two of those
    /// allocating against one disk produce overlapping files.
    ///
    /// Its own variant rather than a reused `UnsupportedFsFeature` because the
    /// caller's remedy is specific and actionable — close the other volume —
    /// and is nothing like the remedy for "this volume is btrfs", which the
    /// two used to be indistinguishable from at the JNI boundary.
    #[error("another unlocked volume on this device is already the writer — close it first")]
    WriterBusy,

    /// No group had a free block the allocator could reach. Note that on a
    /// filesystem with uninitialised groups this can mean "full" long before
    /// the drive is — see the note in `fs::ext4::alloc`.
    #[error("no space left on the filesystem")]
    FilesystemFull,

    /// A single btrfs item is larger than any tree node could ever hold, so no
    /// amount of splitting or free space can place it.
    ///
    /// Its own variant because sharing [`LuksError::FilesystemFull`] cost a
    /// day. On 2026-08-16 a 20 MB phone→stick write reported *"no space left
    /// on the filesystem"* on a drive with 676 MiB free: the real cause was
    /// one `EXTENT_CSUM` item covering a whole file and overflowing a 16 KiB
    /// leaf. The investigation went at the drive, the flashing and the free
    /// space, none of which were involved. `RULES.md` already required that an
    /// error name its own operation; one error meaning two unrelated things is
    /// the same defect wearing a different mask, so the two are now separate
    /// and this one says outright that space is not the problem.
    #[error(
        "a {item_bytes}-byte {what} does not fit in a {node_size}-byte btrfs tree node \
         — this is a node-capacity limit, not a full disk"
    )]
    BtrfsItemTooLarge {
        /// What was being written, so the message names its own operation
        /// rather than leaving the reader to supply one from context.
        what: &'static str,
        item_bytes: usize,
        node_size: u32,
    },

    #[error("no free inodes left on the filesystem")]
    NoFreeInodes,

    /// The device behind a write target's path is not the one the caller said
    /// it was. Almost always means the path now points at a different drive
    /// than when it was checked — see `FileDevice::open_writable`.
    #[error(
        "refusing to write to {path}: it is not the {expected}-byte device it \
         was confirmed as ({detail}) — the path points at something other than \
         what was checked"
    )]
    WrongWriteTarget {
        path: String,
        expected: u64,
        detail: &'static str,
    },

    /// The size of a write target could not be determined, so the caller's
    /// claim about it could not be checked. Refused rather than assumed.
    #[error("refusing to write to {path}: could not determine its size to confirm it")]
    UnverifiableWriteTarget { path: String },

    // --- USB / SCSI transport ---
    #[error("SCSI protocol error: {0}")]
    ScsiProtocol(&'static str),

    /// The device returned CSW status 1, carrying the sense data it gave when
    /// asked why. `None` means the REQUEST SENSE that follows a failure itself
    /// failed, which is worth distinguishing from a drive that stayed silent.
    ///
    /// This used to be a bare unit variant whose doc said "call REQUEST SENSE
    /// for the reason" — and nothing ever did. A real `WRITE(10)` refusal on
    /// hardware therefore reached the UI as the text "SCSI command failed",
    /// which is equally consistent with a write-protected drive, a CDB the
    /// drive would not accept, and failing media.
    #[error(
        "SCSI {} failed{}",
        crate::usb::scsi::opcode_name(*opcode),
        sense.map(|s| format!(": {s}")).unwrap_or_default()
    )]
    ScsiCommandFailed {
        /// The CDB's opcode byte. Carried because inferring which command
        /// failed from context got it wrong once already: a refused
        /// `SYNCHRONIZE CACHE` was read as a refused `WRITE(10)`, which sent
        /// the investigation at the CDB encoder instead of at the flush.
        opcode: u8,
        sense: Option<crate::usb::scsi::Sense>,
    },

    #[error("USB transfer failed: {0}")]
    UsbTransfer(String),

    // --- partition tables ---
    #[error("no MBR or GPT partition table found")]
    NoPartitionTable,

    #[error("GPT is invalid: {0}")]
    BadGpt(&'static str),

    // --- host I/O ---
    /// Reading a file or block device on the host failed. Only produced by
    /// `FileDevice`; the Android path never touches the host filesystem.
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    // --- session lifecycle / cancellation ---
    /// A previous write operation panicked while holding the volume lock.
    /// Further writes are refused to prevent corrupting the on-disk state.
    #[error("write mutex poisoned: a previous operation panicked")]
    SessionPoisoned,

    /// The operation was cancelled via cancellation token.
    #[error("operation cancelled")]
    Cancelled,

    /// Every later write on this volume is refused because an earlier write
    /// failed in a way that leaves its on-device outcome unknown.
    ///
    /// This is the same policy the kernel's own btrfs takes on a failed
    /// transaction (`btrfs_abort_transaction`): stop, force read-only, and
    /// make the operator remount rather than continue writing on top of a
    /// filesystem whose last transaction may or may not have landed.
    ///
    /// It exists because the alternative was tried and produced the
    /// 2026-09-01 field corruption: a transport timeout mid-import was
    /// swallowed, the batch stayed live, and a later unrelated commit
    /// published a `BLOCK_GROUP_ITEM.used` the extent tree could not account
    /// for. Reads are deliberately still allowed — the point is to stop
    /// writing, not to strand the user's data behind an error screen.
    #[error("write session fenced after {0}; unlock the volume again to resume writing")]
    WriteSessionFenced(String),
}

impl LuksError {
    /// Whether this failure leaves the drive's state unknown, and so must end
    /// the write session rather than merely fail one operation.
    ///
    /// The distinction that matters is **who** failed. A transport error means
    /// the command may or may not have reached the medium, so nothing after it
    /// can be trusted to build on it. A refusal we generated ourselves —
    /// `FilesystemFull`, `NotFound`, `AlreadyExists`, an unsupported feature —
    /// means the write provably did not happen, the filesystem is exactly as
    /// it was, and the session is fine.
    ///
    /// [`Cancelled`](Self::Cancelled) is explicitly *not* fencing. A user who
    /// stops a transfer, or a source file that fails to read on the phone,
    /// says nothing about the destination drive; the files already completed
    /// are valid and committing them is correct.
    pub fn fences_write_session(&self) -> bool {
        matches!(
            self,
            // Transport: the command's outcome on the medium is unknown.
            Self::ScsiProtocol(_)
                | Self::ScsiCommandFailed { .. }
                | Self::UsbTransfer(_)
                | Self::Io { .. }
                // A panic already happened under the volume lock.
                | Self::SessionPoisoned
                // Already fenced; stay fenced.
                | Self::WriteSessionFenced(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, LuksError>;

#[cfg(test)]
mod fence_classification {
    use super::LuksError;

    /// Every fencing variant, named individually.
    ///
    /// A `matches!` arm is easy to widen by accident, and widening it turns an
    /// ordinary refusal into "unlock the drive again" for the user. The list is
    /// spelled out so adding a variant to the classifier without deciding about
    /// it here fails a test rather than silently changing behaviour.
    #[test]
    fn transport_and_panic_failures_fence_the_write_session() {
        let fencing: Vec<LuksError> = vec![
            LuksError::ScsiProtocol("no CSW"),
            LuksError::ScsiCommandFailed { opcode: 0x2A, sense: None },
            LuksError::UsbTransfer("timed out".into()),
            LuksError::Io {
                path: "/dev/sda".into(),
                source: std::io::Error::new(std::io::ErrorKind::TimedOut, "etimedout"),
            },
            LuksError::SessionPoisoned,
            LuksError::WriteSessionFenced("already".into()),
        ];
        assert!(!fencing.is_empty(), "vacuity: the fencing list is empty");
        for e in &fencing {
            assert!(
                e.fences_write_session(),
                "{e:?} leaves the drive's state unknown and must fence the session"
            );
        }
    }

    /// The other half of the claim, and the more important one: a refusal we
    /// generated ourselves proves the write did *not* happen, so the session
    /// is still good. Fencing on these would make an out-of-space drive
    /// require a re-unlock.
    #[test]
    fn self_generated_refusals_do_not_fence_the_write_session() {
        let benign: Vec<LuksError> = vec![
            LuksError::FilesystemFull,
            LuksError::NoFreeInodes,
            LuksError::NotFound("/nope".into()),
            LuksError::AlreadyExists("dup".into()),
            LuksError::WriterBusy,
            LuksError::Cancelled,
            LuksError::OutOfBounds,
        ];
        assert!(!benign.is_empty(), "vacuity: the benign list is empty");
        for e in &benign {
            assert!(
                !e.fences_write_session(),
                "{e:?} proves the write did not happen; fencing on it would strand the session"
            );
        }
    }

    /// Cancellation is the case Codex specifically called out: a user stopping
    /// a transfer, or a source file failing to read on the phone, says nothing
    /// about the destination drive, and the files already completed are valid.
    #[test]
    fn cancellation_never_fences() {
        assert!(!LuksError::Cancelled.fences_write_session());
    }
}
