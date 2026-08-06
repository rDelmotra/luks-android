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
}

pub type Result<T> = std::result::Result<T, LuksError>;
