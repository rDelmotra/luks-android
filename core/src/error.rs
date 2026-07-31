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
}

pub type Result<T> = std::result::Result<T, LuksError>;
