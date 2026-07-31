//! LUKS container support.
//!
//! Phase 2 fills in `keyslot` (Argon2id/PBKDF2 + AF-merge) and `volume`
//! (AES-XTS sector decryption). Header parsing lands first because everything
//! else needs the parameters it yields.

pub mod header;

pub use header::{
    detect_version, parse, Area, Digest, HeaderCopy, Kdf, Keyslot, Luks2Header, LuksVersion,
    Metadata, Segment, SegmentSize,
};
