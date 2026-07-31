//! LUKS container support.

pub mod header;
pub mod keyslot;
pub mod volume;

pub use header::{
    detect_version, parse, Area, Digest, HeaderCopy, Kdf, Keyslot, Luks2Header, LuksVersion,
    Metadata, Segment, SegmentSize,
};
pub use keyslot::{derive_key, unlock};
pub use volume::LuksVolume;
