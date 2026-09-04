//! Byte containers that refuse to leak.
//!
//! Anything derived from, or usable to attack, the master key lives in a
//! [`Secret`]. The type deliberately has no `Display`, its `Debug` prints only a
//! length, and it zeroes its storage on drop. That makes the common accidents —
//! `dbg!`, `{:?}` in a log line, a panic message, a serialized error — non-events.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque secret bytes. Never printed, zeroed on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Explicit, greppable accessor. Call sites are easy to audit precisely
    /// because this is the only way out.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.0.len())
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use serde::de::Error;

        let s = String::deserialize(d)?;
        // LUKS2 pads base64 salt fields; be permissive about trailing whitespace.
        let bytes = STANDARD
            .decode(s.trim())
            .map_err(|e| D::Error::custom(format!("invalid base64 in secret field: {e}")))?;
        Ok(Secret::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_contents() {
        let s = Secret::new(b"hunter2-the-actual-salt".to_vec());
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "[REDACTED 23 bytes]");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn debug_of_a_struct_containing_a_secret_is_also_clean() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Wrapper {
            name: &'static str,
            salt: Secret,
        }
        let w = Wrapper {
            name: "keyslot0",
            salt: Secret::new(vec![0xAB; 32]),
        };
        let rendered = format!("{w:?}");
        assert!(rendered.contains("keyslot0"));
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn base64_round_trip() {
        let s: Secret = serde_json::from_str("\"aGVsbG8=\"").unwrap();
        assert_eq!(s.expose(), b"hello");
    }

    // N.7 (`notes/feature-remediation.md` §4): the test that proves
    // `ZeroizeOnDrop` actually scrubs `Secret`'s backing bytes — as opposed
    // to merely asserting a mock's `.close()` was called, which is the
    // failure this item exists to correct — lives in
    // `core/tests/secret_zeroize.rs`, not here. It needs a small amount of
    // `unsafe` (a `#[global_allocator]` hook that snapshots a watched
    // allocation's contents at `dealloc` time), and this crate is
    // `#![forbid(unsafe_code)]` (see `core/src/lib.rs`); an external
    // integration-test crate is not bound by that attribute, so that is
    // where the proof has to live.
}
