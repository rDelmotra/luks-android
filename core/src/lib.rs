//! `luks_core` — userspace engine for reading LUKS-encrypted drives.
//!
//! Layered, with each layer usable and testable on its own:
//!
//! 1. `usb`   — SCSI Bulk-Only Transport over a raw USB fd (Phase 1)
//! 2. `luks`  — header parsing, key derivation, AES-XTS sector decryption
//! 3. `fs`    — filesystem readers over a decrypted block device
//!
//! V1 is read-only. Write opcodes live behind the `dangerous-write-support`
//! feature and are absent from a default build.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod device;
pub mod error;
pub mod fs;
pub mod luks;
pub mod secret;

pub use error::{LuksError, Result};

/// Crate version, surfaced across the JNI bridge for the Phase 0 milestone.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
