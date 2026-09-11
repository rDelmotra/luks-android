//! Guards the crypto backend selection — AES, and now SHA-256.
//!
//! The `aes` 0.8 crate hides its ARMv8 hardware backend behind a custom cfg
//! flag (`aes_armv8`) rather than behind `target_feature`. Without the flag it
//! silently compiles pure-software AES: **correct output, 60x slower**.
//! Measured here, AES-256-XTS went from 65 MiB/s to 3900 MiB/s.
//!
//! A performance bug that produces correct results is invisible to every other
//! test in this suite, and a stray `cargo build` from a directory that misses
//! `../.cargo/config.toml` would reintroduce it. Hence an explicit assertion.

use luks_core::luks::keyslot::xts_decrypt;
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Deterministic, zero-flake: does the compiled crate actually have the flag?
///
/// Only meaningful on aarch64. On x86_64 the `aes` crate autodetects AES-NI
/// with no flag needed, so the requirement does not apply.
#[test]
fn armv8_aes_backend_is_enabled_on_aarch64() {
    if !cfg!(target_arch = "aarch64") {
        return;
    }
    assert!(
        cfg!(aes_armv8),
        "aarch64 build without `--cfg aes_armv8`: the `aes` crate has silently \
         fallen back to software AES, which is ~60x slower (65 MiB/s vs 3.9 GiB/s). \
         Restore `[build] rustflags = [\"--cfg\", \"aes_armv8\"]` in .cargo/config.toml. \
         Note this is safe on all aarch64 devices — the crate compiles both \
         backends and selects at runtime via cpufeatures."
    );
}

/// Reports the real number. Only asserts in release, because a debug build
/// compiles the cipher unoptimised and any threshold would be meaningless.
#[test]
fn xts_throughput_is_in_the_hardware_range() {
    const BYTES: usize = 32 * 1024 * 1024;
    let key = [0x42u8; 64];
    let mut buf = vec![0u8; BYTES];

    // Warm the allocation so the first-touch page faults are not counted.
    xts_decrypt(&key, &mut buf[..4096], 512, 0, 1).unwrap();

    let t = Instant::now();
    xts_decrypt(&key, &mut buf, 512, 0, 1).unwrap();
    let mib_s = (BYTES as f64 / (1024.0 * 1024.0)) / t.elapsed().as_secs_f64();

    println!("AES-256-XTS decrypt: {mib_s:.0} MiB/s");

    if cfg!(debug_assertions) {
        println!("(debug build — threshold not enforced)");
        return;
    }
    // Software AES measures ~65 MiB/s, hardware ~3900. 500 sits an order of
    // magnitude clear of both, so this cannot flake on a loaded machine.
    assert!(
        mib_s > 500.0,
        "only {mib_s:.0} MiB/s — this is the software AES backend. See .cargo/config.toml."
    );
}

/// The same trap, found the same way, in a different crate.
///
/// `sha2` 0.10 gates its aarch64 hardware backend behind a **non-default
/// `asm` feature**:
///
/// ```text
/// } else if #[cfg(all(feature = "asm", target_arch = "aarch64"))] {
/// ```
///
/// Without it the crate compiles the portable software implementation, at
/// **525 MiB/s against 1912** on this machine — a 3.6x miss, with correct
/// digests throughout. It went unnoticed for as long as it did because SHA-256
/// was 4% of a read that was bound by a slow device node; once the device got
/// 5.4x faster it became 45%.
///
/// Enabling `asm` is safe everywhere despite the name: on aarch64 the code
/// selected is Rust intrinsics with a `cpufeatures` runtime check that falls
/// back to software, not unconditional assembly, so a device without the
/// crypto extensions runs slower rather than dying on an illegal instruction.
/// The `sha2-asm` crate it pulls in is only used on x86; it costs 2.8 KB of
/// the Android `.so` and is MIT.
///
/// The general lesson, twice over now: **check the measured rate against what
/// the silicon can do.** Both crates report the obvious `target_feature` check
/// as true while compiling the software path.
#[test]
fn sha256_throughput_is_in_the_hardware_range() {
    const BYTES: usize = 32 * 1024 * 1024;
    let data = vec![0xa5u8; BYTES];

    // Warm up, so page faults on first touch are not charged to the hash.
    let mut warm = Sha256::new();
    warm.update(&data[..4096]);
    let _ = warm.finalize();

    let t = Instant::now();
    let mut h = Sha256::new();
    h.update(&data);
    let _ = h.finalize();
    let mib_s = (BYTES as f64 / (1024.0 * 1024.0)) / t.elapsed().as_secs_f64();

    println!("SHA-256: {mib_s:.0} MiB/s");

    if cfg!(debug_assertions) {
        println!("(debug build — threshold not enforced)");
        return;
    }
    if !cfg!(target_arch = "aarch64") {
        // On x86_64 the crate autodetects SHA-NI, and not every x86 CPU has
        // it. Report the number, assert nothing.
        return;
    }
    // Software measures ~525, hardware ~1900. 1000 sits clear of both.
    assert!(
        mib_s > 1000.0,
        "only {mib_s:.0} MiB/s — this is the software SHA-256 backend. Restore \
         `features = [\"asm\"]` on the sha2 dependency in core/Cargo.toml."
    );
}
