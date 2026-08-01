//! Guards the AES backend selection.
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
