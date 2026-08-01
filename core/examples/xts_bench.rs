//! Measure AES-XTS decryption throughput in isolation.
//!
//! Separates three costs that are easy to confuse when only the end-to-end
//! number is visible:
//!
//!   1. raw AES-XTS rate           — one big call, key schedule amortised
//!   2. per-call key schedule      — many small calls, same total bytes
//!   3. whether the backend is hardware AES at all
//!
//! A software (bitsliced) AES backend runs around 100-200 MiB/s. ARMv8 or
//! x86 AES-NI runs at several GiB/s. An order-of-magnitude gap between this
//! and `read_image`'s end-to-end number means the loss is above the cipher.

use luks_core::luks::keyslot::xts_decrypt;
use std::time::Instant;

fn bench(label: &str, total: usize, chunk: usize, sector_size: usize) {
    let key = [0x42u8; 64];
    let mut buf = vec![0u8; total];

    let t = Instant::now();
    let mut tweak = 0u128;
    for c in buf.chunks_mut(chunk) {
        xts_decrypt(&key, c, sector_size, tweak, 1).unwrap();
        tweak += (c.len() / sector_size) as u128;
    }
    let secs = t.elapsed().as_secs_f64();
    let mib = total as f64 / (1024.0 * 1024.0);
    println!(
        "  {label:<34} {:>8.1} MiB/s   ({} calls)",
        mib / secs,
        total.div_ceil(chunk)
    );
}

fn main() {
    println!("target features:");
    for f in ["aes", "neon", "sha2", "sse2", "avx2"] {
        // Compile-time detection: this is what the aes crate keys off.
        let on = match f {
            "aes" => cfg!(target_feature = "aes"),
            "neon" => cfg!(target_feature = "neon"),
            "sha2" => cfg!(target_feature = "sha2"),
            "sse2" => cfg!(target_feature = "sse2"),
            "avx2" => cfg!(target_feature = "avx2"),
            _ => false,
        };
        println!("  {f:<6} {}", if on { "yes" } else { "no" });
    }
    println!("  arch   {}", std::env::consts::ARCH);

    const TOTAL: usize = 256 * 1024 * 1024;

    println!("\nAES-256-XTS decrypt, 512-byte sectors:");
    bench("one 256 MiB call", TOTAL, TOTAL, 512);
    bench("1 MiB calls", TOTAL, 1024 * 1024, 512);
    bench("64 KiB calls", TOTAL, 64 * 1024, 512);
    bench("4 KiB calls  (ext4 block)", TOTAL, 4096, 512);
    bench("1 KiB calls", TOTAL, 1024, 512);

    println!("\nAES-256-XTS decrypt, 4096-byte sectors:");
    bench("one 256 MiB call", TOTAL, TOTAL, 4096);
    bench("4 KiB calls", TOTAL, 4096, 4096);
}
