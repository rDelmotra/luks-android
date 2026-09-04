//! Measures Argon2id cost at standard 1 GiB reference parameters.
//!
//!   cargo run --release --example argon2_bench
//!
//! Two questions this answers:
//!
//! 1. **Does RustCrypto's `argon2` parallelize the lanes?** Argon2 with p=4 does
//!    the same total work as p=1 over the same memory. If lanes run
//!    concurrently, p=4 is several times faster in wall-clock. If they are
//!    walked sequentially, the times match — which would mean the drive's p=4
//!    buys us nothing and unlock is ~4x slower than a naive estimate suggests.
//!
//! 2. **Roughly how long does a 1 GiB derivation take?** This is a Mac, so the
//!    absolute number is optimistic for a Pixel 8 — but it establishes the order
//!    of magnitude and the shape of the memory/time curve.

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

fn run(label: &str, m_kib: u32, t: u32, p: u32) {
    let params = match Params::new(m_kib, t, p, Some(32)) {
        Ok(p) => p,
        Err(e) => {
            println!("{label:<28} SKIPPED ({e})");
            return;
        }
    };
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    let start = Instant::now();
    let result = a2.hash_password_into(b"correct horse battery staple", &[0x42; 16], &mut out);
    let elapsed = start.elapsed();

    match result {
        Ok(()) => println!(
            "{label:<28} m={m_kib:>8} KiB  t={t}  p={p}   {:>8.2} s",
            elapsed.as_secs_f64()
        ),
        Err(e) => println!("{label:<28} FAILED: {e}"),
    }
}

fn main() {
    println!("Argon2id — RustCrypto argon2 {}\n", env!("CARGO_PKG_VERSION"));

    println!("--- parallelism check (same memory and passes, differing lanes) ---");
    run("p=1", 262_144, 4, 1);
    run("p=2", 262_144, 4, 2);
    run("p=4", 262_144, 4, 4);
    println!("  Equal times => lanes are sequential, p buys nothing.\n");

    println!("--- the drive's actual parameters ---");
    run("REAL: 1 GiB t=4 p=4", 1_048_576, 4, 4);
    println!();

    println!("--- memory scaling ---");
    for m in [65_536u32, 262_144, 524_288, 1_048_576] {
        run(&format!("{} MiB", m / 1024), m, 4, 4);
    }

    println!("\nNote: measured on Apple Silicon. A Pixel 8 will be slower —");
    println!("Argon2 is memory-bandwidth bound and phone LPDDR is well behind.");
}
