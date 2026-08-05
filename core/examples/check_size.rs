//! Verify the write-target size check against a real device — **read-only**.
//!
//! ```text
//! cargo build --release --example check_size
//! sudo ./target/release/examples/check_size /dev/rdisk4 61524148224
//! ```
//!
//! Exists because the check in `FileDevice::open_writable` cannot be tested on
//! a raw device from `cargo test`: opening one needs root, and a test that
//! needed root would simply be skipped and rot. `seek(SeekFrom::End)` reporting
//! 0 on `/dev/rdisk4` was found this way, after being assumed to work.
//!
//! This opens the device **read-only** and never writes, so it is safe to point
//! at anything, including a disk holding real data.

use luks_core::device::{FileDevice, ReadAt};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(claim)) = (args.next(), args.next()) else {
        eprintln!("usage: check_size <device> <expected-bytes>");
        std::process::exit(2);
    };
    let expected: u64 = claim.parse().expect("expected-bytes must be a number");

    let dev = match FileDevice::open(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot open {path}: {e}");
            std::process::exit(2);
        }
    };

    println!("device   {path}");
    println!("raw      {}", if dev.is_raw() { "yes — reads widened" } else { "no" });
    println!("metadata {:?}  (0 or None is normal for a device node)", dev.len());
    println!("claim    {expected} bytes");

    // Exactly what open_writable does, spelled out so the answer is legible.
    let mut byte = [0u8; 1];
    let last_ok = dev.read_at(expected - 1, &mut byte).is_ok();
    let past_ok = dev.read_at(expected, &mut byte).is_ok();

    println!();
    println!("read at {:>16} (last byte)  -> {}", expected - 1, yn(last_ok));
    println!("read at {:>16} (one past)   -> {}", expected, yn(past_ok));
    println!();

    match (last_ok, past_ok) {
        (true, false) => println!("VERDICT: the claim is exactly right — the check works on this device"),
        (false, _) => println!("VERDICT: device is SMALLER than claimed (or unreadable there)"),
        (true, true) => println!("VERDICT: device is LARGER than claimed"),
    }

    // A deliberately wrong claim must be rejected, or the check is vacuous —
    // a device that answered "yes" to every read would pass the test above.
    let bogus = expected + 4096;
    let bogus_last = dev.read_at(bogus - 1, &mut byte).is_ok();
    println!();
    println!(
        "control: a claim 4096 bytes too large is {} (must be rejected)",
        if bogus_last { "ACCEPTED — CHECK IS VACUOUS" } else { "rejected" }
    );
}

fn yn(b: bool) -> &'static str {
    if b {
        "ok"
    } else {
        "failed"
    }
}
