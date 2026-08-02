//! Read a LUKS image or block device from the host and verify it.
//!
//! Exercises the whole stack except the USB transport: partition scan, LUKS
//! header parse, unlock, ext4 mount, file read. Because it runs natively it is
//! the fastest way to tell a bug in the *storage* layer apart from a bug in the
//! *transport* layer — if this passes on an image and the phone fails on the
//! same bytes, the fault is in the usbfs code.
//!
//! It also times the decrypt, which measures AES-XTS throughput independently
//! of USB. That ceiling matters: software AES that only manages 200 MB/s caps
//! the product no matter how fast the bus is.
//!
//! The passphrase is **never** taken from argv or the environment. On a
//! terminal it is prompted for with echo off, exactly as cryptsetup does;
//! piped in, it is read from stdin. Both matter for different reasons: argv is
//! visible in `ps` to every user on the machine, and a passphrase typed into a
//! shell pipeline lands in `~/.zsh_history` where it outlives the session.
//!
//! ```text
//! sudo cargo run --release --example read_image -- /dev/disk4s3   # prompts
//! printf 'test' | cargo run --release --example read_image -- disk.img  # scripted
//! ```

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::MountedFs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::secret::Secret;
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: read_image <image|device> [file-to-hash]");
            eprintln!("       the passphrase is prompted for, or piped in on stdin");
            std::process::exit(2);
        }
    };
    let hash_target = args.next();

    let password = read_password();

    let result = run(&path, password.expose(), hash_target.as_deref());
    // `password` is a Secret: dropping it zeroes the bytes. Dropped here
    // explicitly rather than at the end of main, so it is gone before the
    // process spends any time printing.
    drop(password);

    if let Err(e) = result {
        eprintln!("\nFAILED: {e}");
        std::process::exit(1);
    }
}

/// Prompt with echo off when there is a terminal; otherwise read stdin.
///
/// `String::into_bytes` reuses the allocation rather than copying, so the
/// prompted passphrase exists as exactly one buffer, which `Secret` then zeroes
/// on drop. What this cannot control is whether `rpassword` reallocated its
/// buffer while reading — a freed copy could linger. That is acceptable for a
/// host-side diagnostic on the developer's own machine and would not be on the
/// phone, where the password never becomes a String at all.
fn read_password() -> Secret {
    let mut bytes = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("passphrase: ")
            .expect("read passphrase from the terminal")
            .into_bytes()
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .expect("read passphrase from stdin");
        buf
    };

    // Tolerate a trailing newline from `echo`, since getting that wrong looks
    // exactly like a wrong password.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Secret::new(bytes)
}

fn run(path: &str, password: &[u8], hash_target: Option<&str>) -> luks_core::error::Result<()> {
    let dev = FileDevice::open(path)?;
    println!("device  {}  ({:?} bytes)", dev.path(), dev.len());

    // A whole disk has a partition table; a bare container does not. Try for a
    // table, and fall back to treating the whole thing as one LUKS volume.
    let offset = match partition::scan(&dev, 512) {
        Ok(table) => {
            println!("table   {:?}, {} partitions", table.kind, table.partitions.len());
            for p in &table.partitions {
                println!(
                    "  {}: lba {:>10}  {:>6} MiB  luks={}  {}",
                    p.index,
                    p.start_lba,
                    p.size_bytes() / (1024 * 1024),
                    p.is_luks,
                    p.name
                );
            }
            match table.luks_partitions().next() {
                Some(p) => p.offset_bytes(),
                None => {
                    println!("no LUKS partition in the table; trying offset 0");
                    0
                }
            }
        }
        Err(e) => {
            println!("table   none ({e}); treating as a bare container");
            0
        }
    };
    println!("luks at offset {offset} ({} MiB)", offset / (1024 * 1024));

    let header = luks::read_from(&dev, offset)?;
    let seg = header.primary_segment()?;
    println!(
        "header  {} keyslots, {}, sector {}, tweak step {}",
        header.metadata.keyslots.len(),
        seg.encryption,
        seg.sector_size,
        seg.tweak_step()
    );

    let t = Instant::now();
    let volume = LuksVolume::open(&dev, offset, &header, password)?;
    println!("unlock  {:.2} s", t.elapsed().as_secs_f64());

    // Which filesystem it is, decided by signature — the same call the phone
    // makes, so a failure here is a failure there.
    let fs = MountedFs::mount(&volume)?;
    println!(
        "fs      {}, label {:?}",
        fs.kind().name(),
        fs.label().unwrap_or("(none)")
    );

    // On btrfs the interesting content usually is not in the top-level tree:
    // a Fedora install keeps / and /home in separate subvolumes.
    let subvols = fs.subvolumes()?;
    if !subvols.is_empty() {
        println!("subvolumes ({}):", subvols.len());
        for s in &subvols {
            println!(
                "  {:>6}  {}{}",
                s.id,
                s.path,
                if s.is_read_only() { "  (read-only)" } else { "" }
            );
        }
    }

    for e in fs.list_dir("/")? {
        println!(
            "  {:?} {}{}",
            e.file_type,
            e.name,
            if e.is_subvolume { "  [subvolume]" } else { "" }
        );
    }

    if let Some(target) = hash_target {
        let t = Instant::now();
        let data = fs.read_file(target)?;
        let secs = t.elapsed().as_secs_f64();
        let mib = data.len() as f64 / (1024.0 * 1024.0);
        let digest = Sha256::digest(&data);
        println!(
            "\n{target}\n  {} bytes\n  sha256 {:x}\n  read+decrypt {:.2} s = {:.1} MiB/s",
            data.len(),
            digest,
            secs,
            mib / secs
        );
    }

    println!("\nOK");
    Ok(())
}
