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
//! sudo cargo run --release --example read_image -- /dev/rdisk4s3  # prompts
//! printf 'test' | cargo run --release --example read_image -- disk.img  # scripted
//! ```
//!
//! Prefer `/dev/rdiskN` over `/dev/diskN` on macOS. The raw character device
//! measured 722 MiB/s against the buffered node's 132 on the developer's SSD,
//! because the buffered path copies through the page cache for data that is
//! read exactly once. `FileDevice` handles the block-alignment the raw node
//! demands.

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::MountedFs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::secret::Secret;
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read};
use std::time::Instant;

/// Join without doubling the separator at the root.
fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

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
    // A directory gets listed, a file gets read and hashed. Guessing from the
    // filesystem beats making the caller say which, and on btrfs the
    // interesting paths are inside subvolumes, several levels down.
    let target = args.next();

    let password = read_password();

    let result = run(&path, password.expose(), target.as_deref());
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

fn run(path: &str, password: &[u8], target: Option<&str>) -> luks_core::error::Result<()> {
    let dev = FileDevice::open(path)?;
    println!(
        "device  {}  ({:?} bytes){}",
        dev.path(),
        dev.len(),
        if dev.is_raw() {
            "  [raw character device — reads widened to 4 KiB]"
        } else {
            ""
        }
    );
    // A raw device reports no length, so nothing upstream can bounds-check
    // against it. Say so once rather than leaving it to be inferred from a
    // `None` above.
    if dev.is_raw() {
        println!("        (no length reported; bounds checks come from the LUKS header)");
    }

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

    let listing = match target {
        // A directory: list it. A file: fall through and hash it.
        Some(t) => match fs.file_info(t) {
            Ok(info) if info.file_type.is_dir() => Some(t),
            _ => None,
        },
        None => Some("/"),
    };

    if let Some(dir) = listing {
        println!("\n{dir}");
        let mut entries = fs.list_dir(dir)?;
        entries.sort_by(|a, b| {
            b.file_type
                .is_dir()
                .cmp(&a.file_type.is_dir())
                .then_with(|| a.name.cmp(&b.name))
        });
        for e in &entries {
            // Sizes come from a per-entry inode read, which is why the app
            // fetches them lazily; here the whole point is to look around.
            let size = fs
                .file_info(&join(dir, &e.name))
                .map(|i| i.size)
                .unwrap_or(0);
            println!(
                "  {:<9} {:>12}  {}{}",
                format!("{:?}", e.file_type),
                size,
                e.name,
                if e.is_subvolume { "  [subvolume]" } else { "" }
            );
        }
        if target.is_some() {
            println!("\nOK");
            return Ok(());
        }
    }

    if let Some(target) = target {
        // Streamed in 1 MiB chunks rather than slurped: a multi-gigabyte file
        // should not need multi-gigabytes of RAM to hash, and this is the same
        // loop the phone runs, so the throughput number means something.
        let file = fs.open(target)?;
        let size = file.size();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut done = 0u64;

        let t = Instant::now();
        while done < size {
            let want = std::cmp::min(buf.len() as u64, size - done) as usize;
            let got = fs.read_open(&file, done, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            hasher.update(&buf[..got]);
            done += got as u64;
        }
        let secs = t.elapsed().as_secs_f64();

        let mib = done as f64 / (1024.0 * 1024.0);
        println!(
            "\n{target}\n  {done} bytes\n  sha256 {:x}\n  \
             read+decrypt+verify+hash {:.2} s = {:.1} MiB/s",
            hasher.finalize(),
            secs,
            mib / secs
        );
    }

    println!("\nOK");
    Ok(())
}
