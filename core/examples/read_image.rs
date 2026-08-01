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
//! The passphrase is read from **stdin**, never argv or the environment, so it
//! does not show up in `ps` or in a shell history.
//!
//! ```text
//! printf 'test' | cargo run --release --example read_image -- disk.img
//! printf 'test' | cargo run --release --example read_image -- disk.img /bigfile.bin
//! ```

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::Ext4;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: printf 'password' | read_image <image|device> [file-to-hash]");
            std::process::exit(2);
        }
    };
    let hash_target = args.next();

    let mut password = Vec::new();
    std::io::stdin()
        .read_to_end(&mut password)
        .expect("read password from stdin");
    // Tolerate a trailing newline from `echo`, since getting that wrong looks
    // exactly like a wrong password.
    if password.last() == Some(&b'\n') {
        password.pop();
    }
    if password.last() == Some(&b'\r') {
        password.pop();
    }

    if let Err(e) = run(&path, &password, hash_target.as_deref()) {
        eprintln!("\nFAILED: {e}");
        std::process::exit(1);
    }
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

    let fs = Ext4::mount(&volume)?;
    println!("ext4    label {:?}", fs.volume_name());

    for e in fs.list_dir("/")? {
        println!("  {:?} {}", e.file_type, e.name);
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
