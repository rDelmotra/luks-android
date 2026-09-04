//! Read-only probe of a real drive's btrfs superblock and chunk layout.
//!
//! Exists to answer, against a real target rather than a synthetic fixture,
//! the two questions the write engine's scope depends on before any write
//! code exists: which `compat_ro`/`incompat` flags the filesystem actually
//! carries, and whether its metadata chunks are DUP or SINGLE. Read-only
//! end to end — no `dangerous-write-support`, so this crate has no write path
//! compiled in at all when this runs, and it is safe to point at a live,
//! mounted OS install.
//!
//! ```text
//! sudo cargo run --release --example btrfs_probe -- /dev/rdiskNsM
//! ```
//!
//! The passphrase is prompted for with echo off, exactly as `read_image.rs`
//! does, and is never taken from argv or the environment.

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::btrfs::Btrfs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::secret::Secret;
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};

// BTRFS_FEATURE_COMPAT_RO_* — checked against
// include/uapi/linux/btrfs.h, not guessed: FREE_SPACE_TREE 1<<0,
// FREE_SPACE_TREE_VALID 1<<1, VERITY 1<<2, BLOCK_GROUP_TREE 1<<3.
const RO_FREE_SPACE_TREE: u64 = 0x1;
const RO_FREE_SPACE_TREE_VALID: u64 = 0x2;
const RO_VERITY: u64 = 0x4;
const RO_BLOCK_GROUP_TREE: u64 = 0x8;

// BTRFS_BLOCK_GROUP_* — same constants `core::fs::btrfs::chunk` uses
// internally; only DATA/SYSTEM/METADATA are exported from there, so the
// profile bits are re-declared here for display purposes only.
const DATA: u64 = 0x1;
const SYSTEM: u64 = 0x2;
const METADATA: u64 = 0x4;
const RAID0: u64 = 0x8;
const RAID1: u64 = 0x10;
const DUP: u64 = 0x20;
const RAID10: u64 = 0x40;
const RAID5: u64 = 0x80;
const RAID6: u64 = 0x100;
const RAID1C3: u64 = 0x200;
const RAID1C4: u64 = 0x400;

fn describe_profile(t: u64) -> String {
    let mut kind = Vec::new();
    if t & DATA != 0 {
        kind.push("DATA");
    }
    if t & SYSTEM != 0 {
        kind.push("SYSTEM");
    }
    if t & METADATA != 0 {
        kind.push("METADATA");
    }

    let mut profile = Vec::new();
    if t & RAID0 != 0 {
        profile.push("RAID0");
    }
    if t & RAID1 != 0 {
        profile.push("RAID1");
    }
    if t & DUP != 0 {
        profile.push("DUP");
    }
    if t & RAID10 != 0 {
        profile.push("RAID10");
    }
    if t & RAID5 != 0 {
        profile.push("RAID5");
    }
    if t & RAID6 != 0 {
        profile.push("RAID6");
    }
    if t & RAID1C3 != 0 {
        profile.push("RAID1C3");
    }
    if t & RAID1C4 != 0 {
        profile.push("RAID1C4");
    }
    if profile.is_empty() {
        profile.push("SINGLE");
    }

    format!("{}|{}", kind.join("+"), profile.join("+"))
}

// Identical to read_image.rs's read_password: prompted with echo off on a
// terminal, read from stdin otherwise. Never argv, never the environment.
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
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Secret::new(bytes)
}

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: btrfs_probe <image|device>");
            eprintln!("       the passphrase is prompted for, or piped in on stdin");
            std::process::exit(2);
        }
    };

    let password = read_password();
    let result = run(&path, password.expose());
    drop(password);

    if let Err(e) = result {
        eprintln!("\nFAILED: {e}");
        std::process::exit(1);
    }
}

fn run(path: &str, password: &[u8]) -> luks_core::error::Result<()> {
    let dev = FileDevice::open(path)?;
    println!(
        "device  {path}  ({:?} bytes){}",
        dev.len(),
        if dev.is_raw() {
            "  [raw character device]"
        } else {
            ""
        }
    );

    let (offset, part_len) = match partition::scan(&dev, 512) {
        Ok(table) => match table.luks_partitions().next() {
            Some(p) => (p.offset_bytes(), Some(p.size_bytes())),
            None => (0, None),
        },
        Err(_) => (0, None),
    };
    println!("luks at offset {offset} ({} MiB)", offset / (1024 * 1024));

    let header = luks::read_from(&dev, offset)?;
    let volume = LuksVolume::open(&dev, offset, part_len, &header, password)?;
    println!("unlocked");

    let btrfs = Btrfs::mount(&volume)?;
    let sb = btrfs.superblock();

    println!("\n--- superblock ---");
    println!("label            {:?}", btrfs.label());
    println!("fsid             {:02x?}", btrfs.fsid());
    println!("generation       {}", sb.generation);
    println!("sector_size      {}", sb.sector_size);
    println!("node_size        {}", sb.node_size);
    println!("csum_type        {:?}", sb.csum_type);
    println!("total_bytes      {}", sb.total_bytes);
    println!("bytes_used       {}", sb.bytes_used);
    println!("num_devices      {}", sb.num_devices);
    println!("incompat_flags   0x{:x}", sb.incompat_flags);
    println!(
        "compat_ro_flags  0x{:x}  free_space_tree={} free_space_tree_valid={} \
         block_group_tree={} verity={}",
        sb.compat_ro_flags,
        sb.compat_ro_flags & RO_FREE_SPACE_TREE != 0,
        sb.compat_ro_flags & RO_FREE_SPACE_TREE_VALID != 0,
        sb.compat_ro_flags & RO_BLOCK_GROUP_TREE != 0,
        sb.compat_ro_flags & RO_VERITY != 0,
    );

    println!("\n--- subvolumes ---");
    for s in btrfs.subvolumes()? {
        println!(
            "  {:>6}  {}{}",
            s.id,
            s.path,
            if s.is_read_only() { "  (read-only)" } else { "" }
        );
    }

    println!("\n--- chunk profiles ({} chunks) ---", btrfs.chunk_map().len());
    let mut profiles: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for c in btrfs.chunk_map().chunks() {
        let e = profiles.entry(describe_profile(c.chunk_type)).or_insert((0, 0));
        e.0 += 1;
        e.1 += c.length;
    }
    for (profile, (count, bytes)) in profiles {
        println!(
            "  {:<28} {:>4} chunks  {:>10} MiB",
            profile,
            count,
            bytes / (1024 * 1024)
        );
    }

    println!("\nOK");
    Ok(())
}
