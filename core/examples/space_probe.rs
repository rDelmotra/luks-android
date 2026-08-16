//! Print a btrfs volume's real free space, block group by block group — **read-only**.
//!
//! ```text
//! cargo run --features dangerous-write-support --example space_probe -- <image> [password]
//! ```
//!
//! Run this first when a write fails with "no space left on the filesystem".
//!
//! That error is `LuksError::FilesystemFull`, and the write path raises it for
//! two very different reasons: the allocator genuinely could not find a free
//! range, or **an item did not fit in a 16 KiB tree node**. The second is not a
//! space problem at all, and this tool is how you tell them apart in one step
//! instead of guessing. Measured 2026-08-16: a 20 MB file write reported "no
//! space" on a stick with 405 MiB free and one contiguous 405 MiB run — the
//! real cause was a single `EXTENT_CSUM` item too large for one leaf (see
//! `INCIDENTS.md`, and `feature-btrfs-write.md` §10).
//!
//! So: if this prints plenty of free space and a write still fails, the
//! failure is a node-capacity limit, not the disk.
//!
//! Read-only — it opens the device writable only because `Btrfs::mount` is
//! generic over the device and the write-side allocator types need that bound;
//! nothing here writes, and it never builds a transaction.

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::write::alloc::FreeSpaceMap;
use luks_core::fs::btrfs::write::extent_tree::ExtentTree;
use luks_core::fs::btrfs::Btrfs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;

const MIB: u64 = 1024 * 1024;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: space_probe <image> [password]");
        eprintln!("       omit the password for a bare (non-LUKS) btrfs image");
        std::process::exit(2);
    };
    let password = args.next();

    let len = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .len();
    let dev = FileDevice::open_writable(&path, len).expect("open");

    // A bare image has no partition table and no LUKS header; a stick image has
    // both. Decide by looking, rather than by taking a flag that can be wrong.
    match password {
        Some(pw) => {
            let table = partition::scan(&dev, 512).expect("scan partition table");
            let part = table
                .luks_partitions()
                .next()
                .expect("no LUKS partition on this image");
            let header = luks::read_from(&dev, part.offset_bytes()).expect("luks header");
            let volume = LuksVolume::open(
                &dev,
                part.offset_bytes(),
                Some(part.size_bytes()),
                &header,
                pw.as_bytes(),
            )
            .expect("unlock");
            report(&Btrfs::mount(volume).expect("mount"));
        }
        None => report(&Btrfs::mount(dev).expect("mount")),
    }
}

fn report<D: luks_core::device::ReadAt>(fs: &Btrfs<D>) {
    let node_size = fs.superblock().node_size;
    let sector_size = fs.superblock().sector_size;
    println!("node_size {node_size}  sector_size {sector_size}");

    let extent_tree = ExtentTree::read(fs).expect("read extent tree");
    let map = FreeSpaceMap::from_extent_tree_and_chunk_map(&extent_tree, fs.chunk_map()).expect("derive free space map");

    let mut total_free = 0u64;
    for bg in &map.block_groups {
        let f = bg.block_group.flags;
        let mut kind = Vec::new();
        if f & 0x1 != 0 {
            kind.push("DATA");
        }
        if f & 0x2 != 0 {
            kind.push("SYSTEM");
        }
        if f & 0x4 != 0 {
            kind.push("METADATA");
        }
        let profile = if f & 0x20 != 0 { "DUP" } else { "single" };

        println!(
            "\n{:<16} {:>6} MiB total  {:>6} MiB used  {:>6} MiB free   ({} free ranges)",
            format!("{}|{}", kind.join("+"), profile),
            bg.block_group.length / MIB,
            bg.block_group.used / MIB,
            bg.total_free_bytes / MIB,
            bg.free_ranges.len(),
        );

        // Largest first: a write needs one *contiguous* run, so the biggest
        // single range is what decides whether it fits, not the total.
        let mut ranges = bg.free_ranges.clone();
        ranges.sort_by_key(|r| std::cmp::Reverse(r.length));
        for r in ranges.iter().take(3) {
            println!(
                "    largest free run  {:>10} bytes ({} MiB) at {:#x}",
                r.length,
                r.length / MIB,
                r.start
            );
        }
        total_free += bg.total_free_bytes;
    }

    // The ceiling that is not about space at all. One EXTENT_CSUM item holds
    // csum_size bytes per sector for the whole extent, and it must fit in one
    // leaf — so file size is capped well below whatever free space says.
    let csum_size = fs.superblock().csum_type.size() as u64;
    let usable = node_size as u64 - 101 /* header */ - 25 /* one item descriptor */;
    let max_file = usable / csum_size * sector_size as u64;

    println!("\n{:-<70}", "");
    println!("total free across all block groups: {} MiB", total_free / MIB);
    println!(
        "single-item checksum ceiling:       ~{} MiB per file",
        max_file / MIB
    );
    println!(
        "  ({} usable bytes in a {}-byte leaf / {} bytes per {}-byte sector)",
        usable, node_size, csum_size, sector_size
    );
    println!(
        "A write larger than that ceiling fails as FilesystemFull no matter how\n\
         much space is free — see INCIDENTS.md 2026-08-16."
    );
}
