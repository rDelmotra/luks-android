//! Copy a file onto a real LUKS+btrfs drive. **This writes to hardware.**
//!
//! ```text
//! cargo build --release --features dangerous-write-support --example write_btrfs_to_drive
//! printf 'test' | sudo ./target/release/examples/write_btrfs_to_drive \
//!     /dev/rdiskN <expected-bytes> ./some-file.txt name-on-drive.txt
//! ```
//!
//! The btrfs sibling of `write_to_drive.rs`. Same discipline: the expected
//! byte count is mandatory and is checked against the device before anything
//! is opened for writing (`FileDevice::open_writable`). Get it from
//! `diskutil info diskN` (macOS) or `lsblk -b` (Linux) and read it with your
//! own eyes — that number is the only thing standing between a typo in the
//! device path and the wrong drive.
//!
//! Root-directory writes only — `Btrfs::create_file`/`write_file` refuse
//! anything outside `FS_TREE_OBJECTID` (feature-btrfs-write.md, "not doing
//! this yet"). A filesystem whose free-space tree spans more than one leaf
//! is refused by name (Fix 1, 2026-08-14) rather than silently mishandled —
//! this is the gate that currently keeps large storage devices out of reach; a
//! partition whose free-space tree fits in one leaf is unaffected.

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::Btrfs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::secret::Secret;
use std::io::{IsTerminal, Read};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(device), Some(claim), Some(source), Some(dest)) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!(
            "usage: write_btrfs_to_drive <device> <expected-bytes> <source-file> <name-on-drive>"
        );
        std::process::exit(2);
    };

    let expected: u64 = claim.parse().expect("expected-bytes must be a number");
    let content = std::fs::read(&source).expect("read the source file");

    println!("device   {device}");
    println!("claim    {expected} bytes");
    println!("source   {source} ({} bytes)", content.len());
    println!("dest     /{dest}");

    let password = read_password();
    let result = run(&device, expected, password.expose(), &content, &dest);
    drop(password);

    match result {
        Ok(()) => {
            println!();
            println!("OK — wrote /{dest}. Unplug cleanly, then verify with a Linux");
            println!("kernel rather than with this tool: tools/verify-image.sh, plus");
            println!("a real btrfs scrub — see feature-btrfs-write.md §5 Pass A.");
        }
        Err(e) => {
            eprintln!();
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run(
    device: &str,
    expected: u64,
    password: &[u8],
    content: &[u8],
    dest: &str,
) -> luks_core::error::Result<()> {
    // The size check happens inside here, before a writable descriptor exists.
    let dev = FileDevice::open_writable(device, expected)?;
    println!(
        "opened   writable{}",
        if dev.is_raw() {
            " (raw character device — writes widened to 4 KiB)"
        } else {
            ""
        }
    );

    // Find the LUKS partition rather than assuming partition 1: a real disk
    // can carry an unencrypted partition ahead of the interesting one.
    let table = partition::scan(&dev, 512)?;
    let part = table
        .luks_partitions()
        .next()
        .expect("no LUKS partition on this device");
    let offset = part.offset_bytes();
    let part_len = Some(part.size_bytes());
    println!("luks at  {offset} bytes");

    let header = luks::read_from(&dev, offset)?;
    let volume = LuksVolume::open(&dev, offset, part_len, &header, password)?;
    println!("unlocked");

    let mut fs = Btrfs::mount(volume)?;
    println!(
        "btrfs    fs_tree level {}, node_size {}",
        fs.fs_tree().level,
        fs.superblock().node_size
    );

    fs.create_file_with_data("/", dest, content)?;
    println!("written and flushed");

    Ok(())
}

/// Same handling as `read_image`/`write_to_drive`: never on the command
/// line, since argv is visible to every user on the machine via `ps`.
fn read_password() -> Secret {
    let mut bytes = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("passphrase: ")
            .expect("read passphrase")
            .into_bytes()
    } else {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).expect("read stdin");
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
