//! Copy a file onto a real LUKS+ext4 drive. **This writes to hardware.**
//!
//! ```text
//! cargo build --release --features dangerous-write-support --example write_to_drive
//! printf 'test' | sudo ./target/release/examples/write_to_drive \
//!     /dev/rdisk4 61524148224 ./some-file.txt name-on-drive.txt
//! ```
//!
//! The expected byte count is mandatory and is checked against the device
//! before anything is opened for writing — see `FileDevice::open_writable`.
//! Get it from `diskutil info diskN` (macOS) or `lsblk -b` (Linux) and read it
//! with your own eyes; that number is the only thing standing between a typo
//! in the device path and the wrong drive.
//!
//! Deliberately minimal: no file picker, no progress bar, no recursion. It
//! exists to put the write path on real hardware for the first time, where the
//! things a fixture cannot reproduce live — a raw character device that
//! refuses unaligned writes, a 4 GiB filesystem with 33 block groups instead
//! of a 3 MiB one with a single group, and most of those groups flagged
//! BLOCK_UNINIT so the allocator has to skip them.

use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
use luks_core::fs::FileType;
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
            "usage: write_to_drive <device> <expected-bytes> <source-file> <name-on-drive>"
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
        Ok(ino) => {
            println!();
            println!("OK — wrote inode {ino}. Unplug cleanly, then verify with a Linux");
            println!("kernel rather than with this tool. See STATE.md.");
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
) -> luks_core::error::Result<u64> {
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

    let mut fs = Ext4::mount(volume)?;
    println!(
        "ext4     {} block groups, {} blocks free",
        fs.groups().len(),
        fs.superblock().free_blocks_count
    );

    // One call, not `write_new_file` then `link_file`: the two-call sequence
    // leaves an allocated, unreferenced inode behind if the link fails — most
    // often because the name is already taken, which is what happens the
    // second time this is run with the same arguments.
    let ino = fs.create_file(2, dest, content, FileType::Regular)?;

    // Without this the write can still be sitting in a cache when the cable
    // comes out, which is the normal way a person ends a transfer.
    fs.flush()?;
    println!("flushed");

    Ok(ino)
}

/// Same handling as `read_image`: never on the command line, since argv is
/// visible to every user on the machine via `ps`.
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
