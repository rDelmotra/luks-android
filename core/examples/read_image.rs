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
//! sudo cargo run --release --example read_image -- /dev/rdiskNsM  # prompts
//! printf 'test' | cargo run --release --example read_image -- disk.img  # scripted
//! ```
//!
//! Prefer `/dev/rdiskN` over `/dev/diskN` on macOS. The raw character device
//! measured 722 MiB/s against the buffered node's 132 on the developer's storage device,
//! because the buffered path copies through the page cache for data that is
//! read exactly once. `FileDevice` handles the block-alignment the raw node
//! demands.

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::MountedFs;
use luks_core::luks::{self, LuksVolume};
use luks_core::partition;
use luks_core::secret::Secret;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{IsTerminal, Read};
use std::time::{Duration, Instant};

/// Counts and times every read that reaches the device.
///
/// This exists because the performance story was being told by subtraction —
/// "total minus what I think the CPU costs" — and subtraction produced two
/// numbers that could not both be true: an estimated 1.2 s of CPU nobody could
/// name, and a buffered device apparently reading faster than `dd` manages on
/// the same node. Either the estimate was wrong or the assumption about read
/// sizes was. Measuring directly settles which.
///
/// The size histogram is the part that matters most. `dd` reads in 1 MiB
/// blocks; we read 16 KiB btrfs nodes and whatever the extent map hands back.
/// A raw character device has no cache to hide small reads behind, so if the
/// distribution is dominated by small reads then the fix is to read in bigger
/// pieces, not to shave allocations.
///
/// `Cell` rather than atomics: this is a single-threaded diagnostic, and the
/// counters must not cost enough to distort what they measure.
struct Timed<D: ReadAt> {
    inner: D,
    time: Cell<Duration>,
    reads: Cell<u64>,
    bytes: Cell<u64>,
    /// Buckets by request size: <=4K, 8K, 16K, 32K, 64K, 128K, 256K, larger.
    hist: [Cell<u64>; 8],
}

#[derive(Clone, Copy)]
struct Snapshot {
    time: Duration,
    reads: u64,
    bytes: u64,
}

impl<D: ReadAt> Timed<D> {
    fn new(inner: D) -> Self {
        Self {
            inner,
            time: Cell::new(Duration::ZERO),
            reads: Cell::new(0),
            bytes: Cell::new(0),
            hist: std::array::from_fn(|_| Cell::new(0)),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            time: self.time.get(),
            reads: self.reads.get(),
            bytes: self.bytes.get(),
        }
    }

    /// What happened between two snapshots, so the unlock's reads do not get
    /// counted against the file read.
    fn since(&self, start: Snapshot) -> Snapshot {
        let now = self.snapshot();
        Snapshot {
            time: now.time - start.time,
            reads: now.reads - start.reads,
            bytes: now.bytes - start.bytes,
        }
    }

    fn print_histogram(&self) {
        const LABELS: [&str; 8] = [
            "<= 4 KiB", "8 KiB", "16 KiB", "32 KiB", "64 KiB", "128 KiB", "256 KiB", "> 256 KiB",
        ];
        // Cumulative over the whole run. The unlock contributes a couple of
        // dozen reads against tens of thousands, so it does not move the shape.
        println!("  read sizes (whole run):");
        for (label, count) in LABELS.iter().zip(&self.hist) {
            if count.get() > 0 {
                println!("    {:>9}  {:>9}", label, count.get());
            }
        }
    }
}

impl<D: ReadAt> ReadAt for Timed<D> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> luks_core::error::Result<()> {
        let bucket = match buf.len() {
            0..=4096 => 0,
            4097..=8192 => 1,
            8193..=16384 => 2,
            16385..=32768 => 3,
            32769..=65536 => 4,
            65537..=131072 => 5,
            131073..=262144 => 6,
            _ => 7,
        };
        self.hist[bucket].set(self.hist[bucket].get() + 1);
        self.reads.set(self.reads.get() + 1);
        self.bytes.set(self.bytes.get() + buf.len() as u64);

        let t = Instant::now();
        let r = self.inner.read_at(offset, buf);
        self.time.set(self.time.get() + t.elapsed());
        r
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

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
    let raw = FileDevice::open(path)?;
    println!(
        "device  {}  ({:?} bytes){}",
        raw.path(),
        raw.len(),
        if raw.is_raw() {
            "  [raw character device — reads widened to 4 KiB]"
        } else {
            ""
        }
    );
    // A raw device reports no length, so nothing upstream can bounds-check
    // against it. Say so once rather than leaving it to be inferred from a
    // `None` above.
    if raw.is_raw() {
        println!("        (no length reported; bounds checks come from the LUKS header)");
    }
    let dev = Timed::new(raw);

    // A whole disk has a partition table; a bare container does not. Try for a
    // table, and fall back to treating the whole thing as one LUKS volume.
    let (offset, part_len) = match partition::scan(&dev, 512) {
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
                Some(p) => (p.offset_bytes(), Some(p.size_bytes())),
                None => {
                    println!("no LUKS partition in the table; trying offset 0");
                    (0, None)
                }
            }
        }
        Err(e) => {
            println!("table   none ({e}); treating as a bare container");
            (0, None)
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
    let volume = LuksVolume::open(&dev, offset, part_len, &header, password)?;
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
    // a standard Linux install keeps / and /home in separate subvolumes.
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
        let mut hash_time = Duration::ZERO;

        // Everything before this point — partition scan, header, unlock,
        // mount, subvolume walk — is metadata, and counting it against the
        // file read is what made the earlier arithmetic disagree with itself.
        let mark = dev.snapshot();
        let t = Instant::now();
        while done < size {
            let want = std::cmp::min(buf.len() as u64, size - done) as usize;
            let got = fs.read_open(&file, done, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            let h = Instant::now();
            hasher.update(&buf[..got]);
            hash_time += h.elapsed();
            done += got as u64;
        }
        let secs = t.elapsed().as_secs_f64();
        let io = dev.since(mark);

        let mib = done as f64 / (1024.0 * 1024.0);
        println!(
            "\n{target}\n  {done} bytes\n  sha256 {:x}\n  \
             read+decrypt+verify+hash {:.2} s = {:.1} MiB/s",
            hasher.finalize(),
            secs,
            mib / secs
        );

        // The three buckets that were previously estimated. "Everything else"
        // is the LUKS decrypt, the extent walk, the csum verification and every
        // memory copy between them — whatever is left once the two costs we
        // can name are removed.
        let io_secs = io.time.as_secs_f64();
        let hash_secs = hash_time.as_secs_f64();
        let rest = secs - io_secs - hash_secs;
        let io_mib = io.bytes as f64 / (1024.0 * 1024.0);
        println!("\nwhere the {secs:.2} s went");
        println!(
            "  device I/O      {:>6.2} s  {:>4.0}%   {:>8} reads, {:.1} MiB at {:.0} MiB/s",
            io_secs,
            100.0 * io_secs / secs,
            io.reads,
            io_mib,
            io_mib / io_secs
        );
        println!(
            "  SHA-256         {:>6.2} s  {:>4.0}%",
            hash_secs,
            100.0 * hash_secs / secs
        );
        println!(
            "  everything else {:>6.2} s  {:>4.0}%   decrypt + extents + csums + copies",
            rest,
            100.0 * rest / secs
        );
        // Read amplification: bytes pulled off the device per byte of file.
        // Anything well above 1.0 means the reader is fetching the same data
        // twice, or fetching far more than it needs per request.
        println!(
            "  amplification   {:>6.2}x  (device bytes per file byte)",
            io.bytes as f64 / done as f64
        );
        if let Some((hits, misses)) = fs.cache_stats() {
            let total = hits + misses;
            println!(
                "  node cache      {:>6.1}% hit   {hits} hits, {misses} misses",
                if total == 0 {
                    0.0
                } else {
                    100.0 * hits as f64 / total as f64
                }
            );
        }
        dev.print_histogram();
    }

    println!("\nOK");
    Ok(())
}
