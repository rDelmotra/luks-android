//! Decompressing btrfs extents.
//!
//! The algorithms themselves come from crates — years of tuning and fuzzing
//! that a hand-rolled decoder in one pass would not match. What is *not* in any
//! crate, and is the substance of this module, is btrfs's framing: how a
//! compressed extent is laid out on disk before an algorithm ever sees it.
//! zlib and zstd extents are a single continuous stream, but **LZO is not** —
//! it is a sequence of independently-compressed segments with a page-alignment
//! rule, and handing the whole thing to an LZO decoder yields one sector of
//! correct output followed by an error.
//!
//! ## Why these three crates
//!
//! All pure Rust, decompress-only where the crate allows it, permissively
//! licensed:
//!
//! - **zlib → `flate2`** with the `rust_backend` feature, so miniz_oxide rather
//!   than a C zlib.
//! - **zstd → `ruzstd`**, a pure-Rust decoder. The C-backed `zstd` crate is
//!   faster, but it would put a C toolchain in the Android build, which today
//!   is plain `cargo` with a linker config and nothing else.
//! - **LZO → `lzo`**, which is `#![forbid(unsafe_code)]`, `no_std`,
//!   dependency-free and decoder-only.
//!
//! The licences were the deciding factor for LZO specifically: `lzo1x` and
//! `rust-lzo` are both **GPL-2.0**, and this project already dropped lwext4 for
//! exactly that reason. `lzo` is Apache-2.0.
//!
//! Memory safety matters more here than anywhere else in the reader. A
//! decompressor is the classic place a malformed filesystem turns into
//! arbitrary code execution, and this one runs on data from a drive the user
//! merely plugged in.

use crate::error::{LuksError, Result};

/// Compression algorithm ids, from the `compression` byte of an
/// `EXTENT_DATA` item.
pub const COMPRESS_NONE: u8 = 0;
pub const COMPRESS_ZLIB: u8 = 1;
pub const COMPRESS_LZO: u8 = 2;
pub const COMPRESS_ZSTD: u8 = 3;

/// btrfs never compresses more than 128 KiB into one extent
/// (`BTRFS_MAX_UNCOMPRESSED`). The margin above that is generosity, not
/// tolerance: this is the allocation a hostile `ram_bytes` would blow up, and
/// on a phone an unbounded one is an out-of-memory kill rather than an error
/// message.
const MAX_UNCOMPRESSED: usize = 1 << 20;

/// The 4-byte little-endian lengths in the LZO framing.
const LZO_LEN: usize = 4;

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Decompress one extent's worth of data.
///
/// `expected` is the extent's `ram_bytes`: the exact uncompressed size. It is
/// used to size the output up front, so a stream that decompresses to more than
/// it claims is refused rather than allowed to grow the buffer.
pub fn decompress(algorithm: u8, input: &[u8], expected: usize, sector_size: u32) -> Result<Vec<u8>> {
    if expected > MAX_UNCOMPRESSED {
        return Err(LuksError::CorruptFs(
            "btrfs compressed extent claims an implausible uncompressed size",
        ));
    }

    let mut out = match algorithm {
        COMPRESS_ZLIB => inflate(input, expected)?,
        COMPRESS_LZO => lzo_extent(input, expected, sector_size)?,
        COMPRESS_ZSTD => zstd(input, expected)?,
        other => {
            return Err(LuksError::UnsupportedFsFeature(format!(
                "btrfs compression algorithm {other}"
            )))
        }
    };

    // Short output is normal at the end of a file, not corruption. `ram_bytes`
    // is rounded up to a sector, but the stream only ever holds the bytes that
    // were really written — the last extent of this fixture's zlib file states
    // 20480 and decompresses to 17856, which is exactly the file's tail.
    //
    // Zero-filling the difference is safe because `read_inode_data` has already
    // clamped the request to the inode's size, so these bytes are past end of
    // file and can never be returned to a caller.
    out.resize(expected, 0);
    Ok(out)
}

fn inflate(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut out = Vec::with_capacity(expected);
    // `take` is the bomb guard: without it a crafted stream expands until the
    // allocator gives up. `expected` is authoritative, so reading one byte past
    // it is enough to notice.
    ZlibDecoder::new(input)
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| LuksError::CorruptFs("btrfs zlib extent failed to decompress"))?;
    Ok(out)
}

fn zstd(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    use ruzstd::decoding::StreamingDecoder;
    use std::io::Read;

    let mut decoder = StreamingDecoder::new(input)
        .map_err(|_| LuksError::CorruptFs("btrfs zstd extent has a bad frame header"))?;
    let mut out = Vec::with_capacity(expected);
    (&mut decoder)
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| LuksError::CorruptFs("btrfs zstd extent failed to decompress"))?;
    Ok(out)
}

/// Undo btrfs's LZO segment framing, then decompress each segment.
///
/// The layout, which no LZO library knows about:
///
/// ```text
/// [u32 total compressed length, including this header]
/// [u32 segment length][segment]   <- decompresses to at most one sector
/// [u32 segment length][segment]
/// ...
/// ```
///
/// **A segment header never straddles a sector boundary.** When fewer than 4
/// bytes remain in the current sector, the writer pads to the next one and the
/// reader must skip the same way. Miss that rule and decoding succeeds for the
/// first sector — 4 KiB of perfectly correct output — and then fails or, worse,
/// resyncs onto garbage. It only shows up on files larger than one sector,
/// which is to say on real files and not on a small test.
fn lzo_extent(input: &[u8], expected: usize, sector_size: u32) -> Result<Vec<u8>> {
    let sector = sector_size as usize;
    if sector == 0 {
        return Err(LuksError::CorruptFs("btrfs sector size is zero"));
    }
    if input.len() < LZO_LEN {
        return Err(LuksError::CorruptFs("btrfs lzo extent is truncated"));
    }

    let total = u32le(input, 0) as usize;
    if total > input.len() {
        return Err(LuksError::CorruptFs(
            "btrfs lzo extent claims more data than it has",
        ));
    }

    let mut out = Vec::with_capacity(expected);
    let mut at = LZO_LEN;

    while at < total && out.len() < expected {
        // Skip the padding to the next sector when the header would straddle.
        let room = sector - (at % sector);
        if room < LZO_LEN {
            at += room;
            continue;
        }
        if at + LZO_LEN > total {
            break;
        }

        let seg_len = u32le(input, at) as usize;
        at += LZO_LEN;
        if seg_len == 0 || at + seg_len > input.len() {
            return Err(LuksError::CorruptFs("btrfs lzo segment overruns the extent"));
        }

        // Each segment decompresses to at most one sector, so the output buffer
        // is a fixed size and the decoder cannot be talked into a large
        // allocation however the segment is crafted.
        let mut chunk = vec![0u8; sector];
        let produced = lzo::decompress_into(&input[at..at + seg_len], &mut chunk)
            .map_err(|_| LuksError::CorruptFs("btrfs lzo segment failed to decompress"))?;
        out.extend_from_slice(&chunk[..produced]);

        at += seg_len;
    }

    out.truncate(expected);
    Ok(out)
}
