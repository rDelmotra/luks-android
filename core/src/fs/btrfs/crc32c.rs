//! CRC-32C (Castagnoli), the default btrfs checksum.
//!
//! The algorithm comes from the `crc32c` crate, which dispatches to the ARMv8
//! CRC instructions (and SSE4.2 on x86) at runtime with a software fallback.
//! **Not `crc32fast`** — that is the IEEE/zlib polynomial (0xEDB88320) and
//! btrfs uses Castagnoli (0x82F63B78), so the crate already in the tree is the
//! wrong algorithm and would produce checksums that never match.
//!
//! This was a hand-written table for most of the reader's life, on the
//! reasoning that checksums only ever covered metadata: a 1 GiB file read
//! touches a few hundred tree nodes, single-digit megabytes, and a table-driven
//! CRC at several hundred MB/s is far past what that needs.
//!
//! That reasoning expired when data checksums landed. Every byte of every file
//! now goes through here, and the table version was measured at **472 MiB/s** —
//! 1.1 seconds of the 6.06 seconds it took to read a 515 MB file off the
//! developer's drive, 18% of the total, to compute checksums. The hardware
//! instruction makes that disappear.
//!
//! The two conventions below are the part no crate can be trusted to guess at,
//! and both are pinned by tests against real `mkfs.btrfs` output.

/// The raw accumulator: seeded with `seed`, with no final inversion.
///
/// `crc32c_append` takes and returns *inverted* values — it is built so that
/// `crc32c_append(0, data) == crc32c(data)` — so both ends are flipped here to
/// expose the register itself, which is what the name hash needs.
pub fn crc32c_seed(seed: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!seed, data)
}

pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_seed(!0, data)
}

/// The hash btrfs files a directory entry under, which is the `offset` of its
/// `DIR_ITEM` key.
///
/// **Same polynomial as the block checksum, different convention**: seeded with
/// `!1` instead of `!0`, and *not* inverted. There is no principle behind the
/// difference; it is simply what btrfs does, and assuming one convention covers
/// both is the kind of mistake that makes every directory lookup miss while the
/// checksums all verify. Confirmed against all 228 `DIR_ITEM`s in
/// `fixtures/btrfs/plain.img`.
pub fn name_hash(name: &[u8]) -> u64 {
    crc32c_seed(!1, name) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_check_vector() {
        // The CRC-32C check value from RFC 3720 appendix B.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn the_empty_input_is_zero() {
        // Seed and final inversion cancel, which is what pins down that the
        // inversion is present at all.
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn a_single_flipped_bit_changes_the_result() {
        let a = crc32c(b"the quick brown fox");
        let b = crc32c(b"the quick brown fox".to_ascii_uppercase().as_slice());
        assert_ne!(a, b);
    }
}
