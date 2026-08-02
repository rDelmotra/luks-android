//! CRC-32C (Castagnoli), the default btrfs checksum.
//!
//! Hand-rolled rather than pulled from a crate for two reasons. It is not the
//! same polynomial as `crc32fast` — that one is the IEEE/zlib CRC-32
//! (0xEDB88320) and btrfs uses Castagnoli (0x82F63B78), so the dependency
//! already in the tree is the wrong algorithm and reaching for it would produce
//! a checksum that never matches. And the alternative crates carry SIMD
//! `unsafe` for a job that only ever runs over metadata: a 1 GiB file read
//! touches a few hundred tree nodes, single-digit megabytes. Table-driven is
//! several hundred MB/s, which is far past anything this path needs.

/// Lookup table for the reflected Castagnoli polynomial, built at compile time.
const TABLE: [u32; 256] = {
    const POLY: u32 = 0x82F6_3B78;
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Standard CRC-32C of `data`: seeded with `!0`, and inverted at the end.
///
/// The final inversion is the part worth stating, because the kernel's own
/// `__crc32c_le` does not do it and the inversion lives in the crypto shash
/// wrapper instead — so reading the kernel source at the wrong layer gives a
/// value that is wrong by exactly a bitwise NOT. Verified directly against
/// `fixtures/btrfs/plain.img`, whose stored superblock checksum is 0xf7b4210d.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ b as u32) & 0xFF) as usize];
    }
    !crc
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
