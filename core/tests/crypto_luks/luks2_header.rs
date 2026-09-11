//! LUKS2 header parsing tests.
//!
//! Headers are assembled here byte-by-byte from the on-disk spec rather than
//! produced by the parser's own code, so a wrong offset in `header.rs` shows up
//! as a failure instead of cancelling out.
//!
//! These cover mechanics. Validation against images produced by real
//! `cryptsetup` is a separate, and more authoritative, test.

use luks_core::error::LuksError;
use luks_core::luks::{self, HeaderCopy, Kdf, LuksVersion, SegmentSize};
use sha2::{Digest, Sha256};

const HDR_SIZE: usize = 16 * 1024;
const BINARY_LEN: usize = 4096;

/// Realistic Linux reference metadata: argon2id at 1 GiB, aes-xts-plain64,
/// 16 MiB payload offset.
fn standard_linux_json() -> String {
    r#"{
      "keyslots": {
        "0": {
          "type": "luks2",
          "key_size": 64,
          "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
          "area": {
            "type": "raw",
            "offset": "32768",
            "size": "258048",
            "encryption": "aes-xts-plain64",
            "key_size": 64
          },
          "kdf": {
            "type": "argon2id",
            "time": 7,
            "memory": 1048576,
            "cpus": 4,
            "salt": "c2FsdHlzYWx0eXNhbHR5c2FsdHlzYWx0eXNhbHR5c2E="
          }
        }
      },
      "tokens": {},
      "segments": {
        "0": {
          "type": "crypt",
          "offset": "16777216",
          "size": "dynamic",
          "iv_tweak": "0",
          "encryption": "aes-xts-plain64",
          "sector_size": 512
        }
      },
      "digests": {
        "0": {
          "type": "pbkdf2",
          "keyslots": ["0"],
          "segments": ["0"],
          "hash": "sha256",
          "iterations": 234567,
          "salt": "ZGlnZXN0c2FsdGRpZ2VzdHNhbHRkaWdlc3RzYWx0MDA=",
          "digest": "ZGlnZXN0dmFsdWVkaWdlc3R2YWx1ZWRpZ2VzdHZhbHU="
        }
      },
      "config": { "json_size": "12288", "keyslots_size": "16744448" }
    }"#
    .to_string()
}

/// Write one header copy (binary + JSON) at `offset`, with a correct checksum.
fn write_copy(buf: &mut [u8], offset: usize, magic: &[u8; 6], seqid: u64, json: &str) {
    let h = &mut buf[offset..offset + HDR_SIZE];
    h.fill(0);

    h[0..6].copy_from_slice(magic);
    h[6..8].copy_from_slice(&2u16.to_be_bytes()); // version
    h[8..16].copy_from_slice(&(HDR_SIZE as u64).to_be_bytes()); // hdr_size
    h[16..24].copy_from_slice(&seqid.to_be_bytes()); // seqid

    let put = |h: &mut [u8], range: std::ops::Range<usize>, s: &str| {
        h[range.start..range.start + s.len()].copy_from_slice(s.as_bytes());
    };
    put(h, 24..72, "testlabel"); // label
    put(h, 72..104, "sha256"); // checksum_alg
    h[104..168].fill(0xAA); // salt
    put(h, 168..208, "7f3b2c1d-0000-4444-8888-abcdefabcdef"); // uuid
    put(h, 208..256, "testsubsystem"); // subsystem
    h[256..264].copy_from_slice(&(offset as u64).to_be_bytes()); // hdr_offset

    h[BINARY_LEN..BINARY_LEN + json.len()].copy_from_slice(json.as_bytes());

    // Checksum covers the whole copy with the csum field zeroed.
    let mut scratch = h.to_vec();
    scratch[448..512].fill(0);
    let digest = Sha256::digest(&scratch);
    h[448..480].copy_from_slice(&digest);
}

/// A complete two-copy LUKS2 header region (32 KiB).
fn build(primary_seqid: u64, secondary_seqid: u64) -> Vec<u8> {
    let json = standard_linux_json();
    let mut buf = vec![0u8; HDR_SIZE * 2];
    write_copy(&mut buf, 0, b"LUKS\xba\xbe", primary_seqid, &json);
    write_copy(&mut buf, HDR_SIZE, b"SKUL\xba\xbe", secondary_seqid, &json);
    buf
}

// ---------------------------------------------------------------------------

#[test]
fn detects_luks2() {
    let buf = build(1, 1);
    assert_eq!(luks::detect_version(&buf).unwrap(), LuksVersion::V2);
}

#[test]
fn detects_luks1_and_declines_it() {
    let mut buf = build(1, 1);
    buf[6..8].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(luks::detect_version(&buf).unwrap(), LuksVersion::V1);
    assert!(matches!(
        luks::parse(&buf),
        Err(LuksError::Luks1NotImplemented)
    ));
}

#[test]
fn rejects_non_luks_data() {
    let buf = vec![0x42u8; HDR_SIZE * 2];
    assert!(matches!(
        luks::detect_version(&buf),
        Err(LuksError::BadMagic { .. })
    ));
}

#[test]
fn rejects_truncated_input() {
    let buf = build(1, 1);
    assert!(matches!(
        luks::parse(&buf[..100]),
        Err(LuksError::Truncated { .. })
    ));
}

#[test]
fn parses_binary_header_fields() {
    let hdr = luks::parse(&build(9, 9)).unwrap();
    assert_eq!(hdr.binary.version, 2);
    assert_eq!(hdr.binary.hdr_size, HDR_SIZE as u64);
    assert_eq!(hdr.binary.label, "testlabel");
    assert_eq!(hdr.binary.checksum_alg, "sha256");
    assert_eq!(hdr.binary.uuid, "7f3b2c1d-0000-4444-8888-abcdefabcdef");
    assert_eq!(hdr.binary.subsystem, "testsubsystem");
    assert_eq!(hdr.binary.salt.len(), 64);
}

#[test]
fn parses_segment() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    let seg = hdr.primary_segment().unwrap();
    assert_eq!(seg.encryption, "aes-xts-plain64");
    assert_eq!(seg.sector_size, 512);
    assert_eq!(seg.offset, 16_777_216);
    assert_eq!(seg.size, SegmentSize::Dynamic);
    assert_eq!(seg.iv_tweak, 0);
}

#[test]
fn parses_keyslot_and_kdf() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    let slot = &hdr.metadata.keyslots["0"];
    assert_eq!(slot.key_size, 64);
    assert_eq!(slot.area.offset, 32_768);
    assert_eq!(slot.area.encryption, "aes-xts-plain64");
    assert_eq!(slot.af.as_ref().unwrap().stripes, 4000);

    match &slot.kdf {
        Kdf::Argon2id(p) => {
            assert_eq!(p.memory, 1_048_576);
            assert_eq!(p.time, 7);
            assert_eq!(p.cpus, 4);
            assert_eq!(p.salt.len(), 32);
        }
        other => panic!("expected argon2id, got {other:?}"),
    }
}

#[test]
fn reports_peak_kdf_memory() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    // 1 GiB. This is the number that decides whether a phone can unlock at all.
    assert_eq!(hdr.max_kdf_memory_kib(), Some(1_048_576));
}

#[test]
fn parses_large_integers_sent_as_json_strings() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    assert_eq!(hdr.metadata.config.keyslots_size, 16_744_448);
    assert_eq!(hdr.metadata.config.json_size, 12_288);
}

#[test]
fn accepts_4096_byte_sectors() {
    let json = standard_linux_json().replace("\"sector_size\": 512", "\"sector_size\": 4096");
    let mut buf = vec![0u8; HDR_SIZE * 2];
    write_copy(&mut buf, 0, b"LUKS\xba\xbe", 1, &json);
    write_copy(&mut buf, HDR_SIZE, b"SKUL\xba\xbe", 1, &json);
    let hdr = luks::parse(&buf).unwrap();
    assert_eq!(hdr.primary_segment().unwrap().sector_size, 4096);
}

#[test]
fn accepts_fixed_segment_size() {
    let json = standard_linux_json().replace("\"size\": \"dynamic\"", "\"size\": \"981467136\"");
    let mut buf = vec![0u8; HDR_SIZE * 2];
    write_copy(&mut buf, 0, b"LUKS\xba\xbe", 1, &json);
    write_copy(&mut buf, HDR_SIZE, b"SKUL\xba\xbe", 1, &json);
    let hdr = luks::parse(&buf).unwrap();
    assert_eq!(
        hdr.primary_segment().unwrap().size,
        SegmentSize::Fixed(981_467_136)
    );
}

// --- corruption handling ---------------------------------------------------

#[test]
fn detects_a_corrupted_json_area() {
    let mut buf = build(1, 1);
    buf[BINARY_LEN + 10] ^= 0xFF; // corrupt primary JSON
    buf[HDR_SIZE + BINARY_LEN + 10] ^= 0xFF; // and secondary
    assert!(matches!(
        luks::parse(&buf),
        Err(LuksError::ChecksumMismatch)
    ));
}

#[test]
fn falls_back_to_secondary_when_primary_is_corrupt() {
    let mut buf = build(1, 1);
    buf[BINARY_LEN + 10] ^= 0xFF; // break only the primary
    let hdr = luks::parse(&buf).expect("should recover from the backup copy");
    assert_eq!(hdr.source, HeaderCopy::Secondary);
    assert_eq!(hdr.binary.label, "testlabel");
}

#[test]
fn prefers_the_copy_with_the_higher_seqid() {
    let hdr = luks::parse(&build(4, 11)).unwrap();
    assert_eq!(hdr.source, HeaderCopy::Secondary);
    assert_eq!(hdr.binary.seqid, 11);

    let hdr = luks::parse(&build(12, 11)).unwrap();
    assert_eq!(hdr.source, HeaderCopy::Primary);
    assert_eq!(hdr.binary.seqid, 12);
}

#[test]
fn recovers_when_the_primary_declares_an_implausible_size() {
    // A garbage hdr_size in the primary must not sink the volume: the backup
    // copy still sits at a known metadata size and should be found by probing.
    let mut buf = build(1, 1);
    buf[8..16].copy_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
    let hdr = luks::parse(&buf).expect("backup copy should still be reachable");
    assert_eq!(hdr.source, HeaderCopy::Secondary);
    assert_eq!(hdr.binary.label, "testlabel");
}

#[test]
fn gives_up_when_both_copies_are_unusable() {
    let mut buf = build(1, 1);
    buf[8..16].copy_from_slice(&(64u64 * 1024 * 1024).to_be_bytes()); // primary size garbage
    buf[HDR_SIZE..HDR_SIZE + 6].copy_from_slice(b"XXXXXX"); // backup magic destroyed
    assert!(matches!(
        luks::parse(&buf),
        Err(LuksError::ImplausibleHeaderSize(_))
    ));
}

#[test]
fn finds_the_backup_even_at_a_non_default_metadata_size() {
    // 32 KiB metadata instead of the 16 KiB default, with a garbage size field
    // in the primary so the parser is forced to probe for the backup.
    const BIG: usize = 32 * 1024;
    let json = standard_linux_json();
    let mut buf = vec![0u8; BIG * 2];

    let write_at = |buf: &mut Vec<u8>, off: usize, magic: &[u8; 6], seqid: u64| {
        let h = &mut buf[off..off + BIG];
        h.fill(0);
        h[0..6].copy_from_slice(magic);
        h[6..8].copy_from_slice(&2u16.to_be_bytes());
        h[8..16].copy_from_slice(&(BIG as u64).to_be_bytes());
        h[16..24].copy_from_slice(&seqid.to_be_bytes());
        h[72..78].copy_from_slice(b"sha256");
        h[BINARY_LEN..BINARY_LEN + json.len()].copy_from_slice(json.as_bytes());
        let mut scratch = h.to_vec();
        scratch[448..512].fill(0);
        h[448..480].copy_from_slice(&Sha256::digest(&scratch));
    };
    write_at(&mut buf, 0, b"LUKS\xba\xbe", 1);
    write_at(&mut buf, BIG, b"SKUL\xba\xbe", 1);

    buf[8..16].copy_from_slice(&0u64.to_be_bytes()); // force probing

    let hdr = luks::parse(&buf).expect("should probe 32 KiB and find the backup");
    assert_eq!(hdr.source, HeaderCopy::Secondary);
    assert_eq!(hdr.binary.hdr_size, BIG as u64);
}

// --- secret hygiene --------------------------------------------------------

#[test]
fn debug_output_never_contains_salts_or_digests() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    let rendered = format!("{hdr:?}");

    // Plaintext of the base64 salts/digests used in the fixture.
    for leak in ["saltysalty", "digestsalt", "digestvalue"] {
        assert!(!rendered.contains(leak), "Debug leaked {leak}");
    }
    assert!(rendered.contains("REDACTED"));
}

#[test]
fn summary_is_safe_to_log() {
    let hdr = luks::parse(&build(1, 1)).unwrap();
    let s = hdr.summary();
    assert!(s.contains("aes-xts-plain64"));
    assert!(s.contains("1048576"));
    for leak in ["saltysalty", "digestsalt", "digestvalue", "REDACTED"] {
        assert!(!s.contains(leak), "summary leaked {leak}");
    }
}
