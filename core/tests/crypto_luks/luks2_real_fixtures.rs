//! Validation against headers produced by real `cryptsetup` 2.7.0.
//!
//! `luks2_header.rs` checks mechanics against hand-built headers. This file is
//! the authoritative check: every expected value below is transcribed from
//! `cryptsetup luksDump` output recorded in `fixtures/luks/EXPECTED.txt` at
//! generation time. If our reading of the spec is wrong, these fail.
//!
//! Fixtures are 2 * hdr_size — they stop before the keyslots area at 32 KiB and
//! therefore contain no wrapped key material. Password is "test"; the KDF
//! parameters are deliberately weak. Regenerate with `tools/gen-luks-fixtures.sh`.

use luks_core::error::LuksError;
use luks_core::luks::{self, Kdf, LuksVersion, SegmentSize};

fn load(name: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/luks/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}

fn parse(name: &str) -> luks::Luks2Header {
    luks::parse(&load(name)).unwrap_or_else(|e| panic!("{name} failed to parse: {e}"))
}

/// The shape of a standard Linux encrypted drive: aes-xts-plain64, 512-byte sectors.
#[test]
fn argon2id_512_matches_cryptsetup() {
    let h = parse("luks2-argon2id-512.img");

    assert_eq!(h.binary.uuid, "f0778ad1-e26b-4133-982e-8edb8f3e8eee");
    assert_eq!(h.binary.hdr_size, 16384); // "Metadata area: 16384 [bytes]"
    assert_eq!(h.binary.checksum_alg, "sha256");
    assert_eq!(h.binary.label, ""); // "(no label)"
    assert_eq!(h.metadata.config.keyslots_size, 16_744_448);

    let seg = h.primary_segment().unwrap();
    assert_eq!(seg.kind, "crypt");
    assert_eq!(seg.encryption, "aes-xts-plain64");
    assert_eq!(seg.sector_size, 512);
    assert_eq!(seg.offset, 16_777_216);
    assert_eq!(seg.size, SegmentSize::Dynamic); // "length: (whole device)"

    assert_eq!(h.metadata.keyslots.len(), 1);
    let slot = &h.metadata.keyslots["0"];
    assert_eq!(slot.kind, "luks2");
    assert_eq!(slot.key_size, 64); // "Key: 512 bits"
    assert_eq!(slot.area.offset, 32_768);
    assert_eq!(slot.area.size, 258_048);
    assert_eq!(slot.area.encryption, "aes-xts-plain64");

    let af = slot.af.as_ref().expect("AF params");
    assert_eq!(af.stripes, 4000);
    assert_eq!(af.hash, "sha256");

    match &slot.kdf {
        Kdf::Argon2id(p) => {
            assert_eq!(p.time, 4);
            assert_eq!(p.memory, 32);
            assert_eq!(p.cpus, 1);
            assert!(!p.salt.is_empty());
        }
        other => panic!("expected argon2id, got {other:?}"),
    }

    let digest = &h.metadata.digests["0"];
    assert_eq!(digest.kind, "pbkdf2");
    assert_eq!(digest.hash, "sha256");
    assert_eq!(digest.iterations, 1000);
    assert_eq!(digest.keyslots, vec!["0"]);
}

/// cryptsetup 2.7 defaults to 4096-byte sectors, which renumber the XTS tweak.
#[test]
fn argon2id_4096_byte_sectors() {
    let h = parse("luks2-argon2id-4096.img");
    assert_eq!(h.binary.uuid, "de61af96-4136-41bb-ae95-678bbaa2c372");
    assert_eq!(h.primary_segment().unwrap().sector_size, 4096);
    assert_eq!(h.primary_segment().unwrap().offset, 16_777_216);
}

#[test]
fn argon2i_variant() {
    let h = parse("luks2-argon2i.img");
    assert_eq!(h.binary.uuid, "f48804e0-139f-4137-a030-3aff69c46e2a");
    match &h.metadata.keyslots["0"].kdf {
        Kdf::Argon2i(p) => {
            assert_eq!(p.time, 4);
            assert_eq!(p.memory, 32);
        }
        other => panic!("expected argon2i, got {other:?}"),
    }
    assert_eq!(h.metadata.keyslots["0"].kdf.algorithm(), "argon2i");
}

#[test]
fn pbkdf2_keyslot_reports_no_memory_cost() {
    let h = parse("luks2-pbkdf2.img");
    assert_eq!(h.binary.uuid, "bd26383d-f455-444e-a664-738cd0d06dea");
    match &h.metadata.keyslots["0"].kdf {
        Kdf::Pbkdf2 {
            hash, iterations, ..
        } => {
            assert_eq!(hash, "sha256");
            assert_eq!(*iterations, 1000);
        }
        other => panic!("expected pbkdf2, got {other:?}"),
    }
    // PBKDF2 is memory-cheap; there is no allocation to plan for.
    assert_eq!(h.max_kdf_memory_kib(), None);
}

/// 64 KiB metadata puts the backup copy at a non-default offset.
#[test]
fn non_default_metadata_size() {
    let h = parse("luks2-metadata-64k.img");
    assert_eq!(h.binary.uuid, "792cfbc4-0a1a-4bcf-95c0-902d2c538b99");
    assert_eq!(h.binary.hdr_size, 65_536);
    assert_eq!(h.metadata.keyslots["0"].area.offset, 131_072);
}

/// We must parse older ciphers cleanly even though decryption comes later.
#[test]
fn cbc_essiv_cipher_parses() {
    let h = parse("luks2-cbc-essiv.img");
    assert_eq!(h.binary.uuid, "deb9fabf-8ba7-4f86-b717-058f21fddf58");
    assert_eq!(
        h.primary_segment().unwrap().encryption,
        "aes-cbc-essiv:sha256"
    );
    assert_eq!(h.metadata.keyslots["0"].key_size, 32); // 256 bits
}

/// Peak memory must be the max across slots, not whichever is enumerated first.
#[test]
fn peak_memory_is_the_max_across_keyslots() {
    let h = parse("luks2-two-keyslots.img");
    assert_eq!(h.binary.uuid, "2352e288-3f3b-47e1-8642-fb9c8b46dae8");
    assert_eq!(h.metadata.keyslots.len(), 2);

    let mut mems: Vec<u32> = h
        .metadata
        .keyslots
        .values()
        .filter_map(|k| k.kdf.memory_kib())
        .collect();
    mems.sort_unstable();
    assert_eq!(mems, vec![32, 64]);

    assert_eq!(h.max_kdf_memory_kib(), Some(64));
}

#[test]
fn luks1_is_detected_and_declined() {
    let raw = load("luks1.img");
    assert_eq!(luks::detect_version(&raw).unwrap(), LuksVersion::V1);
    assert!(matches!(
        luks::parse(&raw),
        Err(LuksError::Luks1NotImplemented)
    ));
}

#[test]
fn every_luks2_fixture_parses_and_verifies_its_checksum() {
    // A checksum mismatch here means our field offsets are wrong, since the
    // digest covers the whole header copy.
    for name in [
        "luks2-argon2id-512.img",
        "luks2-argon2id-4096.img",
        "luks2-argon2i.img",
        "luks2-pbkdf2.img",
        "luks2-metadata-64k.img",
        "luks2-cbc-essiv.img",
        "luks2-two-keyslots.img",
    ] {
        let h = parse(name);
        assert_eq!(h.binary.version, 2, "{name}");
        assert!(!h.metadata.keyslots.is_empty(), "{name}");
        assert!(h.primary_segment().is_ok(), "{name}");
    }
}

/// Corrupting the primary of a real header must still recover from the backup.
#[test]
fn real_header_recovers_from_its_backup_copy() {
    let mut raw = load("luks2-argon2id-512.img");
    raw[5000] ^= 0xFF; // inside the primary JSON area
    let h = luks::parse(&raw).expect("backup copy should carry the volume");
    assert_eq!(h.source, luks::HeaderCopy::Secondary);
    assert_eq!(h.binary.uuid, "f0778ad1-e26b-4133-982e-8edb8f3e8eee");
}

#[test]
fn real_headers_do_not_leak_secrets_when_formatted() {
    for name in ["luks2-argon2id-512.img", "luks2-two-keyslots.img"] {
        let h = parse(name);
        let debug = format!("{h:?}");
        assert!(debug.contains("REDACTED"), "{name}");
        let summary = h.summary();
        assert!(!summary.contains("REDACTED"), "{name}");
        assert!(summary.contains(&h.binary.uuid), "{name}");
    }
}
