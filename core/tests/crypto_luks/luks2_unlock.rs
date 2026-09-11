//! End-to-end unlock and decryption against complete LUKS2 containers built by
//! real `cryptsetup` 2.7.0.
//!
//! Two independent checks, so neither can hide a bug in the other:
//!
//! 1. **Derivation** — the master key we derive from the password must equal
//!    the one `cryptsetup luksDump --dump-master-key` reported. If Argon2, the
//!    keyslot XTS decryption, or AF-merge is wrong, this fails.
//! 2. **Decryption** — reading the plaintext must reveal the ext4 filesystem
//!    that was written inside via device-mapper. If the XTS tweak numbering is
//!    wrong, this fails even when derivation is right.
//!
//! Containers are throwaway: password "test", weak KDF, master keys published
//! here on purpose. Regenerate with `tools/gen-luks-containers.sh`.

use luks_core::error::LuksError;
use luks_core::luks::{self, LuksVolume};
use luks_core::secret::Secret;

const PASSWORD: &[u8] = b"test";

/// From `cryptsetup luksDump --dump-master-key`, recorded at generation time.
const MK_ARGON2ID_512: &str = "beda42fbd58d27d0de94bba27eb5021f24d01db63e5beb89d240f82eeb86c272\
f6857ae73e5485a1158f24cc5f1ebe7ad8af83773000dfb714394fdeb7cecd48";
const MK_ARGON2ID_4096: &str = "4ac28e1c16ae2c2dc448b3aab8067a4e0500e75457527e4ca0602808f394209b\
874b2fce2c36852b185fd5ecea0b44c125c21ef5f0535fc5df41f9bffc52b604";
const MK_PBKDF2_512: &str = "fa7d9bd24328c104d5dd0ac51d4092f4be9db588d49a391821a3e5ab022af3c6\
3ac3c034d5f9d6722b72aae66e73a111c5e9d3c593b990c5451df041f99483eb";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn container(name: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/containers/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing container {path}: {e}"))
}

// --- derivation ------------------------------------------------------------

fn assert_derives(name: &str, expected_hex: &str) {
    let data = container(name);
    let header = luks::parse(&data).expect("header parses");
    let key = luks::unlock(&data, 0, &header, PASSWORD).expect("password should be accepted");
    assert_eq!(
        key.expose(),
        unhex(expected_hex).as_slice(),
        "{name}: derived master key does not match cryptsetup"
    );
}

#[test]
fn derives_master_key_argon2id_512() {
    assert_derives("unlock-argon2id-512.img", MK_ARGON2ID_512);
}

#[test]
fn derives_master_key_argon2id_4096() {
    assert_derives("unlock-argon2id-4096.img", MK_ARGON2ID_4096);
}

#[test]
fn derives_master_key_pbkdf2() {
    assert_derives("unlock-pbkdf2-512.img", MK_PBKDF2_512);
}

#[test]
fn wrong_password_is_rejected() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    for bad in [b"Test".as_slice(), b"test ", b"", b"testtest"] {
        assert!(
            matches!(
                luks::unlock(&data, 0, &header, bad),
                Err(LuksError::WrongPassword)
            ),
            "password {bad:?} should have been rejected"
        );
    }
}

// --- decryption ------------------------------------------------------------

/// ext4 puts its superblock 1024 bytes in; the 0xEF53 magic sits at +0x38.
const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;
const EXT4_UUID_OFFSET: u64 = 1024 + 0x68;
const EXT4_LABEL_OFFSET: u64 = 1024 + 0x78;

fn assert_reveals_ext4(name: &str) {
    let data = container(name);
    let header = luks::parse(&data).unwrap();
    let vol = LuksVolume::open(&data, 0, None, &header, PASSWORD).expect("volume opens");

    let mut magic = [0u8; 2];
    vol.read_at(EXT4_MAGIC_OFFSET, &mut magic).unwrap();
    assert_eq!(
        u16::from_le_bytes(magic),
        0xEF53,
        "{name}: no ext4 magic — decryption produced garbage"
    );

    let mut label = [0u8; 16];
    vol.read_at(EXT4_LABEL_OFFSET, &mut label).unwrap();
    let label = String::from_utf8_lossy(&label);
    assert!(
        label.starts_with("LUKSDATA"),
        "{name}: label was {label:?}"
    );

    let mut uuid = [0u8; 16];
    vol.read_at(EXT4_UUID_OFFSET, &mut uuid).unwrap();
    assert_eq!(
        uuid,
        [
            0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66
        ],
        "{name}: filesystem UUID mismatch"
    );
}

#[test]
fn decrypts_to_ext4_512_byte_sectors() {
    assert_reveals_ext4("unlock-argon2id-512.img");
}

/// 4096-byte sectors renumber the XTS tweak. Getting this wrong yields garbage,
/// not an error, so it needs its own check.
#[test]
fn decrypts_to_ext4_4096_byte_sectors() {
    assert_reveals_ext4("unlock-argon2id-4096.img");
}

#[test]
fn decrypts_to_ext4_pbkdf2() {
    assert_reveals_ext4("unlock-pbkdf2-512.img");
}

// --- read semantics --------------------------------------------------------

#[test]
fn unaligned_reads_agree_with_aligned_ones() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    let vol = LuksVolume::open(&data, 0, None, &header, PASSWORD).unwrap();

    // One big aligned read as the reference.
    let mut whole = vec![0u8; 8192];
    vol.read_at(0, &mut whole).unwrap();

    // Every awkward offset and length must agree with it.
    for (offset, len) in [
        (0u64, 1usize),
        (1, 1),
        (511, 2),   // straddles a sector boundary
        (513, 100), // starts mid-sector
        (1023, 3),
        (1024, 4096),
        (4095, 4097), // straddles several
        (7000, 1192),
    ] {
        let mut got = vec![0u8; len];
        vol.read_at(offset, &mut got).unwrap();
        assert_eq!(
            got,
            &whole[offset as usize..offset as usize + len],
            "mismatch at offset={offset} len={len}"
        );
    }
}

#[test]
fn empty_read_is_a_noop() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    let vol = LuksVolume::open(&data, 0, None, &header, PASSWORD).unwrap();
    let mut empty: [u8; 0] = [];
    assert!(vol.read_at(0, &mut empty).is_ok());
}

/// Opening with a known master key must match opening with the password —
/// this separates a derivation bug from a decryption bug.
#[test]
fn master_key_path_and_password_path_agree() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();

    let by_password = LuksVolume::open(&data, 0, None, &header, PASSWORD).unwrap();
    let by_key =
        LuksVolume::with_master_key(&data, 0, None, &header, Secret::new(unhex(MK_ARGON2ID_512))).unwrap();

    let mut a = vec![0u8; 4096];
    let mut b = vec![0u8; 4096];
    by_password.read_at(0, &mut a).unwrap();
    by_key.read_at(0, &mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn master_key_is_not_printable() {
    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    let key = luks::unlock(&data, 0, &header, PASSWORD).unwrap();

    let rendered = format!("{key:?}");
    assert_eq!(rendered, "[REDACTED 64 bytes]");
    assert!(!rendered.contains("beda42"));
}

// --- regression: XTS tweak step for large sectors --------------------------

/// dm-crypt counts the IV in 512-byte units, so a 4096-byte sector advances the
/// tweak by 8. Sector 0 decrypts correctly either way, which is why an earlier
/// version of this suite — reading only the ext4 magic at offset 1024 — passed
/// while every later sector decrypted to garbage.
#[test]
fn tweak_step_follows_the_sector_size() {
    let data = container("unlock-argon2id-4096.img");
    let header = luks::parse(&data).unwrap();
    let seg = header.primary_segment().unwrap();
    assert_eq!(seg.sector_size, 4096);
    assert!(!seg.flags.iter().any(|f| f == "iv-large-sectors"));
    assert_eq!(seg.tweak_step(), 8);

    let data = container("unlock-argon2id-512.img");
    let header = luks::parse(&data).unwrap();
    assert_eq!(header.primary_segment().unwrap().tweak_step(), 1);
}

/// Both containers hold a filesystem made with identical `mkfs.ext4` options,
/// so structural metadata past the first sector must agree. With the wrong
/// tweak step the 4096-byte volume yields noise here.
#[test]
fn content_past_the_first_sector_agrees_across_sector_sizes() {
    let mut descriptors = Vec::new();
    for name in ["unlock-argon2id-512.img", "unlock-argon2id-4096.img"] {
        let data = container(name);
        let header = luks::parse(&data).unwrap();
        let vol = LuksVolume::open(&data, 0, None, &header, PASSWORD).unwrap();

        // Block group descriptor at block 1: inode table pointer at +8.
        let mut gd = [0u8; 16];
        vol.read_at(4096, &mut gd).unwrap();
        descriptors.push(u32::from_le_bytes([gd[8], gd[9], gd[10], gd[11]]));
    }
    assert_eq!(
        descriptors[0], descriptors[1],
        "inode table pointer differs across sector sizes: {descriptors:?}"
    );
    // Sanity: a plausible early block, not noise.
    assert!(descriptors[0] > 0 && descriptors[0] < 1000, "{descriptors:?}");
}
