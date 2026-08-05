//! Turning a password into a verified master key.
//!
//! ```text
//!   password
//!     |  KDF (argon2id / argon2i / pbkdf2), salt + cost from the keyslot
//!     v
//!   derived key            <- unwraps the keyslot area, nothing more
//!     |  AES-XTS decrypt of the keyslot area
//!     v
//!   AF-striped material    <- stripes * key_size bytes
//!     |  AF-merge (XOR + diffuse), the anti-forensic splitter in reverse
//!     v
//!   candidate master key
//!     |  PBKDF2 against the stored digest
//!     v
//!   verified master key
//! ```
//!
//! The anti-forensic splitter exists so that recovering *part* of the keyslot
//! area yields nothing: every output byte depends on every input byte.

use crate::device::ReadAt;
use crate::error::{LuksError, Result};
use crate::luks::header::{Digest as LuksDigest, Kdf, Keyslot, Luks2Header};
use crate::secret::Secret;
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Keyslot areas are always addressed in 512-byte cipher blocks, independent of
/// the data segment's sector size.
const KEYSLOT_SECTOR_SIZE: usize = 512;

/// Derive the key that unwraps a keyslot. This is the expensive step: for a
/// Fedora default (argon2id, 1 GiB) it allocates 1 GiB and runs for seconds.
pub fn derive_key(kdf: &Kdf, password: &[u8], out_len: usize) -> Result<Secret> {
    let mut out = vec![0u8; out_len];

    match kdf {
        Kdf::Argon2id(p) | Kdf::Argon2i(p) => {
            use argon2::{Algorithm, Argon2, Params, Version};

            let algorithm = match kdf {
                Kdf::Argon2id(_) => Algorithm::Argon2id,
                _ => Algorithm::Argon2i,
            };
            let params = Params::new(p.memory, p.time, p.cpus, Some(out_len))
                .map_err(|e| LuksError::KdfFailed(e.to_string()))?;

            Argon2::new(algorithm, Version::V0x13, params)
                .hash_password_into(password, p.salt.expose(), &mut out)
                .map_err(|e| LuksError::KdfFailed(e.to_string()))?;
        }
        Kdf::Pbkdf2 {
            salt,
            hash,
            iterations,
        } => {
            pbkdf2_into(hash, password, salt.expose(), *iterations, &mut out)?;
        }
    }

    let secret = Secret::new(out.clone());
    out.zeroize();
    Ok(secret)
}

fn pbkdf2_into(hash: &str, password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> Result<()> {
    use hmac::Hmac;
    match hash {
        "sha256" => pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, rounds, out)
            .map_err(|e| LuksError::KdfFailed(e.to_string())),
        "sha512" => pbkdf2::pbkdf2::<Hmac<Sha512>>(password, salt, rounds, out)
            .map_err(|e| LuksError::KdfFailed(e.to_string())),
        other => Err(LuksError::UnsupportedHash(other.to_string())),
    }
}

/// Decrypt a keyslot's area in place with AES-XTS.
///
/// Tweaks count from zero at the start of the area, not from the partition LBA.
fn decrypt_keyslot_area(encryption: &str, key: &Secret, buf: &mut [u8]) -> Result<()> {
    if encryption != "aes-xts-plain64" {
        return Err(LuksError::UnsupportedCipher(encryption.to_string()));
    }
    // Keyslot areas are always 512-byte blocks, so the step is 1.
    xts_decrypt(key.expose(), buf, KEYSLOT_SECTOR_SIZE, 0, 1)
}

/// AES-XTS-plain64 decryption over `buf`, split into `sector_size` chunks.
///
/// The tweak for chunk *i* is `first_tweak + i * tweak_step`.
///
/// `tweak_step` exists because dm-crypt counts the IV in **512-byte units**
/// regardless of the encryption sector size. A volume with 4096-byte sectors
/// therefore advances its tweak by 8 per sector, not by 1, unless it sets the
/// `iv-large-sectors` flag. Getting this wrong decrypts sector 0 correctly and
/// everything after it into garbage — which is exactly how it hides.
pub fn xts_decrypt(
    key: &[u8],
    buf: &mut [u8],
    sector_size: usize,
    first_tweak: u128,
    tweak_step: u128,
) -> Result<()> {
    use aes::cipher::KeyInit;
    use aes::{Aes128, Aes256};

    // XTS works in whole cipher sectors — there is no partial-sector mode in
    // dm-crypt. A short trailing chunk would either panic inside the XTS
    // crate (under 16 bytes) or silently do ciphertext stealing (16 up to a
    // sector), producing bytes the kernel will never reproduce. Every in-crate
    // caller passes whole sectors; this pins that as a contract rather than a
    // habit, since both functions are `pub`.
    if sector_size == 0 || !buf.len().is_multiple_of(sector_size) {
        return Err(LuksError::CorruptFs(
            "XTS length is not a whole number of cipher sectors",
        ));
    }
    use xts_mode::{get_tweak_default, Xts128};

    // An XTS key is two independent keys: one for data, one for the tweak.
    match key.len() {
        64 => {
            let xts = Xts128::new(
                Aes256::new_from_slice(&key[..32]).map_err(|_| LuksError::BadKeyLength(64))?,
                Aes256::new_from_slice(&key[32..]).map_err(|_| LuksError::BadKeyLength(64))?,
            );
            for (i, chunk) in buf.chunks_mut(sector_size).enumerate() {
                let tweak = first_tweak + (i as u128) * tweak_step;
                xts.decrypt_sector(chunk, get_tweak_default(tweak));
            }
        }
        32 => {
            let xts = Xts128::new(
                Aes128::new_from_slice(&key[..16]).map_err(|_| LuksError::BadKeyLength(32))?,
                Aes128::new_from_slice(&key[16..]).map_err(|_| LuksError::BadKeyLength(32))?,
            );
            for (i, chunk) in buf.chunks_mut(sector_size).enumerate() {
                let tweak = first_tweak + (i as u128) * tweak_step;
                xts.decrypt_sector(chunk, get_tweak_default(tweak));
            }
        }
        other => return Err(LuksError::BadKeyLength(other)),
    }
    Ok(())
}

/// AES-XTS-plain64 **encryption** over `buf`, the exact mirror of
/// [`xts_decrypt`].
///
/// Only compiled with `dangerous-write-support`. Same tweak rules — and the
/// same trap: `tweak_step` counts in 512-byte units regardless of the sector
/// size, so getting it wrong encrypts sector 0 correctly and turns everything
/// after it into ciphertext the kernel will decrypt to garbage. Read the note
/// on [`xts_decrypt`] before touching either.
///
/// This is graded against the kernel rather than against our own decryptor:
/// take a region of a container that real `cryptsetup` and dm-crypt produced,
/// decrypt it with the proven read path, re-encrypt the plaintext with this
/// function, and require the ciphertext to come back **byte-identical**. A
/// pair of functions that are merely inverses of each other would pass a round
/// trip and still write a drive Linux cannot read.
#[cfg(feature = "dangerous-write-support")]
pub fn xts_encrypt(
    key: &[u8],
    buf: &mut [u8],
    sector_size: usize,
    first_tweak: u128,
    tweak_step: u128,
) -> Result<()> {
    use aes::cipher::KeyInit;
    use aes::{Aes128, Aes256};

    // Same whole-sector contract as `xts_decrypt` — see the note there.
    if sector_size == 0 || !buf.len().is_multiple_of(sector_size) {
        return Err(LuksError::CorruptFs(
            "XTS length is not a whole number of cipher sectors",
        ));
    }
    use xts_mode::{get_tweak_default, Xts128};

    match key.len() {
        64 => {
            let xts = Xts128::new(
                Aes256::new_from_slice(&key[..32]).map_err(|_| LuksError::BadKeyLength(64))?,
                Aes256::new_from_slice(&key[32..]).map_err(|_| LuksError::BadKeyLength(64))?,
            );
            for (i, chunk) in buf.chunks_mut(sector_size).enumerate() {
                let tweak = first_tweak + (i as u128) * tweak_step;
                xts.encrypt_sector(chunk, get_tweak_default(tweak));
            }
        }
        32 => {
            let xts = Xts128::new(
                Aes128::new_from_slice(&key[..16]).map_err(|_| LuksError::BadKeyLength(32))?,
                Aes128::new_from_slice(&key[16..]).map_err(|_| LuksError::BadKeyLength(32))?,
            );
            for (i, chunk) in buf.chunks_mut(sector_size).enumerate() {
                let tweak = first_tweak + (i as u128) * tweak_step;
                xts.encrypt_sector(chunk, get_tweak_default(tweak));
            }
        }
        other => return Err(LuksError::BadKeyLength(other)),
    }
    Ok(())
}

/// Reverse the anti-forensic splitter: fold `stripes` blocks down to one.
///
/// `d = 0; for each stripe but the last: d = diffuse(d XOR stripe); d ^= last`
fn af_merge(src: &[u8], block_size: usize, stripes: u32, hash: &str) -> Result<Secret> {
    let stripes = stripes as usize;
    if stripes == 0 {
        return Err(LuksError::Missing("AF stripes"));
    }
    let needed = block_size
        .checked_mul(stripes)
        .ok_or(LuksError::Missing("AF stripes"))?;
    if src.len() < needed {
        return Err(LuksError::Truncated {
            needed,
            got: src.len(),
        });
    }

    let mut d = vec![0u8; block_size];
    for i in 0..stripes - 1 {
        let stripe = &src[i * block_size..(i + 1) * block_size];
        for (acc, b) in d.iter_mut().zip(stripe) {
            *acc ^= b;
        }
        diffuse(&mut d, hash)?;
    }
    let last = &src[(stripes - 1) * block_size..stripes * block_size];
    for (acc, b) in d.iter_mut().zip(last) {
        *acc ^= b;
    }

    let out = Secret::new(d.clone());
    d.zeroize();
    Ok(out)
}

/// AF diffusion: hash the block in digest-sized chunks, each prefixed with its
/// big-endian index, so a change anywhere propagates everywhere.
fn diffuse(block: &mut [u8], hash: &str) -> Result<()> {
    let digest_size = match hash {
        "sha256" => 32,
        "sha512" => 64,
        other => return Err(LuksError::UnsupportedHash(other.to_string())),
    };

    let mut out = vec![0u8; block.len()];
    for (i, chunk) in block.chunks(digest_size).enumerate() {
        let iv = (i as u32).to_be_bytes();
        let digest: Vec<u8> = match hash {
            "sha256" => {
                let mut h = Sha256::new();
                h.update(iv);
                h.update(chunk);
                h.finalize().to_vec()
            }
            _ => {
                let mut h = Sha512::new();
                h.update(iv);
                h.update(chunk);
                h.finalize().to_vec()
            }
        };
        let start = i * digest_size;
        let take = chunk.len().min(digest.len());
        out[start..start + take].copy_from_slice(&digest[..take]);
    }

    block.copy_from_slice(&out);
    out.zeroize();
    Ok(())
}

/// Check a candidate master key against the stored digest, in constant time.
fn verify_digest(digest: &LuksDigest, master_key: &Secret) -> Result<bool> {
    if digest.kind != "pbkdf2" {
        return Err(LuksError::UnsupportedDigest(digest.kind.clone()));
    }
    let expected = digest.digest.expose();
    let mut computed = vec![0u8; expected.len()];
    pbkdf2_into(
        &digest.hash,
        master_key.expose(),
        digest.salt.expose(),
        digest.iterations,
        &mut computed,
    )?;

    let ok = computed.ct_eq(expected).into();
    computed.zeroize();
    Ok(ok)
}

/// Try one keyslot. `Ok(None)` means the password does not open *this* slot,
/// which is normal — other slots may still match.
pub fn try_keyslot<D: ReadAt + ?Sized>(
    device: &D,
    partition_offset: u64,
    header: &Luks2Header,
    slot: &Keyslot,
    password: &[u8],
) -> Result<Option<Secret>> {
    let derived = derive_key(&slot.kdf, password, slot.area.key_size)?;

    let af = slot.af.as_ref().ok_or(LuksError::Missing("AF parameters"))?;
    let material_len = slot
        .key_size
        .checked_mul(af.stripes as usize)
        .ok_or(LuksError::Missing("AF stripes"))?;
    if material_len as u64 > slot.area.size {
        return Err(LuksError::Truncated {
            needed: material_len,
            got: slot.area.size as usize,
        });
    }

    // Read whole 512-byte blocks: XTS decrypts by cipher block, not by the
    // AF material length, which is not necessarily a multiple of 512.
    let read_len = material_len.div_ceil(KEYSLOT_SECTOR_SIZE) * KEYSLOT_SECTOR_SIZE;
    let mut area = vec![0u8; read_len];
    device.read_at(partition_offset + slot.area.offset, &mut area)?;

    decrypt_keyslot_area(&slot.area.encryption, &derived, &mut area)?;

    let candidate = af_merge(&area, slot.key_size, af.stripes, &af.hash)?;
    area.zeroize();

    for digest in header.metadata.digests.values() {
        if verify_digest(digest, &candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Try every keyslot until one opens.
///
/// Cost is per slot, so a wrong password on a Fedora volume pays the full
/// Argon2 price for each slot before failing.
pub fn unlock<D: ReadAt + ?Sized>(
    device: &D,
    partition_offset: u64,
    header: &Luks2Header,
    password: &[u8],
) -> Result<Secret> {
    if header.metadata.keyslots.is_empty() {
        return Err(LuksError::Missing("keyslots"));
    }
    for slot in header.metadata.keyslots.values() {
        if slot.kind != "luks2" {
            continue;
        }
        if let Some(key) = try_keyslot(device, partition_offset, header, slot, password)? {
            return Ok(key);
        }
    }
    Err(LuksError::WrongPassword)
}
