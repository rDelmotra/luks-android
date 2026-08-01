//! LUKS2 on-disk header parsing.
//!
//! Layout of a LUKS2 partition (default 16 KiB metadata size):
//!
//! ```text
//!   0        binary header  (4096 bytes, big-endian)   \
//!   4096     JSON metadata  (hdr_size - 4096 bytes)    /  primary  copy
//!   hdr_size binary header  ("SKUL" magic)             \
//!   +4096    JSON metadata                             /  secondary copy
//!   32768    keyslots area  (AF-striped wrapped master key)   <-- SECRET
//! ```
//!
//! This module only ever looks at the first `2 * hdr_size` bytes. The wrapped
//! master key lives past that and is never touched here.
//!
//! Both header copies are checksummed and carry a `seqid`. cryptsetup writes
//! them alternately so that a crash mid-update always leaves one intact; we
//! mirror its recovery rule and take the valid copy with the highest `seqid`.

use crate::error::{LuksError, Result};
use crate::secret::Secret;
use serde::{Deserialize, Deserializer};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const MAGIC_PRIMARY: [u8; 6] = *b"LUKS\xba\xbe";
pub const MAGIC_SECONDARY: [u8; 6] = *b"SKUL\xba\xbe";

/// Size of the fixed binary header that precedes the JSON area.
pub const BINARY_HEADER_LEN: usize = 4096;

/// Byte range of the `csum` field within the binary header.
const CSUM_RANGE: std::ops::Range<usize> = 448..512;

/// cryptsetup permits metadata areas from 16 KiB up to 4 MiB.
const MIN_HDR_SIZE: u64 = 16 * 1024;
const MAX_HDR_SIZE: u64 = 4 * 1024 * 1024;

/// Metadata sizes cryptsetup can produce, used to locate the backup copy when
/// the primary header's size field cannot be trusted.
const VALID_HDR_SIZES: [u64; 9] = [
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2048 * 1024,
    4096 * 1024,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuksVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCopy {
    Primary,
    Secondary,
}

/// The fixed-size binary portion of a LUKS2 header.
#[derive(Debug, Clone)]
pub struct BinaryHeader {
    pub version: u16,
    /// Total bytes of this header copy, including the JSON area.
    pub hdr_size: u64,
    /// Update counter. The higher of the two copies is authoritative.
    pub seqid: u64,
    pub label: String,
    pub checksum_alg: String,
    pub salt: Secret,
    pub uuid: String,
    pub subsystem: String,
    pub hdr_offset: u64,
}

/// A fully parsed, checksum-verified LUKS2 header.
#[derive(Debug)]
pub struct Luks2Header {
    pub binary: BinaryHeader,
    pub metadata: Metadata,
    /// Which on-disk copy this came from.
    pub source: HeaderCopy,
}

// ---------------------------------------------------------------------------
// JSON metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub keyslots: BTreeMap<String, Keyslot>,
    pub segments: BTreeMap<String, Segment>,
    pub digests: BTreeMap<String, Digest>,
    pub config: Config,
    #[serde(default)]
    pub tokens: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Keyslot {
    #[serde(rename = "type")]
    pub kind: String,
    pub key_size: usize,
    pub kdf: Kdf,
    pub area: Area,
    #[serde(default)]
    pub af: Option<AntiForensic>,
    #[serde(default)]
    pub priority: Option<i64>,
}

/// Key derivation parameters. Externally tagged on the JSON `type` field.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Kdf {
    #[serde(rename = "argon2i")]
    Argon2i(Argon2Params),
    #[serde(rename = "argon2id")]
    Argon2id(Argon2Params),
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        salt: Secret,
        hash: String,
        iterations: u32,
    },
}

#[derive(Debug, Deserialize)]
pub struct Argon2Params {
    pub salt: Secret,
    /// Iterations (Argon2 "t" cost).
    pub time: u32,
    /// Memory cost in KiB. This is the number that decides whether a phone can
    /// unlock the volume at all — 1048576 here means a 1 GiB allocation.
    pub memory: u32,
    /// Parallelism (Argon2 "p" / lanes).
    pub cpus: u32,
}

impl Kdf {
    /// Memory cost in KiB, or `None` for PBKDF2 (which is memory-cheap).
    pub fn memory_kib(&self) -> Option<u32> {
        match self {
            Kdf::Argon2i(p) | Kdf::Argon2id(p) => Some(p.memory),
            Kdf::Pbkdf2 { .. } => None,
        }
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            Kdf::Argon2i(_) => "argon2i",
            Kdf::Argon2id(_) => "argon2id",
            Kdf::Pbkdf2 { .. } => "pbkdf2",
        }
    }
}

/// Anti-forensic splitter parameters. The wrapped key is stored as `stripes`
/// XORed slices so that partial recovery of the keyslot area yields nothing.
#[derive(Debug, Deserialize)]
pub struct AntiForensic {
    #[serde(rename = "type")]
    pub kind: String,
    pub stripes: u32,
    pub hash: String,
}

/// Where and how a keyslot's wrapped key material is stored.
#[derive(Debug, Deserialize)]
pub struct Area {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(deserialize_with = "u64_from_json")]
    pub offset: u64,
    #[serde(deserialize_with = "u64_from_json")]
    pub size: u64,
    pub encryption: String,
    pub key_size: usize,
}

/// A span of encrypted user data.
#[derive(Debug, Deserialize)]
pub struct Segment {
    #[serde(rename = "type")]
    pub kind: String,
    /// Byte offset from the start of the partition to the ciphertext.
    #[serde(deserialize_with = "u64_from_json")]
    pub offset: u64,
    pub size: SegmentSize,
    /// Starting value for the XTS tweak. Sector N of the segment uses
    /// `iv_tweak + N` — not the partition-absolute LBA.
    #[serde(default, deserialize_with = "u64_from_json_opt")]
    pub iv_tweak: u64,
    pub encryption: String,
    /// Cipher block size. 4096 is legal and changes the tweak numbering.
    pub sector_size: u32,
    /// Segment flags. `iv-large-sectors` switches the IV from counting in
    /// 512-byte units to counting in whole encryption sectors.
    #[serde(default)]
    pub flags: Vec<String>,
}

impl Segment {
    /// How much the XTS tweak advances per encryption sector.
    ///
    /// dm-crypt counts the IV in 512-byte units by default, so a 4096-byte
    /// sector advances the tweak by 8. `iv-large-sectors` makes it advance by 1.
    pub fn tweak_step(&self) -> u128 {
        if self.flags.iter().any(|f| f == "iv-large-sectors") {
            1
        } else {
            (self.sector_size as u128 / 512).max(1)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentSize {
    /// Extends to the end of the partition.
    Dynamic,
    Fixed(u64),
}

impl<'de> Deserialize<'de> for SegmentSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw == "dynamic" {
            return Ok(SegmentSize::Dynamic);
        }
        raw.parse::<u64>()
            .map(SegmentSize::Fixed)
            .map_err(|_| serde::de::Error::custom(format!("bad segment size {raw:?}")))
    }
}

/// Verifier for a candidate master key.
#[derive(Debug, Deserialize)]
pub struct Digest {
    #[serde(rename = "type")]
    pub kind: String,
    pub keyslots: Vec<String>,
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: u32,
    pub salt: Secret,
    pub digest: Secret,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(deserialize_with = "u64_from_json")]
    pub json_size: u64,
    #[serde(deserialize_with = "u64_from_json")]
    pub keyslots_size: u64,
}

/// LUKS2 encodes large integers as JSON *strings* to dodge float precision
/// loss, but not universally. Accept either form.
fn u64_from_json<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    use serde::de::Error;
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => s
            .parse()
            .map_err(|_| D::Error::custom(format!("expected integer, got {s:?}"))),
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom(format!("not a u64: {n}"))),
        other => Err(D::Error::custom(format!("expected integer, got {other}"))),
    }
}

fn u64_from_json_opt<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    u64_from_json(d)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Identify the LUKS version from the first bytes of a partition.
pub fn detect_version(data: &[u8]) -> Result<LuksVersion> {
    if data.len() < 8 {
        return Err(LuksError::Truncated {
            needed: 8,
            got: data.len(),
        });
    }
    let magic: [u8; 6] = data[0..6].try_into().expect("slice is 6 bytes");
    if magic != MAGIC_PRIMARY {
        return Err(LuksError::BadMagic { found: magic });
    }
    match u16::from_be_bytes([data[6], data[7]]) {
        1 => Ok(LuksVersion::V1),
        2 => Ok(LuksVersion::V2),
        other => Err(LuksError::UnsupportedVersion(other)),
    }
}

/// Read and parse a LUKS2 header directly from a device.
///
/// Reads the fixed binary header first to learn `hdr_size`, then fetches both
/// copies. `partition_offset` is the byte offset of the partition on the device.
pub fn read_from<D: crate::device::ReadAt + ?Sized>(
    device: &D,
    partition_offset: u64,
) -> Result<Luks2Header> {
    let mut probe = vec![0u8; BINARY_HEADER_LEN];
    device.read_at(partition_offset, &mut probe)?;

    let declared = if probe.len() >= 16 {
        be_u64(&probe[8..16])
    } else {
        0
    };
    // Fall back to the largest plausible metadata size if the field is unusable,
    // so a damaged primary can still be recovered from the backup.
    let span = if (MIN_HDR_SIZE..=MAX_HDR_SIZE).contains(&declared) {
        declared * 2
    } else {
        MIN_HDR_SIZE * 2
    };

    let mut buf = vec![0u8; span as usize];
    device.read_at(partition_offset, &mut buf)?;
    parse(&buf)
}

/// Parse a LUKS2 header from the start of a partition.
///
/// `data` must cover both header copies (`2 * hdr_size`, normally 32 KiB).
/// Verifies checksums on both copies and returns the valid one with the highest
/// `seqid`, matching cryptsetup's recovery behaviour.
pub fn parse(data: &[u8]) -> Result<Luks2Header> {
    match detect_version(data)? {
        LuksVersion::V1 => return Err(LuksError::Luks1NotImplemented),
        LuksVersion::V2 => {}
    }

    let primary = parse_copy(data, 0, MAGIC_PRIMARY);
    let secondary = find_secondary(data);

    match (primary, secondary) {
        (Ok(p), Ok(s)) => Ok(if s.binary.seqid > p.binary.seqid { s } else { p }),
        (Ok(p), Err(_)) => Ok(p),
        (Err(_), Ok(s)) => Ok(s),
        (Err(e), Err(_)) => Err(e),
    }
}

/// Locate and parse the backup header copy.
///
/// The backup exists for the case where the primary is damaged, so this must
/// not depend on the primary parsing cleanly. We take the primary's `hdr_size`
/// field at face value if it is plausible — a bad checksum does not necessarily
/// mean that particular field is wrong — and otherwise probe every metadata
/// size cryptsetup is able to emit.
fn find_secondary(data: &[u8]) -> Result<Luks2Header> {
    let mut candidates: Vec<usize> = Vec::new();

    if data.len() >= 16 {
        let declared = be_u64(&data[8..16]);
        if (MIN_HDR_SIZE..=MAX_HDR_SIZE).contains(&declared) {
            candidates.push(declared as usize);
        }
    }
    for size in VALID_HDR_SIZES {
        let off = size as usize;
        if !candidates.contains(&off) {
            candidates.push(off);
        }
    }

    let mut last = LuksError::Missing("secondary header");
    for off in candidates {
        if off + BINARY_HEADER_LEN > data.len() {
            continue;
        }
        // Cheap magic check first; probing is otherwise wasted work.
        if data[off..off + 6] != MAGIC_SECONDARY {
            continue;
        }
        match parse_copy(data, off, MAGIC_SECONDARY) {
            Ok(h) => return Ok(h),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn parse_copy(data: &[u8], offset: usize, expect_magic: [u8; 6]) -> Result<Luks2Header> {
    let end = offset
        .checked_add(BINARY_HEADER_LEN)
        .ok_or(LuksError::ImplausibleHeaderSize(offset as u64))?;
    if data.len() < end {
        return Err(LuksError::Truncated {
            needed: end,
            got: data.len(),
        });
    }
    let hdr = &data[offset..];

    let magic: [u8; 6] = hdr[0..6].try_into().expect("slice is 6 bytes");
    if magic != expect_magic {
        return Err(LuksError::BadMagic { found: magic });
    }

    let version = u16::from_be_bytes([hdr[6], hdr[7]]);
    if version != 2 {
        return Err(LuksError::UnsupportedVersion(version));
    }

    let hdr_size = be_u64(&hdr[8..16]);
    if !(MIN_HDR_SIZE..=MAX_HDR_SIZE).contains(&hdr_size) {
        return Err(LuksError::ImplausibleHeaderSize(hdr_size));
    }

    let total = offset
        .checked_add(hdr_size as usize)
        .ok_or(LuksError::ImplausibleHeaderSize(hdr_size))?;
    if data.len() < total {
        return Err(LuksError::Truncated {
            needed: total,
            got: data.len(),
        });
    }

    let binary = BinaryHeader {
        version,
        hdr_size,
        seqid: be_u64(&hdr[16..24]),
        label: c_string(&hdr[24..72]),
        checksum_alg: c_string(&hdr[72..104]),
        salt: Secret::new(hdr[104..168].to_vec()),
        uuid: c_string(&hdr[168..208]),
        subsystem: c_string(&hdr[208..256]),
        hdr_offset: be_u64(&hdr[256..264]),
    };

    verify_checksum(&data[offset..total], &binary)?;

    let json_bytes = &data[offset + BINARY_HEADER_LEN..total];
    let metadata = parse_json(json_bytes)?;

    Ok(Luks2Header {
        binary,
        metadata,
        source: if expect_magic == MAGIC_PRIMARY {
            HeaderCopy::Primary
        } else {
            HeaderCopy::Secondary
        },
    })
}

/// The checksum covers the whole header copy (binary + JSON) with the `csum`
/// field itself zeroed.
fn verify_checksum(copy: &[u8], binary: &BinaryHeader) -> Result<()> {
    if binary.checksum_alg != "sha256" {
        return Err(LuksError::UnsupportedChecksumAlg(
            binary.checksum_alg.clone(),
        ));
    }

    let stored = &copy[CSUM_RANGE];

    let mut scratch = copy.to_vec();
    scratch[CSUM_RANGE].fill(0);
    let computed = Sha256::digest(&scratch);

    // The field is 64 bytes; SHA-256 fills the first 32 and leaves the rest zero.
    if stored[..32] == computed[..] {
        Ok(())
    } else {
        Err(LuksError::ChecksumMismatch)
    }
}

fn parse_json(area: &[u8]) -> Result<Metadata> {
    // The JSON area is NUL-padded out to its full length.
    let end = area.iter().position(|&b| b == 0).unwrap_or(area.len());
    let text = std::str::from_utf8(&area[..end]).map_err(|_| LuksError::JsonNotUtf8)?;
    Ok(serde_json::from_str(text)?)
}

fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("slice is 8 bytes"))
}

/// Read a NUL-terminated string out of a fixed-width field.
fn c_string(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Convenience accessors
// ---------------------------------------------------------------------------

impl Luks2Header {
    /// The data segment, if there is exactly one (the normal case).
    pub fn primary_segment(&self) -> Result<&Segment> {
        self.metadata
            .segments
            .values()
            .next()
            .ok_or(LuksError::Missing("segments"))
    }

    /// Highest Argon2 memory cost across all keyslots, in KiB.
    ///
    /// This is the peak allocation an unlock attempt may need, and therefore
    /// the number that determines whether a phone can open the volume.
    pub fn max_kdf_memory_kib(&self) -> Option<u32> {
        self.metadata
            .keyslots
            .values()
            .filter_map(|k| k.kdf.memory_kib())
            .max()
    }

    /// A one-line summary safe to log: contains no salts, digests or key material.
    pub fn summary(&self) -> String {
        let seg = self.primary_segment().ok();
        let cipher = seg.map(|s| s.encryption.as_str()).unwrap_or("?");
        let sector = seg.map(|s| s.sector_size).unwrap_or(0);
        let kdfs: Vec<&str> = self
            .metadata
            .keyslots
            .values()
            .map(|k| k.kdf.algorithm())
            .collect();
        format!(
            "LUKS2 uuid={} label={:?} cipher={} sector_size={} keyslots={} kdf={:?} max_kdf_mem={} KiB",
            self.binary.uuid,
            self.binary.label,
            cipher,
            sector,
            self.metadata.keyslots.len(),
            kdfs,
            self.max_kdf_memory_kib().unwrap_or(0),
        )
    }
}
