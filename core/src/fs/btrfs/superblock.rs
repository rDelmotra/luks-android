//! The btrfs superblock, and the feature gate that decides whether the rest of
//! the reader is allowed to run.
//!
//! Every field offset here was read out of a real `mkfs.btrfs` image and
//! checked against `btrfs inspect-internal dump-super`, not copied from a
//! header file. See `tools/gen-btrfs-fixtures.sh`.

use super::crc32c::crc32c;
use crate::error::{LuksError, Result};

/// `_BHRfS_M`, at offset 0x40 of every superblock copy.
pub const MAGIC: &[u8; 8] = b"_BHRfS_M";

/// btrfs keeps identical superblocks at fixed absolute offsets. A copy only
/// counts if the device is actually big enough to hold it.
pub const SUPER_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];

/// Bytes read and checksummed for one copy.
pub const SUPER_SIZE: usize = 4096;

/// The checksum covers everything after the checksum field itself.
const CSUM_START: usize = 32;

// --- incompat_flags ---------------------------------------------------------
// Values confirmed against the fixtures by comparing the raw flag word with
// dump-super's decoded names: plain.img is 0x341, compress.img 0x379,
// mixed-4k.img 0x345.
const INCOMPAT_MIXED_BACKREF: u64 = 0x1;
const INCOMPAT_DEFAULT_SUBVOL: u64 = 0x2;
const INCOMPAT_MIXED_GROUPS: u64 = 0x4;
const INCOMPAT_COMPRESS_LZO: u64 = 0x8;
const INCOMPAT_COMPRESS_ZSTD: u64 = 0x10;
const INCOMPAT_BIG_METADATA: u64 = 0x20;
const INCOMPAT_EXTENDED_IREF: u64 = 0x40;
const INCOMPAT_RAID56: u64 = 0x80;
const INCOMPAT_SKINNY_METADATA: u64 = 0x100;
const INCOMPAT_NO_HOLES: u64 = 0x200;
const INCOMPAT_METADATA_UUID: u64 = 0x400;
const INCOMPAT_RAID1C34: u64 = 0x800;
const INCOMPAT_ZONED: u64 = 0x1000;
const INCOMPAT_EXTENT_TREE_V2: u64 = 0x2000;
const INCOMPAT_RAID_STRIPE_TREE: u64 = 0x4000;
const INCOMPAT_SIMPLE_QUOTA: u64 = 0x8000;

/// Everything a read-only reader can cope with.
///
/// Most of these need no code at all — they describe how the *allocator* and
/// the back-reference bookkeeping work, which a reader never consults.
/// `RAID1C34` is in the list because a chunk item states its own stripe count
/// and profile, so mirrored data is read by picking any one stripe; the flag
/// tells us nothing the chunk does not.
const SUPPORTED_INCOMPAT: u64 = INCOMPAT_MIXED_BACKREF
    | INCOMPAT_DEFAULT_SUBVOL
    | INCOMPAT_MIXED_GROUPS
    | INCOMPAT_COMPRESS_LZO
    | INCOMPAT_COMPRESS_ZSTD
    | INCOMPAT_BIG_METADATA
    | INCOMPAT_EXTENDED_IREF
    | INCOMPAT_SKINNY_METADATA
    | INCOMPAT_NO_HOLES
    | INCOMPAT_METADATA_UUID
    | INCOMPAT_RAID1C34
    | INCOMPAT_SIMPLE_QUOTA;

/// Checksum algorithm from `csum_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsumType {
    Crc32c,
    Sha256,
}

impl CsumType {
    fn from_raw(raw: u16) -> Result<Self> {
        match raw {
            0 => Ok(CsumType::Crc32c),
            2 => Ok(CsumType::Sha256),
            // xxhash64 and blake2b would each be a new dependency for a case
            // no default mkfs produces. Refuse by name rather than silently
            // skipping verification, which would be the tempting shortcut and
            // would quietly drop the only corruption check we have.
            1 => Err(LuksError::UnsupportedFsFeature("btrfs xxhash64 checksums".into())),
            3 => Err(LuksError::UnsupportedFsFeature("btrfs blake2b checksums".into())),
            other => Err(LuksError::UnsupportedFsFeature(format!(
                "btrfs checksum type {other}"
            ))),
        }
    }

    /// Compute the checksum of `data` and compare it with the leading bytes of
    /// `stored`, which is always the full 32-byte csum field.
    /// Bytes per checksum. Data checksums are packed at this width, so getting
    /// it wrong misaligns every checksum after the first.
    pub fn size(self) -> usize {
        match self {
            CsumType::Crc32c => 4,
            CsumType::Sha256 => 32,
        }
    }

    pub fn verify(self, stored: &[u8], data: &[u8]) -> bool {
        match self {
            CsumType::Crc32c => {
                let want = u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]);
                crc32c(data) == want
            }
            CsumType::Sha256 => {
                use sha2::{Digest, Sha256};
                let got = Sha256::digest(data);
                // Constant time is pointless here — this is corruption
                // detection over public metadata, not authentication.
                got.as_slice() == &stored[..32]
            }
        }
    }

    pub fn calculate(self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        match self {
            CsumType::Crc32c => {
                let c = crc32c(data);
                out[0..4].copy_from_slice(&c.to_le_bytes());
            }
            CsumType::Sha256 => {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(data);
                out.copy_from_slice(digest.as_slice());
            }
        }
        out
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// Parsed btrfs superblock — the fields a read-only reader needs, plus the raw
/// bootstrap chunk array.
#[derive(Debug, Clone)]
pub struct Superblock {
    pub fsid: [u8; 16],
    /// Where this copy claims to live. It must equal the offset it was read
    /// from, which is what stops a stale copy in a re-used partition from
    /// being mistaken for this filesystem's.
    pub bytenr: u64,
    pub generation: u64,
    /// Logical address of the root tree.
    pub root: u64,
    /// Logical address of the chunk tree — the one address that is bootstrapped
    /// from `sys_chunk_array` rather than mapped.
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    /// Objectid of the tree holding the default subvolume's root. 6 = FS_TREE.
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    /// `dev_item.devid` — the id this device answers to in every chunk stripe.
    pub dev_id: u64,
    pub sector_size: u32,
    pub node_size: u32,
    pub stripe_size: u32,
    pub incompat_flags: u64,
    pub compat_ro_flags: u64,
    pub csum_type: CsumType,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub label: String,
    /// Populated only when `METADATA_UUID` is set; otherwise equal to `fsid`.
    pub metadata_uuid: [u8; 16],
    /// The bootstrap chunk array, exactly as stored: enough `(key, chunk)`
    /// pairs to map `chunk_root` and nothing more.
    pub sys_chunk_array: Vec<u8>,
}

impl Superblock {
    /// Find the newest valid superblock copy on `device`.
    ///
    /// The kernel picks by generation too, and it matters more here than the
    /// equivalent would on ext4: btrfs writes the mirrors in a fixed order, so
    /// a machine that lost power mid-commit can leave copy 0 stale while copy 1
    /// is current. Taking the primary unconditionally would mount a filesystem
    /// as it was one transaction ago — which reads perfectly and shows the
    /// wrong contents, the worst failure this reader could have.
    pub fn find<D: crate::device::ReadAt + ?Sized>(device: &D) -> Result<Self> {
        let device_len = device.len();
        let mut best: Option<Superblock> = None;
        let mut first_error: Option<LuksError> = None;

        for offset in SUPER_OFFSETS {
            // A mirror only exists if the device is long enough for it. On a
            // 146 MiB fixture only the first two are present, and on anything
            // under 256 GiB the third never is.
            if let Some(len) = device_len {
                if offset + SUPER_SIZE as u64 > len {
                    continue;
                }
            }

            let mut buf = vec![0u8; SUPER_SIZE];
            if device.read_at(offset, &mut buf).is_err() {
                // A short device whose length we could not learn. Not an error
                // in itself: the copy simply is not there.
                continue;
            }

            match Superblock::parse(&buf, offset) {
                Ok(sb) => {
                    if best.as_ref().is_none_or(|b| sb.generation > b.generation) {
                        best = Some(sb);
                    }
                }
                // Report what the *primary* copy said. "bad checksum on the
                // mirror at 64 MiB" is a baffling thing to show someone whose
                // drive simply is not btrfs.
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }

        best.ok_or_else(|| first_error.unwrap_or(LuksError::NotBtrfs([0; 8])))
    }

    /// Parse and verify one superblock copy read from `offset`.
    pub fn parse(raw: &[u8], offset: u64) -> Result<Self> {
        if raw.len() < SUPER_SIZE {
            return Err(LuksError::Truncated {
                needed: SUPER_SIZE,
                got: raw.len(),
            });
        }
        let b = &raw[..SUPER_SIZE];

        if &b[0x40..0x48] != MAGIC {
            let mut found = [0u8; 8];
            found.copy_from_slice(&b[0x40..0x48]);
            return Err(LuksError::NotBtrfs(found));
        }

        // Checksum before anything else is believed. Every length and pointer
        // below comes out of this block, and this reader is pointed at drives
        // it did not create.
        let csum_type = CsumType::from_raw(u16le(b, 0xc4))?;
        if !csum_type.verify(&b[..32], &b[CSUM_START..]) {
            return Err(LuksError::FsChecksumMismatch("btrfs superblock"));
        }

        let bytenr = u64le(b, 0x30);
        if bytenr != offset {
            // A leftover superblock from a previous filesystem, or a copy read
            // from the wrong place. Either way the trees it points at are not
            // the ones here.
            return Err(LuksError::CorruptFs(
                "btrfs superblock is not where it says it is",
            ));
        }

        let sector_size = u32le(b, 0x90);
        let node_size = u32le(b, 0x94);
        if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
            return Err(LuksError::CorruptFs("implausible btrfs sector size"));
        }
        // 64 KiB is the on-disk maximum; anything larger means we misread the
        // field, and it would size every subsequent node allocation.
        if !node_size.is_power_of_two() || node_size < sector_size || node_size > 65536 {
            return Err(LuksError::CorruptFs("implausible btrfs node size"));
        }

        let incompat_flags = u64le(b, 0xbc);
        let unsupported = incompat_flags & !SUPPORTED_INCOMPAT;
        if unsupported != 0 {
            return Err(LuksError::UnsupportedFsFeature(describe_incompat(
                unsupported,
            )));
        }

        let num_devices = u64le(b, 0x88);
        if num_devices != 1 {
            // A multi-device filesystem's chunks point at device ids we have no
            // way to open — the other members are separate USB devices. Say so
            // rather than reading one device's worth of a striped extent.
            return Err(LuksError::UnsupportedFsFeature(format!(
                "btrfs spanning {num_devices} devices"
            )));
        }

        let sys_array_size = u32le(b, 0xa0) as usize;
        if sys_array_size > 2048 {
            return Err(LuksError::CorruptFs("btrfs sys_chunk_array overruns"));
        }

        let mut fsid = [0u8; 16];
        fsid.copy_from_slice(&b[0x20..0x30]);
        let mut metadata_uuid = [0u8; 16];
        if incompat_flags & INCOMPAT_METADATA_UUID != 0 {
            metadata_uuid.copy_from_slice(&b[0x23b..0x24b]);
        } else {
            metadata_uuid = fsid;
        }

        let label_end = b[0x12b..0x22b].iter().position(|&c| c == 0).unwrap_or(256);
        let label = String::from_utf8_lossy(&b[0x12b..0x12b + label_end]).into_owned();

        Ok(Superblock {
            fsid,
            bytenr,
            generation: u64le(b, 0x48),
            root: u64le(b, 0x50),
            chunk_root: u64le(b, 0x58),
            log_root: u64le(b, 0x60),
            total_bytes: u64le(b, 0x70),
            bytes_used: u64le(b, 0x78),
            root_dir_objectid: u64le(b, 0x80),
            num_devices,
            // dev_item starts at 0xc9 and opens with its devid.
            dev_id: u64le(b, 0xc9),
            sector_size,
            node_size,
            stripe_size: u32le(b, 0x9c),
            incompat_flags,
            compat_ro_flags: u64le(b, 0xb4),
            csum_type,
            root_level: b[0xc6],
            chunk_root_level: b[0xc7],
            label,
            metadata_uuid,
            sys_chunk_array: b[0x32b..0x32b + sys_array_size].to_vec(),
        })
    }

    pub fn has_no_holes(&self) -> bool {
        self.incompat_flags & INCOMPAT_NO_HOLES != 0
    }

    pub fn is_mixed_groups(&self) -> bool {
        self.incompat_flags & INCOMPAT_MIXED_GROUPS != 0
    }

    /// Whether tree blocks are recorded as skinny `METADATA_ITEM`s (key
    /// offset = level) rather than legacy `EXTENT_ITEM`s carrying an inline
    /// `tree_block_info` header. The write engine's extent-tree parser only
    /// understands the skinny layout — see `write::extent_tree`.
    pub fn has_skinny_metadata(&self) -> bool {
        self.incompat_flags & INCOMPAT_SKINNY_METADATA != 0
    }
}

/// Name the flags we refused, so the error says what the drive uses rather than
/// printing a hex word the user cannot act on.
fn describe_incompat(bits: u64) -> String {
    let named = [
        (INCOMPAT_RAID56, "RAID5/6"),
        (INCOMPAT_ZONED, "zoned devices"),
        (INCOMPAT_EXTENT_TREE_V2, "extent tree v2"),
        (INCOMPAT_RAID_STRIPE_TREE, "raid stripe tree"),
    ];
    let mut parts: Vec<String> = named
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();

    let leftover = bits & !named.iter().map(|(b, _)| b).sum::<u64>();
    if leftover != 0 {
        parts.push(format!("unknown incompat flags 0x{leftover:x}"));
    }
    format!("btrfs {}", parts.join(", "))
}
