//! Helpers for reproducing the kernel's *packed* `EXTENT_CSUM` layout.
//!
//! `mkfs.btrfs` and the Linux kernel store the checksums of adjacent sectors
//! contiguously inside a single `EXTENT_CSUM` item, so one B-tree item can cover
//! several unrelated files — including files living in different trees, since
//! `CSUM_TREE` is global and not per-subvolume. This driver never packs: it emits
//! one item per extent. Tests that need to exercise trimming therefore have to
//! synthesise the packed state the kernel would have written.
//!
//! This is how the 61.5 GB stick was laid out when deleting `/home/user` left an
//! orphan checksum behind — see §6e of the subvolume-write engineering doc.

use std::fs;
use std::path::PathBuf;

use luks_core::device::{FileDevice, ReadAt};
use luks_core::fs::btrfs::tree::{EXTENT_CSUM_KEY, EXTENT_CSUM_OBJECTID, EXTENT_DATA_KEY};
use luks_core::fs::btrfs::write::node::Leaf;
use luks_core::fs::btrfs::{Btrfs, Key};

/// First on-disk data extent address backing `path`.
///
/// Resolution starts at `FS_TREE` but follows into whatever tree the path lands
/// in, so subvolume paths such as `/home/user/docs/one-block.bin` work.
pub fn get_file_disk_bytenr<D: ReadAt>(fs: &Btrfs<D>, path: &str) -> u64 {
    let loc = fs.resolve_no_follow(fs.fs_tree(), path).expect("resolve path");
    let mut disk_bytenr = None;
    fs.for_each_item(
        loc.tree.bytenr,
        loc.inode.objectid,
        EXTENT_DATA_KEY,
        &mut |key, data| {
            let fe = luks_core::fs::btrfs::extent::FileExtent::parse(key.offset, data)?;
            if fe.has_disk_bytes() {
                disk_bytenr = Some(fe.disk_bytenr);
            }
            Ok(true)
        },
    )
    .expect("for_each_item");
    disk_bytenr.expect("file must have a data extent on disk")
}

/// Fuse `num_sectors` consecutive single-sector `EXTENT_CSUM` items starting at
/// `start_bytenr` into one packed item, writing the leaf straight back to disk.
///
/// The real checksum bytes are preserved and merely relocated, so the data still
/// verifies afterwards — only the item framing changes. The assertions are
/// vacuity guards: if the driver ever starts packing on its own, or the csum root
/// stops being a leaf, the helper fails loudly rather than quietly doing nothing.
pub fn pack_adjacent_csums(image_path: &PathBuf, start_bytenr: u64, num_sectors: usize) {
    let file_len = fs::metadata(image_path).unwrap().len();
    let dev = FileDevice::open_writable(image_path, file_len).expect("open writable");
    let fs_btrfs = Btrfs::mount(dev).expect("mount btrfs");
    let sb = fs_btrfs.superblock();
    let sector_size = sb.sector_size as u64;
    let csum_size = sb.csum_type.size();

    let csum_root = fs_btrfs
        .tree_root(luks_core::fs::btrfs::tree::CSUM_TREE_OBJECTID)
        .expect("csum root");
    assert_eq!(
        csum_root.level, 0,
        "vacuity: expected csum root to be leaf in test fixture"
    );
    let physicals = fs_btrfs
        .chunk_map()
        .map_all_stripes(csum_root.bytenr)
        .expect("map csum root stripes");
    assert!(
        !physicals.is_empty(),
        "vacuity: csum root must map to physical stripes"
    );

    let node = fs_btrfs.read_node(csum_root.bytenr).expect("read csum root node");
    let mut leaf = Leaf::from_node(&node, sb.csum_type).expect("parse leaf");

    let mut combined_data = Vec::with_capacity(num_sectors * csum_size);
    let mut keys_to_remove = Vec::new();

    for i in 0..num_sectors {
        let expected_offset = start_bytenr + i as u64 * sector_size;
        let key = Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, expected_offset);
        let idx = leaf
            .find_item(&key)
            .unwrap_or_else(|| panic!("csum item not found at offset {expected_offset:#x}"));
        assert_eq!(
            leaf.items[idx].data.len(),
            csum_size,
            "expected single-sector csum item at {expected_offset:#x}"
        );
        combined_data.extend_from_slice(&leaf.items[idx].data);
        if i > 0 {
            keys_to_remove.push(key);
        }
    }

    assert_eq!(combined_data.len(), num_sectors * csum_size);

    let first_key = Key::new(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, start_bytenr);
    let first_idx = leaf.find_item(&first_key).expect("first key");
    leaf.items[first_idx].data = combined_data;

    for k in keys_to_remove {
        leaf.delete_item(&k).expect("delete subsequent csum key");
    }

    let emitted = leaf.emit(sb.node_size).expect("emit leaf");
    drop(fs_btrfs);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(image_path)
            .expect("open image for raw write");
        for phys in physicals {
            file.seek(SeekFrom::Start(phys)).expect("seek to node phys");
            file.write_all(&emitted).expect("write emitted node");
        }
        file.flush().expect("flush");
    }
}
