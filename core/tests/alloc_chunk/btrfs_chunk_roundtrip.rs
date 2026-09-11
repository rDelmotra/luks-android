//! Byte-identical round-trip verification for CHUNK_ITEM and DEV_EXTENT (Pass H.1).
//!
//! Ground truth: Every chunk in sys_chunk_array and chunk_tree, and every
//! DEV_EXTENT in dev_tree across all btrfs fixture images, when parsed into
//! [`Chunk`] or [`DevExtent`] and re-emitted via [`Chunk::emit`] /
//! [`DevExtent::emit`], must produce 100% byte-identical reproduction of the
//! raw on-disk bytes.

use luks_core::device::FileDevice;
use luks_core::fs::btrfs::chunk::{
    Chunk, DevExtent, CHUNK_ITEM_HEAD, DEV_EXTENT_SIZE, STRIPE_SIZE,
};
use luks_core::fs::btrfs::tree::{
    self, Key, CHUNK_ITEM_KEY, DEV_EXTENT_KEY, DEV_TREE_OBJECTID, FIRST_CHUNK_TREE_OBJECTID,
};
use luks_core::fs::btrfs::Btrfs;

const IMAGES: [&str; 4] = ["plain.img", "compress.img", "mixed-4k.img", "subvol.img"];

fn fixture_path(name: &str) -> String {
    format!("{}/../fixtures/btrfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn mount(name: &str) -> Btrfs<FileDevice> {
    let dev = FileDevice::open(fixture_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    Btrfs::mount(dev).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn sys_chunk_array_round_trip_is_byte_identical_on_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let sb = fs.superblock();
        let a = &sb.sys_chunk_array;
        let mut at = 0usize;
        let mut count = 0;

        while at < a.len() {
            let key = Key::new(
                u64::from_le_bytes(a[at..at + 8].try_into().unwrap()),
                a[at + 8],
                u64::from_le_bytes(a[at + 9..at + 17].try_into().unwrap()),
            );
            at += tree::KEY_SIZE;

            assert_eq!(
                key.item_type, CHUNK_ITEM_KEY,
                "{name}: expected CHUNK_ITEM_KEY in sys_chunk_array"
            );
            assert_eq!(
                key.objectid, FIRST_CHUNK_TREE_OBJECTID,
                "{name}: expected FIRST_CHUNK_TREE_OBJECTID in sys_chunk_array"
            );

            let num_stripes = u16::from_le_bytes(a[at + 44..at + 46].try_into().unwrap()) as usize;
            let item_len = CHUNK_ITEM_HEAD + num_stripes * STRIPE_SIZE;
            let raw_data = &a[at..at + item_len];

            // 1. Parse raw data into Chunk
            let chunk = Chunk::parse(key.offset, raw_data)
                .unwrap_or_else(|e| panic!("{name}: failed to parse sys_chunk at {}: {e}", key.offset));

            // 2. Re-emit via Chunk::emit
            let (emitted_key, emitted_bytes) = chunk.emit();

            // 3. Assert 100% byte-identical key and payload reproduction
            assert_eq!(emitted_key, key, "{name}: emitted key mismatch at offset {}", key.offset);
            assert_eq!(
                emitted_bytes.as_slice(),
                raw_data,
                "{name}: emitted sys_chunk_array bytes differ for logical {}",
                key.offset
            );

            // 4. Assert re-parsed chunk is identical
            let re_parsed = Chunk::parse(emitted_key.offset, &emitted_bytes)
                .expect("re-parsed emitted chunk must succeed");
            assert_eq!(re_parsed, chunk, "{name}: re-parsed chunk struct differs");

            at += item_len;
            count += 1;
        }

        assert!(count > 0, "{name}: sys_chunk_array had no chunks");
    }
}

#[test]
fn chunk_tree_items_round_trip_is_byte_identical_on_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let sb = fs.superblock();
        let mut count = 0;

        fs.walk_tree(sb.chunk_root, &mut |key, raw_data| {
            if key.item_type == CHUNK_ITEM_KEY && key.objectid == FIRST_CHUNK_TREE_OBJECTID {
                // 1. Parse chunk
                let chunk = Chunk::parse(key.offset, raw_data)
                    .unwrap_or_else(|e| panic!("{name}: failed to parse chunk at {}: {e}", key.offset));

                // 2. Emit chunk
                let (emitted_key, emitted_bytes) = chunk.emit();

                // 3. Assert byte-identical key and payload reproduction
                assert_eq!(emitted_key, key, "{name}: emitted key mismatch at offset {}", key.offset);
                assert_eq!(
                    emitted_bytes.as_slice(),
                    raw_data,
                    "{name}: emitted chunk_tree bytes differ for logical {}",
                    key.offset
                );

                // 4. Assert re-parsed chunk is identical
                let re_parsed = Chunk::parse(emitted_key.offset, &emitted_bytes)
                    .expect("re-parsed emitted chunk must succeed");
                assert_eq!(re_parsed, chunk, "{name}: re-parsed chunk struct differs");

                count += 1;
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{name}: failed to walk chunk tree: {e}"));

        assert!(count > 0, "{name}: chunk tree had no CHUNK_ITEMs");
    }
}

#[test]
fn dev_extent_items_round_trip_is_byte_identical_on_all_fixtures() {
    for name in IMAGES {
        let fs = mount(name);
        let dev_tree = fs
            .tree_root(DEV_TREE_OBJECTID)
            .unwrap_or_else(|e| panic!("{name}: dev_tree root lookup failed: {e}"));

        let mut count = 0;
        let mut dev_extents = Vec::new();

        fs.walk_tree(dev_tree.bytenr, &mut |key, raw_data| {
            if key.item_type == DEV_EXTENT_KEY {
                assert_eq!(
                    raw_data.len(),
                    DEV_EXTENT_SIZE,
                    "{name}: DEV_EXTENT payload size must be 48 bytes"
                );

                // 1. Parse dev extent
                let dev_extent = DevExtent::parse(&key, raw_data)
                    .unwrap_or_else(|e| panic!("{name}: failed to parse dev extent at {}: {e}", key.offset));

                // 2. Emit dev extent
                let (emitted_key, emitted_bytes) = dev_extent.emit();

                // 3. Assert byte-identical key and payload reproduction
                assert_eq!(emitted_key, key, "{name}: emitted dev extent key mismatch at {}", key.offset);
                assert_eq!(
                    emitted_bytes.as_slice(),
                    raw_data,
                    "{name}: emitted DEV_EXTENT bytes differ for physical {}",
                    key.offset
                );

                // 4. Assert re-parsed dev extent is identical
                let re_parsed = DevExtent::parse(&emitted_key, &emitted_bytes)
                    .expect("re-parsed emitted dev extent must succeed");
                assert_eq!(re_parsed, dev_extent, "{name}: re-parsed dev extent struct differs");

                // 5. Check semantic invariants (§2.3)
                assert_eq!(dev_extent.chunk_tree, tree::CHUNK_TREE_OBJECTID, "{name}: chunk_tree must be 3");
                assert_eq!(
                    dev_extent.chunk_objectid, FIRST_CHUNK_TREE_OBJECTID,
                    "{name}: chunk_objectid must be 256"
                );
                assert_eq!(
                    dev_extent.chunk_tree_uuid,
                    fs.chunk_tree_uuid().unwrap(),
                    "{name}: chunk_tree_uuid must match chunk tree uuid"
                );

                dev_extents.push(dev_extent);
                count += 1;
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{name}: failed to walk dev tree: {e}"));

        assert!(count > 0, "{name}: dev tree had no DEV_EXTENT items");

        // 6. Cross-check DEV_EXTENT items with ChunkMap stripes
        let total_stripes: usize = fs.chunk_map().chunks().iter().map(|c| c.stripes.len()).sum();
        assert_eq!(
            dev_extents.len(),
            total_stripes,
            "{name}: dev extents count ({}) must match total stripes across all chunks ({})",
            dev_extents.len(),
            total_stripes
        );

        for chunk in fs.chunk_map().chunks() {
            for stripe in &chunk.stripes {
                let matching = dev_extents
                    .iter()
                    .find(|de| de.physical_offset == stripe.offset && de.devid == stripe.devid);
                assert!(
                    matching.is_some(),
                    "{name}: stripe at physical {} has no matching DEV_EXTENT",
                    stripe.offset
                );
                let de = matching.unwrap();
                assert_eq!(de.chunk_offset, chunk.logical, "{name}: dev extent chunk_offset mismatch");
                assert_eq!(de.length, chunk.length, "{name}: dev extent length mismatch");
            }
        }
    }
}
