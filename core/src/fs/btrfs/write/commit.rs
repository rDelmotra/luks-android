//! Committing in-memory btrfs transactions to the underlying device.
//!
//! Strict write ordering:
//! 1. All new metadata blocks (written to EVERY DUP stripe).
//! 2. Flush device (`device.flush()`).
//! 3. Updated superblock copies (written to all valid `SUPER_OFFSETS` with bumped generation and cleared FST VALID bit).
//! 4. Final flush (`device.flush()`).
//! 5. Update in-memory mount state & clear node cache.

use crate::device::WriteAt;
use crate::error::Result;
use crate::fs::btrfs::superblock::{Superblock, SUPER_OFFSETS, SUPER_SIZE};
use crate::fs::btrfs::write::txn::Transaction;
use crate::fs::btrfs::Btrfs;

/// Commit an in-memory transaction to `fs.device_mut()`.
pub fn commit_transaction<D: WriteAt>(
    fs: &mut Btrfs<D>,
    txn: Transaction,
) -> Result<()> {
    // Read raw superblock copy #0 as a template.
    let mut template = vec![0u8; SUPER_SIZE];
    fs.device().read_at(SUPER_OFFSETS[0], &mut template)?;

    // Verify the template before trusting a single byte of it. This used to
    // be the only unverified superblock read in the codebase: `emit_copy`
    // below stamps a FRESH, valid checksum over whatever `template` holds
    // and writes the result to all three mirrors. Without this check, a
    // transport glitch on this one read (desynced USB pipe, torn cable)
    // would not be caught — our own checksum would certify the garbage and
    // launder it into permanent, "verified" corruption across every
    // mirror, surviving a replug. `Superblock::parse` is the exact
    // mechanism every other superblock read in this codebase is checked
    // with (magic at 0x40, then checksum per `csum_type`); reuse it here
    // instead of duplicating the CRC/SHA256 dispatch. See
    // notes/btrfs-recon-2026-08-30/PLAN-2026-09-01.md, item H5.
    Superblock::parse(&template, SUPER_OFFSETS[0])?;

    let dev_len = fs.device().len();

    // 1. Write all new data blocks to all physical stripes.
    for (bytenr, data_bytes) in &txn.pending_data {
        let stripes = fs.chunk_map().map_all_stripes(*bytenr)?;
        for phys in stripes {
            fs.device_mut().write_at(phys, data_bytes)?;
        }
    }

    // 2. Write all new metadata blocks to all physical stripes.
    for (bytenr, block_bytes) in &txn.pending_blocks {
        let stripes = fs.chunk_map().map_all_stripes(*bytenr)?;
        for phys in stripes {
            fs.device_mut().write_at(phys, block_bytes)?;
        }
    }

    // 3. Push all data and metadata blocks to medium before writing superblock.
    fs.device_mut().flush()?;

    // 3. Prepare updated superblock.
    let mut new_sb = fs.superblock().clone();
    new_sb.generation = txn.new_generation;
    new_sb.root = txn.final_root_bytenr;
    new_sb.root_level = txn.final_root_level;
    if let Some((chunk_root_bytenr, chunk_root_level)) = txn.final_chunk_root {
        new_sb.chunk_root = chunk_root_bytenr;
        new_sb.chunk_root_level = chunk_root_level;
        new_sb.chunk_root_generation = txn.new_generation;
    }
    new_sb.bytes_used = txn.final_bytes_used;
    // Keep compat_ro_flags consistent with the emitted Free Space Tree.

    // Write superblock mirrors.
    for offset in SUPER_OFFSETS {
        if let Some(len) = dev_len {
            if offset + SUPER_SIZE as u64 > len {
                continue;
            }
        }
        let raw_copy = new_sb.emit_copy(&template, offset);
        fs.device_mut().write_at(offset, &raw_copy)?;
    }

    // 4. Final flush ensuring superblock is committed to disk.
    fs.device_mut().flush()?;

    // 5. Update in-memory mount state and clear node cache.
    fs.update_mount_state(new_sb, txn.new_fs_tree);

    crate::forensic::record_btrfs(crate::forensic::BtrfsEvent::Commit {
        generation: txn.new_generation,
        transid: txn.new_generation,
        nodes_written: txn.pending_blocks.len(),
    });

    Ok(())
}
