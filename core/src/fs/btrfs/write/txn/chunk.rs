//! `Transaction::allocate_data_chunk` — thin driver over `chunk_alloc`.

use crate::device::ReadAt;
use crate::error::Result;
use crate::fs::btrfs::Btrfs;

use super::Transaction;

impl Transaction {
    /// Prepare a transaction that allocates a new single DATA chunk.
    pub fn allocate_data_chunk<D: ReadAt>(
        fs: &Btrfs<D>,
    ) -> Result<(Self, crate::fs::btrfs::chunk::Chunk)> {
        crate::fs::btrfs::write::chunk_alloc::allocate_data_chunk_transaction(fs)
    }

    /// Same as [`Transaction::allocate_data_chunk`], but excludes `reserved`
    /// logical ranges from the allocator used for this chunk's own metadata
    /// CoW. See `chunk_alloc::allocate_data_chunk_transaction_excluding`.
    pub fn allocate_data_chunk_excluding<D: ReadAt>(
        fs: &Btrfs<D>,
        reserved: &[(u64, u64)],
    ) -> Result<(Self, crate::fs::btrfs::chunk::Chunk)> {
        crate::fs::btrfs::write::chunk_alloc::allocate_data_chunk_transaction_excluding(
            fs, reserved,
        )
    }
}
