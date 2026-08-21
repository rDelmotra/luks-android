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
}
