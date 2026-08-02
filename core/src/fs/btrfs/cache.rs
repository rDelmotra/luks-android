//! A small cache of parsed tree nodes.
//!
//! Measured on the developer's 1 TB drive, reading one 492 MiB file: **4254
//! device reads, of which 3729 were 16 KiB tree nodes** against 618 large data
//! reads. Six metadata reads per data read, because every call to
//! [`verify_data`](super::csum) starts a fresh `search_le` at the checksum
//! tree's root and every extent lookup re-descends the fs tree beside it.
//! Neither remembered anything between calls.
//!
//! Those 3729 reads fetched about 58 MiB to cover roughly 1 MiB of distinct
//! nodes — the same handful of blocks pulled off the device around sixty times
//! each. On a raw character device, which has no cache underneath to hide them,
//! that cost ~170 µs apiece: **0.63 s of a 2.33 s read, 27% of the total.**
//!
//! It is worth much more than that on the phone. A SCSI command over USB was
//! measured at 760 µs, so the same 3729 reads are **2.8 seconds of pure
//! latency** per 500 MB — spent on the link that is already the bottleneck.
//!
//! The same measurement explained an anomaly that had looked like an error:
//! through macOS's *buffered* device node the reader appeared to sustain 145
//! MiB/s where `dd` manages only 132. That is real, and it is this — the page
//! cache was serving the metadata re-reads for free. The buffered path was
//! winning precisely on the reads that should never have been issued.
//!
//! # What is safe to cache, and why
//!
//! The filesystem is mounted read-only and this crate cannot write to a device
//! at all (`dangerous-write-support` is an empty non-default feature), so a
//! node's contents cannot change underneath the cache. There is no invalidation
//! and there is nothing to invalidate. A drive physically swapped mid-read is
//! outside what any cache could defend against, and the `fsid` check on every
//! parsed node is what catches that.
//!
//! A hit skips the checksum verification that a miss performs — the node was
//! verified when it was first parsed, and re-verifying an in-memory copy would
//! only detect memory corruption, which is not the threat this reader is built
//! against.
//!
//! # Why it hands back a clone
//!
//! The obvious alternative is `Arc<Node>`, which would make a hit free. It
//! would also change the signature of `read_node` and every type that holds a
//! node — [`Cursor`](super::Cursor) most of all — for a copy of 16 KiB that
//! takes about a microsecond against the 170 to 760 µs it replaces. Three
//! thousand hits is a few milliseconds of memcpy to save six hundred of I/O.
//! If node reads ever stop being I/O-bound, this is the thing to revisit.

use super::tree::Node;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Roughly how much memory the cache may hold in nodes.
///
/// 2 MiB is chosen against the phone, not the desktop: it is nothing next to
/// the 1 GiB Argon2 allocation the same process survives, and the working set
/// it needs to hold is far smaller — a tree descent touches one node per level
/// and btrfs allows at most 8. The budget is generous so that reading several
/// files, or a directory listing interleaved with data reads, does not evict
/// the levels that every one of them shares.
const BUDGET_BYTES: usize = 2 * 1024 * 1024;

/// The fewest nodes worth keeping, whatever the node size.
///
/// A node can legally be 64 KiB, which would leave the budget holding 32. The
/// floor matters more than the budget does: fewer than one entry per tree level
/// and a descent evicts its own root before the next descent reuses it, which
/// is the pathological case the cache exists to remove.
const MIN_ENTRIES: usize = 16;

pub(super) struct NodeCache {
    inner: Mutex<Inner>,
    capacity: usize,
}

struct Inner {
    nodes: HashMap<u64, Node>,
    /// Insertion order, for eviction. FIFO rather than LRU on purpose: the
    /// working set is a handful of nodes against a capacity of a hundred or
    /// more, so the two policies never disagree in practice, and FIFO needs no
    /// bookkeeping on the hot path (a hit touches nothing).
    order: VecDeque<u64>,
    hits: u64,
    misses: u64,
}

impl NodeCache {
    pub(super) fn new(node_size: u32) -> Self {
        let node_size = node_size.max(1) as usize;
        let capacity = (BUDGET_BYTES / node_size).max(MIN_ENTRIES);
        Self {
            inner: Mutex::new(Inner {
                nodes: HashMap::new(),
                order: VecDeque::new(),
                hits: 0,
                misses: 0,
            }),
            capacity,
        }
    }

    /// The node at `bytenr`, if it is held.
    pub(super) fn get(&self, bytenr: u64) -> Option<Node> {
        let mut inner = self.lock();
        match inner.nodes.get(&bytenr) {
            Some(node) => {
                let node = node.clone();
                inner.hits += 1;
                Some(node)
            }
            None => {
                inner.misses += 1;
                None
            }
        }
    }

    pub(super) fn insert(&self, bytenr: u64, node: &Node) {
        let mut inner = self.lock();
        // A concurrent miss on the same node can insert twice. Re-inserting
        // would push a second copy of the key into `order` and evict a live
        // entry early, so leave the existing one alone.
        if inner.nodes.contains_key(&bytenr) {
            return;
        }
        while inner.order.len() >= self.capacity {
            match inner.order.pop_front() {
                Some(old) => {
                    inner.nodes.remove(&old);
                }
                None => break,
            }
        }
        inner.order.push_back(bytenr);
        inner.nodes.insert(bytenr, node.clone());
    }

    /// Hits and misses since mount, for diagnostics.
    pub(super) fn stats(&self) -> (u64, u64) {
        let inner = self.lock();
        (inner.hits, inner.misses)
    }

    /// A poisoned cache is recoverable: the worst a panic mid-update can leave
    /// behind is a stale entry or a missing one, and both merely cost a reread.
    /// Propagating the poison would turn an unrelated panic in one thread into
    /// a filesystem that cannot be read from any thread.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}
