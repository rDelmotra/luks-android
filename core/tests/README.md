# Integration Test Suite (`core/tests/`)

This directory contains the integration test suite for `luks_core`, organized into domain-specific subdirectories.

All integration tests are registered in [`core/Cargo.toml`](../Cargo.toml) with explicit target names, ensuring that running tests by name (e.g. `cargo test -p luks_core --test <name>`) works seamlessly without needing directory path arguments.

---

## Directory Organization

| Directory | Count | Domain Description | Feature Gate |
|---|---|---|---|
| [`crypto_luks/`](crypto_luks/) | 7 | Cryptographic backends, Argon2id/PBKDF2, AES, secret zeroization, LUKS2 headers, keyslot unlocking | Default / `dangerous-write-support` |
| [`device_scsi/`](device_scsi/) | 6 | USB Mass Storage Bulk-Only Transport (BOT), SCSI command emulation (INQUIRY, READ/WRITE), mock drive, write cost metrics | Default / `dangerous-write-support` |
| [`ext4/`](ext4/) | 11 | ext4 inode allocation/deallocation, directory indexing (htree), checksumming, block allocators, streaming | Default / `dangerous-write-support` |
| [`fs_permutation/`](fs_permutation/) | 11 | Structural B-tree permutations, leaf splits, node surgery, interior collapse, FST collapse, scale convergence, and oracles | `dangerous-write-support` |
| [`txn_batch/`](txn_batch/) | 10 | Atomic commit pipeline, reservation stages (B2, C, FG), transaction batching, crash safety, fail-closed aborts | `dangerous-write-support` |
| [`alloc_chunk/`](alloc_chunk/) | 8 | Btrfs chunk allocation, free space search, block group management, system chunk valves, extent trees | Default / `dangerous-write-support` |
| [`btrfs_ops/`](btrfs_ops/) | 14 | High-level file and directory CRUD (read, create, write, delete, mkdir, rename, finish csum, timestamp, gates, subvolume prep) | Default / `dangerous-write-support` |
| [`integration/`](integration/) | 6 | Full-stack scenarios, statfs capacity, tree import replays, forensic logs, and oracle ledgers | Default / `dangerous-write-support` |
| [`common/`](common/) | - | Shared test harnesses: `accounting.rs`, `btree_validator.rs`, `fs_model.rs`, `mem_device.rs`, `oracle.rs`, `scratch.rs` | Shared helper modules |

---

## How to Run Tests

### Running Individual Tests by Name
Because test names are preserved in `core/Cargo.toml`, you do not need to know the subfolder path to run any test:
```bash
# Read-only tests (default build):
cargo test -p luks_core --test aes_backend
cargo test -p luks_core --test luks2_header

# Write-enabled tests:
cargo test -p luks_core --features dangerous-write-support --test btrfs_btree_permutations
cargo test -p luks_core --features dangerous-write-support --test btrfs_conformance
```

### Running Entire Test Suites
```bash
# Run all read-only tests across workspace:
cargo test --workspace

# Run all core tests including write paths:
cargo test -p luks_core --features dangerous-write-support

# Run the 7-tier verified harness:
bash tools/run-harness.sh --all

# Check structural transition coverage:
bash tools/run-harness.sh --transitions
```

---

## Complete Path Lookup Table (Legacy -> Modular)

If documentation, commit notes, or an agent refers to a legacy path directly under `core/tests/<name>.rs`, use this table to locate the file:

### `crypto_luks/`
- `core/tests/aes_backend.rs` -> `core/tests/crypto_luks/aes_backend.rs`
- `core/tests/secret_zeroize.rs` -> `core/tests/crypto_luks/secret_zeroize.rs`
- `core/tests/luks2_header.rs` -> `core/tests/crypto_luks/luks2_header.rs`
- `core/tests/luks2_unlock.rs` -> `core/tests/crypto_luks/luks2_unlock.rs`
- `core/tests/luks2_real_fixtures.rs` -> `core/tests/crypto_luks/luks2_real_fixtures.rs`
- `core/tests/luks_write.rs` -> `core/tests/crypto_luks/luks_write.rs`
- `core/tests/luks_ext4_write.rs` -> `core/tests/crypto_luks/luks_ext4_write.rs`

### `device_scsi/`
- `core/tests/raw_device.rs` -> `core/tests/device_scsi/raw_device.rs`
- `core/tests/usb_scsi.rs` -> `core/tests/device_scsi/usb_scsi.rs`
- `core/tests/write_device.rs` -> `core/tests/device_scsi/write_device.rs`
- `core/tests/write_target.rs` -> `core/tests/device_scsi/write_target.rs`
- `core/tests/write_cost.rs` -> `core/tests/device_scsi/write_cost.rs`
- `core/tests/scsi_write.rs` -> `core/tests/device_scsi/scsi_write.rs`

### `ext4/`
- `core/tests/ext4_read.rs` -> `core/tests/ext4/ext4_read.rs`
- `core/tests/ext4_csum.rs` -> `core/tests/ext4/ext4_csum.rs`
- `core/tests/ext4_write_gate.rs` -> `core/tests/ext4/ext4_write_gate.rs`
- `core/tests/ext4_alloc.rs` -> `core/tests/ext4/ext4_alloc.rs`
- `core/tests/ext4_inode_patch.rs` -> `core/tests/ext4/ext4_inode_patch.rs`
- `core/tests/ext4_file.rs` -> `core/tests/ext4/ext4_file.rs`
- `core/tests/ext4_mkdir.rs` -> `core/tests/ext4/ext4_mkdir.rs`
- `core/tests/ext4_delete.rs` -> `core/tests/ext4/ext4_delete.rs`
- `core/tests/ext4_rename.rs` -> `core/tests/ext4/ext4_rename.rs`
- `core/tests/ext4_dirent.rs` -> `core/tests/ext4/ext4_dirent.rs`
- `core/tests/ext4_streaming_unknown.rs` -> `core/tests/ext4/ext4_streaming_unknown.rs`

### `fs_permutation/`
- `core/tests/btrfs_btree_permutations.rs` -> `core/tests/fs_permutation/btrfs_btree_permutations.rs`
- `core/tests/btrfs_conformance.rs` -> `core/tests/fs_permutation/btrfs_conformance.rs`
- `core/tests/btrfs_structural_transitions.rs` -> `core/tests/fs_permutation/btrfs_structural_transitions.rs`
- `core/tests/btrfs_interior_collapse.rs` -> `core/tests/fs_permutation/btrfs_interior_collapse.rs`
- `core/tests/btrfs_fst_collapse.rs` -> `core/tests/fs_permutation/btrfs_fst_collapse.rs`
- `core/tests/btrfs_root_split.rs` -> `core/tests/fs_permutation/btrfs_root_split.rs`
- `core/tests/btrfs_node_surgery.rs` -> `core/tests/fs_permutation/btrfs_node_surgery.rs`
- `core/tests/btrfs_cow_fixup.rs` -> `core/tests/fs_permutation/btrfs_cow_fixup.rs`
- `core/tests/btrfs_empty_leaf.rs` -> `core/tests/fs_permutation/btrfs_empty_leaf.rs`
- `core/tests/btrfs_scale_convergence.rs` -> `core/tests/fs_permutation/btrfs_scale_convergence.rs`
- `core/tests/btrfs_accounting_oracle.rs` -> `core/tests/fs_permutation/btrfs_accounting_oracle.rs`

### `txn_batch/`
- `core/tests/btrfs_batch_cross_file.rs` -> `core/tests/txn_batch/btrfs_batch_cross_file.rs`
- `core/tests/btrfs_batch_double_alloc.rs` -> `core/tests/txn_batch/btrfs_batch_double_alloc.rs`
- `core/tests/btrfs_batch_equality.rs` -> `core/tests/txn_batch/btrfs_batch_equality.rs`
- `core/tests/btrfs_batch_n_greater_1.rs` -> `core/tests/txn_batch/btrfs_batch_n_greater_1.rs`
- `core/tests/btrfs_batch_resume_corruption.rs` -> `core/tests/txn_batch/btrfs_batch_resume_corruption.rs`
- `core/tests/btrfs_commit_template_corruption.rs` -> `core/tests/txn_batch/btrfs_commit_template_corruption.rs`
- `core/tests/btrfs_abandon_fail_closed.rs` -> `core/tests/txn_batch/btrfs_abandon_fail_closed.rs`
- `core/tests/btrfs_stage_b2_release.rs` -> `core/tests/txn_batch/btrfs_stage_b2_release.rs`
- `core/tests/btrfs_stage_c_reservation.rs` -> `core/tests/txn_batch/btrfs_stage_c_reservation.rs`
- `core/tests/btrfs_stage_fg.rs` -> `core/tests/txn_batch/btrfs_stage_fg.rs`

### `alloc_chunk/`
- `core/tests/btrfs_chunk_alloc_controls.rs` -> `core/tests/alloc_chunk/btrfs_chunk_alloc_controls.rs`
- `core/tests/btrfs_chunk_alloc_search.rs` -> `core/tests/alloc_chunk/btrfs_chunk_alloc_search.rs`
- `core/tests/btrfs_chunk_alloc_txn.rs` -> `core/tests/alloc_chunk/btrfs_chunk_alloc_txn.rs`
- `core/tests/btrfs_chunk_roundtrip.rs` -> `core/tests/alloc_chunk/btrfs_chunk_roundtrip.rs`
- `core/tests/btrfs_large_file_chunk_alloc.rs` -> `core/tests/alloc_chunk/btrfs_large_file_chunk_alloc.rs`
- `core/tests/btrfs_streaming_chunk_alloc.rs` -> `core/tests/alloc_chunk/btrfs_streaming_chunk_alloc.rs`
- `core/tests/btrfs_valves.rs` -> `core/tests/alloc_chunk/btrfs_valves.rs`
- `core/tests/btrfs_extent_tree.rs` -> `core/tests/alloc_chunk/btrfs_extent_tree.rs`

### `btrfs_ops/`
- `core/tests/btrfs_read.rs` -> `core/tests/btrfs_ops/btrfs_read.rs`
- `core/tests/btrfs_create_file.rs` -> `core/tests/btrfs_ops/btrfs_create_file.rs`
- `core/tests/btrfs_data_write.rs` -> `core/tests/btrfs_ops/btrfs_data_write.rs`
- `core/tests/btrfs_delete.rs` -> `core/tests/btrfs_ops/btrfs_delete.rs`
- `core/tests/btrfs_mkdir.rs` -> `core/tests/btrfs_ops/btrfs_mkdir.rs`
- `core/tests/btrfs_rename.rs` -> `core/tests/btrfs_ops/btrfs_rename.rs`
- `core/tests/btrfs_finish_file_csum.rs` -> `core/tests/btrfs_ops/btrfs_finish_file_csum.rs`
- `core/tests/btrfs_timestamp_write.rs` -> `core/tests/btrfs_ops/btrfs_timestamp_write.rs`
- `core/tests/btrfs_streaming_unknown.rs` -> `core/tests/btrfs_ops/btrfs_streaming_unknown.rs`
- `core/tests/btrfs_streaming_crash_safety.rs` -> `core/tests/btrfs_ops/btrfs_streaming_crash_safety.rs`
- `core/tests/btrfs_crash_safety.rs` -> `core/tests/btrfs_ops/btrfs_crash_safety.rs`
- `core/tests/btrfs_write_gate.rs` -> `core/tests/btrfs_ops/btrfs_write_gate.rs`
- `core/tests/btrfs_csum_type_gate.rs` -> `core/tests/btrfs_ops/btrfs_csum_type_gate.rs`
- `core/tests/btrfs_subvol_prep.rs` -> `core/tests/btrfs_ops/btrfs_subvol_prep.rs`

### `integration/`
- `core/tests/end_to_end.rs` -> `core/tests/integration/end_to_end.rs`
- `core/tests/full_stack.rs` -> `core/tests/integration/full_stack.rs`
- `core/tests/statfs.rs` -> `core/tests/integration/statfs.rs`
- `core/tests/tree_import_oracle.rs` -> `core/tests/integration/tree_import_oracle.rs`
- `core/tests/forensic_log.rs` -> `core/tests/integration/forensic_log.rs`
- `core/tests/oracle_ledger.rs` -> `core/tests/integration/oracle_ledger.rs`

---

## Authoring New Tests

When adding a new integration test:
1. Place the `.rs` file in the appropriate domain subdirectory (`core/tests/<category>/<name>.rs`).
2. If it requires shared utilities from `common/`, import via:
   ```rust
   #[path = "../common/mod.rs"]
   mod common;
   ```
3. Register the test in [`core/Cargo.toml`](../Cargo.toml):
   ```toml
   [[test]]
   name = "<name>"
   path = "tests/<category>/<name>.rs"
   required-features = ["dangerous-write-support"]  # omit if read-only
   ```
