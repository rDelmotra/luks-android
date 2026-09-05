# Architecture

The system is structured as a 5-layer pipeline connecting Jetpack Compose down to physical USB endpoints:

```mermaid
flowchart TD
    UI["Jetpack Compose UI<br/>Browser / Devices / Diagnostics"] -->|Kotlin Coroutines| JNI["JNI Interop Layer<br/>Generational Handles & Panic Boundaries"]
    JNI -->|Direct ByteBuffer| Core["Rust Core Engine"]
    
    subgraph Core["Rust Core Engine"]
        direction TB
        Btrfs["Btrfs Engine<br/>B-Tree CoW / ChunkMap"] --- Ext4["ext4 Engine<br/>Extent Trees / Bitmaps"]
        Btrfs & Ext4 --> LUKS["LUKS2 Crypto Volume<br/>AES-256-XTS ARMv8"]
        LUKS --> SCSI["SCSI Translation<br/>READ 10 / WRITE 10"]
    end
    
    Core -->|BulkTransport Trait| USBFS["Userspace USBFS Driver<br/>URB Arena & Drain Recovery"]
    USBFS -->|ioctl /dev/bus/usb| Drive[("Physical Storage Device<br/>External Drive / Flash Storage")]
```

| Layer | Component | Responsibility |
| :--- | :--- | :--- |
| **Presentation** | Android Jetpack Compose | Modern UI handling device attach events, directory browsing, file transfers, and real-time session state. |
| **Bridge** | JNI Interop Layer | Translates Kotlin calls to Rust, enforces panic barriers, and exposes zero-copy `DirectByteBuffer` buffers. |
| **Filesystems** | Btrfs & ext4 Engines | Parses and mutates filesystem structures, handles inode resolution, extent mapping, and directory indexing. |
| **Cryptography** | LUKS2 Crypto Layer | Decrypts volume headers, parses JSON metadata, derives master keys, and performs hardware-accelerated AES-XTS transforms. |
| **Transport** | Userspace USBFS Driver | Issues low-level SCSI commands (INQUIRY, READ 10, WRITE 10) directly over `/dev/bus/usb` ioctls with robust retry logic. |

---

## Hardware Benchmarks

Measured on physical ARM64 hardware (Android 14+):

| Benchmark Setup | Raw Read | App Export | App Import | Unlock Latency |
| :--- | :---: | :---: | :---: | :---: |
| **Rig A:** Commodity USB 3.2 Gen 1 (OTG) | `29.8 MiB/s` | `21.2 MiB/s` | `6.2–7.4 MiB/s` * | `~1.8 s` *(Argon2id, 256 MiB)* |
| **Rig B:** High-Speed NVMe Storage (USB-C) | `108.7 MiB/s` | `96.5 MiB/s` | `75.0–90.0 MiB/s` | `~6.7 s` *(Argon2id, 1 GiB)* |

> [!NOTE]
> *Write throughput on Rig A is limited by the physical flash write characteristics and pSLC cache exhaustion common on commodity USB thumb drives (~7–10 MB/s sustained flash write).

---

## Feature Support Matrix

| Feature | Read | Write | Implementation Status |
| :--- | :---: | :---: | :--- |
| **LUKS2 (Argon2id & PBKDF2)** | Supported | Supported | Full keyslot parsing, header validation, and key derivation |
| **ext4** | Supported | Supported | Extent trees, directory indexing, block group management |
| **Btrfs (Single device)** | Supported | Supported | Dynamic chunk allocation, B-tree transactions, and CRC32c verification |
| **Btrfs Subvolumes** | Supported | Refused (Fail-closed) | Subvolume writes refused by design to prevent cross-tree mismatches |
| **Btrfs Reflink Deletion** | Supported | Supported | Reflink-safe extent pruning preserving shared extents |
| **Btrfs Compression** | Supported | Planned | ZSTD, LZO, and ZLIB decompression supported; write compression deferred |
| **Btrfs Multi-device (RAID)** | Refused | Refused | Fail-closed refusal to protect multi-device arrays on mobile |
| **SAF DocumentsProvider** | Supported | Planned | Exposes storage to Android system file pickers (Read-only) |

> [!NOTE]
> This matrix describes what the source on `main` supports. The downloadable `v0.1.0` release APK is a read-only build — see the caution note in the [root README](../README.md#quickstart). Write support ships in a tagged release once it's release-hardened.
