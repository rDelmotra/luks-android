# LUKS-Android

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org/)
[![Android API](https://img.shields.io/badge/Android-API%2029%2B%20(10%2B)-green.svg)](https://developer.android.com)
[![Architecture](https://img.shields.io/badge/Arch-arm64--v8a-purple.svg)]()
[![Oracle](https://img.shields.io/badge/Oracle-Linux%20Kernel%20Graded-brightgreen.svg)]()

A high-performance, rootless userspace storage engine and Android application bringing encrypted **LUKS2**, **Btrfs**, and **ext4** filesystem read and write support to Android devices over USB-OTG.

---

## Highlights

- **Zero Root Required**: Runs entirely in unprivileged Android userspace via Android's USB Host APIs (`/dev/bus/usb`). No root, no kernel modules, no custom ROMs required.
- **LUKS2 Decryption & Encryption**:
  - Full support for **Argon2id** and **PBKDF2** key derivation functions.
  - AES-256-XTS cryptographic engine accelerated by ARMv8 Cryptography Extensions (`pmull`, `aes`).
  - Strict key hygiene: Master keys and key schedules are scrubbed on drop via `zeroize`.
- **Btrfs Read & Write Engine**:
  - Complete B-tree traversal and Copy-on-Write (CoW) node mutation engine.
  - Live CRC32c Castagnoli checksum calculation and on-the-fly checksum tiling.
  - Dynamic chunk allocation: Scales seamlessly from megabytes to multi-gigabytes without pre-allocation limits.
  - Atomic two-phase commits with superblock generation stamping for crash resilience.
  - Empty-root self-healing, leaf pruning, and shared-extent protection (`cp --reflink` safe).
- **ext4 Read & Write Engine**:
  - Extent tree allocations, directory indexing, and block group bitmap management.
  - Formally oracle-verified against Linux `e2fsck`.
- **Robust USB Mass Storage Driver**:
  - Custom userspace USBFS driver implementing the SCSI Bulk-Only Transport (BOT) protocol.
  - Non-blocking URB arena management with generation tracking to prevent use-after-free and driver stalls.
  - Probed hardware transfer limits (128 KiB single SCSI commands) to ensure broad compatibility with commodity USB bridges (e.g. SanDisk, Realtek RTL9210, ASMedia).
- **In-App Live Forensic Ring Buffer**:
  - 256-slot non-allocating circular memory buffer capturing low-level USB submits, reaps, SCSI CDBs, sense bytes, and filesystem events.
  - On-device log viewer and ADB broadcast trigger (`dev.luksandroid.DUMP_FORENSIC`) for hardware diagnostics.
- **Fail-Closed Safety Architecture**:
  - Compile-time write gating (`dangerous-write-support` feature flag): Release default builds contain **zero** write opcodes in the binary.
  - Every write transaction is verified against live Linux kernel oracles (`cryptsetup`, `btrfs check`, `e2fsck`).

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   Android Jetpack Compose UI                     │
│        (DevicesScreen · BrowserScreen · DiagnosticsScreen)        │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ Kotlin Coroutines & TransferManager
┌────────────────────────────────▼─────────────────────────────────┐
│                      JNI Interop Layer (`luks_jni`)               │
│        Generational Handle Registry · Panic Boundary Trapping     │
│        Direct ByteBuffer Transfer · Writer Exclusion Locks        │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│                      Rust Core (`luks_core`)                     │
│  ┌───────────────────────┐             ┌───────────────────────┐ │
│  │     Btrfs Engine      │             │      ext4 Engine      │ │
│  │ B-Tree CoW · ChunkMap │             │ Extent Trees · Inodes │ │
│  │ FreeSpaceMap · Commit │             │ Block Group Bitmaps   │ │
│  └───────────┬───────────┘             └───────────┬───────────┘ │
│              └─────────────────┬───────────────────┘             │
│                                │                                 │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │                  LUKS2 Cryptographic Volume                │  │
│  │      Argon2id / PBKDF2 KDF · AES-256-XTS (ARMv8 Crypto)    │  │
│  └─────────────────────────────┬──────────────────────────────┘  │
│                                │ Physical Block Addressing       │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │                SCSI Block Device Translation               │  │
│  │       INQUIRY · READ CAPACITY · READ(10) / WRITE(10)       │  │
│  └─────────────────────────────┬──────────────────────────────┘  │
└────────────────────────────────┼─────────────────────────────────┘
                                 │ BulkTransport Trait
┌────────────────────────────────▼─────────────────────────────────┐
│                   Userspace USBFS (`luks_usbfs`)                 │
│      USBDEVFS_SUBMITURB / REAPURB · UrbArena · Drain Recovery     │
│             One-Way Transport Fencing (Healthy -> Dead)          │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ ioctl (/dev/bus/usb/...)
┌────────────────────────────────▼─────────────────────────────────┐
│                    Physical USB-OTG Storage                      │
│               (USB Thumb Drive · External NVMe SSD)              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Performance & Benchmarks

Measured on physical hardware (Pixel 8 running Android 14+):

| Benchmark Setup | Raw Read | Application Export | Application Import | Unlock Latency |
|---|---|---|---|---|
| **Rig A**: SanDisk Ultra USB 3.2 Gen 1 (OTG adapter) | 29.8 MiB/s | 21.2 MiB/s | 6.20–7.40 MiB/s * | ~1.8 s (Argon2id, 256 MiB) |
| **Rig B**: Realtek RTL9210 NVMe M.2 Enclosure (USB-C cable) | 108.7 MiB/s | 96.5 MiB/s | 75.0–90.0 MiB/s | ~6.7 s (Argon2id, 1 GiB) |

*\* Note: Write throughput on Rig A is strictly bottlenecked by the physical TLC flash write speeds and pSLC folding characteristics of commodity USB thumb drives (~7–10 MB/s sustained flash write).*

---

## Getting Started

### Prerequisites

1. **Rust Toolchain**: 1.80+ with `aarch64-linux-android` target installed:
   ```bash
   rustup target add aarch64-linux-android
   ```
2. **Android NDK**: NDK r25c or newer (set `ANDROID_NDK_HOME`).
3. **Android SDK**: Build tools 34.0.0+, JDK 17+.
4. **Colima / Docker** *(Optional, for Linux Kernel Oracle tests)*: Required to run kernel-graded validation suites.

---

### Building the Project

#### 1. Compile the Native Android Library (`libluks_jni.so`)

- **Default Safe (Read-Only) Build**:
  ```bash
  ./tools/build-android-libs.sh
  ```
- **Write-Enabled Testing Build**:
  ```bash
  ./tools/build-android-libs.sh --write
  ```

#### 2. Build the Android Application

Open the `android/` directory and run Gradle:

```bash
cd android
./gradlew assembleDebug
```

To install directly to a connected USB debugging device:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Testing & Verification

The test framework enforces strict correctness: tests are graded against an actual Linux kernel running in a virtual environment (`Colima`), checking filesystem mounts, `btrfs check`, `btrfs scrub`, and `e2fsck`.

### 1. Workspace Unit & Integration Tests
```bash
# Standard workspace tests
cargo test --workspace

# Write-enabled workspace tests
cargo test --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
```

### 2. Kernel-Graded Oracle Test Suite
```bash
tools/test-graded.sh --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
```

### 3. Write-Path Safety Gate
Ensures release artifacts cannot inadvertently include write opcodes:
```bash
bash tools/verify-no-write-code.sh
```

### 4. Android Unit Tests
```bash
cd android && ./gradlew testDebugUnitTest
```

---

## Diagnostic Logging

To extract the native 256-slot ring buffer from a running device via ADB:

```bash
# Trigger an immediate forensic dump to logcat
adb shell am broadcast -a dev.luksandroid.DUMP_FORENSIC

# Inspect the logcat trace
adb logcat -d -s LUKS_FORENSIC_DUMP:I
```

The dump contains timestamps, SCSI CDB opcodes, return statuses, sense bytes, URB submit/reap lifecycle events, and Btrfs generation counts without logging any plaintext user data or filenames.

---

## Feature Support Matrix

| Feature | Read Support | Write Support | Notes |
|---|---|---|---|
| **LUKS2 (Argon2id)** | Supported | Supported | Full keyslot & header validation |
| **LUKS2 (PBKDF2)** | Supported | Supported | Supported for legacy containers |
| **ext4** | Supported | Supported | Directory indexing, extent trees |
| **Btrfs (Single device)** | Supported | Supported | Dynamic chunk allocation, CoW B-trees |
| **Btrfs Subvolumes** | Supported | Supported (Path-Gated) | Read-only subvolumes are enforced fail-closed |
| **Btrfs Reflink Deletion** | Supported | Supported | Preserves shared extents (`refs > 1`) |
| **Btrfs Compression** | Decompress (ZSTD/LZO/ZLIB) | Planned | Write compression deferred for CPU efficiency |
| **Btrfs Multi-device (RAID)** | Refused | Refused | Fail-closed refusal for mobile safety |
| **SAF DocumentsProvider** | Supported (Read-only) | Deferred | Exposes files to Android's "Files" app |

---

## Security & Privacy Policy

- **No Plaintext Leaks**: Passwords, key material, and user filenames are never formatted into standard logs or crash dumps.
- **Key Zeroization**: Sensitive cryptographic structures implement `Zeroize` and `ZeroizeOnDrop` to purge cryptographic material from memory.
- **Fail-Closed Design**: Any transport failure, USB stall, or filesystem corruption instantly fences the write session to prevent cascaded drive damage.

---

## License

This project is licensed under the [MIT License](LICENSE).
