# LUKS-Android

A rootless, userspace storage and cryptographic stack for Android: LUKS2 decryption plus ext4 and Btrfs filesystem drivers over Android's USB Host APIs. Zero root, zero kernel modules, fail-closed safety.

<!-- Demonstration banner / social preview placeholder -->
<!-- <img src="./readmeAssets/social-preview.png" alt="LUKS-Android Userspace Storage Stack" width="860" /> -->

[![Latest release](https://img.shields.io/github/v/release/rDelmotra/luks-android?style=flat-square&label=release&color=0969da&labelColor=0d1117)](https://github.com/rDelmotra/luks-android/releases/latest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square&labelColor=0d1117)](LICENSE-APACHE)

- [What is LUKS-Android?](#what-is-luks-android)
- [Quickstart](#quickstart)
- [How to use](#how-to-use)
- [Features](#features)
- [Architecture, benchmarks & feature matrix](doc/architecture.md)
- [Build from source](#build-from-source)
- [Testing, verification & diagnostics](doc/testing.md)
- [Security & Safety](#security--safety)
- [Contributing](#contributing)

> [!NOTE]
> **Zero root required.** Android does not provide native kernel drivers for Btrfs, ext4, or LUKS2-encrypted external drives. LUKS-Android bypasses this restriction by implementing the entire cryptographic transform, SCSI translation, and filesystem engines in userspace via Android's USB Host API (`/dev/bus/usb`).

---

## What is LUKS-Android?

**LUKS-Android is an open-source userspace driver and filesystem explorer that lets Android devices unlock, read, and write LUKS-encrypted drives formatted with Btrfs or ext4.** Plug any standard encrypted USB-OTG drive or external storage device into an Android phone or tablet, grant USB access, enter the passphrase, and browse the filesystem directly.

Traditional solutions require rooting the Android device, installing custom kernels, or cross-compiling kernel modules (`dm-crypt`, `btrfs.ko`). LUKS-Android moves the entire stack into an unprivileged userspace process. A high-performance Rust core handles cryptographic decryption and B-tree operations, while a modern Jetpack Compose UI provides intuitive directory browsing, file transfers, and diagnostics.

<div align="center">
<!-- Demonstration screenshot / recording placeholder -->
<!-- <img src="./readmeAssets/app-demo.png" alt="LUKS-Android application interface" width="720" /> -->
</div>

---

## Quickstart

**[⬇ Download the latest release](https://github.com/rDelmotra/luks-android/releases/latest)** — grab `app-release.apk` (v0.2.0) directly, no build required. Requires Android 10+ (API 29) on an arm64-v8a device.

> [!NOTE]
> The `v0.2.0` release introduces **full write support** (file creation, directory CRUD, rename, delete) across ext4, single-device Btrfs, and Btrfs subvolumes, plus **plain (unencrypted) partition support** with an explicit per-session confirmation gate.

> [!WARNING]
> **Write at your own risk.** Writing directly to raw block storage from unprivileged userspace over mobile USB OTG carries inherent physical risk. While this engine is verified against Linux kernel oracles and enforces fail-closed write fencing, real-world hardware disruptions (unstable OTG adapters, loose USB-C cables, surprise disconnections, or drive controllers rejecting cache flush) can interrupt in-flight transactions. **Always maintain verified backups of critical data before performing write operations.**

| Target | Artifact | Size | Description |
| :--- | :--- | :--- | :--- |
| **Android Release (Recommended)** | [`app-release.apk`](https://github.com/rDelmotra/luks-android/releases/latest) | `~4.1 MB` | Prebuilt, signed v2/v3, ready to install |
| **Android Debug** *(build from source)* | `app-debug.apk` | `~31 MB` | For development and live diagnostics |
| **Native Core (Rust crate)** | `luks_core` / `luks_jni` | `< 2 MB` | Use the engine standalone via Rust or JNI |

### Install via ADB

```bash
# Download app-release.apk from the Releases page above, then:
adb install -r app-release.apk

# Or, after building the release APK from source yourself (see below):
adb install -r android/app/build/outputs/apk/release/app-release.apk
```

> [!TIP]
> No ADB? Open the [release APK link](https://github.com/rDelmotra/luks-android/releases/latest) directly on the Android device and tap the downloaded file to install — Android will prompt to allow "Install unknown apps" for the browser or file manager you used.

---

## How to use

1. **Connect the drive.** Plug a USB-OTG drive or external enclosure into the Android device.
2. **Grant USB permission.** Accept the standard Android USB Host dialog to allow userspace communication via `/dev/bus/usb`.
3. **Unlock the volume.** Enter the passphrase to decrypt the LUKS2 keyslot (Argon2id or PBKDF2).
4. **Browse and transfer.** Explore folders, view file metadata, stream media, or export files directly to internal storage.

---

## Features

- **Rootless operation.** Runs entirely in unprivileged userspace using Android's USB Host APIs. No root access, unlocked bootloaders, or custom ROMs required.
- **LUKS2 container cryptography.** Full support for Argon2id and PBKDF2 key derivation functions with AES-256-XTS ciphers, hardware-accelerated via ARMv8 crypto extensions (`pmull`, `aes`).
- **Memory security and key zeroization.** Master keys, subkeys, and expanded cipher schedules implement `Zeroize` and `ZeroizeOnDrop`, purging sensitive material from memory immediately upon exit.
- **Btrfs filesystem engine.** Complete B-tree Copy-on-Write (CoW) mutation engine, live Castagnoli CRC32c checksum calculations, dynamic multi-gigabyte chunk allocation, and Free-Space Tree (FST) CoW management.
- **Btrfs subvolume write support.** First-class write transactions directly targeting subvolumes (`@`, `@home`, snapshots) via single-tree encapsulation, extent backrefs, and packed checksum trimming.
- **Plain (non-LUKS) volume support.** Open, browse, and write to unencrypted ext4 and Btrfs drives with hardened 7-point superblock detection and explicit per-session write confirmation.
- **Transparent decompression.** Reads compressed Btrfs extents on-the-fly supporting Zstandard (zstd), LZO, and Zlib algorithms.
- **ext4 filesystem engine.** Extent tree traversals, directory hash-tree indexing, block group bitmap allocations, and file creation/deletion validated against reference Linux `e2fsck`.
- **SCSI Bulk-Only Transport (BOT).** Custom userspace USBFS engine driving 128 KiB chunked SCSI transfers with a non-blocking URB arena and generational drain recovery.
- **Fail-closed safety model.** Release builds enforce compile-time write gating (`dangerous-write-support`). Any transport stall, cable disconnect, or corruption fences the session instantly.
- **Lightweight footprint.** Complete Android application is ~4.1 MB, with ProGuard/R8 code and resource shrinking.
- **In-memory forensic ring buffer.** A 256-slot non-allocating circular ring buffer records hardware events, SCSI CDBs, sense codes, and filesystem operations with zero plaintext leakage.

Full system architecture, hardware benchmarks, and the per-feature read/write support matrix are in [doc/architecture.md](doc/architecture.md).

---

## Build from source

### Prerequisites

1. **Rust Toolchain (1.80+)**: `rustup target add aarch64-linux-android`
2. **Android NDK**: NDK r25c or newer (set `ANDROID_NDK_HOME`).
3. **Android SDK**: Build tools 34.0.0+, JDK 17+.
4. **Colima / Docker** *(Optional)*: Required to run Linux kernel-graded oracle validation tests.

### 1. Compile the Native Android Library (`libluks_jni.so`)

The cryptographic and filesystem engine compiles to an arm64 shared library:

```bash
# Safe, Read-Only Default Build
./tools/build-android-libs.sh

# Write-Enabled Testing Build (opt-level 3, LTO, stripped)
./tools/build-android-libs.sh --write
```

### 2. Build the Android Application

```bash
cd android

# Production Release Build (R8-optimized, requires -PallowWriteInRelease=true if native write is enabled)
./gradlew assembleRelease -PallowWriteInRelease=true
# Output: app/build/outputs/apk/release/app-release.apk

# Debug Build (Fast local compilation with debug tracing)
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk
```

Full test suite, kernel-oracle grading, and live diagnostic log extraction are in [doc/testing.md](doc/testing.md).

---

## Security & Safety

- **No Plaintext Logging:** Passphrases, derived keys, and directory contents are never written to disk, Android logcat, or diagnostic buffers.
- **Immediate Memory Purging:** Cryptographic secrets implement `ZeroizeOnDrop`, clearing backing memory buffers as soon as an operation finishes.
- **Fail-Closed Default:** If a USB transfer stalls, a device disconnects unexpectedly, or an inconsistent filesystem state is detected, the driver halts immediately to prevent data loss.

---

## Contributing

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR — testing and hardware-in-the-loop expectations are there.
- Bug reports: include hardware details, kernel version, and ADB diagnostic logs.
- Security issues go through [SECURITY.md](SECURITY.md), not a public issue.

---

## License

Created and maintained by **Rehaan Delmotra**.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
