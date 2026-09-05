# Security Policy

LUKS-Android decrypts LUKS2 volumes and handles passphrases, derived key material, and the contents of encrypted drives. Treat anything that could leak plaintext, bypass authentication, corrupt a drive via the write path, or produce a memory-safety bug in the Rust core as a security issue.

## In scope

- Passphrase or key material leaking to logs, disk, crash dumps, or the diagnostic ring buffer.
- LUKS2 header/keyslot parsing or key-derivation bugs (Argon2id, PBKDF2, AES-256-XTS).
- Memory-safety issues in `core/` or `jni/` (UB, use-after-free, buffer overflows), including in `unsafe` blocks.
- A way to make the write path (`dangerous-write-support`) reachable from a default release build, or to make it write outside the target device.
- Filesystem (Btrfs/ext4) mutation bugs that can silently corrupt a volume without the fail-closed session fence triggering.

## Out of scope

UI bugs, crashes without a security implication, performance regressions, and feature requests — file these as normal [issues](https://github.com/rDelmotra/luks-android/issues) instead.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (**Security** tab → **Report a vulnerability**) rather than a public issue, so it isn't disclosed before a fix is available:

<https://github.com/rDelmotra/luks-android/security/advisories/new>

Include what you can: affected file/commit, reproduction steps, and impact (what an attacker gains). Hardware-dependent findings should include device model, USB bridge chipset, and drive filesystem where relevant.

## Response

This is a solo-maintained, pre-1.0 project. There's no SLA, but security reports get priority over feature work — expect an initial response within a few days. Only the latest tagged release is supported; there's no back-porting of fixes to older tags.

## Disclosure

Coordinated disclosure is preferred: please hold off on public disclosure until a fix ships. Credit is given in the release notes unless you'd rather stay anonymous.
