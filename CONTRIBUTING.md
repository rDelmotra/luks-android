# Contributing

Contributions, bug reports, and discussions are welcome. This project is solo-maintained and pre-1.0, so please read this before opening a PR — it'll save both of us time.

## Reporting bugs

Open an [issue](https://github.com/rDelmotra/luks-android/issues) with:
- Device model, Android version, and the USB bridge/drive chipset if it's hardware-related.
- Kernel version if you're grading output against a Linux oracle (`cryptsetup`, `e2fsck`, `btrfs check`).
- ADB diagnostic output where relevant — see [doc/testing.md](doc/testing.md) for how to pull the forensic ring buffer.

Suspected security issues (leaked key material, memory-safety bugs, write-path corruption) go through [SECURITY.md](SECURITY.md) instead — not a public issue.

## Development setup

See [Build from source](README.md#build-from-source) in the README for toolchain requirements and build commands.

## Testing expectations

This project grades correctness against real Linux kernel tooling, not just its own test suite:

- Run `cargo test --workspace` before opening a PR. For anything touching the write path, also run with `--features luks_core/dangerous-write-support,luks_jni/dangerous-write-support`.
- Prefer the graded suite (`tools/test-graded.sh`) over raw `cargo test` where practical — it verifies output against `cryptsetup`, `e2fsck`, and `btrfs check` rather than just checking the code agrees with itself.
- Tests must fail when the code under test is actually broken. A passing test over an empty collection, a mocked assertion, or a swallowed error (`.ok()`, `let _ =`, `unwrap_or_default()`) proves nothing — don't add one.
- No silent skips. If a fixture or tool is missing, the test should panic or record an explicit skip, not pass quietly.

## Hardware-in-the-loop changes

Changes to the Btrfs/ext4 write path or the USBFS transport are gated on a real device run, not just unit tests — corruption bugs here are effectively unrecoverable for whoever's drive gets corrupted. If you're testing writes:
- Use a disposable USB stick, never an irreplaceable drive.
- Include the hardware event count, SCSI error count, and post-run `btrfs check`/`e2fsck` result in your PR description.

## Commit messages

Clear, imperative summary line. Explain *why* in the body if it's not obvious from the diff — not a restatement of the diff itself. Reference issue numbers where relevant.
