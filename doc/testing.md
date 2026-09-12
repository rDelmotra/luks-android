# Testing & Verification

Correctness is validated against official Linux kernel implementations in automated test suites:

### 0. Generate Local Test Fixtures
Only lightweight headers and trace fixtures are stored in the repository. Full disk and filesystem images are generated locally:
```bash
# See detailed per-platform commands in:
cat tools/README-fixtures.md
```

### 1. Workspace Unit & Integration Tests
```bash
cargo test --workspace
cargo test --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
```
`core/tests/` is organized into domain subdirectories (`btrfs_ops/`, `fs_permutation/`,
`txn_batch/`, etc.) — see [`core/tests/README.md`](../core/tests/README.md) for the
layout and a legacy-path lookup table. Test names are preserved as explicit
`[[test]]` targets in `core/Cargo.toml`, so `cargo test --test <name>` still works
without knowing which subdirectory a test lives in.

### 2. Autonomous Test Harness (recommended before a PR)
```bash
# All 7 tiers: fast/stress/integration/oracle/strict/transitions/android
tools/run-harness.sh --all

# Just the structural transition coverage gate
tools/run-harness.sh --transitions

# Quick local iteration: fast unit + stress permutation tests only (<20s)
tools/run-harness.sh
```
Executes six-tree B-tree validation, in-process accounting oracle (A-1 through A-7),
structural transition coverage gating, and Linux kernel oracle verification.
Run `tools/run-harness.sh` with no arguments to view all tier flags.

### 3. Linux Kernel Oracle Graded Suite (granular alternative to `--oracle`)
```bash
tools/test-graded.sh --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
```

### 4. Write-Path Safety Gate
Verifies that release builds contain zero write symbols or entry points:
```bash
# Standalone ELF symbol and entry-point check
bash tools/verify-no-write-code.sh
```

In Android builds, Gradle enforces this at build time via the `checkNoWriteCodeInRelease` task. If write-enabled native libraries (`libluks_jni.so`) are present when assembling a release APK, Gradle will fail closed. To deliberately produce a write-enabled release build (as in `v0.2.0`):
```bash
cd android && ./gradlew assembleRelease -PallowWriteInRelease=true
```

### 5. Android Unit Tests
```bash
cd android && ./gradlew testDebugUnitTest
```
Currently 221 unit tests passing, covering session lifecycle, device state, plain volume write consent, breadcrumbs, and error handling.

---

## Diagnostic Logging

The engine includes a 256-slot non-allocating circular memory buffer that tracks USB transfer submissions, reaps, SCSI CDBs, sense codes, and filesystem events.

Extract the live forensic ring buffer via ADB:

```bash
# Trigger an immediate forensic dump to Android logcat
adb shell am broadcast -a dev.luksandroid.DUMP_FORENSIC

# Inspect the structured trace output
adb logcat -d -s LUKS_FORENSIC_DUMP:I
```

*The diagnostic trace logs timing, SCSI status codes, and recovery states while strictly omitting any user data or filenames.*
