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

### 2. Linux Kernel Oracle Graded Suite
```bash
tools/test-graded.sh --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
```

### 3. Write-Path Safety Gate
Verifies that release builds contain zero write symbols or entry points:
```bash
bash tools/verify-no-write-code.sh
```

### 4. Android Unit Tests
```bash
cd android && ./gradlew testDebugUnitTest
```

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
