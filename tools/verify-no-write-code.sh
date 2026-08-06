#!/bin/bash
# Check, at the artifact level, that a default build contains no write code.
#
#   tools/verify-no-write-code.sh
#
# The entire safety argument of this project is that a default build cannot
# corrupt a drive because the instruction is not in the binary. That claim was
# previously "verified" by inspecting symbols — a check that silently proved
# nothing, because the path it globbed for the rlib did not exist, so `grep -c`
# returned 0 for a file that was never there. Zero symbols found and zero
# symbols possible look identical if you only run the test case.
#
# So this script runs a CONTROL and refuses to pass without it: the
# write-enabled build must show the symbols the default build must not. If the
# control comes back empty the check has stopped measuring anything, and that
# is reported as a failure rather than as success.
#
# What this does and does not prove
# ---------------------------------
# An rlib stores generic functions as MIR, not object code, so the write
# methods on `Ext4<D>` have no symbols until something instantiates them. Only
# non-generic items — `write_extent_tree` among them — show up reliably. This
# check is therefore real but weak: it can catch write code appearing in a
# default build, and it cannot by itself prove the absence of all of it.
#
# The primary argument remains structural: every write module is behind
# `#[cfg(feature = "dangerous-write-support")]`, so it is not compiled at all.
# This is the artifact-level cross-check on that argument, not a replacement.
set -euo pipefail

cd "$(dirname "$0")/.."

# Non-generic write-path items. Generic methods are deliberately not relied on
# here — see the note above.
PATTERN='write_new_file|link_file|alloc_block|alloc_inode|write_superblock|write_extent_tree'
RLIB="target/debug/libluks_core.rlib"

build() {
    rm -f "$RLIB"
    cargo build -p luks_core "$@" >/dev/null 2>&1 || {
        echo "build failed: cargo build -p luks_core $*" >&2
        exit 2
    }
    [ -f "$RLIB" ] || { echo "no rlib produced at $RLIB" >&2; exit 2; }
}

build
DEFAULT_HITS="$(nm "$RLIB" 2>/dev/null | grep -cE "$PATTERN" || true)"
DEFAULT_SIZE="$(wc -c < "$RLIB" | tr -d ' ')"

build --features dangerous-write-support
CONTROL_HITS="$(nm "$RLIB" 2>/dev/null | grep -cE "$PATTERN" || true)"
CONTROL_SIZE="$(wc -c < "$RLIB" | tr -d ' ')"

echo "default build: ${DEFAULT_SIZE} bytes, ${DEFAULT_HITS} write-path symbols"
echo "control build: ${CONTROL_SIZE} bytes, ${CONTROL_HITS} write-path symbols"

# Leave the tree in the state a developer expects.
rm -f "$RLIB"
cargo build -p luks_core >/dev/null 2>&1 || true

if [ "$CONTROL_HITS" -eq 0 ]; then
    echo "VACUOUS: the control build shows no write symbols either, so this" >&2
    echo "check is not measuring anything. Fix the check before trusting it." >&2
    exit 1
fi

if [ "$DEFAULT_HITS" -ne 0 ]; then
    echo "FAIL: the default build contains write-path symbols" >&2
    exit 1
fi

# --- the JNI entry point ----------------------------------------------------
#
# Stronger than the rlib check above, and worth having separately: the library
# the app actually loads is a cdylib, and a JNI entry point is `#[no_mangle]`
# and non-generic, so it is either an exported symbol or it does not exist.
# There is no "compiled but unreachable" middle state to argue about — which
# makes this the one artifact-level check that proves what it claims.
DYLIB_HITS() {
    # cdylib extension differs by host; the Android build produces the .so.
    for f in target/debug/libluks_jni.dylib target/debug/libluks_jni.so; do
        [ -f "$f" ] && { nm -gU "$f" 2>/dev/null | grep -cE 'nativeWriteFile' || true; return; }
    done
    echo "MISSING"
}

cargo build -p luks_jni >/dev/null 2>&1 || { echo "jni default build failed" >&2; exit 2; }
JNI_DEFAULT="$(DYLIB_HITS)"
cargo build -p luks_jni --features dangerous-write-support >/dev/null 2>&1 || {
    echo "jni control build failed" >&2; exit 2; }
JNI_CONTROL="$(DYLIB_HITS)"

cargo build -p luks_jni >/dev/null 2>&1 || true

echo "jni default: ${JNI_DEFAULT} nativeWriteFile exports"
echo "jni control: ${JNI_CONTROL} nativeWriteFile exports"

if [ "$JNI_DEFAULT" = "MISSING" ] || [ "$JNI_CONTROL" = "MISSING" ]; then
    echo "VACUOUS: no cdylib was found to inspect — the check proved nothing." >&2
    exit 1
fi
if [ "$JNI_CONTROL" -eq 0 ]; then
    echo "VACUOUS: the control build exports no nativeWriteFile either, so this" >&2
    echo "check is not measuring anything. Fix the check before trusting it." >&2
    exit 1
fi
if [ "$JNI_DEFAULT" -ne 0 ]; then
    echo "FAIL: a default JNI build exports nativeWriteFile — the app could write" >&2
    exit 1
fi

echo "VERDICT: clean — the control can see write code, and the default build has none"
