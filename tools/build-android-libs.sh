#!/usr/bin/env bash
#
# build-android-libs.sh — cross-compile libluks_jni.so into the APK's jniLibs.
#
# Gradle does not know about Cargo. Rather than wiring a Gradle plugin (one more
# moving part that breaks on every AGP bump), this script is the seam: run it,
# then build the APK. `app/build.gradle.kts` fails the build with a pointer back
# here if the .so is missing, so the two cannot silently drift.
#
# Usage:
#   tools/build-android-libs.sh              # arm64 only, release  (the Pixel)
#   tools/build-android-libs.sh --debug      # unoptimised
#   tools/build-android-libs.sh --all-abis   # arm64 + armv7 + x86_64
#
# ⚠️  --debug builds AES ~60x slower and Argon2 slower still. Use it to chase a
#     crash, never to judge performance.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
JNILIBS="$ROOT/android/app/src/main/jniLibs"

PROFILE=release
ABIS=(arm64-v8a)

for arg in "$@"; do
    case "$arg" in
        --debug)     PROFILE=debug ;;
        --release)   PROFILE=release ;;
        --all-abis)  ABIS=(arm64-v8a armeabi-v7a x86_64) ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Android ABI name -> Rust target triple. These names are not interchangeable
# and getting them backwards puts an arm64 .so in the armeabi-v7a directory,
# where it fails at dlopen time with a message that names neither.
target_for() {
    case "$1" in
        arm64-v8a)   echo aarch64-linux-android ;;
        armeabi-v7a) echo armv7-linux-androideabi ;;
        x86_64)      echo x86_64-linux-android ;;
        *) echo "unknown ABI: $1" >&2; return 1 ;;
    esac
}

# rustup's toolchain, not Homebrew's — the latter has no Android targets and
# fails with a baffling "can't find crate for `core`".
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 1; }

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is not set — see tools/setup-android-toolchain.sh}"
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
command -v aarch64-linux-android29-clang >/dev/null \
    || { echo "NDK linkers not on PATH under $ANDROID_NDK_HOME" >&2; exit 1; }

flags=()
[[ "$PROFILE" == release ]] && flags+=(--release)

for abi in "${ABIS[@]}"; do
    triple="$(target_for "$abi")"
    echo "==> $abi ($triple, $PROFILE)"
    cargo build -p luks_jni --target "$triple" "${flags[@]}"

    src="$ROOT/target/$triple/$PROFILE/libluks_jni.so"
    [[ -f "$src" ]] || { echo "expected $src to exist" >&2; exit 1; }

    mkdir -p "$JNILIBS/$abi"
    cp "$src" "$JNILIBS/$abi/libluks_jni.so"
    printf '    %s (%s bytes)\n' "$JNILIBS/$abi/libluks_jni.so" "$(stat -f%z "$src")"
done

# An ELF for the wrong architecture is the classic silent failure here: it
# copies fine and only fails at runtime inside System.loadLibrary.
if [[ -f "$JNILIBS/arm64-v8a/libluks_jni.so" ]]; then
    file "$JNILIBS/arm64-v8a/libluks_jni.so" | grep -q 'ARM aarch64' \
        || { echo "arm64-v8a/libluks_jni.so is not an aarch64 ELF" >&2; exit 1; }
fi

echo "==> done. Now: cd android && ./gradlew installDebug"
