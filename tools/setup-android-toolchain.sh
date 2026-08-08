#!/usr/bin/env bash
#
# setup-android-toolchain.sh — Phase 1 Android toolchain bring-up
#
# Installs the Android SDK + NDK headlessly, wires up the Rust cross-compile
# linkers, and verifies the result with a build that actually invokes the linker.
#
# Idempotent: safe to re-run. Non-destructive: never uninstalls anything.
#
# Corrections to environment_setup_guide.md baked in here:
#   - Does NOT `brew uninstall rust`         (DEC-026)
#   - Does NOT install CMake                 (DEC-011-R dropped lwext4)
#   - Uses API 29 linkers, not 21            (DEC-012 sets minSdk 29)
#   - Verifies with --examples, not a bare rlib build (see VERIFY below)
#
# The Android Studio IDE is a separate, optional install:
#   brew install --cask android-studio
# It auto-detects the SDK this script sets up. Install it for the Compose
# previews / logcat / device manager (DEC-016), but it is not needed to build.

set -euo pipefail

MIN_FREE_GB=15   # NDK alone is ~5-7 GB; 8 was optimistic
API_LEVEL=29          # linker API level; matches DEC-012 minSdk

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 0. preflight

say "Preflight"

[[ "$(uname -s)" == "Darwin" ]] || die "This script targets macOS."

free_gb=$(df -g / | awk 'NR==2 {print $4}')
(( free_gb >= MIN_FREE_GB )) || die "Only ${free_gb} GB free; need ${MIN_FREE_GB} GB."
ok "${free_gb} GB free"

command -v brew >/dev/null || die "Homebrew not found."
command -v java >/dev/null || die "No JDK on PATH. sdkmanager needs one (you have JDK 21 per STATE.md)."
ok "brew + JDK present"

# Homebrew's rust and rustup's can both be on PATH (DEC-021 keeps Homebrew's
# because rust-wasm depends on it). Homebrew's build has NO Android targets, so
# if it wins the PATH the cross-build fails with a baffling "can't find crate
# for `core`". Force rustup's toolchain and refuse to continue otherwise.
export PATH="$HOME/.cargo/bin:$PATH"

command -v rustup >/dev/null || die "rustup not found. Run: source \"\$HOME/.cargo/env\""

rustc_v="$(rustc --version)"
if [[ "$rustc_v" == *"(Homebrew)"* ]]; then
    die "Homebrew's rustc is winning the PATH: $rustc_v
     It has no Android targets. Ensure \$HOME/.cargo/bin precedes /opt/homebrew/bin."
fi
ok "rustc: $rustc_v"
ok "  -> $(command -v rustc)"

rustup target list --installed | grep -q aarch64-linux-android \
    || die "aarch64-linux-android target missing. Run: rustup target add aarch64-linux-android"
ok "aarch64-linux-android target present"

# ------------------------------------------------------------ 1. locate/install SDK

say "Android SDK"

STUDIO_SDK="$HOME/Library/Android/sdk"
BREW_SDK="/opt/homebrew/share/android-commandlinetools"

if [[ -d "$STUDIO_SDK/cmdline-tools" ]]; then
    ANDROID_HOME="$STUDIO_SDK"; ok "using Android Studio SDK at $ANDROID_HOME"
elif [[ -d "$BREW_SDK/cmdline-tools" ]]; then
    ANDROID_HOME="$BREW_SDK";   ok "using command-line tools at $ANDROID_HOME"
else
    warn "no SDK found — installing command-line tools (~120 MB)"
    brew install --cask android-commandlinetools
    ANDROID_HOME="$BREW_SDK"
fi
export ANDROID_HOME

SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
[[ -x "$SDKMANAGER" ]] || SDKMANAGER="$(find "$ANDROID_HOME/cmdline-tools" -name sdkmanager -type f 2>/dev/null | head -1)"
[[ -x "$SDKMANAGER" ]] || die "sdkmanager not found under $ANDROID_HOME/cmdline-tools"

# ------------------------------------------------------------- 2. pick versions

say "Resolving package versions"

listing=$("$SDKMANAGER" --list 2>/dev/null || true)

# Newest-first, from the "Available Packages" section only, excluding release
# candidates. Google advertises preview entries (e.g. platforms;android-37)
# in the listing before they are actually publishable, so the newest name in
# the list is not necessarily installable.
avail() {
    sed -n '/Available Packages/,$p' <<<"$listing" \
        | grep -oE "$1" | grep -v -- '-rc' | sort -V -u -r
}

read -r -a PLATFORMS  <<<"$(avail 'platforms;android-[0-9]+' | tr '\n' ' ')"
read -r -a BUILDTOOLS <<<"$(avail 'build-tools;[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ' ')"
read -r -a NDKS       <<<"$(avail 'ndk;[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ' ')"

(( ${#PLATFORMS[@]}  )) || die "no platforms listed"
(( ${#BUILDTOOLS[@]} )) || die "no build-tools listed"
(( ${#NDKS[@]}       )) || die "no NDK listed"

ok "candidates: ${PLATFORMS[0]}, ${BUILDTOOLS[0]}, ${NDKS[0]} (will step down if unavailable)"

# --------------------------------------------------------------- 3. install

say "Installing (this is the multi-GB step)"

yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true

LOG=/tmp/sdk-install.log
CHOSEN=""
install_first() {
    local label="$1"; shift
    local pkg
    for pkg in "$@"; do
        printf '    %-14s %-28s ' "$label" "$pkg"
        if "$SDKMANAGER" --install "$pkg" >>"$LOG" 2>&1; then
            printf '\033[32mok\033[0m\n'; CHOSEN="$pkg"; return 0
        fi
        printf '\033[33munavailable\033[0m\n'
    done
    die "$label: no installable version found (see $LOG)"
}

: > "$LOG"
install_first "platform-tools" "platform-tools"
install_first "platform"    "${PLATFORMS[@]}";  PLATFORM="$CHOSEN"
install_first "build-tools" "${BUILDTOOLS[@]}"; BUILDTOOLS_PKG="$CHOSEN"
install_first "ndk"         "${NDKS[@]}";       NDK="$CHOSEN"

ok "platform:    $PLATFORM"
ok "build-tools: $BUILDTOOLS_PKG"
ok "ndk:         $NDK"

NDK_VERSION="${NDK#ndk;}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
[[ -d "$ANDROID_NDK_HOME" ]] || die "NDK missing at $ANDROID_NDK_HOME"

# 'darwin-x86_64' is a legacy directory name; the binaries inside are arm64.
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
[[ -d "$NDK_BIN" ]] || die "NDK toolchain bin missing at $NDK_BIN"
export PATH="$ANDROID_HOME/platform-tools:$NDK_BIN:$PATH"
ok "NDK toolchain at $NDK_BIN"

# ------------------------------------------------------- 4. rust android targets

say "Rust targets"
for t in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
    rustup target add "$t" >/dev/null 2>&1 || true
    ok "$t"
done

# ------------------------------------------------------------ 5. cargo linkers

say "Cargo linker config"

CARGO_CFG="$HOME/.cargo/config.toml"
if grep -q 'target.aarch64-linux-android' "$CARGO_CFG" 2>/dev/null; then
    warn "already configured — leaving $CARGO_CFG untouched"
    warn "confirm it points at API $API_LEVEL, not 21"
else
    cat >> "$CARGO_CFG" << EOF

# --- android cross-compile (setup-android-toolchain.sh) ---
# API $API_LEVEL matches DEC-012 minSdk. The setup guide's 21 is stale.
[target.aarch64-linux-android]
linker = "aarch64-linux-android${API_LEVEL}-clang"

[target.armv7-linux-androideabi]
linker = "armv7a-linux-androideabi${API_LEVEL}-clang"

[target.x86_64-linux-android]
linker = "x86_64-linux-android${API_LEVEL}-clang"
EOF
    ok "appended to $CARGO_CFG"
fi

# ----------------------------------------------------------------- 6. shell env

say "Shell environment"

ZSHRC="$HOME/.zshrc"
MARKER="# --- android toolchain (setup-android-toolchain.sh) ---"
if grep -qF "$MARKER" "$ZSHRC" 2>/dev/null; then
    warn "$ZSHRC already has the block — not duplicating"
else
    cat >> "$ZSHRC" << EOF

$MARKER
export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_NDK_HOME="\$ANDROID_HOME/ndk/$NDK_VERSION"
# platform-tools FIRST: Homebrew ships a rival adb that will otherwise shadow it.
export PATH="\$ANDROID_HOME/platform-tools:\$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:\$PATH"
EOF
    ok "appended to $ZSHRC"
fi

# ------------------------------------------------------------------ 7. VERIFY

say "Verify"

LINKER="aarch64-linux-android${API_LEVEL}-clang"
command -v "$LINKER" >/dev/null || die "$LINKER not on PATH"
ok "$LINKER -> $(command -v "$LINKER")"

adb_path=$(command -v adb || true)
if [[ "$adb_path" == "$ANDROID_HOME/platform-tools/adb" ]]; then
    ok "adb -> $adb_path"
else
    warn "adb resolves to '$adb_path' (expected $ANDROID_HOME/platform-tools/adb)"
    warn "Homebrew's copy is winning. Open a new shell, or fix PATH order."
fi

# THE point of this step:
# luks_core is crate-type = ["rlib"], and an rlib NEVER invokes a linker.
# `cargo build --target aarch64-linux-android` therefore succeeds even with a
# completely broken NDK. Building the examples forces a real link.
CORE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../core" && pwd)"
say "Linking argon2_bench for aarch64-linux-android (proves the NDK works)"
( cd "$CORE" && cargo build --target aarch64-linux-android --release --examples )
ok "cross-link succeeded"

say "Done"
cat << EOF

    SDK   $ANDROID_HOME
    NDK   $NDK_VERSION
    API   $API_LEVEL

Open a new terminal (or 'source ~/.zshrc') so the PATH changes take effect.

Next, per STATE.md Phase 1c/1d:
  1. Add "cdylib" to crate-type in core/Cargo.toml to emit the .so
  2. Optionally: brew install --cask android-studio   (DEC-016; IDE only)
  3. Create the Android app (Empty Compose Activity, minSdk $API_LEVEL)
  4. Plug in the Pixel 8 and confirm: adb devices

Note: do NOT install the Android Emulator. USB host passthrough does not work
in it, so every Phase 1 test needs the physical phone regardless.
EOF
