#!/bin/bash
# Generate small COMPLETE LUKS2 containers for testing unlock and decryption.
#
# Unlike tools/gen-luks-fixtures.sh (headers only), these include the keyslots
# area, so they contain real wrapped key material — and an ext4 filesystem in the
# data area, so a successful decryption is verifiable by checking for the ext4
# superblock magic rather than by trusting our own crypto.
#
# Kept small by shrinking the keyslots area and moving the payload offset in from
# the 16 MiB default. Password is "test"; KDF parameters are deliberately weak.
# These are throwaway test vectors: their master keys are recorded in plaintext.
set -euo pipefail

OUT="${1:-/tmp/luks-containers}"
PASS="test"

WORK="$(mktemp -d)"
trap 'for m in /dev/mapper/luksfix_*; do [ -e "$m" ] && cryptsetup close "$(basename "$m")" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

WEAK=(--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 32 --pbkdf-parallel 1)

# 256 KiB keyslots area holds one slot (64-byte key x 4000 AF stripes = 250 KiB).
# Payload at sector 1024 = 512 KiB, leaving room for 32 KiB of headers + keyslots.
SMALL=(--luks2-keyslots-size 256k --offset 1024)

make_container() {
    local name="$1"; shift
    local img="$OUT/$name.img"
    local map="luksfix_$name"

    dd if=/dev/zero of="$img" bs=1M count=3 status=none
    printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "${SMALL[@]}" "$@" "$img" -

    # Put a real ext4 filesystem inside so decryption is independently verifiable.
    printf '%s' "$PASS" | cryptsetup open --batch-mode --key-file=- "$img" "$map"
    mkfs.ext4 -q -L LUKSDATA -U 22222222-3333-4444-5555-666666666666 "/dev/mapper/$map"
    local mnt="$WORK/mnt"; mkdir -p "$mnt"
    mount "/dev/mapper/$map" "$mnt"
    printf 'decrypted successfully\n' > "$mnt/marker.txt"
    mkdir -p "$mnt/subdir"
    printf 'nested content\n' > "$mnt/subdir/nested.txt"
    umount "$mnt"
    cryptsetup close "$map"

    {
        echo "=== $name ==="
        cryptsetup luksDump "$img" 2>&1 | grep -viE "^\s+[0-9a-f]{2}( [0-9a-f]{2})+\s*$"
        echo "--- master key (throwaway fixture) ---"
        printf '%s' "$PASS" | cryptsetup luksDump --dump-master-key --batch-mode \
            --key-file=- "$img" 2>&1 | grep -A4 -i "mk dump\|master key"
        echo
    } >> "$OUT/CONTAINERS.txt"

    echo "  -> $name.img"
}

{
    echo "# Complete LUKS2 containers with ext4 inside. Password: test"
    echo "# $(cryptsetup --version)"
    echo "# Master keys are printed below: these are DISPOSABLE test fixtures."
    echo
} > "$OUT/CONTAINERS.txt"

echo "Generating containers..."
make_container unlock-argon2id-512 "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512
make_container unlock-argon2id-4096 "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 4096
make_container unlock-pbkdf2-512 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512

echo "Done:"
ls -la "$OUT"
