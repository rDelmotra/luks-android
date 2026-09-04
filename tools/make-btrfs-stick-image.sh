#!/bin/bash
# Build a LUKS2 + Btrfs image to write onto the physical test stick.
#
#   tools/make-btrfs-stick-image.sh <output.img> [size] [password] [--fast-kdf|--phone-kdf]
#
# The image is built by real `sgdisk`, real `cryptsetup` and real `mkfs.btrfs`
# inside the colima VM, for the same reason every fixture in this repo is: a
# target we generated ourselves would only prove our writer agrees with our
# reader. This one is the kernel's own idea of a LUKS2 Btrfs drive, and the
# Btrfs writer will be graded against `btrfs check` and `btrfs scrub` on it.
#
# WARNING: The passphrase is a *test* passphrase. Anything written to a drive made by
# this script is readable by anyone who has read this file. The stick is a test
# target and must never hold real data.
#
# Layout matches a drive a person would actually plug in — GPT, one partition
# at the conventional 1 MiB offset — so the partition scanner is exercised
# rather than bypassed.
set -euo pipefail

FAST_KDF=0
if [ "${PHONE_KDF:-0}" = "1" ] || [ "${FAST_KDF:-0}" = "1" ]; then
    FAST_KDF=1
fi

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast-kdf|--phone-kdf)
            FAST_KDF=1
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -lt 1 ]; then
    echo "usage: make-btrfs-stick-image.sh <output.img> [size] [password] [--fast-kdf|--phone-kdf]" >&2
    exit 2
fi

OUT="${POSITIONAL[0]}"
SIZE="${POSITIONAL[1]:-4G}"
PASSWORD="${POSITIONAL[2]:-test}"

if [ "$FAST_KDF" = "1" ]; then
    PBKDF_MEM=262144
    PBKDF_PARALLEL=1
    PBKDF_ITERS=4
else
    PBKDF_MEM=1048576
    PBKDF_PARALLEL=4
    PBKDF_ITERS=4
fi

command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="mkbtrfs-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
REMOTE_PW="/tmp/$NAME.pw"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# Copied as a file, not piped: stdin belongs to the passphrase alone.
cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
SIZE="$2"
NAME="$3"
PBKDF_MEM="$4"
PBKDF_PARALLEL="$5"
PBKDF_ITERS="$6"
PW_FILE="$7"
MAPPER="/dev/mapper/$NAME"
MNT="/tmp/mnt-$NAME"
LOOP=""

cleanup() {
    umount "$MNT" 2>/dev/null || true
    cryptsetup close "$NAME" 2>/dev/null || true
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$MNT" "$PW_FILE"
}
trap cleanup EXIT

rm -f "$IMG"
truncate -s "$SIZE" "$IMG"

# 8300 = Linux filesystem. Starting at 1 MiB is what every partitioner does,
# and it keeps the LUKS payload aligned to the flash erase block.
sgdisk --new=1:1MiB:0 --typecode=1:8300 --change-name=1:luks-btrfs-test "$IMG" >/dev/null

wait_for_partitions() {
    local loop="$1" i p
    udevadm settle --timeout=5 >/dev/null 2>&1 || true
    for i in $(seq 1 50); do
        for p in "${loop}"p*; do
            [ -b "$p" ] && return 0
        done
        sleep 0.1
    done
    return 1
}

LOOP="$(losetup --find --show --partscan "$IMG")"
wait_for_partitions "$LOOP" || {
    echo "partition nodes never appeared for $LOOP" >&2
    exit 1
}
PART="${LOOP}p1"
[ -b "$PART" ] || { echo "no partition device at $PART" >&2; exit 1; }

# Argon2id with 1 GiB of memory by default (matching the reference storage device header), or
# 256 MiB / 1 thread if --fast-kdf / --phone-kdf / PHONE_KDF=1 is specified.
cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --pbkdf argon2id \
    --pbkdf-memory "$PBKDF_MEM" \
    --pbkdf-parallel "$PBKDF_PARALLEL" \
    --pbkdf-force-iterations "$PBKDF_ITERS" \
    --batch-mode \
    --key-file="$PW_FILE" \
    "$PART"

cryptsetup open --key-file="$PW_FILE" "$PART" "$NAME"

# mkfs.btrfs with standard defaults (skinny-metadata, free-space-tree)
mkfs.btrfs -q -L luks-btrfs-test "$MAPPER"

# Known contents, so a later write can be checked for having disturbed them.
mkdir -p "$MNT"
mount "$MAPPER" "$MNT"
echo "hello from the kernel" > "$MNT/hello.txt"
mkdir -p "$MNT/docs" "$MNT/existing"
echo "# Btrfs Test Stick" > "$MNT/docs/readme.md"
head -c 4096 /dev/urandom > "$MNT/existing/one-block.bin"
head -c $((256*1024)) /dev/urandom > "$MNT/existing/many-blocks.bin"
sync
ls -la "$MNT"
umount "$MNT"

cryptsetup close "$NAME"
losetup -d "$LOOP"; LOOP=""

echo "built ok"
REMOTE_SCRIPT

printf '%s' "$PASSWORD" | colima ssh -- tee "$REMOTE_PW" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null
colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$SIZE" "$NAME" "$PBKDF_MEM" "$PBKDF_PARALLEL" "$PBKDF_ITERS" "$REMOTE_PW"

colima ssh -- sudo cat "$REMOTE" > "$OUT"
colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" "$REMOTE_PW"

echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
