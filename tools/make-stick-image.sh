#!/bin/bash
# Build a LUKS2 + ext4 image to write onto the physical test stick.
#
#   tools/make-stick-image.sh <output.img> [size] [password]
#
# The image is built by real `sgdisk`, real `cryptsetup` and real `mkfs.ext4`
# inside the colima VM, for the same reason every fixture in this repo is: a
# target we generated ourselves would only prove our writer agrees with our
# reader. This one is the kernel's own idea of a LUKS2 ext4 drive, and the
# ext4 writer will be graded against `e2fsck` on it.
#
# WARNING: The passphrase is a *test* passphrase. Anything written to a drive made by
# this script is readable by anyone who has read this file. The stick is a test
# target and must never hold real data.
#
# Layout matches a drive a person would actually plug in — GPT, one partition
# at the conventional 1 MiB offset — so the partition scanner is exercised
# rather than bypassed.
set -euo pipefail

OUT="${1:?usage: make-stick-image.sh <output.img> [size] [password]}"
SIZE="${2:-4G}"
PASSWORD="${3:-test}"

command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="mkstick-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# Copied as a file, not piped: stdin belongs to the passphrase alone. See the
# same note in verify-image.sh — this cost an hour once.
cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
SIZE="$2"
NAME="$3"
MAPPER="/dev/mapper/$NAME"
MNT="/tmp/mnt-$NAME"
LOOP=""

cleanup() {
    umount "$MNT" 2>/dev/null || true
    cryptsetup close "$NAME" 2>/dev/null || true
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$MNT"
}
trap cleanup EXIT

rm -f "$IMG"
truncate -s "$SIZE" "$IMG"

# 8300 = Linux filesystem. Starting at 1 MiB is what every partitioner does,
# and it keeps the LUKS payload aligned to the flash erase block.
sgdisk --new=1:1MiB:0 --typecode=1:8300 --change-name=1:luks-test "$IMG" >/dev/null

LOOP="$(losetup --find --show --partscan "$IMG")"
PART="${LOOP}p1"
[ -b "$PART" ] || { echo "no partition device at $PART" >&2; exit 1; }

# Argon2id with 1 GiB of memory, matching the reference storage device header, so unlock
# timing measured on the phone against this stick is comparable to the reference device's
# 6.76 s rather than an artefact of a cheaper KDF.
cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --pbkdf argon2id \
    --pbkdf-memory 1048576 \
    --pbkdf-parallel 4 \
    --pbkdf-force-iterations 4 \
    --batch-mode \
    --key-file=- \
    "$PART" < /tmp/pw

cryptsetup open --key-file=- "$PART" "$NAME" < /tmp/pw

mkfs.ext4 -q -L luks-test "$MAPPER"

# Known contents, so a later write can be checked for having disturbed them.
# Sizes chosen to span the interesting cases: inline-ish, single block, and
# several blocks so the extent tree has something in it.
mkdir -p "$MNT"
mount "$MAPPER" "$MNT"
echo "hello from the kernel" > "$MNT/hello.txt"
mkdir -p "$MNT/existing"
head -c 4096      /dev/urandom > "$MNT/existing/one-block.bin"
head -c $((256*1024)) /dev/urandom > "$MNT/existing/many-blocks.bin"
sync
ls -la "$MNT"
umount "$MNT"

cryptsetup close "$NAME"
losetup -d "$LOOP"; LOOP=""

echo "built ok"
REMOTE_SCRIPT

printf '%s' "$PASSWORD" | colima ssh -- tee /tmp/pw > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null
colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$SIZE" "$NAME"

colima ssh -- sudo cat "$REMOTE" > "$OUT"
colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" /tmp/pw

echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
