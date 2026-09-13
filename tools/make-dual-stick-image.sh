#!/bin/bash
# Build a dual-partition (LUKS2 ext4 + Plain ext4) test image for the physical stick.
#
#   tools/make-dual-stick-image.sh <output.img> [password]
#
# Layout on disk:
#   Partition 1: 4 GiB (1 MiB -> 4097 MiB)  - LUKS2 container (Argon2id, phone-KDF) + ext4 ("LUKS_EXT4")
#   Space Apart: ~512 MiB unallocated gap (4097 MiB -> 4608 MiB)
#   Partition 2: 4 GiB (4608 MiB -> 8704 MiB) - Plain unencrypted ext4 ("PLAIN_EXT4")
#
# Both partitions are populated with distinct test files so you can verify
# unlocking Partition 1 (with password) and mounting Partition 2 (without password)
# on the same physical USB stick in the app!
set -euo pipefail

OUT="${1:?usage: make-dual-stick-image.sh <output.img> [password]}"
PASSWORD="${2:-test}"

command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="mkdual-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
NAME="$2"
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
truncate -s 10G "$IMG"

# Partition 1: 1MiB -> 4097MiB (4 GiB)
# Gap: 4097MiB -> 4608MiB (~511 MiB space apart)
# Partition 2: 4608MiB -> 8704MiB (4 GiB)
sgdisk --new=1:1MiB:4097MiB    --typecode=1:8300 --change-name=1:luks-ext4  "$IMG" >/dev/null
sgdisk --new=2:4608MiB:8704MiB --typecode=2:8300 --change-name=2:plain-ext4 "$IMG" >/dev/null

LOOP="$(losetup --find --show --partscan "$IMG")"
PART1="${LOOP}p1"
PART2="${LOOP}p2"
[ -b "$PART1" ] || { echo "no partition device at $PART1" >&2; exit 1; }
[ -b "$PART2" ] || { echo "no partition device at $PART2" >&2; exit 1; }

mkdir -p "$MNT"

echo "==> Setting up Partition 1: LUKS2 ext4 (phone KDF, 256 MiB Argon2id)"
cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --pbkdf argon2id \
    --pbkdf-memory 262144 \
    --pbkdf-parallel 1 \
    --pbkdf-force-iterations 4 \
    --batch-mode \
    --key-file=- \
    "$PART1" < /tmp/pw

cryptsetup open --key-file=- "$PART1" "$NAME" < /tmp/pw
mkfs.ext4 -q -L LUKS_EXT4 "$MAPPER"
mount "$MAPPER" "$MNT"
echo "Hello from encrypted LUKS2 ext4 partition!" > "$MNT/encrypted_notes.txt"
mkdir -p "$MNT/secure_vault"
echo "Sensitive file inside LUKS container" > "$MNT/secure_vault/secret.txt"
head -c $((64*1024)) /dev/urandom > "$MNT/secure_vault/random.bin"
sync
umount "$MNT"
cryptsetup close "$NAME"

echo "==> Setting up Partition 2: Plain unencrypted ext4 (spaced 512 MiB apart)"
mkfs.ext4 -q -L PLAIN_EXT4 "$PART2"
mount "$PART2" "$MNT"
echo "Hello from plain unencrypted ext4 partition!" > "$MNT/public_readme.txt"
mkdir -p "$MNT/shared_media"
echo "Public file on plain partition" > "$MNT/shared_media/photo_info.txt"
head -c $((64*1024)) /dev/urandom > "$MNT/shared_media/sample.bin"
sync
umount "$MNT"

losetup -d "$LOOP"; LOOP=""
echo "Dual-partition image built successfully"
REMOTE_SCRIPT

printf '%s' "$PASSWORD" | colima ssh -- tee /tmp/pw > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null
colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$NAME"

colima ssh -- sudo cat "$REMOTE" > "$OUT"
colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" /tmp/pw

echo "Wrote dual-partition image to $OUT ($(du -h "$OUT" | cut -f1))"
