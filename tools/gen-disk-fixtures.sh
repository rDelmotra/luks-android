#!/bin/bash
# Build whole-disk images: partition table + LUKS partition + ext4 inside.
#
# These exercise the full stack in one artifact — GPT/MBR parsing, LUKS
# detection by magic, unlock, and filesystem read.
#
# Needs Linux with loop devices and device-mapper (see tools/README-fixtures.md).
# Password is "test"; KDF parameters are deliberately weak.
set -euo pipefail

OUT="${1:-/tmp/disk-fixtures}"
PASS="test"
mkdir -p "$OUT"

WORK="$(mktemp -d)"
cleanup() {
    umount "$WORK/mnt" 2>/dev/null || true
    cryptsetup close diskfix 2>/dev/null || true
    for l in $(losetup -j "$OUT/gpt-luks.img" -O NAME --noheadings 2>/dev/null); do
        losetup -d "$l" 2>/dev/null || true
    done
    for l in $(losetup -j "$OUT/mbr-luks.img" -O NAME --noheadings 2>/dev/null); do
        losetup -d "$l" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

WEAK=(--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 32 --pbkdf-parallel 1)
SMALL=(--luks2-keyslots-size 256k --offset 1024)

populate() {
    local mapper="$1"
    mkfs.ext4 -q -L DISKDATA -U 44444444-5555-6666-7777-888888888888 "$mapper"
    mkdir -p "$WORK/mnt"
    mount "$mapper" "$WORK/mnt"
    printf 'whole disk stack works\n' > "$WORK/mnt/proof.txt"
    mkdir -p "$WORK/mnt/dir"
    printf 'inside a directory\n' > "$WORK/mnt/dir/inner.txt"
    umount "$WORK/mnt"
}

# --- GPT -------------------------------------------------------------------
echo "Building gpt-luks.img..."
IMG="$OUT/gpt-luks.img"
dd if=/dev/zero of="$IMG" bs=1M count=24 status=none

sgdisk -o "$IMG" >/dev/null
# Partition 1: a small plain partition, so the table has more than one entry.
sgdisk -n 1:2048:6143 -t 1:8300 -c 1:"plainpart" "$IMG" >/dev/null
# Partition 2: tagged with the LUKS type GUID.
sgdisk -n 2:6144:0 -t 2:CA7D7CCB-63ED-4C53-861C-1742536059CC -c 2:"cryptdata" "$IMG" >/dev/null

LOOP="$(losetup -f --show -P "$IMG")"
printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "${WEAK[@]}" "${SMALL[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512 "${LOOP}p2" -
printf '%s' "$PASS" | cryptsetup open --batch-mode --key-file=- "${LOOP}p2" diskfix
populate /dev/mapper/diskfix
cryptsetup close diskfix
losetup -d "$LOOP"
sgdisk -p "$IMG" > "$OUT/GPT-LAYOUT.txt" 2>&1 || true
echo "  -> gpt-luks.img"

# --- MBR -------------------------------------------------------------------
echo "Building mbr-luks.img..."
IMG="$OUT/mbr-luks.img"
dd if=/dev/zero of="$IMG" bs=1M count=24 status=none

# One primary Linux partition covering the disk from sector 2048.
printf 'label: dos\n2048,,83\n' | sfdisk -q "$IMG" >/dev/null

LOOP="$(losetup -f --show -P "$IMG")"
printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "${WEAK[@]}" "${SMALL[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512 "${LOOP}p1" -
printf '%s' "$PASS" | cryptsetup open --batch-mode --key-file=- "${LOOP}p1" diskfix
populate /dev/mapper/diskfix
cryptsetup close diskfix
losetup -d "$LOOP"
echo "  -> mbr-luks.img"

echo "Done:"
ls -la "$OUT"
