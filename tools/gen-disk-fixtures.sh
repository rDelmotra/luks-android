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
TARGETS="${2:-gpt mbr gpt-btrfs}"
PASS="test"
mkdir -p "$OUT"

want() { case " $TARGETS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

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
    for l in $(losetup -j "$OUT/gpt-luks-btrfs.img" -O NAME --noheadings 2>/dev/null); do
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
if want gpt; then
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
fi

# --- MBR -------------------------------------------------------------------
if want mbr; then
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
fi

# --- GPT + LUKS + btrfs ------------------------------------------------------
# The same stack as gpt-luks.img with the other filesystem inside, so the JNI
# bridge's "which filesystem is this?" decision is exercised on a real
# encrypted volume rather than only on a bare image.
#
# Default geometry deliberately — not mixed block groups — so this matches what
# is actually on the developer's drive. That costs a 128 MiB image, since
# btrfs's floor for a non-mixed filesystem is ~109 MiB, but almost all of it is
# never written and so stays zeros through the encryption: LUKS only produces
# ciphertext where something was stored.
#
# One subvolume, because the whole point of the previous two passes is that a
# real btrfs root is not a single tree.
if want gpt-btrfs; then
echo "Building gpt-luks-btrfs.img..."
IMG="$OUT/gpt-luks-btrfs.img"
dd if=/dev/zero of="$IMG" bs=1M count=128 status=none

sgdisk -o "$IMG" >/dev/null
sgdisk -n 1:2048:0 -t 1:CA7D7CCB-63ED-4C53-861C-1742536059CC -c 1:"cryptbtrfs" "$IMG" >/dev/null

LOOP="$(losetup -f --show -P "$IMG")"
printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "${WEAK[@]}" "${SMALL[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512 "${LOOP}p1" -
printf '%s' "$PASS" | cryptsetup open --batch-mode --key-file=- "${LOOP}p1" diskfix

mkfs.btrfs -q -L DISKBTRFS -U 55555555-6666-7777-8888-999999999999 /dev/mapper/diskfix
mkdir -p "$WORK/mnt"
mount /dev/mapper/diskfix "$WORK/mnt"
printf 'whole disk stack works\n' > "$WORK/mnt/proof.txt"
mkdir -p "$WORK/mnt/dir"
printf 'inside a directory\n' > "$WORK/mnt/dir/inner.txt"
btrfs subvolume create "$WORK/mnt/sub" >/dev/null
printf 'inside a subvolume\n' > "$WORK/mnt/sub/nested.txt"
sync
umount "$WORK/mnt"

cryptsetup close diskfix
losetup -d "$LOOP"
echo "  -> gpt-luks-btrfs.img"
fi

echo "Done:"
ls -la "$OUT"
