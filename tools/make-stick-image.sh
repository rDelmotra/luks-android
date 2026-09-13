#!/bin/bash
# Build an ext4 (LUKS2 encrypted or plain) image to write onto the physical test stick.
#
#   tools/make-stick-image.sh <output.img> [size] [password] [--fast-kdf|--phone-kdf] [--plain]
#
# The image is built by real `sgdisk`, real `cryptsetup` and real `mkfs.ext4`
# inside the colima VM, for the same reason every fixture in this repo is: a
# target we generated ourselves would only prove our writer agrees with our
# reader. This one is the kernel's own idea of a LUKS2/plain ext4 drive, and the
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

FAST_KDF=0
PLAIN=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast-kdf|--phone-kdf)
            FAST_KDF=1
            shift
            ;;
        --plain)
            PLAIN=1
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -lt 1 ]; then
    echo "usage: make-stick-image.sh <output.img> [size] [password] [--fast-kdf|--phone-kdf] [--plain]" >&2
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

NAME="mkstick-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
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
PLAIN="$7"
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
# and it keeps the LUKS/ext4 payload aligned to the flash erase block.
sgdisk --new=1:1MiB:0 --typecode=1:8300 --change-name=1:ext4-test "$IMG" >/dev/null

LOOP="$(losetup --find --show --partscan "$IMG")"
PART="${LOOP}p1"
[ -b "$PART" ] || { echo "no partition device at $PART" >&2; exit 1; }

mkdir -p "$MNT"

if [ "$PLAIN" = "1" ]; then
    echo "==> Formatting plain ext4 on $PART"
    mkfs.ext4 -q -L plain-ext4 "$PART"
    mount "$PART" "$MNT"
else
    echo "==> Formatting LUKS2 on $PART (mem=${PBKDF_MEM}k)"
    cryptsetup luksFormat \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --pbkdf argon2id \
        --pbkdf-memory "$PBKDF_MEM" \
        --pbkdf-parallel "$PBKDF_PARALLEL" \
        --pbkdf-force-iterations "$PBKDF_ITERS" \
        --batch-mode \
        --key-file=- \
        "$PART" < /tmp/pw

    cryptsetup open --key-file=- "$PART" "$NAME" < /tmp/pw
    echo "==> mkfs.ext4 on $MAPPER"
    mkfs.ext4 -q -L luks-ext4 "$MAPPER"
    mount "$MAPPER" "$MNT"
fi

# Known contents, so a later write can be checked for having disturbed them.
echo "hello from the kernel" > "$MNT/hello.txt"
mkdir -p "$MNT/existing"
head -c 4096          /dev/urandom > "$MNT/existing/one-block.bin"
head -c $((256*1024)) /dev/urandom > "$MNT/existing/many-blocks.bin"
sync
ls -la "$MNT"
umount "$MNT"

if [ "$PLAIN" != "1" ]; then
    cryptsetup close "$NAME"
fi

losetup -d "$LOOP"; LOOP=""
echo "built ok"
REMOTE_SCRIPT

printf '%s' "$PASSWORD" | colima ssh -- tee /tmp/pw > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null
colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$SIZE" "$NAME" "$PBKDF_MEM" "$PBKDF_PARALLEL" "$PBKDF_ITERS" "$PLAIN"

colima ssh -- sudo cat "$REMOTE" > "$OUT"
colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" /tmp/pw

echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
