#!/bin/bash
# Rekey a LUKS2 image or device to lighter Argon2id parameters (256 MiB memory,
# 1 thread, 4 iterations) for fast unlocking on phones.
#
#   tools/rekey-luks-stick.sh [--verify] <image-or-device> [password]
#
# Like verify-image.sh and make-stick-image.sh, this runs in the colima VM
# using real cryptsetup.
#
# SAFETY PROPERTIES:
#   * Backs up the LUKS header before altering keyslots.
#   * Tests unlocking the volume immediately after rekeying.
#   * Streams the image back to the host only after successful unlock verification.
#   * Passphrase is provided via keyfile / stdin, never exposed on argv.
#
# Pass `--verify` to run tools/verify-image.sh on the rekeyed target.
set -euo pipefail

DO_VERIFY=false
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify)
            DO_VERIFY=true
            shift
            ;;
        -h|--help)
            echo "usage: $(basename "$0") [--verify] <image-or-device> [password]"
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -lt 1 ]; then
    echo "usage: $(basename "$0") [--verify] <image-or-device> [password]" >&2
    exit 2
fi

IMG="${POSITIONAL[0]}"
PASSWORD="${POSITIONAL[1]:-test}"

if [ -f "$IMG" ]; then
    [ -r "$IMG" ] && [ -w "$IMG" ] || {
        echo "cannot read/write $IMG" >&2
        exit 2
    }
elif [ -b "$IMG" ]; then
    [ -r "$IMG" ] && [ -w "$IMG" ] || {
        echo "cannot read/write $IMG — run 'diskutil unmountDisk $IMG' first, and" >&2
        echo "if that still isn't accessible, re-run under sudo." >&2
        exit 2
    }
else
    echo "no such image or device: $IMG" >&2
    exit 2
fi

command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="rekey-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
REMOTE_PW="/tmp/$NAME.pw"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
NAME="$2"
PW_FILE="$3"
MAPPER="/dev/mapper/$NAME"
BACKUP="/tmp/$NAME.hdr"
LOOP=""
OPENED=""

cleanup() {
    [ -n "$OPENED" ] && cryptsetup close "$NAME" 2>/dev/null || true
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -f "$PW_FILE" "$BACKUP"
}
trap cleanup EXIT

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

TARGET="$IMG"
PTTYPE="$(blkid -o value -s PTTYPE "$IMG" 2>/dev/null || true)"
if [ "$PTTYPE" = "gpt" ] || [ "$PTTYPE" = "dos" ]; then
    LOOP="$(losetup --find --show --partscan "$IMG")"
    wait_for_partitions "$LOOP" || {
        echo "partition nodes never appeared for $LOOP (not an image fault)" >&2
        exit 1
    }
    TARGET=""
    for part in "${LOOP}"p*; do
        [ -b "$part" ] || continue
        if [ "$(blkid -o value -s TYPE "$part" 2>/dev/null || true)" = "crypto_LUKS" ]; then
            TARGET="$part"
            echo "container: partitioned ($PTTYPE), ${part##*/}"
            break
        fi
    done
    [ -n "$TARGET" ] || { echo "partition table present but no LUKS partition" >&2; exit 1; }
else
    if [ "$(blkid -o value -s TYPE "$IMG" 2>/dev/null || true)" = "crypto_LUKS" ] || cryptsetup isLuks "$IMG" 2>/dev/null; then
        echo "container: bare LUKS"
    else
        echo "not a recognized LUKS image or partitioned disk" >&2
        exit 1
    fi
fi

echo "backing up LUKS header..."
cryptsetup luksHeaderBackup "$TARGET" --header-backup-file "$BACKUP"

echo "rekeying LUKS keyslot with Argon2id (memory: 256 MiB, 1 thread, 4 iterations)..."
cryptsetup luksChangeKey "$TARGET" "$PW_FILE" \
    --pbkdf argon2id \
    --pbkdf-memory 262144 \
    --pbkdf-parallel 1 \
    --pbkdf-force-iterations 4 \
    --batch-mode \
    --key-file "$PW_FILE"

echo "verifying keyslot opens with new parameters..."
cryptsetup open --key-file "$PW_FILE" --type luks "$TARGET" "$NAME"
OPENED=1

cryptsetup close "$NAME"
OPENED=""

if [ -n "$LOOP" ]; then
    losetup -d "$LOOP" 2>/dev/null || true
    LOOP=""
fi

echo "rekey successful"
REMOTE_SCRIPT

printf '%s' "$PASSWORD" | colima ssh -- tee "$REMOTE_PW" > /dev/null
colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$NAME" "$REMOTE_PW"

if [ -f "$IMG" ]; then
    TMP_OUT="${IMG}.tmp-$$"
    colima ssh -- sudo cat "$REMOTE" > "$TMP_OUT"
    mv -f "$TMP_OUT" "$IMG"
else
    colima ssh -- sudo cat "$REMOTE" > "$IMG"
fi

colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" "$REMOTE_PW" 2>/dev/null || true

echo "rekeyed $IMG ($(du -h "$IMG" | cut -f1))"

if [ "$DO_VERIFY" = true ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    echo "verifying rekeyed image with $SCRIPT_DIR/verify-image.sh..."
    "$SCRIPT_DIR/verify-image.sh" "$IMG" "$PASSWORD"
fi
