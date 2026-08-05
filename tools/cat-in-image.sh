#!/bin/bash
# Read a file out of an image using the real Linux kernel.
#
#   tools/cat-in-image.sh <image> <path-inside-image> [password]
#
# The final oracle for the write path. verify-ext4.sh and verify-image.sh ask
# e2fsck whether the structures are well-formed; this asks the kernel to
# actually mount the filesystem and hand back the bytes — which is the only
# claim that matters, because "e2fsck is happy" and "Linux can open your file by
# name" are not the same statement.
#
# Handles all three shapes this repo produces: a bare filesystem image, a bare
# LUKS container, and a whole disk with a GPT. Which one it is comes from
# `blkid` and from whether a password was given, never from the filename.
#
# The file's contents go to stdout, so the caller can compare them byte-for-byte
# against what it wrote. Everything diagnostic goes to stderr.
set -euo pipefail

IMG="${1:?usage: cat-in-image.sh <image> <path> [password]}"
INNER="${2:?usage: cat-in-image.sh <image> <path> [password]}"
PASSWORD="${3:-}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="cat-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# The script is copied as a *file* and then run, rather than piped into
# `sudo bash -s`, so that stdin is free for the passphrase alone. Piping both
# does not fail loudly — the passphrase silently reads as empty. Same note as
# verify-image.sh; it cost an hour once.
cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
INNER="$2"
NAME="$3"
HAVE_PW="$4"
MNT="/tmp/mnt-$NAME"
LOOP=""
OPENED=""

cleanup() {
    umount "$MNT" 2>/dev/null || true
    [ -n "$OPENED" ] && cryptsetup close "$NAME" 2>/dev/null || true
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$MNT" "$IMG"
}
trap cleanup EXIT

# `losetup --partscan` returns as soon as the loop device itself is attached.
# The kernel discovers the partitions and udev creates the loopXpN nodes a
# moment later, asynchronously. Globbing them right away is a race: it loses
# only under load, and when it loses it reports "no partition of type ..." for
# an image that is perfectly fine. That is a *false failure* in the oracle the
# whole write path is graded against, which is worse than it sounds — an oracle
# that cries wolf one run in five teaches you to ignore it.
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
if [ "$(blkid -o value -s PTTYPE "$IMG" 2>/dev/null || true)" = "gpt" ]; then
    LOOP="$(losetup --find --show --partscan "$IMG")"
    wait_for_partitions "$LOOP" || {
        echo "partition nodes never appeared for $LOOP (not an image fault)" >&2
        exit 1
    }
    # Do not assume partition 1. A real disk — and the gpt-luks fixture — can
    # carry an unencrypted partition ahead of the interesting one, and picking
    # p1 blindly reports "not a valid LUKS device" for a perfectly good image.
    # Ask blkid what each partition is, exactly as the kernel sees it.
    WANT="ext2 ext3 ext4 btrfs"
    [ "$HAVE_PW" = "yes" ] && WANT="crypto_LUKS"
    TARGET=""
    for part in "${LOOP}"p*; do
        [ -b "$part" ] || continue
        TYPE="$(blkid -o value -s TYPE "$part" 2>/dev/null || true)"
        for want in $WANT; do
            if [ "$TYPE" = "$want" ]; then
                TARGET="$part"
                echo "container: GPT, ${part##*/} ($TYPE)" >&2
                break 2
            fi
        done
    done
    [ -n "$TARGET" ] || { echo "no partition of type: $WANT" >&2; exit 1; }
fi

if [ "$HAVE_PW" = "yes" ]; then
    # --key-file=- reads from stdin, which is the only place the passphrase
    # ever appears. Never on a command line: argv is world-readable via `ps`.
    cryptsetup open --key-file=- --type luks "$TARGET" "$NAME"
    OPENED=1
    TARGET="/dev/mapper/$NAME"
    echo "container: LUKS, opened" >&2
fi

mkdir -p "$MNT"
# Read-only: this script must never be the thing that modifies an image under
# test. If the kernel needed to write in order to mount, that is itself a
# finding rather than something to paper over.
mount -o ro "$TARGET" "$MNT"

ls -la "$MNT" >&2
cat "$MNT/$INNER"
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

if [ -n "$PASSWORD" ]; then
    printf '%s' "$PASSWORD" | colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$INNER" "$NAME" yes
else
    colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$INNER" "$NAME" no
fi
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true
