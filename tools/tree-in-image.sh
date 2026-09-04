#!/bin/bash
# List a whole directory tree out of an image using the real Linux kernel.
#
#   tools/tree-in-image.sh <image> <path-inside-image> [password]
#
# The tree-shaped sibling of cat-in-image.sh. That script asks the kernel for
# the bytes of *one* file, which is the right oracle for a single write. A
# directory transfer's claim is different in kind: "every file landed, under
# the right name, in the right directory, with the right bytes, and nothing
# extra appeared." Checking that a file at a time is one colima round trip per
# file — a hundred-file tree becomes a hundred VM copies of the same image,
# which is slow enough that nobody runs it, and an oracle nobody runs is not
# an oracle.
#
# So: mount once, walk once, print a manifest. Same rule as every verify
# script here — **never check our output with our own code.** The structure
# comes from the kernel's own directory reads and the hashes from sha256sum
# inside the VM, so a writer and a reader of ours that share a
# misunderstanding of the on-disk format cannot agree their way to a pass.
#
# The manifest goes to stdout, one entry per line, `LC_ALL=C` sorted so it is
# byte-stable across runs and diffable:
#
#   d <relpath>
#   f <relpath> <size> <sha256>
#
# Paths are relative to <path-inside-image>, which is itself not listed. A
# caller compares this against what it believes it wrote — including the
# absence of lines, which is how "the cancelled half of the tree is not
# there" gets asserted.
#
# Only directories and regular files are emitted. Anything else (symlink,
# device node, socket) is a `?` line rather than a silent omission: this
# feature does not create them, so one appearing is a finding, and a manifest
# that quietly dropped it would hide exactly that.
#
# Handles the same three image shapes as cat-in-image.sh — bare filesystem,
# bare LUKS container, whole disk with a GPT — decided by `blkid` and by
# whether a password was given, never by the filename.
#
# Exit status is the verdict: 0 clean, non-zero and the reason is on stderr.
set -euo pipefail

IMG="${1:?usage: tree-in-image.sh <image> <path> [password]}"
# `${2?...}` not `${2:?...}`: an empty path is the meaningful request "manifest
# the whole filesystem from its root", which the colon form would reject.
INNER="${2?usage: tree-in-image.sh <image> <path> [password]}"
PASSWORD="${3:-}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="tree-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# Copied as a file and run, not piped into `sudo bash -s` — the same
# stdin-collision gotcha documented in cat-in-image.sh and verify-image.sh.
# The passphrase needs stdin to itself; piping both does not fail loudly, it
# silently reads the passphrase as empty.
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
    # Leave the mount before unmounting it. The walk below `cd`s into the
    # subtree, which holds the mount busy — umount then fails, and the `rm -rf`
    # that follows starts deleting *through* the still-mounted filesystem. It
    # is read-only, so that turns into a wall of "cannot remove" and a fatal
    # exit for an image that verified perfectly. cat-in-image.sh never needed
    # this because it never cd's in.
    cd / 2>/dev/null || true
    umount "$MNT" 2>/dev/null || true
    [ -n "$OPENED" ] && cryptsetup close "$NAME" 2>/dev/null || true
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$MNT" "$IMG"
}
trap cleanup EXIT

# See cat-in-image.sh: losetup returns before udev has created the loopXpN
# nodes, so globbing them immediately is a race that loses under load and
# reports a false failure for a perfectly good image.
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
    # Do not assume partition 1: a real disk can carry an unencrypted
    # partition ahead of the interesting one. Ask blkid, as in cat-in-image.sh.
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
    # --key-file=- reads from stdin, the only place the passphrase appears.
    # Never on a command line: argv is world-readable via `ps`.
    cryptsetup open --key-file=- --type luks "$TARGET" "$NAME"
    OPENED=1
    TARGET="/dev/mapper/$NAME"
    echo "container: LUKS, opened" >&2
fi

mkdir -p "$MNT"
# Read-only: this script must never be the thing that modifies an image under
# test. If the kernel needed to write to mount it, that is a finding, not
# something to paper over.
mount -o ro "$TARGET" "$MNT"

ROOT="$MNT/$INNER"
[ -d "$ROOT" ] || { echo "not a directory inside the image: $INNER" >&2; exit 1; }

# -mindepth 1 so the subtree root itself is not listed; -printf gives the
# path relative to ROOT directly. NUL-delimited and read with `-d ''` because
# a filename may legitimately contain a newline — this feature copies whatever
# names the source reports, and a manifest that split on newlines would
# silently mis-parse exactly the name worth checking.
#
# The sort is LC_ALL=C on the *whole* line: locale-aware collation reorders
# punctuation between machines, which would make a byte-comparison against a
# checked-in expectation fail for reasons that have nothing to do with the
# filesystem.
cd "$ROOT"
find . -mindepth 1 -printf '%y\t%P\0' \
| while IFS=$'\t' read -r -d '' TYPE REL; do
    case "$TYPE" in
        d) printf 'd %s\n' "$REL" ;;
        f)
            SIZE="$(stat -c %s -- "$REL")"
            HASH="$(sha256sum -- "$REL" | cut -d' ' -f1)"
            printf 'f %s %s %s\n' "$REL" "$SIZE" "$HASH"
            ;;
        # Not silently dropped: this feature never creates these, so one
        # appearing is the finding, and an omission would hide it.
        *) printf '? %s %s\n' "$REL" "$TYPE" ;;
    esac
done | LC_ALL=C sort
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

if [ -n "$PASSWORD" ]; then
    printf '%s' "$PASSWORD" | colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$INNER" "$NAME" yes
else
    colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$INNER" "$NAME" no
fi
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true
