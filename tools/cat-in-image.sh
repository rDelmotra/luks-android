#!/bin/bash
# Read a file out of an ext4 image using the real Linux kernel.
#
#   tools/cat-in-image.sh <image> <path-inside-image>
#
# The final oracle for the write path. verify-ext4.sh asks e2fsck whether the
# structures are well-formed; this asks the kernel to actually mount the
# filesystem and hand back the bytes — which is the only claim that matters,
# because "e2fsck is happy" and "Linux can open your file by name" are not the
# same statement.
#
# The file's contents go to stdout, so the caller can compare them against what
# it wrote. Anything diagnostic goes to stderr to keep stdout byte-exact.
set -euo pipefail

IMG="${1:?usage: cat-in-image.sh <image> <path>}"
INNER="${2:?usage: cat-in-image.sh <image> <path>}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="cat-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
INNER="$2"
MNT="/tmp/mnt-cat-$$"

cleanup() {
    umount "$MNT" 2>/dev/null || true
    rm -rf "$MNT" "$IMG"
}
trap cleanup EXIT

mkdir -p "$MNT"
# Read-only: this script must never be the thing that modifies an image under
# test. If the kernel needed to write to mount it, that is itself a finding.
mount -o ro "$IMG" "$MNT"

# Diagnostics to stderr so stdout stays exactly the file's bytes.
ls -la "$MNT" >&2
cat "$MNT/$INNER"
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null
colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$INNER"
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true
