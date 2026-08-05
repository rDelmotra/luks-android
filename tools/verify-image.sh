#!/bin/bash
# Grade a LUKS image we wrote to, using the kernel's own tools.
#
#   tools/verify-image.sh <image> [password]
#
# This is the oracle for every filesystem write. The rule that has held for
# every fixture in this repo applies doubly here: **never check our output with
# our own code.** A writer and a reader that share a misunderstanding of the
# on-disk format agree with each other perfectly and corrupt real drives.
#
# So the image goes to Linux, is opened by real `cryptsetup`, checked by real
# `e2fsck` or `btrfs check`, and mounted by the real kernel. If all three are
# happy, the drive is one Linux can use — which is the only claim that matters.
#
# Runs in the colima VM because macOS has neither cryptsetup nor device-mapper
# (see the doc errata in STATE.md — the original planning docs were wrong about
# this). Start it with `colima start` if it is not up.
#
# Exit status is the verdict: 0 clean, non-zero and the reason is on stderr.
set -euo pipefail

IMG="${1:?usage: verify-image.sh <image> [password]}"
PASSWORD="${2:-test}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="verify-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# ⚠️ The remote script is copied as a *file* and then run, rather than piped
# into `sudo bash -s`. This is the gotcha recorded in STATE.md, and it cost an
# hour once before: if the script arrives on stdin, it is competing with the
# passphrase that `cryptsetup --key-file=-` also wants from stdin. The symptom
# is not an error but a hang, or — as here — a passphrase that silently reads
# as empty and fails with "No key available with this passphrase."
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
    rm -rf "$MNT" "$IMG"
}
trap cleanup EXIT

# The image may be a bare LUKS container (the fixtures) or a whole disk with a
# partition table (the test stick, and every real drive). Ask the kernel which,
# rather than guessing from the size or the filename — `blkid` on the raw image
# reports the partition table if there is one.
TARGET="$IMG"
if [ "$(blkid -o value -s PTTYPE "$IMG" 2>/dev/null || true)" = "gpt" ]; then
    LOOP="$(losetup --find --show --partscan "$IMG")"
    TARGET="${LOOP}p1"
    [ -b "$TARGET" ] || { echo "GPT present but no partition 1" >&2; exit 1; }
    echo "container: GPT, partition 1"
else
    echo "container: bare LUKS"
fi

# --key-file=- reads the passphrase from stdin, which is where it already is,
# and which is the only place it ever appears. Never on a command line: argv is
# visible to every user on the machine via `ps`.
cryptsetup open --key-file=- --type luks "$TARGET" "$NAME"

# What is inside decides which checker to run. `blkid` is the kernel's own
# answer, not ours — using our own detector here would be exactly the
# circularity this script exists to avoid.
FSTYPE="$(blkid -o value -s TYPE "$MAPPER" || true)"
echo "filesystem: ${FSTYPE:-unknown}"

case "$FSTYPE" in
    ext2|ext3|ext4)
        # -f forces a full check even if the superblock claims clean; -n
        # answers no to every repair prompt, so damage is reported rather than
        # hidden by fixing it. A harness that silently repairs turns every bug
        # into a passing test.
        e2fsck -fn "$MAPPER"
        ;;
    btrfs)
        btrfs check --readonly "$MAPPER"
        ;;
    "")
        echo "no filesystem signature — the container decrypted to garbage" >&2
        exit 1
        ;;
    *)
        echo "unexpected filesystem: $FSTYPE" >&2
        exit 1
        ;;
esac

# The checker passing is necessary but not sufficient: a filesystem can be
# structurally valid and still refuse to mount. The kernel is the last word.
mkdir -p "$MNT"
mount -o ro "$MAPPER" "$MNT"
echo "--- mounted, root contains ---"
ls -la "$MNT" | head -40
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

# Now stdin is free for the passphrase alone.
printf '%s' "$PASSWORD" | colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$NAME"
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true

echo "VERDICT: clean — cryptsetup opened it, the checker passed, the kernel mounted it"
