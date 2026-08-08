#!/bin/bash
# Repair a LUKS image whose filesystem e2fsck flagged, and write the result
# back out so it can be dd'd onto the stick.
#
#   tools/repair-image.sh <image> [password]
#
# Companion to verify-image.sh, which deliberately never repairs (-fn, so
# damage is reported rather than hidden). This is the other half: once a run
# has been graded and the diffs understood — e.g. the leaked-block/leaked-inode
# pattern an interrupted write leaves, see INCIDENTS.md — this clears them.
#
# Never run blind. Read what verify-image.sh reported first; -fy answers yes
# to every repair prompt with no chance to inspect what it decided to do.
#
# Writes <image>.repaired next to the input. Exit status is the outcome: 0 the
# repaired image now checks and mounts clean, non-zero and the reason is on
# stderr.
set -euo pipefail

IMG="${1:?usage: repair-image.sh <image> [password]}"
PASSWORD="${2:-test}"
OUT="${IMG}.repaired"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="repair-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# Same stdin gotcha as verify-image.sh: the script goes over as a file, not a
# pipe, so it does not compete with the passphrase for stdin.
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
    TARGET=""
    for part in "${LOOP}"p*; do
        [ -b "$part" ] || continue
        if [ "$(blkid -o value -s TYPE "$part" 2>/dev/null || true)" = "crypto_LUKS" ]; then
            TARGET="$part"
            echo "container: GPT, ${part##*/}"
            break
        fi
    done
    [ -n "$TARGET" ] || { echo "GPT present but no LUKS partition" >&2; exit 1; }
else
    echo "container: bare LUKS"
fi

cryptsetup open --key-file=- --type luks "$TARGET" "$NAME"

FSTYPE="$(blkid -o value -s TYPE "$MAPPER" || true)"
echo "filesystem: ${FSTYPE:-unknown}"

case "$FSTYPE" in
    ext2|ext3|ext4)
        # -f forces a full check regardless of the clean flag; -y answers
        # every prompt yes. Unlike verify-image.sh this is allowed to fail
        # with e2fsck's own non-zero-but-fixed exit codes (1: fixed, 2: fixed
        # + reboot advised for a live mount, neither applies to an offline
        # image) — only bail on something e2fsck itself calls unrecoverable.
        e2fsck -fy "$MAPPER" || {
            code=$?
            if [ "$code" -ge 4 ]; then
                echo "e2fsck could not repair this (exit $code)" >&2
                exit "$code"
            fi
        }
        ;;
    btrfs)
        echo "btrfs repair is not wired up here — do it by hand" >&2
        exit 1
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

# Re-check read-only, so the caller gets a clean/not-clean answer rather than
# having to trust that -y's repairs actually converged.
e2fsck -fn "$MAPPER" || { echo "still not clean after repair" >&2; exit 1; }

mkdir -p "$MNT"
mount -o ro "$MAPPER" "$MNT"
echo "--- mounted after repair, root contains ---"
ls -la "$MNT" | head -40
umount "$MNT"
cryptsetup close "$NAME"
losetup -d "$LOOP" 2>/dev/null || true
LOOP=""

echo "repaired image ready"
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

printf '%s' "$PASSWORD" | colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$NAME"

colima ssh -- sudo cat "$REMOTE" > "$OUT"
colima ssh -- sudo rm -f "$REMOTE" "$REMOTE_SH" 2>/dev/null || true

echo "VERDICT: repaired — wrote $OUT ($(wc -c < "$OUT") bytes)"
