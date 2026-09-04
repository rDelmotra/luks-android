#!/bin/bash
# Grade a LUKS image we wrote to, using the kernel's own tools.
#
#   tools/verify-image.sh <image-or-device> [password]
#
# This is the oracle for every filesystem write. The rule that has held for
# every fixture in this repo applies doubly here: **never check our output with
# our own code.** A writer and a reader that share a misunderstanding of the
# on-disk format agree with each other perfectly and corrupt real drives.
#
# So the image goes to Linux, is opened by real `cryptsetup`, checked by real
# `e2fsck` or `btrfs check`, and mounted by the real kernel. When the container
# holds btrfs, it is also scrubbed — see the "btrfs scrub" block below for why
# that is not optional. If all steps are happy, the drive is one Linux can
# use — which is the only claim that matters.
#
# Runs in the colima VM because macOS has neither cryptsetup nor device-mapper
# (see the doc errata in STATE.md — the original planning docs were wrong about
# this). Start it with `colima start` if it is not up.
#
# <image-or-device> may be a regular file (the fixtures, or an image made with
# make-stick-image.sh) OR a raw macOS block device node (/dev/diskN — what
# `diskutil list` names a physically attached stick). Both are just read from
# the *host* and streamed into the VM over `colima ssh -- tee`, exactly the
# same way a file already was — this does not require the colima VM to see
# host block devices at all, only for this host shell to be able to open the
# path for reading, which it can for any device this user owns (measured
# 2026-08-18 against a disk image attached with `hdiutil attach -nomount`,
# which produces the same /dev/diskN block-device node a real USB stick does).
# Do NOT point this at a mounted disk while it is mounted — unmount first with
# `diskutil unmountDisk /dev/diskN`, or the read will race the OS.
#
# Exit status is the verdict: 0 clean, non-zero and the reason is on stderr.
set -euo pipefail

IMG="${1:?usage: verify-image.sh <image-or-device> [password]}"
PASSWORD="${2:-test}"

if [ -f "$IMG" ]; then
    :
elif [ -b "$IMG" ]; then
    [ -r "$IMG" ] || {
        echo "cannot read $IMG — run 'diskutil unmountDisk $IMG' first, and" >&2
        echo "if that still isn't readable, this user does not own the node;" >&2
        echo "re-run under sudo." >&2
        exit 2
    }
else
    echo "no such image or device: $IMG" >&2
    exit 2
fi
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
# See the long note in cat-in-image.sh: `losetup --partscan` returns before the
# loopXpN nodes exist, so globbing them immediately is a race that reports a
# missing partition for a sound image. Same fix, same reason.
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
    # Not necessarily partition 1: a disk can carry an unencrypted partition
    # ahead of the encrypted one, and blindly taking p1 reports "not a valid
    # LUKS device" for an image that is perfectly fine. Ask the kernel.
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
# `|| true`: under `set -o pipefail`, a directory with more than the
# `head -40` cutoff makes `ls` catch SIGPIPE and this pipeline "fail" before
# scrub ever runs (see tools/verify-btrfs.sh, measured 2026-08-14). This is a
# display line, not a check; it must never gate the verdict.
ls -la "$MNT" | head -40 || true

if [ "$FSTYPE" = "btrfs" ]; then
    # `btrfs check` alone is not enough: measured 2026-08-14 (tools/verify-btrfs.sh),
    # its csum pass is metadata-only and misses corrupt file *data*. Scrub reads
    # every block against the checksum tree, data included. `-r` keeps it
    # read-only (report, do not repair) — the same role `-n` plays for e2fsck
    # above.
    echo "--- btrfs scrub start -Bdr ---"
    SCRUB_OUT="$(btrfs scrub start -Bdr "$MNT" 2>&1)" || true
    echo "$SCRUB_OUT"
    # scrub's own exit code is NOT enough. Measured 2026-08-14 (tools/verify-btrfs.sh):
    # zeroing only the second DUP metadata mirror of a live tree block makes
    # scrub print "Error summary: verify=4 / Corrected: 4 / Uncorrectable: 0"
    # and **exit 0** — it self-healed from the surviving good mirror and calls
    # that success. Only a genuinely *uncorrectable* error returns nonzero. So,
    # exactly as verify-btrfs.sh does, grep scrub's own printed summary for the
    # literal "no errors found" line and fail explicitly on anything else,
    # regardless of scrub's exit code. Without this, a regression that quietly
    # stops writing the second DUP mirror — the single invariant the write
    # engine is built around — passes clean.
    if ! grep -q "Error summary:    no errors found" <<<"$SCRUB_OUT"; then
        echo "FAIL: scrub reported errors — see \"Error summary\" above. A" >&2
        echo "'Corrected' count is not success: it means a DUP mirror was wrong" >&2
        echo "and scrub silently repaired it from the other copy, which for this" >&2
        echo "project means the writer failed to write that mirror in the first" >&2
        echo "place. scrub's own exit code does not distinguish this from clean." >&2
        exit 1
    fi
fi
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

# Now stdin is free for the passphrase alone.
printf '%s' "$PASSWORD" | colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "$NAME"
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true

echo "VERDICT: clean — cryptsetup opened it, the checker passed, the kernel mounted it (and scrub found nothing, if btrfs)"
