#!/bin/bash
# Grade a bare btrfs image with the kernel's own tools.
#
#   tools/verify-btrfs.sh <image>
#
# The btrfs sibling of verify-ext4.sh, for images that are not inside a LUKS
# container — the btrfs fixtures the write engine is developed against. Same
# rule as every other verify script here: **never check our output with our
# own code.** A writer and a reader that share a misunderstanding of the
# on-disk format agree with each other perfectly and corrupt real drives.
#
# Three checks, in order, because each catches something the one before it
# does not:
#
#   1. `btrfs check --readonly` — structural: root items, extents, the free
#      space tree, fs roots, root refs. Measured directly (2026-08-14): its
#      csum pass is metadata-only ("checking only csums items (without
#      verifying data)" is its own stated scope) — a file's data can be
#      corrupted and this reports "no error found" regardless.
#   2. A real, read-only kernel mount — necessary but not sufficient on its
#      own: a filesystem can be structurally valid and still refuse to mount.
#   3. `btrfs scrub start -Bdr` — reads every block and checks it against the
#      checksum tree, including file *data*, which check does not. `-r`
#      keeps it read-only (report, do not repair) — the same role `-n` plays
#      for e2fsck elsewhere in this repo. This is the step that catches what
#      check misses, and it is why this script has three steps, not one.
#
# The corruption case above is not a hypothetical: flipping 4 bytes inside a
# file's data extent on a real fixture (fixtures/btrfs/plain.img) and running
# this exact sequence produced `btrfs check --readonly` exit 0 / "no error
# found", then `btrfs scrub start -Bdr` exit 3 / "Uncorrectable: 1" — measured
# 2026-08-14, not assumed. That is this script's control: a check that cannot
# fail on a known-bad input is not a check.
#
# NOTE: scrub's own exit code is NOT enough. Measured 2026-08-14: zeroing only
# the second DUP metadata mirror of a live tree block (exactly the failure
# mode §2 of feature-btrfs-write.md exists to catch) makes `btrfs scrub start
# -Bdr` print "Error summary: verify=4 / Corrected: 4 / Uncorrectable: 0" and
# **exit 0** — scrub self-heals from the surviving good mirror and calls that
# success. Only a genuinely *uncorrectable* error (no good mirror anywhere)
# returns nonzero. So this script greps scrub's own printed summary for the
# literal "no errors found" line and fails explicitly if it's anything else,
# regardless of scrub's exit code. Without this, a regression that silently
# stops writing the second DUP mirror — the single invariant this whole
# write engine is built around — passes clean.
#
# Runs in the colima VM because macOS has neither btrfs-progs nor a btrfs
# kernel module. Start it with `colima start` if it is not up.
#
# Exit status is the verdict: 0 clean, non-zero and the reason is on stderr.
set -euo pipefail

IMG="${1:?usage: verify-btrfs.sh <image>}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

NAME="verify-btrfs-$$"
REMOTE="/tmp/$NAME.img"
REMOTE_SH="/tmp/$NAME.sh"
LOCAL_SH="$(mktemp)"
trap 'rm -f "$LOCAL_SH"' EXIT

# Copied as a file and run, not piped into `sudo bash -s` — the same
# stdin-collision gotcha documented in verify-image.sh. Nothing here reads a
# passphrase, but the pattern is kept identical on purpose: one convention
# for "how a remote check script gets to the VM" across this whole toolset.
cat > "$LOCAL_SH" <<'REMOTE_SCRIPT'
set -euo pipefail
IMG="$1"
MNT="$2"

cleanup() {
    umount "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
    rm -f "$IMG"
}
trap cleanup EXIT

echo "--- btrfs check --readonly ---"
btrfs check --readonly "$IMG"

# btrfs check operates directly on the image file; mounting needs a block
# device, which -o loop sets up implicitly.
mkdir -p "$MNT"
mount -o ro,loop "$IMG" "$MNT"
echo "--- mounted read-only, root contains ---"
# `|| true`: under `set -o pipefail`, a directory with more than the
# `head -40` cutoff makes `ls` catch SIGPIPE and this pipeline "fail" before
# scrub ever runs — measured 2026-08-14 on a 400-entry directory, which
# aborted the whole script at exit 141 with the filesystem itself completely
# clean. This is a display line, not a check; it must never gate the verdict.
ls -la "$MNT" | head -40 || true

echo "--- btrfs scrub start -Bdr ---"
SCRUB_OUT="$(btrfs scrub start -Bdr "$MNT" 2>&1)" || true
echo "$SCRUB_OUT"
if ! grep -q "Error summary:    no errors found" <<<"$SCRUB_OUT"; then
    echo "FAIL: scrub reported errors — see \"Error summary\" above. A" >&2
    echo "'Corrected' count is not success: it means a DUP mirror was wrong" >&2
    echo "and scrub silently repaired it from the other copy, which for this" >&2
    echo "project means the writer failed to write that mirror in the first" >&2
    echo "place. scrub's own exit code does not distinguish this from clean." >&2
    exit 1
fi
REMOTE_SCRIPT

colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
colima ssh -- tee "$REMOTE_SH" < "$LOCAL_SH" > /dev/null

colima ssh -- sudo bash "$REMOTE_SH" "$REMOTE" "/tmp/mnt-$NAME"
colima ssh -- rm -f "$REMOTE_SH" 2>/dev/null || true

echo "VERDICT: clean — check passed, the kernel mounted it, scrub found nothing"
