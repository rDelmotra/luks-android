#!/bin/bash
# Grade a bare ext4 image with the kernel's own checker.
#
#   tools/verify-ext4.sh <image>
#
# The sibling of verify-image.sh, for images that are not inside a LUKS
# container — the ext4 fixtures the allocator is developed against. Same rule:
# **never check our output with our own code.** A writer and a reader that share
# a misunderstanding agree with each other perfectly and corrupt real drives.
#
# `-f` forces a full check even when the superblock claims to be clean, and `-n`
# answers no to every repair prompt, so damage is reported rather than quietly
# fixed. A harness that repairs turns every bug into a passing test.
#
# Exit status is the verdict: 0 clean, non-zero and the reason is on stderr.
set -euo pipefail

IMG="${1:?usage: verify-ext4.sh <image>}"

[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
command -v colima >/dev/null || { echo "colima not installed" >&2; exit 2; }
colima status >/dev/null 2>&1 || { echo "colima is not running — 'colima start'" >&2; exit 2; }

REMOTE="/tmp/verify-ext4-$$.img"
colima ssh -- tee "$REMOTE" < "$IMG" > /dev/null
trap 'colima ssh -- rm -f "$REMOTE" 2>/dev/null || true' EXIT

colima ssh -- sudo e2fsck -fn "$REMOTE"
echo "VERDICT: clean — e2fsck found nothing to fix"
