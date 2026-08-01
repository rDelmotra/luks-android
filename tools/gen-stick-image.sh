#!/bin/bash
# Build the LUKS+ext4 image that goes onto the physical test USB stick.
#
# Different in purpose from gen-disk-fixtures.sh. Those fixtures use deliberately
# weak KDF parameters so `cargo test` stays fast. This one uses the REAL
# parameters of the developer's 1 TB Fedora drive, so unlocking the stick on the
# phone exercises the 1 GiB Argon2 allocation — the project's top open risk —
# without ever touching the real drive.
#
# Two keyslots, which also gives real-hardware coverage of the keyslot loop:
#
#   slot 0   password "test"   argon2id 1 GiB, t=4, p=4    <- realistic, slow
#   slot 1   password "fast"   argon2id 32 MiB, t=4, p=1   <- for quick iteration
#
# Both passwords are throwaway. The stick is a dummy holding generated data.
#
# Needs Linux with loop devices and device-mapper. Run inside the colima VM as
# root, from a file, with stdin redirected from /dev/null — see the VM gotchas
# in STATE.md.
set -euo pipefail

OUT="${1:-$HOME/luks-stick-build}"
IMG="$OUT/stick-luks.img"

SIZE_MIB=2048       # must be <= the target partition
BIGFILE_MIB=1024    # incompressible payload, for throughput + integrity checks
HEADER_MIB=16       # payload offset, matching the real drive

# Real-drive parameters (STATE.md "Hard facts about the target drive").
REAL=(--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 1048576 --pbkdf-parallel 4)
FAST=(--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 32768 --pbkdf-parallel 1)

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

mkdir -p "$OUT"
WORK="$(mktemp -d)"
cleanup() {
    umount "$WORK/mnt" 2>/dev/null || true
    cryptsetup close stickfix 2>/dev/null || true
    for l in $(losetup -j "$IMG" -O NAME --noheadings 2>/dev/null); do
        losetup -d "$l" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

# Passphrases go in files, never on stdin. Piping into `cryptsetup --key-file=-`
# while the script itself arrived on stdin deadlocks in do_semtimedop.
printf 'test' > "$WORK/pass0"
printf 'fast' > "$WORK/pass1"

echo "==> Allocating ${SIZE_MIB} MiB image"
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count="$SIZE_MIB" status=none

LOOP="$(losetup -f --show "$IMG")"
echo "    loop: $LOOP"

echo "==> luksFormat with REAL parameters (1 GiB argon2id — this takes a few seconds)"
cryptsetup luksFormat --batch-mode --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 --sector-size 512 \
    --offset $((HEADER_MIB * 1024 * 1024 / 512)) \
    "${REAL[@]}" \
    --key-file "$WORK/pass0" \
    "$LOOP"

echo "==> Adding fast keyslot 1"
cryptsetup luksAddKey --batch-mode \
    --key-file "$WORK/pass0" \
    "${FAST[@]}" \
    "$LOOP" "$WORK/pass1"

echo "==> Opening"
cryptsetup open --batch-mode --key-file "$WORK/pass0" "$LOOP" stickfix

echo "==> mkfs.ext4"
mkfs.ext4 -q -L STICKDATA -U 11111111-2222-3333-4444-555555555555 /dev/mapper/stickfix

mkdir -p "$WORK/mnt"
mount /dev/mapper/stickfix "$WORK/mnt"

echo "==> Populating (${BIGFILE_MIB} MiB of urandom)"
printf 'usb stick stack works\n'  > "$WORK/mnt/proof.txt"
mkdir -p "$WORK/mnt/dir"
printf 'inside a directory\n'     > "$WORK/mnt/dir/inner.txt"
dd if=/dev/urandom of="$WORK/mnt/bigfile.bin" bs=1M count="$BIGFILE_MIB" status=none

BIG_SHA="$(sha256sum "$WORK/mnt/bigfile.bin" | cut -d' ' -f1)"
sync
df -h "$WORK/mnt" | tail -1
umount "$WORK/mnt"
cryptsetup close stickfix
losetup -d "$LOOP"

# Ground truth, so the reader can be checked against something it did not produce.
cat > "$OUT/STICK-MANIFEST.txt" << EOF
stick-luks.img
  size            ${SIZE_MIB} MiB
  payload offset  ${HEADER_MIB} MiB
  cipher          aes-xts-plain64, key-size 512, sector-size 512
  slot 0          password "test"   argon2id m=1048576 KiB t=4 p=4   (real-drive params)
  slot 1          password "fast"   argon2id m=32768 KiB  t=4 p=1
  filesystem      ext4, label STICKDATA
  uuid            11111111-2222-3333-4444-555555555555

files
  /proof.txt        "usb stick stack works\\n"
  /dir/inner.txt    "inside a directory\\n"
  /bigfile.bin      ${BIGFILE_MIB} MiB urandom
  sha256(bigfile)   ${BIG_SHA}
EOF

echo
echo "==> Done"
cat "$OUT/STICK-MANIFEST.txt"
ls -la "$OUT"
