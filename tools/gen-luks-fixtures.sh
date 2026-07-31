#!/bin/bash
# Generate LUKS header fixtures with real cryptsetup.
#
# Run inside Linux (see tools/README-fixtures.md). Emits header regions only —
# for LUKS2 that is exactly 2 * hdr_size, which stops short of the keyslots area
# at 32 KiB, so the fixtures contain no wrapped key material at all.
#
# The password is "test" and the KDF parameters are deliberately weak so the
# fixtures generate and verify fast. These are test vectors, not secrets.
set -euo pipefail

OUT="${1:-/tmp/luks-fixtures}"
PASS="test"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

# Deliberately insecure. Test data must be cheap to produce.
WEAK=(--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 32 --pbkdf-parallel 1)

# Extract 2 * hdr_size (both header copies) from a LUKS2 container.
extract_luks2() {
    local src="$1" dst="$2"
    local n
    n="$(python3 -c "
import sys,struct
with open('$src','rb') as f:
    f.seek(8); print(struct.unpack('>Q', f.read(8))[0] * 2)
")"
    dd if="$src" of="$dst" bs=1 count="$n" status=none
    echo "  -> $(basename "$dst")  ($n bytes)"
}

# cryptsetup refuses to dump a device smaller than the payload offset, so
# ground truth has to be captured from the full container before truncation.
record_dump() {
    local name="$1" img="$2"
    {
        echo "=== $name ==="
        cryptsetup luksDump "$img" 2>&1 |
            grep -viE "^\s+[0-9a-f]{2}( [0-9a-f]{2})+\s*$"
        echo
    } >> "$OUT/EXPECTED.txt"
}

make_luks2() {
    local name="$1"; shift
    local img="$WORK/$name.container"
    dd if=/dev/zero of="$img" bs=1M count=48 status=none
    printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$@" "$img" -
    record_dump "$name" "$img"
    extract_luks2 "$img" "$OUT/$name.img"
}

{
    echo "# Ground truth from real cryptsetup. Compared against our parser in"
    echo "# core/tests/luks2_real_fixtures.rs"
    echo "# $(cryptsetup --version)"
    echo "# password: test"
    echo
} > "$OUT/EXPECTED.txt"

echo "Generating LUKS2 fixtures..."

# Matches the shape of a Fedora install: aes-xts-plain64, 512-byte sectors.
make_luks2 luks2-argon2id-512 "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 512

# 4096-byte sectors change XTS tweak numbering.
make_luks2 luks2-argon2id-4096 "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --sector-size 4096

# argon2i rather than argon2id.
make_luks2 luks2-argon2i \
    --pbkdf argon2i --pbkdf-force-iterations 4 --pbkdf-memory 32 --pbkdf-parallel 1 \
    --type luks2 --cipher aes-xts-plain64 --key-size 512

# PBKDF2 instead of Argon2 — the memory-cheap path.
make_luks2 luks2-pbkdf2 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --type luks2 --cipher aes-xts-plain64 --key-size 512

# Non-default metadata size, to exercise backup-header probing.
make_luks2 luks2-metadata-64k "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --luks2-metadata-size 64k

# AES-256-CBC with ESSIV — an older cipher we must at least parse.
make_luks2 luks2-cbc-essiv "${WEAK[@]}" \
    --type luks2 --cipher aes-cbc-essiv:sha256 --key-size 256

# Two keyslots: peak KDF memory must be the max across slots, not the first.
NAME=luks2-two-keyslots
IMG="$WORK/$NAME.container"
dd if=/dev/zero of="$IMG" bs=1M count=48 status=none
printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "${WEAK[@]}" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 "$IMG" -
printf '%s' "$PASS" | cryptsetup luksAddKey --batch-mode \
    --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 64 --pbkdf-parallel 1 \
    --key-file=- "$IMG" <(printf '%s' "second") 2>/dev/null \
    || printf '%s\nsecond\nsecond\n' "$PASS" | cryptsetup luksAddKey --batch-mode \
        --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 64 --pbkdf-parallel 1 "$IMG"
record_dump "$NAME" "$IMG"
extract_luks2 "$IMG" "$OUT/$NAME.img"

echo "Generating LUKS1 fixture..."
# LUKS1 has a fixed 592-byte header; 4 KiB is ample for detection tests.
IMG="$WORK/luks1.container"
dd if=/dev/zero of="$IMG" bs=1M count=48 status=none
printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode --type luks1 \
    --pbkdf-force-iterations 1000 --cipher aes-xts-plain64 --key-size 512 "$IMG" -
record_dump "luks1" "$IMG"
dd if="$IMG" of="$OUT/luks1.img" bs=1024 count=4 status=none
echo "  -> luks1.img (4096 bytes)"


echo "Done. Fixtures in $OUT:"
ls -la "$OUT"
