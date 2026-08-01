#!/bin/bash
# Generate ext4 test images. Runs natively on macOS — no VM, no root, no mount.
#
# mke2fs builds the filesystem and debugfs populates it by writing directly into
# the image. Both come from Homebrew's keg-only e2fsprogs.
#
# debugfs splits its arguments on whitespace, so source paths must not contain
# spaces. Destination names may contain UTF-8.
set -euo pipefail

OUT="${1:-fixtures/ext4}"
export PATH="/opt/homebrew/opt/e2fsprogs/sbin:/opt/homebrew/opt/e2fsprogs/bin:$PATH"

command -v mke2fs >/dev/null || { echo "mke2fs not found: brew install e2fsprogs"; exit 1; }

mkdir -p "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Deterministic content the test regenerates and compares against.
python3 - "$STAGE" <<'PY'
import sys, pathlib
stage = pathlib.Path(sys.argv[1])
(stage / "hello.txt").write_bytes(b"hello ext4\n")
(stage / "readme.md").write_bytes(b"# readme\n\nnested content\n")
(stage / "deep.txt").write_bytes(b"three levels down\n")
(stage / "unicode.txt").write_bytes("café naïve 日本語\n".encode())
# 2 MiB pattern: large enough to need several extents, or indirect blocks
# with a 1 KiB block size (>12 direct + single indirect).
(stage / "big.bin").write_bytes(bytes((i * 31 + 7) % 256 for i in range(2 * 1024 * 1024)))
PY

build() {
    local name="$1" size_mb="$2" block_size="$3" fstype="${4:-ext4}" extra="${5:-}"
    local img="$OUT/$name.img"

    dd if=/dev/zero of="$img" bs=1m count="$size_mb" 2>/dev/null
    # shellcheck disable=SC2086
    mke2fs -q -t "$fstype" -b "$block_size" -L EXT4TEST \
        -U 33333333-4444-5555-6666-777777777777 $extra "$img"

    debugfs -w -f /dev/stdin "$img" >/dev/null 2>&1 <<EOF
mkdir /docs
mkdir /docs/nested
cd /
write $STAGE/hello.txt hello.txt
write $STAGE/big.bin big.bin
write $STAGE/unicode.txt café-naïve-日本語.txt
cd /docs
write $STAGE/readme.md readme.md
cd /docs/nested
write $STAGE/deep.txt deep.txt
cd /
symlink /link-to-hello hello.txt
symlink /docs/link-to-deep nested/deep.txt
quit
EOF
    echo "  -> $name.img (${size_mb} MiB, ${block_size}-byte blocks)"
}

echo "Generating ext4 fixtures..."
# 1 KiB blocks force the legacy indirect path for big.bin on ext2-style images
# and exercise small-block extent trees here.
build small-1k 12 1024
build big-4k 24 4096
# ext2: no extents, no journal — pure indirect block mapping.
build ext2-1k 12 1024 ext2 "-O ^has_journal"

echo "Done:"
ls -la "$OUT"
