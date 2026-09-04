#!/bin/bash
# Print NON-SECRET LUKS2 parameters from a partition.
#
# SAFETY PROPERTIES:
#   * Reads ONLY the first 16 KiB (the metadata region).
#     The wrapped master key lives at offset >= 32 KiB and is NEVER read.
#   * Opens the device read-only (dd with if= only; there is no of= to the device).
#   * Redacts all salts and digests before printing.
#   * Writes its temp file to a private dir and shreds it on exit.
#
# Usage:  ./tools/luks-params.sh /dev/diskNsM
set -euo pipefail

DEV="${1:?usage: luks-params.sh /dev/diskNsM}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
chmod 700 "$TMP"

# 16 KiB = binary header (4K) + JSON metadata (12K). Key material starts at 32 KiB.
dd if="$DEV" of="$TMP/meta.bin" bs=4096 count=4 2>/dev/null

python3 - "$TMP/meta.bin" <<'PY'
import json, sys

raw = open(sys.argv[1], 'rb').read()

if raw[0:6] != b'LUKS\xba\xbe':
    print("Not a LUKS partition (magic mismatch).")
    sys.exit(1)

version = int.from_bytes(raw[6:8], 'big')
print(f"LUKS version      : {version}")

if version != 2:
    print("LUKS1 detected - JSON metadata not present. Stopping.")
    sys.exit(0)

# JSON metadata area begins at 4096, NUL-padded to the end of the region.
blob = raw[4096:].split(b'\x00', 1)[0]
meta = json.loads(blob)

SECRET = {'salt', 'digest', 'af', 'encrypted_key', 'key'}

seg = next(iter(meta.get('segments', {}).values()), {})
print(f"Cipher            : {seg.get('encryption')}")
print(f"Sector size       : {seg.get('sector_size')}   <-- 4096 changes XTS tweak numbering")
print(f"Payload offset    : {seg.get('offset')} bytes")
print(f"Segment size      : {seg.get('size')}")

for slot_id, slot in sorted(meta.get('keyslots', {}).items()):
    kdf = slot.get('kdf', {})
    area = slot.get('area', {})
    print(f"\nKeyslot {slot_id}")
    print(f"  KDF             : {kdf.get('type')}")
    if kdf.get('type', '').startswith('argon2'):
        mem = kdf.get('memory', 0)
        print(f"  Argon2 memory   : {mem} KiB  ({mem/1048576:.2f} GiB)   <-- THE RISK")
        print(f"  Argon2 time     : {kdf.get('time')}")
        print(f"  Argon2 threads  : {kdf.get('cpus')}")
    else:
        print(f"  PBKDF2 iters    : {kdf.get('iterations')}")
        print(f"  Hash            : {kdf.get('hash')}")
    print(f"  Slot key bits   : {slot.get('key_size', 0) * 8}")
    print(f"  Area encryption : {area.get('encryption')}")
    print(f"  Salt            : [REDACTED]")

print("\n(Salts and digests withheld. Key material at offset >=32 KiB was never read.)")
PY
