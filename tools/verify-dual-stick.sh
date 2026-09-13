#!/bin/bash
# verify-dual-stick.sh: Verify both LUKS2 ext4 and Plain ext4 partitions on /dev/disk4
# using real Linux kernel tooling (cryptsetup, e2fsck, debugfs) inside Colima.
set -euo pipefail

DEV_S1="${1:-/dev/rdisk4s1}"
DEV_S2="${2:-/dev/rdisk4s2}"
PASSWORD="${3:-test}"

echo "=== Dual Partition Kernel Verification ==="
echo "LUKS partition:  $DEV_S1"
echo "Plain partition: $DEV_S2"

# 1. Check readability of device nodes on macOS
for d in "$DEV_S1" "$DEV_S2"; do
    if [ ! -r "$d" ]; then
        echo "ERROR: Cannot read $d (Permission denied)."
        echo "Please run on macOS host: sudo chmod 644 /dev/disk4* /dev/rdisk4*"
        exit 2
    fi
done

# 2. Check Colima status
colima status >/dev/null 2>&1 || { echo "ERROR: Colima is not running. Start with 'colima start'" >&2; exit 2; }

# Unmount disk on macOS to avoid OS cache races
echo "Unmounting /dev/disk4 on macOS..."
diskutil unmountDisk /dev/disk4 >/dev/null 2>&1 || true

PID=$$

echo ""
echo "========================================================"
echo ">>> [STAGE 1/2] VERIFYING PARTITION 1: LUKS2 ext4 <<<"
echo "========================================================"
echo "Streaming $DEV_S1 into Colima VM..."
dd if="$DEV_S1" bs=4m status=progress | colima ssh -- sudo tee "/tmp/p1_${PID}.img" >/dev/null

REMOTE_S1="/tmp/verify_s1_${PID}.sh"
colima ssh -- sudo tee "$REMOTE_S1" >/dev/null <<'EOF'
#!/bin/bash
set -uo pipefail
PID="$1"
PART1="/tmp/p1_${PID}.img"
MAPPER="luks_verify_${PID}"
MNT_LUKS="/tmp/mnt_luks_${PID}"

cleanup() {
    umount "$MNT_LUKS" 2>/dev/null || true
    cryptsetup close "$MAPPER" 2>/dev/null || true
    rm -rf "$MNT_LUKS" "$PART1"
}
trap cleanup EXIT

echo "1. Checking LUKS container header..."
cryptsetup isLuks "$PART1" && echo "Verified: Valid LUKS header found."

echo "2. Opening LUKS container with cryptsetup..."
cryptsetup open --key-file=- --type luks "$PART1" "$MAPPER"

echo "3. Running e2fsck -fn (Linux kernel ext4 oracle)..."
e2fsck -fn "/dev/mapper/$MAPPER"
E2FSCK_RET=$?
echo ">>> e2fsck exit status: $E2FSCK_RET"

echo "3b. Investigating inode 37 and block allocations via debugfs..."
debugfs -R "stat <37>" "/dev/mapper/$MAPPER" 2>&1 || true
debugfs -R "ncheck 37" "/dev/mapper/$MAPPER" 2>&1 || true
debugfs -R "icheck 122959" "/dev/mapper/$MAPPER" 2>&1 || true

echo "4. Mounting read-only with Linux kernel..."
mkdir -p "$MNT_LUKS"
mount -o ro "/dev/mapper/$MAPPER" "$MNT_LUKS"

echo "5. Inspecting filesystem tree and timestamps:"
ls -la "$MNT_LUKS"
echo "--- Recursive file tree ---"
find "$MNT_LUKS" -mindepth 1 -ls

echo "--- Partition 1 Inspection Complete! ---"
EOF
colima ssh -- sudo chmod +x "$REMOTE_S1"

printf '%s' "$PASSWORD" | colima ssh -- sudo "$REMOTE_S1" "$PID"
colima ssh -- sudo rm -f "$REMOTE_S1" 2>/dev/null || true

echo ""
echo "========================================================"
echo ">>> [STAGE 2/2] VERIFYING PARTITION 2: Plain ext4 <<<"
echo "========================================================"
echo "Streaming $DEV_S2 into Colima VM..."
dd if="$DEV_S2" bs=4m status=progress | colima ssh -- sudo tee "/tmp/p2_${PID}.img" >/dev/null

REMOTE_S2="/tmp/verify_s2_${PID}.sh"
colima ssh -- sudo tee "$REMOTE_S2" >/dev/null <<'EOF'
#!/bin/bash
set -uo pipefail
PID="$1"
PART2="/tmp/p2_${PID}.img"
MNT_PLAIN="/tmp/mnt_plain_${PID}"

cleanup() {
    umount "$MNT_PLAIN" 2>/dev/null || true
    rm -rf "$MNT_PLAIN" "$PART2"
}
trap cleanup EXIT

echo "1. Running e2fsck -fn on plain ext4 partition..."
e2fsck -fn "$PART2"
E2FSCK_S2_RET=$?
echo ">>> e2fsck exit status: $E2FSCK_S2_RET"

echo "2. Mounting read-only with Linux kernel..."
mkdir -p "$MNT_PLAIN"
mount -o ro "$PART2" "$MNT_PLAIN"

echo "3. Inspecting filesystem tree and timestamps:"
ls -la "$MNT_PLAIN"
echo "--- Recursive file tree ---"
find "$MNT_PLAIN" -mindepth 1 -ls

echo "--- Partition 2 Inspection Complete! ---"
EOF
colima ssh -- sudo chmod +x "$REMOTE_S2"

colima ssh -- sudo "$REMOTE_S2" "$PID"
colima ssh -- sudo rm -f "$REMOTE_S2" 2>/dev/null || true

echo ""
echo "========================================================"
echo ">>> VERDICT COMPLETE <<<"
echo "========================================================"
