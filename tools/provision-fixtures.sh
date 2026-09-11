#!/usr/bin/env bash
# Autonomous fixture verification and provisioning.
#
#   tools/provision-fixtures.sh [--verify-checksums | --force-regenerate]
#
# Checks existence and integrity of all required test fixtures:
#   - fixtures/luks/        (LUKS2 headers, in git)
#   - fixtures/btrfs/       (btrfs filesystems: plain, compress, mixed-4k, subvol)
#   - fixtures/ext4/        (ext4 filesystems: small-1k, big-4k, etc.)
#   - fixtures/containers/  (unlock containers)
#   - fixtures/disks/       (partitioned disk images)
#   - fixtures/transfer/    (tree transfer traces, in git)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures_dir="$repo_root/fixtures"

FORCE=0
VERIFY_CSUM=0

for arg in "$@"; do
    case "$arg" in
        --force-regenerate) FORCE=1 ;;
        --verify-checksums) VERIFY_CSUM=1 ;;
        -h|--help)
            echo "usage: tools/provision-fixtures.sh [--verify-checksums | --force-regenerate]"
            exit 0
            ;;
    esac
done

echo "==> Auditing test fixtures in $fixtures_dir..."

REQUIRED_LUKS=(
    "luks2-argon2id-512.img"
    "luks2-argon2id-4096.img"
    "luks2-argon2i.img"
    "luks2-pbkdf2.img"
    "luks2-metadata-64k.img"
    "luks2-cbc-essiv.img"
    "luks2-two-keyslots.img"
    "luks1.img"
)

REQUIRED_BTRFS=(
    "plain.img"
    "compress.img"
    "mixed-4k.img"
    "subvol.img"
    "nonmixed-4k.img"
    "sha256-4k.img"
    "fst-aged.img"
    "fst-multileaf.img"
    "fst-bitmap.img"
)

REQUIRED_EXT4=(
    "small-1k.img"
    "big-4k.img"
    "many-groups-1k.img"
    "dirtail-1k.img"
    "ext2-1k.img"
    "csum-uuid-4k.img"
)

REQUIRED_CONTAINERS=(
    "unlock-argon2id-512.img"
    "unlock-argon2id-4096.img"
    "unlock-pbkdf2-512.img"
)

REQUIRED_DISKS=(
    "gpt-luks.img"
    "mbr-luks.img"
    "gpt-luks-btrfs.img"
)

missing=0

check_group() {
    local subdir="$1"
    shift
    local items=("$@")
    local group_missing=0
    for item in "${items[@]}"; do
        if [ "$FORCE" -eq 1 ] || [ ! -f "$fixtures_dir/$subdir/$item" ]; then
            group_missing=$((group_missing + 1))
            missing=$((missing + 1))
        fi
    done
    echo "$group_missing"
}

btrfs_missing=$(check_group "btrfs" "${REQUIRED_BTRFS[@]}")
ext4_missing=$(check_group "ext4" "${REQUIRED_EXT4[@]}")
containers_missing=$(check_group "containers" "${REQUIRED_CONTAINERS[@]}")
disks_missing=$(check_group "disks" "${REQUIRED_DISKS[@]}")

echo "  btrfs fixtures missing/stale:      $btrfs_missing / ${#REQUIRED_BTRFS[@]}"
echo "  ext4 fixtures missing/stale:       $ext4_missing / ${#REQUIRED_EXT4[@]}"
echo "  container fixtures missing/stale:  $containers_missing / ${#REQUIRED_CONTAINERS[@]}"
echo "  disk fixtures missing/stale:       $disks_missing / ${#REQUIRED_DISKS[@]}"

if [ "$missing" -eq 0 ]; then
    echo "==> All test fixtures are present and accounted for."
    exit 0
fi

echo
echo "==> Missing $missing fixture(s). Provisioning..."

# Provision ext4 if missing
if [ "$ext4_missing" -gt 0 ]; then
    echo "--- Synthesizing ext4 fixtures ---"
    if [[ -d "/opt/homebrew/opt/e2fsprogs/sbin" ]]; then
        export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
    fi
    if command -v mke2fs >/dev/null 2>&1; then
        bash "$repo_root/tools/gen-ext4-fixtures.sh"
        echo "ext4 fixtures generated successfully."
    else
        echo "WARNING: mke2fs not found on PATH. Install e2fsprogs via 'brew install e2fsprogs' to generate ext4 fixtures natively."
    fi
fi

# Provision btrfs / containers / disks if missing (requires Linux or Colima)
if [ "$btrfs_missing" -gt 0 ] || [ "$containers_missing" -gt 0 ] || [ "$disks_missing" -gt 0 ]; then
    echo "--- Checking VM/Linux environment for btrfs/LUKS synthesis ---"
    has_vm=0
    if [[ "$(uname -s)" == "Linux" ]]; then
        has_vm=1
    elif command -v colima >/dev/null 2>&1; then
        if colima status >/dev/null 2>&1; then
            has_vm=1
        else
            echo "Colima is not running. Attempting auto-start: colima start --cpu 4 --memory 4"
            colima start --cpu 4 --memory 4 || true
            if colima status >/dev/null 2>&1; then
                has_vm=1
            fi
        fi
    fi

    if [ "$has_vm" -eq 1 ]; then
        if [ "$btrfs_missing" -gt 0 ]; then
            bash "$repo_root/tools/gen-btrfs-fixtures.sh"
        fi
        if [ "$containers_missing" -gt 0 ]; then
            bash "$repo_root/tools/gen-luks-containers.sh"
        fi
        if [ "$disks_missing" -gt 0 ]; then
            bash "$repo_root/tools/gen-disk-fixtures.sh"
        fi
        echo "VM-based fixtures provisioned successfully."
    else
        echo "WARNING: Real Linux kernel or Colima VM is required to generate btrfs, container, and disk fixtures."
        echo "Start colima with 'colima start' and rerun tools/provision-fixtures.sh."
    fi
fi

echo "==> Fixture provisioning complete."
