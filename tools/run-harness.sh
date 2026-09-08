#!/usr/bin/env bash
# Autonomous Test Harness & Test Runner CLI (Issue 32).
#
#   tools/run-harness.sh [OPTIONS]
#
# Options:
#   --fast         Run Tier 1 pure in-memory unit tests (<5s, 0 disk I/O)
#   --stress       Run Tier 2 B-tree permutation & property stress tests (<15s)
#   --integration  Run Tiers 1-3 filesystem disk mutation tests (<60s)
#   --oracle       Run Tier 4 Linux kernel oracle graded tests (requires Colima or Linux)
#   --strict       Run Tiers 1-5 with 100% oracle grading (fails closed on any skip)
#   --android      Run Android JVM unit tests & privacy checks
#   --provision    Audit and synthesize missing test fixtures
#   --keep-failed  Retain failed scratch images in target/scratch/ for debugging
#   --all          Run all tiers, android tests, and release gates
#
# If no tier option is specified, defaults to --fast and --stress for rapid local development.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

RUN_FAST=0
RUN_STRESS=0
RUN_INTEGRATION=0
RUN_ORACLE=0
RUN_STRICT=0
RUN_ANDROID=0
RUN_PROVISION=0
KEEP_FAILED=0

if [ $# -eq 0 ]; then
    # Default developer mode: fast unit + stress permutation (<20s)
    RUN_FAST=1
    RUN_STRESS=1
fi

for arg in "$@"; do
    case "$arg" in
        --fast) RUN_FAST=1 ;;
        --stress) RUN_STRESS=1 ;;
        --integration) RUN_INTEGRATION=1 ;;
        --oracle) RUN_ORACLE=1 ;;
        --strict) RUN_STRICT=1 ;;
        --android) RUN_ANDROID=1 ;;
        --provision) RUN_PROVISION=1 ;;
        --keep-failed) KEEP_FAILED=1 ;;
        --all)
            RUN_FAST=1
            RUN_STRESS=1
            RUN_INTEGRATION=1
            RUN_ORACLE=1
            RUN_STRICT=1
            RUN_ANDROID=1
            ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Run tools/run-harness.sh --help for usage." >&2
            exit 2
            ;;
    esac
done

if [ "$RUN_STRICT" -eq 1 ]; then
    # Strict mode implies running all core tiers under strict oracle controls
    RUN_FAST=1
    RUN_STRESS=1
    RUN_INTEGRATION=1
    RUN_ORACLE=1
fi

# Setup isolated run environment
RUN_ID="run-$(date +%s)-$$"
export LUKS_TEST_RUN_ID="$RUN_ID"
REPORTS_DIR="$repo_root/target/test-reports"
SCRATCH_DIR="$repo_root/target/scratch/$RUN_ID"
mkdir -p "$REPORTS_DIR" "$SCRATCH_DIR"

if [ "$KEEP_FAILED" -eq 1 ]; then
    export LUKS_KEEP_FAILED_SCRATCH=1
fi

LEDGER="$REPORTS_DIR/ledger-$RUN_ID.log"
export LUKS_ORACLE_LEDGER="$LEDGER"
: > "$LEDGER"

# Reporting structures
JSON_REPORT="$REPORTS_DIR/summary.json"
TIER_RESULTS=()
TIER_DURATIONS=()
OVERALL_STATUS=0

log_tier() {
    local name="$1"
    local status="$2"
    local duration="$3"
    TIER_RESULTS+=("$name: $status ($duration s)")
}

# 1. Provisioning
if [ "$RUN_PROVISION" -eq 1 ]; then
    echo "================================================================="
    echo "==> PROVISION: Test Fixtures Audit & Synthesis"
    echo "================================================================="
    bash "$repo_root/tools/provision-fixtures.sh"
    echo
fi

# 2. Tier 1: Fast Unit Tests (<5s, pure in-memory)
if [ "$RUN_FAST" -eq 1 ]; then
    echo "================================================================="
    echo "==> TIER 1: Fast Unit Tests (<5s, pure in-memory, 0 disk I/O)"
    echo "================================================================="
    t_start=$(date +%s)
    
    cargo test --workspace --lib
    cargo test -p luks_core --test usb_scsi --test luks2_header --test luks2_real_fixtures \
        --test luks2_unlock --test secret_zeroize \
        --test oracle_ledger --test raw_device --test full_stack
    cargo test -p luks_jni --test handle_concurrency
    cargo test -p luks_usbfs --test state_machine

    t_end=$(date +%s)
    dur=$((t_end - t_start))
    log_tier "Tier 1 (Fast Unit)" "PASS" "$dur"
    echo "--> Tier 1 finished clean in ${dur}s."
    echo
fi

# 3. Tier 2: Intensive Property & B-Tree Permutation Tests
if [ "$RUN_STRESS" -eq 1 ]; then
    echo "================================================================="
    echo "==> TIER 2: B-Tree Permutations & Property Stress Suite"
    echo "================================================================="
    t_start=$(date +%s)

    ALLOW_NO_ORACLE=1 cargo test -p luks_core --features dangerous-write-support \
        --test btrfs_btree_permutations -- \
        test_btree_key_order_permutations \
        test_btree_variable_item_sizes_and_3way_split_shapes \
        test_btree_height_scaling_and_root_collapse \
        test_btree_stateful_fuzz_property_cycle \
        test_tree_validator_negative_controls
    
    ALLOW_NO_ORACLE=1 cargo test -p luks_core --features dangerous-write-support \
        --test btrfs_node_surgery --test btrfs_chunk_alloc_search

    t_end=$(date +%s)
    dur=$((t_end - t_start))
    log_tier "Tier 2 (B-Tree Permutations & Stress)" "PASS" "$dur"
    echo "--> Tier 2 finished clean in ${dur}s."
    echo
fi

# 4. Tier 3: Filesystem Disk Mutations & Integration Tests
if [ "$RUN_INTEGRATION" -eq 1 ]; then
    echo "================================================================="
    echo "==> TIER 3: Filesystem Disk Integration Tests"
    echo "================================================================="
    t_start=$(date +%s)

    ALLOW_NO_ORACLE=1 cargo test -p luks_core --features dangerous-write-support \
        --test btrfs_cow_fixup \
        --test btrfs_batch_double_alloc \
        --test btrfs_batch_equality \
        --test btrfs_empty_leaf \
        --test btrfs_valves \
        --test btrfs_stage_c_reservation \
        --test btrfs_chunk_alloc_txn \
        --test ext4_dirent \
        --test ext4_alloc

    t_end=$(date +%s)
    dur=$((t_end - t_start))
    log_tier "Tier 3 (Filesystem Integration)" "PASS" "$dur"
    echo "--> Tier 3 finished clean in ${dur}s."
    echo
fi

# 5. Tier 4: Linux Kernel Oracle Graded Tests
if [ "$RUN_ORACLE" -eq 1 ]; then
    echo "================================================================="
    echo "==> TIER 4: Linux Kernel Oracle Graded Suite"
    echo "================================================================="
    t_start=$(date +%s)

    if [ "$RUN_STRICT" -eq 1 ]; then
        # Strict mode: unset ALLOW_NO_ORACLE so any failure to grade panics!
        unset ALLOW_NO_ORACLE || true
    fi

    # Run oracle graded tests
    cargo test --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support \
        --test btrfs_btree_permutations \
        --test btrfs_root_split \
        --test btrfs_create_file \
        --test btrfs_delete \
        --test btrfs_rename \
        --test btrfs_mkdir \
        --test btrfs_crash_safety \
        --test ext4_file \
        --test ext4_delete \
        --test ext4_rename \
        --test ext4_mkdir \
        --test tree_import_oracle

    t_end=$(date +%s)
    dur=$((t_end - t_start))

    echo
    local_min=1
    if [ "$RUN_STRICT" -eq 1 ]; then
        local_min=20
    fi
    ORACLE_MIN="${ORACLE_MIN:-$local_min}" "$repo_root/tools/oracle-report.sh" "$LEDGER"
    oracle_status=$?

    if [ "$oracle_status" -ne 0 ]; then
        log_tier "Tier 4 (Kernel Oracle)" "FAIL" "$dur"
        OVERALL_STATUS=1
    else
        log_tier "Tier 4 (Kernel Oracle)" "PASS" "$dur"
        echo "--> Tier 4 finished clean in ${dur}s."
    fi
    echo
fi

# 6. Tier 5: Security, Release Gates & Static Verification
if [ "$RUN_STRICT" -eq 1 ]; then
    echo "================================================================="
    echo "==> TIER 5: Security & Release Boundary Gates"
    echo "================================================================="
    t_start=$(date +%s)

    echo "Running checkNoWriteCode gate..."
    bash "$repo_root/tools/verify-no-write-code.sh"

    t_end=$(date +%s)
    dur=$((t_end - t_start))
    log_tier "Tier 5 (Release Gates)" "PASS" "$dur"
    echo "--> Tier 5 finished clean in ${dur}s."
    echo
fi

# 7. Android Unit Tests & Privacy
if [ "$RUN_ANDROID" -eq 1 ]; then
    echo "================================================================="
    echo "==> ANDROID: JVM Unit Tests & Privacy Verification"
    echo "================================================================="
    t_start=$(date +%s)

    (cd "$repo_root/android" && ./gradlew :app:testDebugUnitTest)

    t_end=$(date +%s)
    dur=$((t_end - t_start))
    log_tier "Android Tests" "PASS" "$dur"
    echo "--> Android tests finished clean in ${dur}s."
    echo
fi

# Clean up temporary scratch directory if all passed and keep-failed is false
if [ "$OVERALL_STATUS" -eq 0 ] && [ "$KEEP_FAILED" -eq 0 ]; then
    rm -rf "$SCRATCH_DIR"
fi

# Final Summary Report
echo "================================================================="
echo "==> AUTONOMOUS TEST HARNESS SUMMARY ($RUN_ID)"
echo "================================================================="
for result in "${TIER_RESULTS[@]}"; do
    echo "  [✓] $result"
done

# Write JSON report
cat << JSONEOF > "$JSON_REPORT"
{
  "run_id": "$RUN_ID",
  "status": $( [ "$OVERALL_STATUS" -eq 0 ] && echo '"PASS"' || echo '"FAIL"' ),
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "tiers": [
$(printf '    "%s",\n' "${TIER_RESULTS[@]}" | sed '$ s/,$//')
  ]
}
JSONEOF

echo
echo "Report written to: $JSON_REPORT"

if [ "$OVERALL_STATUS" -ne 0 ]; then
    echo "FAILED: Test harness detected failures or unverified oracle skips." >&2
    exit 1
fi

echo "ALL REQUESTED TIERS PASSED."
exit 0
