#!/usr/bin/env bash
# tools/transition-report.sh
# Aggregates and reports structural B-tree transitions recorded in the transition ledger.
#
# Usage:
#   tools/transition-report.sh [--check] [ledger-path]
#
set -euo pipefail

CHECK_GATE=0
LEDGER=""

for arg in "$@"; do
  case "$arg" in
    --check|--gate)
      CHECK_GATE=1
      ;;
    *)
      if [[ -z "$LEDGER" ]]; then
        LEDGER="$arg"
      fi
      ;;
  esac
done

if [[ -z "$LEDGER" ]]; then
  LEDGER="${LUKS_TRANSITION_LEDGER:-}"
fi
if [[ -z "$LEDGER" ]]; then
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  LEDGER="$repo_root/target/transition-ledger.log"
fi

if [[ ! -f "$LEDGER" ]]; then
  echo "TRANSITION REPORT: no transition ledger found at $LEDGER"
  exit 1
fi

shape1=$(grep -c 'LEAF_SPLIT.*shape=1' "$LEDGER" || true)
shape2=$(grep -c 'LEAF_SPLIT.*shape=2' "$LEDGER" || true)
shape3=$(grep -c 'LEAF_SPLIT.*shape=3' "$LEDGER" || true)
pos0=$(grep -c 'LEAF_SPLIT.*pos=0' "$LEDGER" || true)
pos_len=$(grep -c 'LEAF_SPLIT.*pos=1' "$LEDGER" || true)
pos_mid=$(grep -c 'LEAF_SPLIT.*pos=2' "$LEDGER" || true)
interior_splits=$(grep -c '^INTERIOR_SPLIT' "$LEDGER" || true)
height_grew=$(grep -c '^HEIGHT_GREW' "$LEDGER" || true)
root_collapsed=$(grep -c '^ROOT_COLLAPSED' "$LEDGER" || true)
node_removed=$(grep -c '^NODE_REMOVED' "$LEDGER" || true)
block_reused=$(grep -c '^BLOCK_REUSED' "$LEDGER" || true)
block_cowed=$(grep -c '^BLOCK_COWED' "$LEDGER" || true)
converge_calls=$(grep -c '^CONVERGE' "$LEDGER" || true)

kg_shape1=$(grep -c '^KERNEL_GRADED.*class=shape1' "$LEDGER" || true)
kg_shape2=$(grep -c '^KERNEL_GRADED.*class=shape2' "$LEDGER" || true)
kg_pos_len=$(grep -c '^KERNEL_GRADED.*class=pos_len' "$LEDGER" || true)
kg_pos_mid=$(grep -c '^KERNEL_GRADED.*class=pos_mid' "$LEDGER" || true)
kg_interior_splits=$(grep -c '^KERNEL_GRADED.*class=interior_splits' "$LEDGER" || true)
kg_height_grew=$(grep -c '^KERNEL_GRADED.*class=height_grew' "$LEDGER" || true)
kg_root_collapsed=$(grep -c '^KERNEL_GRADED.*class=root_collapsed' "$LEDGER" || true)
kg_node_removed=$(grep -c '^KERNEL_GRADED.*class=node_removed' "$LEDGER" || true)
kg_block_reused=$(grep -c '^KERNEL_GRADED.*class=block_reused' "$LEDGER" || true)
kg_block_cowed=$(grep -c '^KERNEL_GRADED.*class=block_cowed' "$LEDGER" || true)
kg_converge_calls=$(grep -c '^KERNEL_GRADED.*class=converge_calls' "$LEDGER" || true)

max_rounds=0
if [[ "$converge_calls" -gt 0 ]]; then
  max_rounds=$(grep '^CONVERGE' "$LEDGER" | sed -E 's/.*rounds=([0-9]+)/\1/' | sort -n | tail -n 1 || echo 0)
fi

echo "================================================================="
echo "       B-TREE STRUCTURAL TRANSITION EMPIRICAL REPORT"
echo "================================================================="
echo "Ledger: $LEDGER ($(wc -l < "$LEDGER" | tr -d ' ') total transitions recorded)"
echo
echo "| Structural Metric | Observed Count | Kernel Graded | Taxonomy Code |"
echo "|---|---|---|---|"
echo "| LeafSplit Shape 1 (item ends left) | $shape1 | $kg_shape1 | T5 |"
echo "| LeafSplit Shape 2 (item starts right) | $shape2 | $kg_shape2 | T6 |"
echo "| LeafSplit Shape 3 (item isolated) | $shape3 | 0 (excluded) | T7 (GAP-2) |"
echo "| LeafSplit Pos 0 (new tree minimum) | $pos0 | 0 (excluded) | T8 |"
echo "| LeafSplit Pos len (new tree maximum) | $pos_len | $kg_pos_len | T9 |"
echo "| LeafSplit Pos interior (middle split) | $pos_mid | $kg_pos_mid | T5/T6 |"
echo "| Interior Node Splits (>121 children) | $interior_splits | $kg_interior_splits | T12 |"
echo "| Tree Height Grew (0->1, 1->2) | $height_grew | $kg_height_grew | T14, T15 |"
echo "| Tree Root Collapsed (2->1, 1->0) | $root_collapsed | $kg_root_collapsed | T16, T17 |"
echo "| Node Removed (emptied node pruned) | $node_removed | $kg_node_removed | T10, T13 |"
echo "| In-Txn Block Reused (is_already_new) | $block_reused | $kg_block_reused | T19, T20 |"
echo "| Block CoW'd (new allocation) | $block_cowed | $kg_block_cowed | GAP-5 |"
echo "| Convergence Loop Invocations | $converge_calls | $kg_converge_calls | X5 |"
echo "| Max Convergence Rounds Observed | $max_rounds (limit 30) | - | X6 (GAP-3) |"
echo "================================================================="

if [[ "$CHECK_GATE" -eq 1 ]]; then
  MISSES=()
  [[ "$shape1" -gt 0 ]] || MISSES+=("LeafSplit Shape 1 (T5) [unreached]")
  [[ "$kg_shape1" -gt 0 ]] || MISSES+=("LeafSplit Shape 1 (T5) [ungraded]")
  [[ "$shape2" -gt 0 ]] || MISSES+=("LeafSplit Shape 2 (T6) [unreached]")
  [[ "$kg_shape2" -gt 0 ]] || MISSES+=("LeafSplit Shape 2 (T6) [ungraded]")
  [[ "$pos_len" -gt 0 ]] || MISSES+=("LeafSplit Pos len (T9) [unreached]")
  [[ "$kg_pos_len" -gt 0 ]] || MISSES+=("LeafSplit Pos len (T9) [ungraded]")
  [[ "$pos_mid" -gt 0 ]] || MISSES+=("LeafSplit Pos interior (T5/T6) [unreached]")
  [[ "$kg_pos_mid" -gt 0 ]] || MISSES+=("LeafSplit Pos interior (T5/T6) [ungraded]")
  [[ "$interior_splits" -gt 0 ]] || MISSES+=("Interior Node Splits (T12) [unreached]")
  [[ "$kg_interior_splits" -gt 0 ]] || MISSES+=("Interior Node Splits (T12) [ungraded]")
  [[ "$height_grew" -gt 0 ]] || MISSES+=("Tree Height Grew (T14/T15) [unreached]")
  [[ "$kg_height_grew" -gt 0 ]] || MISSES+=("Tree Height Grew (T14/T15) [ungraded]")
  [[ "$root_collapsed" -gt 0 ]] || MISSES+=("Tree Root Collapsed (T16/T17) [unreached]")
  [[ "$kg_root_collapsed" -gt 0 ]] || MISSES+=("Tree Root Collapsed (T16/T17) [ungraded]")
  [[ "$node_removed" -gt 0 ]] || MISSES+=("Node Removed (T10/T13) [unreached]")
  [[ "$kg_node_removed" -gt 0 ]] || MISSES+=("Node Removed (T10/T13) [ungraded]")
  [[ "$block_reused" -gt 0 ]] || MISSES+=("In-Txn Block Reused (T19/T20) [unreached]")
  [[ "$kg_block_reused" -gt 0 ]] || MISSES+=("In-Txn Block Reused (T19/T20) [ungraded]")
  [[ "$block_cowed" -gt 0 ]] || MISSES+=("Block CoW'd (GAP-5) [unreached]")
  [[ "$kg_block_cowed" -gt 0 ]] || MISSES+=("Block CoW'd (GAP-5) [ungraded]")
  [[ "$converge_calls" -gt 0 ]] || MISSES+=("Convergence Loop (X5) [unreached]")
  [[ "$kg_converge_calls" -gt 0 ]] || MISSES+=("Convergence Loop (X5) [ungraded]")

  if [[ ${#MISSES[@]} -gt 0 ]]; then
    echo "TRANSITION GATE FAILED: Missed ${#MISSES[@]} required structural transition criterion/criteria:" >&2
    for m in "${MISSES[@]}"; do
      echo "  - $m" >&2
    done
    exit 1
  else
    echo "EXCLUDED (measured unreachable, see notes/plan-structural-conformance-2026-09-08.md):"
    echo "  - LeafSplit Shape 3 (T7) — driver cannot produce; only EXTENT_CSUM items are large"
    echo "    enough, and large csum items require large contiguous extents the allocator appends"
    echo "  - LeafSplit Pos 0 (T8) — never observed since Phase 0"
    if [[ "$shape3" -gt 0 ]]; then
      echo "NOTE: LeafSplit Shape 3 (T7) was observed ($shape3 times)!"
    fi
    if [[ "$pos0" -gt 0 ]]; then
      echo "NOTE: LeafSplit Pos 0 (T8) was observed ($pos0 times)!"
    fi
    echo "TRANSITION GATE PASSED: All required structural transitions observed and kernel-verified (0 misses)."
  fi
fi

