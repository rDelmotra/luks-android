#!/usr/bin/env bash
# tools/transition-report.sh
# Aggregates and reports structural B-tree transitions recorded in the transition ledger.
#
# Usage:
#   tools/transition-report.sh [ledger-path]
#
set -euo pipefail

LEDGER="${1:-${LUKS_TRANSITION_LEDGER:-}}"
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
converge_calls=$(grep -c '^CONVERGE' "$LEDGER" || true)

max_rounds=0
if [[ "$converge_calls" -gt 0 ]]; then
  max_rounds=$(grep '^CONVERGE' "$LEDGER" | sed -E 's/.*rounds=([0-9]+)/\1/' | sort -n | tail -n 1 || echo 0)
fi

echo "================================================================="
echo "       B-TREE STRUCTURAL TRANSITION EMPIRICAL REPORT"
echo "================================================================="
echo "Ledger: $LEDGER ($(wc -l < "$LEDGER" | tr -d ' ') total transitions recorded)"
echo
echo "| Structural Metric | Observed Count | Taxonomy Code |"
echo "|---|---|---|"
echo "| LeafSplit Shape 1 (item ends left) | $shape1 | T5 |"
echo "| LeafSplit Shape 2 (item starts right) | $shape2 | T6 |"
echo "| LeafSplit Shape 3 (item isolated) | $shape3 | T7 (GAP-2) |"
echo "| LeafSplit Pos 0 (new tree minimum) | $pos0 | T8 |"
echo "| LeafSplit Pos len (new tree maximum) | $pos_len | T9 |"
echo "| LeafSplit Pos interior (middle split) | $pos_mid | T5/T6 |"
echo "| Interior Node Splits (>121 children) | $interior_splits | T12 |"
echo "| Tree Height Grew (0->1, 1->2) | $height_grew | T14, T15 |"
echo "| Tree Root Collapsed (2->1, 1->0) | $root_collapsed | T16, T17 |"
echo "| Node Removed (emptied node pruned) | $node_removed | T10, T13 |"
echo "| In-Txn Block Reused (is_already_new) | $block_reused | T19, T20 |"
echo "| Convergence Loop Invocations | $converge_calls | X5 |"
echo "| Max Convergence Rounds Observed | $max_rounds (limit 30) | X6 (GAP-3) |"
echo "================================================================="
