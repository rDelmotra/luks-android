#!/usr/bin/env bash
# Summarise an oracle evidence ledger and grade the run by its exit status.
#
# Issue 35: `cargo test` captures stdout and stderr for passing tests, so the
# oracle's own announcements were invisible under the documented command and a
# kernel-graded run looked exactly like an `ALLOW_NO_ORACLE=1` one. The ledger
# (`core/tests/common/oracle.rs`) writes the evidence to a file instead. This
# reads it back and turns it into something a machine can act on.
#
# Exit status:
#   0  every gate ran against a real kernel, and at least ORACLE_MIN of them did
#   1  at least one gate was skipped, or fewer than ORACLE_MIN gates ran
#
# ORACLE_MIN (default 1) is the floor on how many gates a run is expected to
# reach. It exists because "zero skips" is trivially true of a run that never
# called the oracle at all — deleting the gate calls would otherwise look like
# a clean result. The floor is what makes the absence detectable.
#
# ORACLE_MIN=0 is correct for the *default* (read-only) suite: every
# oracle-graded test is behind `#![cfg(feature = "dangerous-write-support")]`,
# so a default build has no write code, produces no image, and has nothing for
# a kernel to grade. That suite is ungraded by construction, not by accident.
#
# Usage: tools/oracle-report.sh [ledger-path]
set -euo pipefail

ORACLE_MIN="${ORACLE_MIN:-1}"

LEDGER="${1:-${LUKS_ORACLE_LEDGER:-}}"
if [[ -z "$LEDGER" ]]; then
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  LEDGER="$repo_root/target/oracle-ledger.log"
fi

if [[ ! -f "$LEDGER" ]]; then
  if [[ "$ORACLE_MIN" -eq 0 ]]; then
    echo "ORACLE REPORT: no ledger at $LEDGER, and none expected (ORACLE_MIN=0)."
    exit 0
  fi
  echo "ORACLE REPORT: no ledger at $LEDGER."
  echo "  Nothing recorded, so nothing is proven. Either no oracle-graded test"
  echo "  ran, or the ledger could not be written."
  exit 1
fi

ran=$(grep -c $'^RAN\t' "$LEDGER" || true)
skipped=$(grep -c $'^SKIPPED\t' "$LEDGER" || true)

echo "ORACLE REPORT ($LEDGER)"
echo "  graded by a real kernel: $ran"
echo "  skipped:                 $skipped"
echo "  floor (ORACLE_MIN):      $ORACLE_MIN"

if [[ "$skipped" -gt 0 ]]; then
  echo
  echo "UNGRADED. These call sites reported success without a kernel ever"
  echo "looking at the image:"
  # Collapse to distinct call sites with counts; a single site skipped 40
  # times is one problem, not forty.
  grep $'^SKIPPED\t' "$LEDGER" \
    | cut -f2,3 \
    | sort | uniq -c | sort -rn \
    | sed 's/^/    /'
  echo
  echo "A green test run above this line means the code did not crash. It does"
  echo "not mean the filesystem it produced is valid."
  exit 1
fi

if [[ "$ran" -lt "$ORACLE_MIN" ]]; then
  echo
  echo "BELOW FLOOR: $ran gates ran, at least $ORACLE_MIN expected. A run with no"
  echo "skips proves nothing if it never asked the oracle in the first place;"
  echo "this is what catches gate calls being removed, or a whole suite of"
  echo "graded tests quietly failing to compile in."
  exit 1
fi

echo
echo "All $ran oracle checks were graded against a real kernel."
