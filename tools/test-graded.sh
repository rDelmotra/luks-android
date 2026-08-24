#!/usr/bin/env bash
# Run the test suite and fail if any of it went ungraded by a real kernel.
#
# This is the command to document and the command to run. Plain `cargo test`
# answers "did the code crash?"; this answers "did a kernel agree the results
# were valid?", which is the question RULES.md actually cares about.
#
# It clears the oracle ledger, runs cargo test with whatever arguments you
# pass, then reports. The run fails if the tests failed *or* if any oracle
# gate was skipped — so `ALLOW_NO_ORACLE=1 tools/test-graded.sh` is honest
# about what it did instead of printing green.
#
# ORACLE_MIN sets the floor on how many gates the run must reach; see
# oracle-report.sh. The default suite has no write code and therefore nothing
# for a kernel to grade, so it is the one suite that legitimately runs zero.
#
# Usage:
#   ORACLE_MIN=0 tools/test-graded.sh --workspace
#   tools/test-graded.sh --workspace --features luks_core/dangerous-write-support,luks_jni/dangerous-write-support
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LUKS_ORACLE_LEDGER="${LUKS_ORACLE_LEDGER:-$repo_root/target/oracle-ledger.log}"

mkdir -p "$(dirname "$LUKS_ORACLE_LEDGER")"
# Truncate: the ledger describes *this* run. Evidence from a previous run
# left lying around would be the same class of bug as the one being fixed.
: > "$LUKS_ORACLE_LEDGER"

echo "ledger: $LUKS_ORACLE_LEDGER"
(cd "$repo_root" && cargo test "$@")
test_status=$?

echo
"$repo_root/tools/oracle-report.sh" "$LUKS_ORACLE_LEDGER"
oracle_status=$?

if [[ "$test_status" -ne 0 ]]; then
  echo
  echo "FAILED: cargo test exited $test_status."
  exit "$test_status"
fi
if [[ "$oracle_status" -ne 0 ]]; then
  echo
  echo "FAILED: the tests passed but the run was not fully kernel-graded."
  exit "$oracle_status"
fi

echo "PASS: tests green and every oracle check kernel-graded."
