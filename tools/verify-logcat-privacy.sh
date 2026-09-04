#!/usr/bin/env bash
#
# verify-logcat-privacy.sh — On-device verification of Security Invariant #7.
#
#   tools/verify-logcat-privacy.sh [session_log_file | --live <forbidden_tokens...>]
#
# Checks that filenames, paths, and directory names NEVER enter Android logcat
# in either `luks` or `luks_err` log tags during on-device operations.
#
# Usage:
#   1. Capture live session while performing create / rename / delete:
#      tools/verify-logcat-privacy.sh --live secret_doc.txt my_private_folder
#
#   2. Or verify an existing logcat dump file:
#      tools/verify-logcat-privacy.sh session.log secret_doc.txt my_private_folder
#
set -euo pipefail

MODE="file"
LOG_FILE=""
TOKENS=()

if [ $# -eq 0 ]; then
    echo "usage: $0 --live <forbidden_token...>" >&2
    echo "   or: $0 <log_file> <forbidden_token...>" >&2
    exit 2
fi

if [ "$1" = "--live" ]; then
    MODE="live"
    shift
    TOKENS=("$@")
    LOG_FILE="$(mktemp /tmp/luks-logcat-XXXXXX.log)"
else
    LOG_FILE="$1"
    shift
    TOKENS=("$@")
    [ -f "$LOG_FILE" ] || { echo "no such log file: $LOG_FILE" >&2; exit 1; }
fi

if [ ${#TOKENS[@]} -eq 0 ]; then
    echo "error: specify at least one token / filename to check against logcat" >&2
    exit 2
fi

if [ "$MODE" = "live" ]; then
    command -v adb >/dev/null || { echo "adb not installed" >&2; exit 2; }
    adb get-state >/dev/null 2>&1 || { echo "no device attached — check 'adb devices'" >&2; exit 2; }

    echo "==> configuring phone logcat buffer (16M)..."
    adb logcat -G 16M >/dev/null
    adb logcat -c

    echo "==> capturing logcat stream (luks:V luks_err:V) to $LOG_FILE..."
    echo "==> perform your test operations on device now (create, rename, delete)."
    echo "==> press Ctrl+C or Enter when done to analyze logs."

    adb logcat -s luks:V luks_err:V > "$LOG_FILE" 2>&1 &
    LOGCAT_PID=$!

    trap 'kill $LOGCAT_PID 2>/dev/null || true' EXIT

    read -r -p "Press [Enter] when on-device operations are complete..." || true
    kill $LOGCAT_PID 2>/dev/null || true
    trap - EXIT
fi

echo "==> analyzing logcat output ($(wc -l < "$LOG_FILE" | tr -d ' ') lines captured)..."

LEAKS_FOUND=0
for token in "${TOKENS[@]}"; do
    # Search case-insensitively in the logcat output
    MATCHES="$(grep -i -F "$token" "$LOG_FILE" || true)"
    if [ -n "$MATCHES" ]; then
        echo "❌ LEAK DETECTED: token '$token' found in logcat output:" >&2
        echo "$MATCHES" | sed 's/^/    /' >&2
        LEAKS_FOUND=$((LEAKS_FOUND + 1))
    else
        echo "✅ OK: token '$token' not present in logcat"
    fi
done

# General pattern checks: verify no full paths (/storage/..., /hiu/..., etc) appeared in luks_err lines
ERR_PATH_MATCHES="$(grep 'luks_err' "$LOG_FILE" | grep -E '(/[a-zA-Z0-9_\.\-]+){2,}' || true)"
if [ -n "$ERR_PATH_MATCHES" ]; then
    echo "⚠️ WARNING: potential path pattern found in luks_err logcat:" >&2
    echo "$ERR_PATH_MATCHES" | sed 's/^/    /' >&2
fi

if [ "$LEAKS_FOUND" -gt 0 ]; then
    echo "==> FAILED: $LEAKS_FOUND forbidden token(s) leaked to logcat." >&2
    exit 1
else
    echo "==> PASSED: zero filename leaks detected across ${#TOKENS[@]} token(s)."
fi
