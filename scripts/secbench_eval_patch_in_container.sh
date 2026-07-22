#!/bin/bash

set -euo pipefail

TAG="${1:?tag required}"
SECB="${2:-secb}"
SRC_DIR="${3:-}"
PATCH_RUN_ID="${4:-$TAG}"
PATCH_SOURCE="/root/workspace/results/$PATCH_RUN_ID/model_patch.diff"
REPRO_OUT="/tmp/secbench_repro.out"

if [[ ! -s "$PATCH_SOURCE" ]]; then
    echo "[SEC-BENCH-EVAL] missing patch: $PATCH_SOURCE" >&2
    exit 1
fi

cp "$PATCH_SOURCE" /testcase/model_patch.diff
if [[ -n "$SRC_DIR" ]]; then
    cd "$SRC_DIR"
fi
"$SECB" patch
"$SECB" build

set +e
"$SECB" repro >"$REPRO_OUT" 2>&1
REPRO_EXIT=$?
set -e

cat "$REPRO_OUT"

if grep -E "(ERROR: .*Sanitizer|SUMMARY: .*Sanitizer|AddressSanitizer:|MemorySanitizer:|LeakSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$REPRO_OUT" >/dev/null; then
    echo "[SEC-BENCH-EVAL] sanitizer still reproduced"
    exit 1
fi

echo "[SEC-BENCH-EVAL] no sanitizer reproduced (secb repro exit=$REPRO_EXIT)"
