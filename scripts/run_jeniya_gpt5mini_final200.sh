#!/bin/bash

set -euo pipefail

usage() {
    echo "Usage: $0 <secbench|arvo>"
    echo "Environment: JOBS (optional), CASE_TIMEOUT (SEC-bench)"
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi
cd "$(dirname "$0")/.."

CONFIG_DIR="workspace/configs/jeniya-gpt5-mini-2025-08-07"
STALK_CONFIG="$CONFIG_DIR/stalk.yml"
export LLM_CONFIG_FILE="configs/jeniya-gpt5-mini-2025-08-07/llm.yaml"
unset LLM_PROFILE

RUN_SUFFIX="jeniya-gpt5-mini-2025-08-07_$(date +%Y%m%d-%H%M%S)_$$"

case "$1" in
    secbench)
        exec scripts/secbench_batch.sh \
            -f "$STALK_CONFIG" \
            --tag-file workspace/secbench/tags/cve_0_200.txt \
            --no-prepare \
            --run-suffix "$RUN_SUFFIX" \
            --timeout "${CASE_TIMEOUT:-7200}" \
            --jobs "${JOBS:-1}"
        ;;
    arvo)
        exec scripts/batch_launch.sh \
            -f "$STALK_CONFIG" \
            -t datasets/tags/408/final_200.txt \
            -r "workspace/batch_logs/arvo_final_200_${RUN_SUFFIX}" \
            -j "${JOBS:-4}" \
            --run-suffix "$RUN_SUFFIX"
        ;;
    *)
        usage
        ;;
esac
