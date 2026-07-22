#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${JUDGE_PYTHON:-${PYTHON:-python3}}"
OUTPUT_DIR=""
JUDGES=()
JUDGE_ARGS=()

usage() {
    cat <<'EOF'
Usage: scripts/run_semantic_security_panel.sh --output-dir DIR [--judge NAME ...] -- JUDGE_ARGS...

Judge names:
  deepseek-v4-pro
  gpt-5.5
  claude-opus-4-8

With no --judge option, all three judges run once and vote by strict majority.
Pass one --judge option to run a single model for one round.

Do not pass --output-dir, --llm-config, --judge-votes, or --temperature inside JUDGE_ARGS.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --judge)
            JUDGES+=("$2")
            shift 2
            ;;
        --)
            shift
            JUDGE_ARGS=("$@")
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown panel option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$OUTPUT_DIR" ]] || [[ ${#JUDGE_ARGS[@]} -eq 0 ]]; then
    usage >&2
    exit 2
fi

for arg in "${JUDGE_ARGS[@]}"; do
    case "$arg" in
        --output-dir|--llm-config|--judge-votes|--temperature)
            echo "Panel controls $arg; remove it from JUDGE_ARGS" >&2
            exit 2
            ;;
    esac
done

if [[ ${#JUDGES[@]} -eq 0 ]]; then
    JUDGES=(deepseek-v4-pro gpt-5.5 claude-opus-4-8)
fi

declare -A CONFIGS=(
    [deepseek-v4-pro]="workspace/configs/ssc-judge-deepseek-v4-pro/llm.yaml"
    [gpt-5.5]="workspace/configs/ssc-judge-jeniya-gpt-5.5/llm.yaml"
    [claude-opus-4-8]="workspace/configs/ssc-judge-jeniya-claude-opus-4-8/llm.yaml"
)

mkdir -p "$OUTPUT_DIR/votes"
VOTE_ARGS=()
for judge in "${JUDGES[@]}"; do
    config="${CONFIGS[$judge]:-}"
    if [[ -z "$config" ]]; then
        echo "Unknown judge: $judge" >&2
        usage >&2
        exit 2
    fi
    vote_dir="$OUTPUT_DIR/votes/$judge"
    "$PYTHON" scripts/semantic_security_judge.py \
        "${JUDGE_ARGS[@]}" \
        --output-dir "$vote_dir" \
        --llm-config "$config" \
        --judge-votes 1 \
        --temperature 0
    VOTE_ARGS+=(--vote "$judge=$vote_dir/summary.json")
done

"$PYTHON" scripts/aggregate_semantic_security_panel.py \
    "${VOTE_ARGS[@]}" \
    --output-dir "$OUTPUT_DIR"
