#!/bin/bash

set -euo pipefail

function usage {
    echo "Usage: $0 [-h] [-f <config>] [--offset N] [--limit N] [--tag-file FILE] [--no-prepare] [--run-suffix NAME]"
    echo "          [--agent|--run-poc|--build-only|--repro-only|--patch-only|--eval-patch] [--ablation-state-only-no-angelic|--ablation-no-cfc|--ablation-lldb-only] [--timeout SECONDS] [--jobs N]"
    echo ""
    echo "Defaults: -f stalker.yml --offset 0 --limit 50 --agent --timeout 7200 --jobs 1"
    echo ""
    echo "Examples:"
    echo "  $0 -f stalker.yml --limit 50"
    echo "  $0 -f stalker.yml --limit 50 --run-poc --timeout 1800"
    echo "  $0 -f stalker.yml --tag-file workspace/secbench/tags/cve_0_50.txt --no-prepare"
    exit 1
}

CONFIG="stalker.yml"
OFFSET=0
LIMIT=50
TAG_FILE=""
PREPARE=1
MODE="agent"
CASE_TIMEOUT=7200
JOBS=1
ABLATION_FLAG=()
ABLATION_COUNT=0
RUN_SUFFIX=""

VALID_ARGS=$(getopt -o hf: --long help,config-file:,offset:,limit:,tag-file:,no-prepare,run-suffix:,agent,run-poc,build-only,repro-only,patch-only,eval-patch,ablation-state-only-no-angelic,ablation-no-cfc,ablation-lldb-only,timeout:,jobs: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1
fi
eval set -- "$VALID_ARGS"

while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -f|--config-file)
            CONFIG="$2"
            shift 2
            ;;
        --offset)
            OFFSET="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --tag-file)
            TAG_FILE="$2"
            shift 2
            ;;
        --no-prepare)
            PREPARE=0
            shift
            ;;
        --run-suffix)
            RUN_SUFFIX="$2"
            shift 2
            ;;
        --agent)
            MODE="agent"
            shift
            ;;
        --run-poc)
            MODE="run-poc"
            shift
            ;;
        --build-only)
            MODE="build"
            shift
            ;;
        --repro-only)
            MODE="repro"
            shift
            ;;
        --patch-only)
            MODE="patch"
            shift
            ;;
        --eval-patch)
            MODE="eval-patch"
            shift
            ;;
        --ablation-state-only-no-angelic)
            ABLATION_FLAG=(--ablation-state-only-no-angelic)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
            shift
            ;;
        --ablation-no-cfc)
            ABLATION_FLAG=(--ablation-no-cfc)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
            shift
            ;;
        --ablation-lldb-only)
            ABLATION_FLAG=(--ablation-lldb-only)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
            shift
            ;;
        --timeout)
            CASE_TIMEOUT="$2"
            shift 2
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
    esac
done

cd "$(dirname "$0")/.."

if [[ ! -f "$CONFIG" ]]; then
    echo "[ERROR] config file not found: $CONFIG" >&2
    exit 1
fi

OPENROUTER_SELECTED=0
if [[ "${LLM_PROFILE:-}" == "openrouter-deepseek-v3.2" ]]; then
    OPENROUTER_SELECTED=1
elif [[ -z "${LLM_PROFILE:-}" ]] && \
     [[ -z "${LLM_CONFIG_FILE:-}" ]] && \
     [[ -f workspace/llm.yml ]] && \
     grep -q "select: openrouter-deepseek-v3.2" workspace/llm.yml; then
    OPENROUTER_SELECTED=1
fi
if [[ $OPENROUTER_SELECTED -eq 1 ]] && [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "[ERROR] OPENROUTER_API_KEY is required by the selected LLM profile" >&2
    exit 1
fi

if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
    echo "[ERROR] --jobs must be a positive integer" >&2
    exit 1
fi

if [[ $ABLATION_COUNT -gt 1 ]]; then
    echo "[ERROR] choose only one ablation mode: --ablation-state-only-no-angelic, --ablation-no-cfc, or --ablation-lldb-only" >&2
    exit 1
fi

if [[ -n "$RUN_SUFFIX" ]] && [[ ! "$RUN_SUFFIX" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "[ERROR] --run-suffix may contain only letters, digits, dot, underscore, and hyphen" >&2
    exit 1
fi

if [[ -z "$TAG_FILE" ]]; then
    TAG_FILE="workspace/secbench/tags/cve_${OFFSET}_$((OFFSET + LIMIT)).txt"
fi

if [[ $PREPARE -eq 1 ]]; then
    "${PYTHON:-python3}" scripts/secbench_prepare.py \
        --offset "$OFFSET" \
        --limit "$LIMIT"
fi

if [[ ! -f "$TAG_FILE" ]]; then
    echo "[ERROR] tag file not found: $TAG_FILE" >&2
    exit 1
fi

MODE_FLAG=()
case "$MODE" in
    agent)
        ;;
    run-poc)
        MODE_FLAG=(--run-poc)
        ;;
    build)
        MODE_FLAG=(--build-only)
        ;;
    repro)
        MODE_FLAG=(--repro-only)
        ;;
    patch)
        MODE_FLAG=(--patch-only)
        ;;
    eval-patch)
        MODE_FLAG=(--eval-patch)
        ;;
    *)
        echo "[ERROR] unknown mode: $MODE" >&2
        exit 1
        ;;
esac

if [[ -n "$TAG_FILE" && $PREPARE -eq 0 ]]; then
    TAG_SLUG=$(basename "$TAG_FILE")
    TAG_SLUG="${TAG_SLUG%.txt}"
else
    TAG_SLUG="cve_${OFFSET}_${OFFSET_PLUS_LIMIT:-$((OFFSET + LIMIT))}"
fi
BATCH_ID="${TAG_SLUG}_${MODE}_$(date +%Y%m%d-%H%M%S)"
if [[ ${#ABLATION_FLAG[@]} -gt 0 ]]; then
    if [[ "${ABLATION_FLAG[0]}" == "--ablation-no-cfc" ]]; then
        BATCH_ID="${TAG_SLUG}_${MODE}_no_cfc_$(date +%Y%m%d-%H%M%S)"
    elif [[ "${ABLATION_FLAG[0]}" == "--ablation-lldb-only" ]]; then
        BATCH_ID="${TAG_SLUG}_${MODE}_lldb_only_$(date +%Y%m%d-%H%M%S)"
    else
        BATCH_ID="${TAG_SLUG}_${MODE}_state_only_no_angelic_$(date +%Y%m%d-%H%M%S)"
    fi
fi
if [[ -n "$RUN_SUFFIX" ]]; then
    BATCH_ID="${BATCH_ID}_${RUN_SUFFIX}"
fi
LOG_DIR="workspace/secbench/batch_logs/$BATCH_ID"
SUMMARY="$LOG_DIR/summary.tsv"
SUMMARY_LOCK="$LOG_DIR/summary.lock"
mkdir -p "$LOG_DIR"

printf "tag\tstatus\texit_code\tseconds\tlog\n" > "$SUMMARY"

RUN_SUFFIX_FLAG=()
if [[ -n "$RUN_SUFFIX" ]]; then
    RUN_SUFFIX_FLAG=(--run-suffix "$RUN_SUFFIX")
fi

CONTAINER_SUFFIX="angelic"
if [[ ${#ABLATION_FLAG[@]} -gt 0 ]]; then
    case "${ABLATION_FLAG[0]}" in
        --ablation-no-cfc) CONTAINER_SUFFIX="no-cfc" ;;
        --ablation-lldb-only) CONTAINER_SUFFIX="lldb-only" ;;
        *) CONTAINER_SUFFIX="no-angelic" ;;
    esac
fi
if [[ -n "$RUN_SUFFIX" ]]; then
    CONTAINER_SUFFIX="${CONTAINER_SUFFIX}-${RUN_SUFFIX}"
fi

STARTED_TAGS=()
terminate_process_tree() {
    local root_pid="$1"
    local signal="$2"
    local child_pid
    local -a child_pids=()

    mapfile -t child_pids < <(pgrep -P "$root_pid" 2>/dev/null || true)
    for child_pid in "${child_pids[@]}"; do
        terminate_process_tree "$child_pid" "$signal"
    done
    kill "-$signal" "$root_pid" 2>/dev/null || true
}

cleanup_batch() {
    local exit_code="$1"
    local pid
    local tag
    local container_name
    local -a child_pids=()

    trap - INT TERM
    echo "[INFO] Interrupt received; stopping this batch..." >&2
    mapfile -t child_pids < <(jobs -pr)
    if [[ ${#child_pids[@]} -gt 0 ]]; then
        for pid in "${child_pids[@]}"; do
            terminate_process_tree "$pid" TERM
        done
        sleep 1
        for pid in "${child_pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                terminate_process_tree "$pid" KILL
            fi
        done
        wait "${child_pids[@]}" 2>/dev/null || true
    fi
    for tag in "${STARTED_TAGS[@]}"; do
        container_name="${tag//[^A-Za-z0-9_.-]/_}-${CONTAINER_SUFFIX}"
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    done
    echo "[INFO] Batch stopped; cleaned ${#STARTED_TAGS[@]} started instance(s)." >&2
    exit "$exit_code"
}
trap 'cleanup_batch 130' INT
trap 'cleanup_batch 143' TERM

run_one() {
    local tag="$1"
    local log_file="$LOG_DIR/$tag.txt"
    local start
    local end
    local seconds_used
    local exit_code
    local status

    start=$(date +%s)
    echo "[INFO] Running $tag; log: $log_file"

    set +e
    timeout "$CASE_TIMEOUT" scripts/secbench_launch.sh \
        -f "$CONFIG" \
        -t "$tag" \
        "${RUN_SUFFIX_FLAG[@]}" \
        "${MODE_FLAG[@]}" \
        "${ABLATION_FLAG[@]}" \
        >"$log_file" 2>&1
    exit_code=$?
    set -e

    end=$(date +%s)
    seconds_used=$((end - start))
    if [[ $exit_code -eq 0 ]]; then
        status="pass"
    elif [[ $exit_code -eq 124 ]]; then
        status="timeout"
    else
        status="fail"
    fi

    (
        flock -x 9
        printf "%s\t%s\t%s\t%s\t%s\n" "$tag" "$status" "$exit_code" "$seconds_used" "$log_file" >> "$SUMMARY"
    ) 9>"$SUMMARY_LOCK"
    echo "[INFO] [$tag] $status exit=$exit_code seconds=$seconds_used"
}

ACTIVE=0
while IFS= read -r TAG || [[ -n "$TAG" ]]; do
    [[ -z "$TAG" ]] && continue
    STARTED_TAGS+=("$TAG")
    run_one "$TAG" </dev/null &
    ACTIVE=$((ACTIVE + 1))
    if [[ $ACTIVE -ge $JOBS ]]; then
        wait -n || true
        ACTIVE=$((ACTIVE - 1))
    fi
done < "$TAG_FILE"

while [[ $ACTIVE -gt 0 ]]; do
    wait -n || true
    ACTIVE=$((ACTIVE - 1))
done

PASSED=$(awk -F '\t' 'NR > 1 && $2 == "pass" { count++ } END { print count + 0 }' "$SUMMARY")
FAILED=$(awk -F '\t' 'NR > 1 && $2 != "pass" { count++ } END { print count + 0 }' "$SUMMARY")
TOTAL=$(awk 'NR > 1 { count++ } END { print count + 0 }' "$SUMMARY")

echo "[INFO] Batch completed: total=$TOTAL pass=$PASSED fail_or_timeout=$FAILED"
echo "[INFO] Summary: $SUMMARY"
