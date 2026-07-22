#!/bin/bash

set -euo pipefail

source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] [-d] [--build-local] [--run-suffix NAME] [--ablation-state-only-no-angelic|--ablation-no-cfc|--ablation-lldb-only] [--run-poc|--build-only|--repro-only|--patch-only|--eval-patch] -f <config> -t <secbench_tag>"
    echo "  -h, --help        : print this message"
    echo "  -d, --debug       : run the container in debug mode"
    echo "      --build-local : build from the generated local SEC-bench Dockerfile instead of using the official image"
    echo "      --run-poc     : run SEC-bench build and repro in the same container"
    echo "      --build-only  : run SEC-bench build only"
    echo "      --repro-only  : run SEC-bench repro only"
    echo "      --patch-only  : run SEC-bench patch only"
    echo "      --eval-patch  : evaluate workspace/results/<tag>/model_patch.diff with secb patch/build/repro"
    echo "      --run-suffix  : isolate logs/results under <tag>_<suffix>"
    echo "      --ablation-state-only-no-angelic : run agent without angelic counterfactual mutation/search"
    echo "      --ablation-no-cfc : run DebugAgent with angelic intervention evidence directly into PatchAgent"
    echo "      --ablation-lldb-only : run observation-only LLDB DebugAgent directly into clean PatchAgent"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tag         : SEC-bench prepared tag, e.g. secbench_njs_cve-2022-32414"
    exit 1
}

VALID_ARGS=$(getopt -o hdf:t: --long help,debug,build-local,run-suffix:,ablation-state-only-no-angelic,ablation-no-cfc,ablation-lldb-only,run-poc,build-only,repro-only,patch-only,eval-patch,config-file:,tag: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1
fi
eval set -- "$VALID_ARGS"

TAG=""
DEBUG=0
BUILD_LOCAL=0
MODE="agent"
ABLATION_ARGS=()
ABLATION_COUNT=0
RUN_SUFFIX=""
CLANGD_PATH=$(pwd)/opt/clangd
LLDBMI_PATH=$(pwd)/opt/lldb-mi
STALKER_PATH=$(pwd)/stalker
PYTHON_PATH=""
PYTHON_MOUNT_SOURCE=""
PYTHON_EXECUTABLE="/root/env/bin/python"
IMAGE_PREFIX="${SECBENCH_IMAGE_PREFIX:-}"

while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -d|--debug)
            DEBUG=1
            shift
            ;;
        --build-local)
            BUILD_LOCAL=1
            shift
            ;;
        --run-suffix)
            RUN_SUFFIX="$2"
            shift 2
            ;;
        --ablation-state-only-no-angelic)
            ABLATION_ARGS=(--ablation-state-only-no-angelic)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
            shift
            ;;
        --ablation-no-cfc)
            ABLATION_ARGS=(--ablation-no-cfc)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
            shift
            ;;
        --ablation-lldb-only)
            ABLATION_ARGS=(--ablation-lldb-only)
            ABLATION_COUNT=$((ABLATION_COUNT + 1))
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
        -f|--config-file)
            load_config "$2"
            shift 2
            ;;
        -t|--tag)
            TAG=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
    esac
done

if [[ -z $TAG ]]; then
    echo_error "SEC-bench tag not set"
    usage
fi

if [[ -z $PYTHON_PATH ]]; then
    echo_error "PYTHON_PATH not set"
    usage
fi

if [[ $ABLATION_COUNT -gt 1 ]]; then
    echo_error "Choose only one ablation mode: --ablation-state-only-no-angelic, --ablation-no-cfc, or --ablation-lldb-only"
    exit 1
fi

if [[ -n "$RUN_SUFFIX" ]] && [[ ! "$RUN_SUFFIX" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo_error "--run-suffix may contain only letters, digits, dot, underscore, and hyphen"
    exit 1
fi

if [[ -d $PYTHON_PATH ]]; then
    if [[ -x "$PYTHON_PATH/bin/python" ]]; then
        PYTHON_MOUNT_SOURCE="$PYTHON_PATH"
        PYTHON_EXECUTABLE="/root/env/bin/python"
    elif [[ -x "$PYTHON_PATH/python" ]]; then
        PYTHON_MOUNT_SOURCE="$PYTHON_PATH"
        PYTHON_EXECUTABLE="/root/env/python"
    else
        echo_error "PYTHON_PATH points to a directory, but no executable python was found under $PYTHON_PATH/bin/python or $PYTHON_PATH/python"
        exit 1
    fi
elif [[ -f $PYTHON_PATH ]]; then
    if [[ ! -x $PYTHON_PATH ]]; then
        echo_error "PYTHON_PATH points to a file, but it is not executable: $PYTHON_PATH"
        exit 1
    fi
    PYTHON_MOUNT_SOURCE="$PYTHON_PATH"
    PYTHON_EXECUTABLE="/root/env"
else
    echo_error "PYTHON_PATH does not exist: $PYTHON_PATH"
    exit 1
fi

PROFILE_PATH="$(pwd)/workspace/profiles/$TAG.json"
if [[ ! -f $PROFILE_PATH ]]; then
    echo_error "Prepared SEC-bench profile not found: $PROFILE_PATH"
    exit 1
fi

INSTANCE_ID=$(python - "$PROFILE_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    profile = json.load(f)
print(profile.get("secbench", {}).get("instance_id") or "")
PY
)
if [[ -z $INSTANCE_ID ]]; then
    echo_error "SEC-bench instance_id missing from profile: $PROFILE_PATH"
    exit 1
fi

SRC_DIR=$(python - "$PROFILE_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    profile = json.load(f)
print(profile.get("src") or "")
PY
)

CASE_DIR="$(pwd)/workspace/secbench/cases/$TAG"
if [[ $BUILD_LOCAL -eq 1 ]]; then
    if [[ ! -d $CASE_DIR ]]; then
        echo_error "Prepared SEC-bench case not found: $CASE_DIR"
        exit 1
    fi
    IMAGE="angelic-secbench:$TAG"
    echo_info "Building SEC-bench image $IMAGE from $CASE_DIR"
    docker build -t "$IMAGE" "$CASE_DIR"
else
    IMAGE="hwiwonlee/secb.eval.x86_64.$INSTANCE_ID"
    if [[ -n $IMAGE_PREFIX ]]; then
        IMAGE="$IMAGE_PREFIX/$IMAGE"
    fi
    echo_info "Using official SEC-bench image $IMAGE"
fi

RUN_ID="$TAG"
CONTAINER_SUFFIX="angelic"
if [[ ${#ABLATION_ARGS[@]} -gt 0 ]]; then
    if [[ "${ABLATION_ARGS[0]}" == "--ablation-no-cfc" ]]; then
        RUN_ID="${TAG}_no_cfc"
        CONTAINER_SUFFIX="no-cfc"
    elif [[ "${ABLATION_ARGS[0]}" == "--ablation-lldb-only" ]]; then
        RUN_ID="${TAG}_lldb_only"
        CONTAINER_SUFFIX="lldb-only"
    else
        RUN_ID="${TAG}_state_only_no_angelic"
        CONTAINER_SUFFIX="no-angelic"
    fi
fi
if [[ -n "$RUN_SUFFIX" ]]; then
    RUN_ID="${RUN_ID}_${RUN_SUFFIX}"
    CONTAINER_SUFFIX="${CONTAINER_SUFFIX}-${RUN_SUFFIX}"
fi
CONTAINER_NAME="${TAG//[^A-Za-z0-9_.-]/_}-$CONTAINER_SUFFIX"

cleanup_container() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
interrupt_launch() {
    local exit_code="$1"
    trap - INT TERM
    echo_warn "Interrupt received; removing container $CONTAINER_NAME"
    cleanup_container
    exit "$exit_code"
}
trap 'interrupt_launch 130' INT
trap 'interrupt_launch 143' TERM

if [[ $MODE == "agent" ]]; then
    STALKER="$PYTHON_EXECUTABLE /root/stalker/stalker.py"
    CMD="/root/workspace/launcher.sh"
    if [[ $DEBUG -eq 1 ]]; then
        CMD="$CMD --debug"
        echo_warn "Running in debug mode"
    fi
    CMD="$CMD $STALKER --project $TAG --logs /root/workspace/logs/$RUN_ID --results /root/workspace/results/$RUN_ID ${ABLATION_ARGS[*]}"
else
    if [[ $BUILD_LOCAL -eq 1 ]]; then
        if [[ $MODE == "run-poc" ]]; then
            CMD="bash -lc 'bash /root/secb build && bash /root/secb repro'"
        elif [[ $MODE == "eval-patch" ]]; then
            CMD="bash /root/scripts/secbench_eval_patch_in_container.sh $TAG /root/secb $SRC_DIR $RUN_ID"
        else
            CMD="bash /root/secb $MODE"
        fi
    else
        if [[ $MODE == "run-poc" ]]; then
            CMD="bash -lc 'secb build && secb repro'"
        elif [[ $MODE == "eval-patch" ]]; then
            CMD="bash /root/scripts/secbench_eval_patch_in_container.sh $TAG secb $SRC_DIR $RUN_ID"
        else
            CMD="secb $MODE"
        fi
    fi
fi

TERM_ARG=""
if [[ -t 1 ]]; then
    TERM_ARG="-it"
else
    echo_warn "Running in non-interactive mode"
fi

MOUNTS=(
    -v "$STALKER_PATH":/root/stalker
    -v "$CLANGD_PATH":/root/opt/clangd
    -v "$LLDBMI_PATH":/root/opt/lldb-mi
    -v "$PYTHON_MOUNT_SOURCE":/root/env
    -v "$(pwd)/workspace":/root/workspace
    -v "$(pwd)/scripts":/root/scripts:ro
)
if [[ $BUILD_LOCAL -eq 1 ]]; then
    MOUNTS+=(
        -v "$CASE_DIR/testcase":/testcase
        -v "$CASE_DIR/secb":/root/secb:ro
    )
fi

DOCKER_ENV_ARGS=()
if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e OPENROUTER_API_KEY)
fi
if [[ -n "${JENIYA_API_KEY:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e JENIYA_API_KEY)
fi
if [[ -n "${LLM_CONFIG_FILE:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e LLM_CONFIG_FILE)
fi
if [[ -n "${LLM_PROFILE:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e LLM_PROFILE)
fi

echo_info "Starting SEC-bench $TAG ($MODE)"
docker run $TERM_ARG --rm                                \
    --name "$CONTAINER_NAME"                             \
    --privileged                                         \
    --network=host                                       \
    --memory=8g                                          \
    --memory-swap=8g                                     \
    "${DOCKER_ENV_ARGS[@]}"                              \
    "${MOUNTS[@]}"                                       \
    -w /root/workspace                                   \
    "$IMAGE"                                             \
    bash -c '                                            \
        echo "[INFO] Disabling ASLR...";                 \
        echo 0 > /proc/sys/kernel/randomize_va_space;    \
        echo "[DEBUG] ASLR status:" $(cat /proc/sys/kernel/randomize_va_space); \
        if [[ "${SECBENCH_CLEAR_PROXY:-0}" == "1" ]]; then \
            unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY; \
        fi;                                             \
        echo "[INFO] Executing command: '"$CMD"'";        \
        exec '"$CMD"';                                   \
    '
