#/bin/bash

# include util functions
source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] [-d] [-v] [--test] [--jam] [--chat] [--run-suffix NAME] [--ablation-state-only-no-angelic|--ablation-no-cfc|--ablation-lldb-only] -f <config> -t <tag>"
    echo "  -h, --help        : print this message"
    echo "  -d, --debug       : run the container in debug mode (no auto-exit)"
    echo "  -v  --validate    : validate patch only"
    echo "      --test        : run the test suite"
    echo "      --jam         : jam the agent from getting constraints"
    echo "      --chat        : run LLM with zero-shot chat mode"
    echo "      --run-suffix  : isolate logs/results under <tag>_<suffix>"
    echo "      --ablation-state-only-no-angelic : run without angelic counterfactual mutation/search"
    echo "      --ablation-no-cfc : run DebugAgent with angelic intervention evidence directly into PatchAgent"
    echo "      --ablation-lldb-only : run observation-only LLDB DebugAgent directly into clean PatchAgent"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tag         : tag for the ARVO docker image"
    exit 1
}

# =============================================================================
# Argument parsing
# =============================================================================

VALID_ARGS=$(getopt -o hdvf:t: --long help,debug,validate,test,jam,chat,run-suffix:,ablation-state-only-no-angelic,ablation-no-cfc,ablation-lldb-only,config-file:,tag: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1;
fi
eval set -- "$VALID_ARGS"

TAG=""
DEBUG=0
TEST=0
JAM=0
CHAT=0
VALIDATE=0
ABLATION=0
NO_CFC=0
LLDB_ONLY=0
RUN_SUFFIX=""
CLANGD_PATH=$(pwd)/opt/clangd
LLDBMI_PATH=$(pwd)/opt/lldb-mi
STALKER_PATH=$(pwd)/stalker
PYTHON_PATH=""
PYTHON_MOUNT_SOURCE=""
PYTHON_EXECUTABLE="/root/env/bin/python"
DOCKER_MEMORY="${DOCKER_MEMORY:-32g}"
DOCKER_MEMORY_SWAP="${DOCKER_MEMORY_SWAP:-$DOCKER_MEMORY}"
DOCKER_CPU_ARG=""
if [[ -n "${DOCKER_CPUS:-}" ]]; then
    DOCKER_CPU_ARG="--cpus=$DOCKER_CPUS"
fi

while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -d|--debug)
            DEBUG=1
            shift
            ;;
        -v|--validate)
            VALIDATE=1
            shift
            ;;
        --test)
            TEST=1
            shift
            ;;
        --jam)
            JAM=1
            shift
            ;;
        --chat)
            CHAT=1
            shift
            ;;
        --run-suffix)
            RUN_SUFFIX=$2
            shift 2
            ;;
        --ablation-state-only-no-angelic)
            ABLATION=1
            shift
            ;;
        --ablation-no-cfc)
            NO_CFC=1
            shift
            ;;
        --ablation-lldb-only)
            LLDB_ONLY=1
            shift
            ;;
        -f|--config-file)
            load_config $2
            echo_info "PYTHON_PATH after function call: [$PYTHON_PATH]"
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

if [[ $TEST -eq 1 ]]; then
    TAG=64664   # Hardcoded for now
    echo_info "Running test suite"
    echo_warn "Overriding tag to 64664"
fi

if [[ -z $TAG ]]; then
    echo_error "ARVO docker image tag not set"
    usage
fi

if [[ -z $PYTHON_PATH ]]; then
    echo_error "PYTHON_PATH not set"
    usage
fi

if [[ $((ABLATION + NO_CFC + LLDB_ONLY)) -gt 1 ]]; then
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


# =============================================================================
# Prepare command
# =============================================================================

RUN_ID="$TAG"
CONTAINER_SUFFIX="angelic"
if [[ $ABLATION -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    RUN_ID="${TAG}_state_only_no_angelic"
    CONTAINER_SUFFIX="no-angelic"
elif [[ $NO_CFC -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    RUN_ID="${TAG}_no_cfc"
    CONTAINER_SUFFIX="no-cfc"
elif [[ $LLDB_ONLY -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    RUN_ID="${TAG}_lldb_only"
    CONTAINER_SUFFIX="lldb-only"
fi
if [[ -n "$RUN_SUFFIX" ]] && [[ $TEST -ne 1 ]]; then
    RUN_ID="${RUN_ID}_${RUN_SUFFIX}"
    CONTAINER_SUFFIX="${CONTAINER_SUFFIX}-${RUN_SUFFIX}"
fi

STALKER="$PYTHON_EXECUTABLE /root/stalker/stalker.py"
ARGS="--project $TAG"
ARGS="$ARGS --logs /root/workspace/logs/$RUN_ID"
ARGS="$ARGS --results /root/workspace/results/$RUN_ID"
if [[ $TEST -eq 1 ]]; then
    ARGS="$ARGS --test"
fi
if [[ $VALIDATE -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --validate"
    echo_warn "Running validation only"
fi
if [[ $JAM -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --disable-constraint"
    echo_warn "Jamming the agent"
fi
if [[ $CHAT -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --zero-shot"
    echo_warn "Running in zero-shot chat mode"
fi
if [[ $ABLATION -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --ablation-state-only-no-angelic"
    echo_warn "Running state-only no-angelic ablation"
fi
if [[ $NO_CFC -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --ablation-no-cfc"
    echo_warn "Running no-CFC ablation"
fi
if [[ $LLDB_ONLY -eq 1 ]] && [[ $TEST -ne 1 ]]; then
    ARGS="$ARGS --ablation-lldb-only"
    echo_warn "Running LLDB-only ablation"
fi

CMD="/root/workspace/launcher.sh"
if [[ $DEBUG -eq 1 ]]; then
    CMD="$CMD --debug"
    echo_warn "Running in debug mode"
fi
CMD="$CMD $STALKER $ARGS"


# =============================================================================
# Launch Bug Stalker
# =============================================================================

echo_info "Starting Bug Stalker in arvo-$TAG-$CONTAINER_SUFFIX"

TERM_ARG=""
if [[ -t 1 ]]; then
    TERM_ARG="-it"
else
    echo_warn "Running in non-interactive mode"
fi

# check if $TAG starts with "e"
IMAGE_PREFIX=""
IMAGE="n132/arvo:$TAG-vul"
if [[ "$TAG" == e* ]]; then
    echo_warn "Running extended ARVO dataset"
    IMAGE="registry.cn-wulanchabu.aliyuncs.com/dockmoil/arvo:$TAG-vul"
fi
IMAGE="$IMAGE_PREFIX/$IMAGE"

DOCKER_ENV_ARGS=()
if [[ -n "${JENIYA_API_KEY:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e JENIYA_API_KEY)
fi
if [[ -n "${LLM_CONFIG_FILE:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e LLM_CONFIG_FILE)
fi
if [[ -n "${LLM_PROFILE:-}" ]]; then
    DOCKER_ENV_ARGS+=(-e LLM_PROFILE)
fi

docker run $TERM_ARG --rm                                  \
    --name arvo-$TAG-$CONTAINER_SUFFIX                       \
    --privileged                                           \
    --network=host                                         \
    --memory=$DOCKER_MEMORY                                \
    --memory-swap=$DOCKER_MEMORY_SWAP                      \
    $DOCKER_CPU_ARG                                        \
    "${DOCKER_ENV_ARGS[@]}"                                \
    -v $STALKER_PATH:/root/stalker                         \
    -v $CLANGD_PATH:/root/opt/clangd                       \
    -v $LLDBMI_PATH:/root/opt/lldb-mi                      \
    -v $PYTHON_MOUNT_SOURCE:/root/env                      \
    -v $(pwd)/workspace:/root/workspace                    \
    -w /root/workspace                                     \
    $IMAGE                                                 \
    bash -c '                                              \
        echo "[INFO] Disabling ASLR...";                   \
        echo 0 > /proc/sys/kernel/randomize_va_space;      \
        echo "[DEBUG] ASLR status:" $(cat /proc/sys/kernel/randomize_va_space); \
        if [ "$(cat /proc/sys/kernel/randomize_va_space)" -eq 0 ]; then         \
            echo "[INFO] ASLR disabled successfully ✅";     \
        else                                                \
            echo "[WARN] Failed to disable ASLR ⚠️";        \
        fi;                                                \
        unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY; \
        echo "[INFO] Executing command: '"$CMD"'";          \
        exec '"$CMD"';                                     \
    '
ret=$?

# Free disk: remove this example's image (container already gone via --rm)
# if docker rmi -f "$IMAGE" >/dev/null 2>&1; then
#     echo_info "Removed image $IMAGE"
# else
#     echo_warn "Could not remove image $IMAGE (in use, absent, or shared layers)"
# fi

if [[ $ret -ne 0 ]]; then
    echo_error "Failed to launch arvo:$TAG"
    exit 1
else
    echo_fine "Bug Stalker for arvo:$TAG finished"
fi
