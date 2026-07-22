#!/bin/bash

# include util functions
source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] [-v] [--jam] [--chat] [--run-suffix NAME] [--ablation-state-only-no-angelic|--ablation-no-cfc|--ablation-lldb-only] [-j <jobs>] -f <config> -t <tag file> -r <result dir>"
    echo "  -h, --help        : print this message"
    echo "  -v, --validate    : validation only"
    echo "  -j, --jobs        : max concurrent jobs (default: 4)"
    echo "      --jam         : jam the agent from getting constraints"
    echo "      --run-suffix  : isolate per-instance logs/results under <tag>_<suffix>"
    echo "      --ablation-state-only-no-angelic : run without angelic counterfactual mutation/search"
    echo "      --ablation-no-cfc : run DebugAgent with angelic intervention evidence directly into PatchAgent"
    echo "      --ablation-lldb-only : run observation-only LLDB DebugAgent directly into clean PatchAgent"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tags        : a file containing the tags to be used"
    echo "  -r, --results     : directory to store the results"
    exit 1
}


# =============================================================================
# Argument parsing
# =============================================================================

VALID_ARGS=$(getopt -o hvf:t:r:j: --long help,validate,jam,chat,run-suffix:,ablation-state-only-no-angelic,ablation-no-cfc,ablation-lldb-only,config-file:,tags:,results:,jobs: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1;
fi
eval set -- "$VALID_ARGS"

VALIDATE=0
JAM=0
CHAT=0
ABLATION=0
NO_CFC=0
LLDB_ONLY=0
JOBS=4
CONFIG_FILE=""
TAG_FILE=""
RESULT_DIR=""
RUN_SUFFIX=""
while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -v|--validate)
            VALIDATE=1
            shift
            ;;
        -j|--jobs)
            JOBS=$2
            shift 2
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
            CONFIG_FILE=$2
            shift 2
            ;;
        -t|--tags)
            TAG_FILE=$2
            shift 2
            ;;
        -r|--results)
            RESULT_DIR=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
    esac
done

if [[ -z $CONFIG_FILE ]] || [[ -z $TAG_FILE ]] || [[ -z $RESULT_DIR ]]; then
    echo_error "Missing required arguments"
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


# =============================================================================
# Main
# =============================================================================

echo_info "Checking result directory $RESULT_DIR"
mkdir -p $RESULT_DIR

echo_info "Loading tags from $TAG_FILE"

if [[ ! -f $TAG_FILE ]]; then
    echo_error "Tag file not found: $TAG_FILE"
    exit 1
fi

start=$(date +%s)
echo_warn "Starting jobs with max concurrency = $JOBS"

while IFS= read -r tag || [[ -n "$tag" ]]; do
    # skip empty lines
    if [[ -z "$tag" ]]; then
        continue
    fi

    echo_info "Launching Bug Stalker for tag: $tag"

    ARGS="-f $CONFIG_FILE -t $tag"
    if [[ -n "$RUN_SUFFIX" ]]; then
        ARGS="$ARGS --run-suffix $RUN_SUFFIX"
    fi
    if [[ $VALIDATE -eq 1 ]]; then
        ARGS="$ARGS -v"
    fi
    if [[ $JAM -eq 1 ]]; then
        ARGS="$ARGS --jam"
    fi
    if [[ $CHAT -eq 1 ]]; then
        ARGS="$ARGS --chat"
    fi
    if [[ $ABLATION -eq 1 ]]; then
        ARGS="$ARGS --ablation-state-only-no-angelic"
    fi
    if [[ $NO_CFC -eq 1 ]]; then
        ARGS="$ARGS --ablation-no-cfc"
    fi
    if [[ $LLDB_ONLY -eq 1 ]]; then
        ARGS="$ARGS --ablation-lldb-only"
    fi

    # throttle concurrency
    while true; do
        running_jobs=$(jobs -pr | wc -l)
        if [[ $running_jobs -lt $JOBS ]]; then
            break
        fi
        sleep 2
    done

    ./scripts/launch.sh $ARGS > $RESULT_DIR/$tag.txt 2>&1 &
    pid=$!
    echo_debug "Tag $tag started with PID $pid"
done < "$TAG_FILE"

echo_warn "Waiting for all jobs to finish"
wait

end=$(date +%s)
echo_info "All jobs finished in $((end-start)) seconds"
echo_info "                          $(( (end-start) / 60 ))m$(( (end-start) % 60))s"
