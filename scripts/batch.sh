#!/bin/bash

# include util functions
source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] [--jam] [--chat] [--ablation-state-only-no-angelic|--ablation-no-cfc|--ablation-lldb-only] -f <config> -t <tag file> -r <result dir> [-b <batch size>]"
    echo "  -h, --help        : print this message"
    echo "  -v, --validate    : validation only"
    echo "      --jam         : jam the agent from getting constraints"
    echo "      --chat        : run LLM with zero-shot chat mode"
    echo "      --ablation-state-only-no-angelic : run without angelic counterfactual mutation/search"
    echo "      --ablation-no-cfc : run DebugAgent with angelic intervention evidence directly into PatchAgent"
    echo "      --ablation-lldb-only : run observation-only LLDB DebugAgent directly into clean PatchAgent"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tags        : a file containing the tags to be used"
    echo "  -r, --results     : directory to store the results"
    echo "  -b, --batch-size  : number of tags to run in a batch"
    exit 1
}


# =============================================================================
# Argument parsing
# =============================================================================

VALID_ARGS=$(getopt -o hvf:t:r:b: --long help,validate,jam,chat,ablation-state-only-no-angelic,ablation-no-cfc,ablation-lldb-only,config-file:,tags:,results:,batch-size: -- "$@")
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
CONFIG_FILE=""
TAG_FILE=""
TMP_TAG_FILE=""
RESULT_DIR=""
BATCH_SIZE=5
while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -v|--validate)
            VALIDATE=1
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
            TMP_TAG_FILE=$(dirname $TAG_FILE)/.tags
            shift 2
            ;;
        -r|--results)
            RESULT_DIR=$2
            shift 2
            ;;
        -b|--batch-size)
            BATCH_SIZE=$2
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

# =============================================================================
# Preparing directories
# =============================================================================
mkdir -p $RESULT_DIR
mkdir -p workspace/logs workspace/results


# =============================================================================
# Main
# =============================================================================

echo_info "Loading tags from $TAG_FILE"
TAGS=$(cat $TAG_FILE)

echo_warn "Batch launch started"
echo_info "Batch size: $BATCH_SIZE"

echo_info "$(date)"
start=$(date +%s)

CMD="./scripts/batch_launch.sh -f $CONFIG_FILE -t $TMP_TAG_FILE -r $RESULT_DIR"
if [[ $VALIDATE -eq 1 ]]; then
    CMD="$CMD -v"
fi
if [[ $JAM -eq 1 ]]; then
    CMD="$CMD --jam"
fi
if [[ $CHAT -eq 1 ]]; then
    CMD="$CMD --chat"
fi
if [[ $ABLATION -eq 1 ]]; then
    CMD="$CMD --ablation-state-only-no-angelic"
fi
if [[ $NO_CFC -eq 1 ]]; then
    CMD="$CMD --ablation-no-cfc"
fi
if [[ $LLDB_ONLY -eq 1 ]]; then
    CMD="$CMD --ablation-lldb-only"
fi

TAG_GROUP=()
cnt=0
for tag in $TAGS; do
    TAG_GROUP+=("$tag")
    cnt=$((cnt + 1))
    if [[ $cnt -eq $BATCH_SIZE ]]; then
        echo_fine "Running tags: ${TAG_GROUP[*]}"
        printf "%s\n" "${TAG_GROUP[@]}" > "$TMP_TAG_FILE"
        $CMD
        TAG_GROUP=()
        cnt=0
    fi
done

# Run the remaining tags
if [[ $cnt -gt 0 ]]; then
    echo_fine "Running tags: ${TAG_GROUP[*]}"
    printf "%s\n" "${TAG_GROUP[@]}" > "$TMP_TAG_FILE"
    $CMD
fi

rm -rf $TMP_TAG_FILE

end=$(date +%s)
echo_info "$(date)"

echo_fine "Batch launch finished"
echo_info "Batch job finished in $((end-start)) seconds"
echo_info "                      $(( (end-start) / 60 ))m$(( (end-start) % 60))s"
