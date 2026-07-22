#!/bin/bash

# include utils.sh
source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] -f <config> -t <tag> -o <output>"
    echo "  -h, --help        : print this message"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tag         : tag for the ARVO docker image"
    exit 1
}

# =============================================================================
# Argument parsing
# =============================================================================
VALID_ARGS=$(getopt -o hf:t: --long help,config-file:,tag:: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1;
fi
eval set -- "$VALID_ARGS"

TAG=""
OUTPUT="/root/workspace/export"
PYTHON_PATH=""
while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -f|--config-file)
            load_config $2
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
    usage
fi

if [[ -z $PYTHON_PATH ]]; then
    echo_error "PYTHON_PATH not set"
    exit 1
fi


# =============================================================================
# Prepare command
# =============================================================================

STALKER="/root/env/bin/python /root/stalker/export.py"
ARGS="--project $TAG"
ARGS="$ARGS --output $OUTPUT"
CMD="$STALKER $ARGS"


# =============================================================================
# Launch ARVO docker container
# =============================================================================

echo_info "Launching Bug Stalker Code Exporter in arvo-$TAG"

TERM_ARG=""
if [[ -t 1 ]]; then
    TERM_ARG="-it"
else
    echo_warn "Running in non-interactive mode"
fi

IMAGE="n132/arvo:$TAG-vul"
if [[ "$TAG" == e* ]]; then
    echo_warn "Running extended ARVO dataset"
    IMAGE="registry.cn-wulanchabu.aliyuncs.com/dockmoil/arvo:$TAG-vul"
fi

docker run $TERM_ARG --rm                                  \
    --name arvo-$TAG-export                                \
    --memory=32g                                           \
    --memory-swap=32g                                      \
    -v $STALKER_PATH:/root/stalker                         \
    -v $PYTHON_PATH:/root/env/                             \
    -v $(pwd)/workspace:/root/workspace                    \
    -w /root/workspace                                     \
    $IMAGE                                                 \
    $CMD
run_ret=$?

if docker rmi -f "$IMAGE" >/dev/null 2>&1; then
    echo_info "Removed image $IMAGE"
else
    echo_warn "Could not remove image $IMAGE (in use, absent, or shared layers)"
fi

if [[ $run_ret -ne 0 ]]; then
    echo_error "Failed to launch arvo:$TAG"
    exit 1
else
    echo_fine "Code exported"
fi
