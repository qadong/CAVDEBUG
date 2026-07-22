#!/bin/bash

# include util functions
source ./scripts/utils.sh

function usage {
    echo "Usage: $0 [-h] -f <config> -t <tag file>"
    echo "  -h, --help        : print this message"
    echo "  -f, --config-file : path to the config file"
    echo "  -t, --tags        : a file containing the tags to be used"
    exit 1
}


# =============================================================================
# Argument parsing
# =============================================================================

VALID_ARGS=$(getopt -o hf:t: --long help,config-file:,tags: -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1;
fi
eval set -- "$VALID_ARGS"

CONFIG_FILE=""
TAG_FILE=""
while [ : ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -f|--config-file)
            CONFIG_FILE=$2
            shift 2
            ;;
        -t|--tags)
            TAG_FILE=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
    esac
done

if [[ -z $CONFIG_FILE ]] || [[ -z $TAG_FILE ]]; then
    echo_error "Missing required arguments"
    usage
fi


# =============================================================================
# Main
# =============================================================================

echo_info "Loading tags from $TAG_FILE"
TAGS=$(cat $TAG_FILE)

pids=""
for tag in $TAGS; do
    echo_info "Launching Bug Stalker Code Exporter for tag: $tag"
    
    ARGS="-f $CONFIG_FILE -t $tag"
    ./scripts/export.sh $ARGS > /dev/null 2>&1 &
    pid=$!
    pids="$pids $pid"
    echo_debug "Tag $tag started with PID $pid"
done

echo_warn "Waiting for all the processes to finish"
start=$(date +%s)

for pid in $pids; do
    wait $pid
    ret=$?
    if [[ $ret -ne 0 ]]; then
        echo_error "Process $pid failed"
    else
        echo_fine "Process $pid finished"
    fi
done

end=$(date +%s)
echo_info "All processes finished in $((end-start)) seconds" 
echo_info "                          $(( (end-start) / 60 ))m$(( (end-start) % 60))s"
