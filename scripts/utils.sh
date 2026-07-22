#!/bin/bash

# =============================================================================
# Utility functions
# =============================================================================

function echo_color {
    if [[ -t 1 ]]; then
        echo -e "\e[$1m$2\e[0m"
    else
        echo $2
    fi
}

function echo_error {
    echo_color "31" "[ERROR] $1"
}

function echo_fine {
    echo_color "32" " [FINE] $1"
}

function echo_warn {
    echo_color "33" " [WARN] $1"
}

function echo_info {
    echo_color "36" " [INFO] $1"
}

function echo_debug {
    echo_color "34" "[DEBUG] $1"
}

function load_config {
    if [[ ! -f $1 ]]; then
        echo_error "Config file $1 not found"
        exit 1
    fi

    echo_info "Loading config from $1"

    while IFS=': ' read -r key value; do
        case $key in
            "STALKER_PATH")
                STALKER_PATH=$value
                ;;
            "CLANGD_PATH")
                CLANGD_PATH=$value
                ;;
            "LLDBMI_PATH")
                LLDBMI_PATH=$value
                ;;
            "PYTHON_PATH")
                PYTHON_PATH=$value
                ;;
        esac
        echo_debug "Read key: [$key], value: [$value]"
    done < $1    
}
