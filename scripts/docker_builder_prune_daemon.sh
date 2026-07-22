#!/bin/bash
# Prune Docker BuildKit build cache on a fixed interval (default: 1 hour).
#
# Usage:
#   ./scripts/docker_builder_prune_daemon.sh
#       Run "docker builder prune -f" once at start, then every BUILDER_PRUNE_INTERVAL_SEC (default 3600).
#   ./scripts/docker_builder_prune_daemon.sh --once
#       Single prune; use from cron, e.g. 0 * * * * cd /path/to/angelic_agent && ./scripts/docker_builder_prune_daemon.sh --once
#
# Note: the CLI subcommand is "docker builder prune", not "docker build prune".

set -u

if [[ "${1:-}" == "--once" ]]; then
    exec docker builder prune -f
fi

INTERVAL_SEC="${BUILDER_PRUNE_INTERVAL_SEC:-3600}"

echo_info() { echo "[docker_builder_prune] $*"; }

echo_info "prune now, then every ${INTERVAL_SEC}s (set BUILDER_PRUNE_INTERVAL_SEC to override)"
docker builder prune -f || echo_info "docker builder prune failed (is Docker running?)"

while true; do
    sleep "$INTERVAL_SEC"
    echo_info "$(date -Iseconds) docker builder prune -f"
    docker builder prune -f || echo_info "docker builder prune failed (is Docker running?)"
done
