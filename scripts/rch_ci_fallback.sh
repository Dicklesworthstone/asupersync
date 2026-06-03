#!/usr/bin/env bash
set -euo pipefail

DEFAULT_TIMEOUT_SEC=3600
DEFAULT_MEMORY_MB=32768

die_usage() {
    echo "usage: $0 exec [--] <command> [args...]" >&2
    exit 64
}

require_non_negative_integer() {
    local name="$1"
    local value="$2"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "rch-ci-fallback: ${name} must be a non-negative integer, got: ${value}" >&2
        exit 64
    fi
}

apply_memory_limit() {
    local memory_mb="$1"

    if [[ "$memory_mb" -eq 0 ]]; then
        echo "[rch-ci-fallback] memory limit: disabled" >&2
        return
    fi

    local memory_kb=$((memory_mb * 1024))
    if ulimit -v "$memory_kb" 2>/dev/null; then
        echo "[rch-ci-fallback] memory limit: ${memory_mb} MiB" >&2
    else
        echo "[rch-ci-fallback] warning: failed to apply virtual-memory limit ${memory_mb} MiB" >&2
    fi
}

if [[ "${1:-}" != "exec" ]]; then
    die_usage
fi

shift
if [[ "${1:-}" == "--" ]]; then
    shift
fi

if [[ "$#" -eq 0 ]]; then
    echo "rch-ci-fallback: missing command" >&2
    exit 64
fi

timeout_sec="${RCH_CI_FALLBACK_TIMEOUT_SEC:-$DEFAULT_TIMEOUT_SEC}"
memory_mb="${RCH_CI_FALLBACK_MEMORY_MB:-$DEFAULT_MEMORY_MB}"
require_non_negative_integer RCH_CI_FALLBACK_TIMEOUT_SEC "$timeout_sec"
require_non_negative_integer RCH_CI_FALLBACK_MEMORY_MB "$memory_mb"

apply_memory_limit "$memory_mb"
echo "[rch-ci-fallback] executing locally: $*" >&2

if [[ "$timeout_sec" -eq 0 ]]; then
    echo "[rch-ci-fallback] timeout: disabled" >&2
    exec "$@"
fi

timeout_bin=""
if command -v timeout >/dev/null 2>&1; then
    timeout_bin="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    timeout_bin="gtimeout"
fi

if [[ -n "$timeout_bin" ]]; then
    echo "[rch-ci-fallback] timeout: ${timeout_sec}s" >&2
    exec "$timeout_bin" "${timeout_sec}s" "$@"
fi

echo "[rch-ci-fallback] warning: timeout command unavailable; running without wall-clock guard" >&2
exec "$@"
