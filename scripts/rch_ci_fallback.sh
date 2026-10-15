#!/usr/bin/env bash
set -euo pipefail

DEFAULT_TIMEOUT_SEC=3600
DEFAULT_MEMORY_MB=32768
MAX_TIMEOUT_SEC=604800
MAX_MEMORY_MB=1048576

die_usage() {
    echo "usage: $0 exec [--] <command> [args...]" >&2
    exit 64
}

normalize_guard_integer() {
    local name="$1"
    local value="$2"
    local max="$3"
    local unit="$4"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "rch-ci-fallback: ${name} must be a non-negative integer, got: ${value}" >&2
        exit 64
    fi

    local normalized="$value"
    while [[ "${#normalized}" -gt 1 && "${normalized:0:1}" == "0" ]]; do
        normalized="${normalized:1}"
    done

    if [[ "${#normalized}" -gt "${#max}" ]] ||
        [[ "${#normalized}" -eq "${#max}" && "$normalized" > "$max" ]]; then
        echo "rch-ci-fallback: ${name} must be <= ${max} ${unit}, got: ${value}" >&2
        exit 64
    fi

    printf '%s' "$normalized"
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

timeout_sec="$(normalize_guard_integer RCH_CI_FALLBACK_TIMEOUT_SEC "${RCH_CI_FALLBACK_TIMEOUT_SEC:-$DEFAULT_TIMEOUT_SEC}" "$MAX_TIMEOUT_SEC" "seconds")"
memory_mb="$(normalize_guard_integer RCH_CI_FALLBACK_MEMORY_MB "${RCH_CI_FALLBACK_MEMORY_MB:-$DEFAULT_MEMORY_MB}" "$MAX_MEMORY_MB" "MiB")"

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
