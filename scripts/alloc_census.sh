#!/usr/bin/env bash
# alloc_census.sh — Allocation census tooling for Asupersync.
#
# Usage:
#   ./scripts/alloc_census.sh
#   ./scripts/alloc_census.sh --tool heaptrack
#   ./scripts/alloc_census.sh --tool valgrind --cmd "cargo bench --bench phase0_baseline"
#   ./scripts/alloc_census.sh --out baselines/alloc_census
#   ./scripts/alloc_census.sh --flamegraph
#
# Notes:
# - Does NOT modify code or outputs; purely observational.
# - Uses external tools if present. Installs are up to the operator.

set -euo pipefail

TOOL="heaptrack"
OUT_DIR="baselines/alloc_census"
CMD=()
FLAMEGRAPH=0

usage() {
    cat <<'USAGE'
Usage: ./scripts/alloc_census.sh [options]

Options:
  --tool <heaptrack|valgrind>   Allocation tool (default: heaptrack)
  --cmd  "<command>"             Command to profile (default: cargo bench --bench phase0_baseline)
  --out  <dir>                   Output directory (default: baselines/alloc_census)
  --flamegraph                   Attempt a flamegraph capture (cargo-flamegraph)
  -h, --help                     Show help

Examples:
  ./scripts/alloc_census.sh
  ./scripts/alloc_census.sh --tool valgrind --cmd "cargo bench --bench scheduler_benchmark"
  ./scripts/alloc_census.sh --flamegraph
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool) TOOL="$2"; shift 2 ;;
        --cmd) CMD=($2); shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --flamegraph) FLAMEGRAPH=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ${#CMD[@]} -eq 0 ]]; then
    CMD=(cargo bench --bench phase0_baseline)
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required for report generation" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$OUT_DIR/alloc_census_${TIMESTAMP}.json"
RAW_FILE=""
SUMMARY_FILE=""
FLAMEGRAPH_FILE=""

case "$TOOL" in
    heaptrack)
        if ! command -v heaptrack &>/dev/null; then
            echo "ERROR: heaptrack is not installed" >&2
            exit 1
        fi
        OUT_PREFIX="$OUT_DIR/heaptrack_${TIMESTAMP}"
        heaptrack -o "$OUT_PREFIX" -- "${CMD[@]}"
        RAW_FILE=$(ls -1t "${OUT_PREFIX}."* 2>/dev/null | head -n 1 || true)
        if [[ -z "$RAW_FILE" ]]; then
            echo "ERROR: heaptrack output not found at ${OUT_PREFIX}.*" >&2
            exit 1
        fi
        SUMMARY_FILE="$OUT_DIR/heaptrack_${TIMESTAMP}.txt"
        heaptrack --analyze "$RAW_FILE" > "$SUMMARY_FILE"
        ;;
    valgrind)
        if ! command -v valgrind &>/dev/null; then
            echo "ERROR: valgrind is not installed" >&2
            exit 1
        fi
        if ! command -v ms_print &>/dev/null; then
            echo "ERROR: ms_print (valgrind massif tools) is required" >&2
            exit 1
        fi
        RAW_FILE="$OUT_DIR/massif_${TIMESTAMP}.out"
        SUMMARY_FILE="$OUT_DIR/massif_${TIMESTAMP}.txt"
        valgrind --tool=massif --massif-out-file="$RAW_FILE" "${CMD[@]}"
        ms_print "$RAW_FILE" > "$SUMMARY_FILE"
        ;;
    *)
        echo "ERROR: Unknown tool '$TOOL'" >&2
        exit 1
        ;;
 esac

if [[ "$FLAMEGRAPH" -eq 1 ]]; then
    if command -v cargo-flamegraph &>/dev/null; then
        FLAMEGRAPH_FILE="$OUT_DIR/flamegraph_${TIMESTAMP}.svg"
        if [[ "${CMD[0]}" == "cargo" ]]; then
            cargo flamegraph --output "$FLAMEGRAPH_FILE" -- ${CMD[@]:1}
        else
            echo "WARN: flamegraph capture only supports cargo commands; skipping" >&2
            FLAMEGRAPH_FILE=""
        fi
    else
        echo "WARN: cargo-flamegraph not installed; skipping flamegraph" >&2
    fi
fi

python3 - <<PY > "$REPORT"
import json
import time

report = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "tool": "${TOOL}",
    "command": "${CMD[*]}",
    "artifacts": {
        "raw": "${RAW_FILE}",
        "summary": "${SUMMARY_FILE}",
        "flamegraph": "${FLAMEGRAPH_FILE}",
    },
}

print(json.dumps(report, indent=2))
PY

echo "Allocation census report: $REPORT"
