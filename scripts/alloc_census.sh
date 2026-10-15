#!/usr/bin/env bash
# alloc_census.sh — Allocation census tooling for Asupersync.
#
# Usage:
#   ./scripts/alloc_census.sh --cmd "path/to/prebuilt-benchmark"
#   ./scripts/alloc_census.sh --tool heaptrack
#   ./scripts/alloc_census.sh --tool valgrind --cmd "path/to/prebuilt-benchmark"
#   ./scripts/alloc_census.sh --out baselines/alloc_census
#   ./scripts/alloc_census.sh --flamegraph
#   CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="scripts/alloc_census.sh --cargo-runner-xctrace" cargo test ...
#   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="scripts/alloc_census.sh --cargo-runner-heaptrack" cargo test ...
#   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="scripts/alloc_census.sh --cargo-runner-valgrind" cargo test ...
#   CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="scripts/alloc_census.sh --cargo-runner-rss" cargo test ...
#
# Notes:
# - Does not modify source code. Raw traces and summaries are written only to
#   the explicit/default census directory.
# - Uses external tools if present. Installs are up to the operator.

set -euo pipefail

TOOL="heaptrack"
OUT_DIR="baselines/alloc_census"
CMD=()
FLAMEGRAPH=0
ALLOW_LOCAL_CARGO="${ALLOW_LOCAL_CARGO:-0}"
CARGO_BIN="${CARGO_BIN:-cargo}"

if [[ "${1:-}" == "--cargo-runner-xctrace" ]]; then
    shift
    if [[ $# -eq 0 ]]; then
        echo "ERROR: --cargo-runner-xctrace requires Cargo's test binary and arguments" >&2
        exit 2
    fi
    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "ERROR: --cargo-runner-xctrace is supported only on macOS" >&2
        exit 2
    fi
    if ! command -v xcrun &>/dev/null; then
        echo "ERROR: xcrun is required for the xctrace allocation runner" >&2
        exit 1
    fi
    TRACE_ROOT="${ASUPERSYNC_ALLOC_CENSUS_DIR:-${TMPDIR:-/tmp}/asupersync_alloc_census}"
    mkdir -p "$TRACE_ROOT"
    TRACE_ID="$(date +%Y%m%d_%H%M%S)_$$"
    TRACE_PATH="$TRACE_ROOT/xctrace_${TRACE_ID}.trace"
    XPATH='/trace-toc/run[@number="1"]/tracks/track[@name="Allocations"]/details/detail[@name="Statistics"]'
    TRACE_ENV=()
    for name in R3_6_REGEX_PERF_TARGET R3_6_REGEX_PERF_SCENARIO; do
        if [[ -v "$name" ]]; then
            TRACE_ENV+=("$name=${!name}")
        fi
    done
    sudo -n env "${TRACE_ENV[@]}" xcrun xctrace record \
        --template Allocations \
        --time-limit "${ASUPERSYNC_XCTRACE_TIME_LIMIT:-300s}" \
        --output "$TRACE_PATH" \
        --launch -- "$@"
    TRACE_TOC="$(sudo -n xcrun xctrace export --input "$TRACE_PATH" --toc)"
    TARGET_EXIT="$(printf '%s\n' "$TRACE_TOC" | sed -n 's/.*return-exit-status="\([0-9][0-9]*\)".*/\1/p' | head -n 1)"
    if [[ -z "$TARGET_EXIT" ]]; then
        echo "ERROR: xctrace did not report the launched process exit status" >&2
        exit 1
    fi
    ALLOCATION_ROWS="$(sudo -n xcrun xctrace export --input "$TRACE_PATH" --xpath "$XPATH")"
    HEAP_ROW="$(printf '%s\n' "$ALLOCATION_ROWS" | grep '<row category="All Heap Allocations"' | head -n 1)"
    if [[ -z "$HEAP_ROW" ]]; then
        echo "ERROR: xctrace did not emit the All Heap Allocations statistics row" >&2
        exit 1
    fi
    printf 'ASUPERSYNC_XCTRACE_ALLOCATION_ROW=%s\n' "$HEAP_ROW"
    printf 'ASUPERSYNC_XCTRACE_PATH=%s\n' "$TRACE_PATH"
    exit "$TARGET_EXIT"
fi

if [[ "${1:-}" == "--cargo-runner-valgrind" ]]; then
    shift
    if [[ $# -eq 0 ]]; then
        echo "ERROR: --cargo-runner-valgrind requires Cargo's test binary and arguments" >&2
        exit 2
    fi
    if ! command -v valgrind &>/dev/null; then
        echo "ERROR: valgrind is required for the allocation runner" >&2
        exit 1
    fi
    exec valgrind \
        --tool=memcheck \
        --leak-check=summary \
        --show-leak-kinds=all \
        --errors-for-leak-kinds=all \
        --error-exitcode=99 \
        "$@"
fi

if [[ "${1:-}" == "--cargo-runner-heaptrack" ]]; then
    shift
    if [[ $# -eq 0 ]]; then
        echo "ERROR: --cargo-runner-heaptrack requires Cargo's test binary and arguments" >&2
        exit 2
    fi
    if ! command -v heaptrack &>/dev/null; then
        echo "ERROR: heaptrack is required for the allocation runner" >&2
        exit 1
    fi
    TRACE_ROOT="${ASUPERSYNC_ALLOC_CENSUS_DIR:-${TMPDIR:-/tmp}/asupersync_alloc_census}"
    mkdir -p "$TRACE_ROOT"
    TRACE_ID="$(date +%Y%m%d_%H%M%S)_$$"
    TRACE_PREFIX="$TRACE_ROOT/heaptrack_${TRACE_ID}"
    set +e
    heaptrack -o "$TRACE_PREFIX" -- "$@"
    TARGET_EXIT=$?
    set -e
    RAW_CANDIDATES=("$TRACE_PREFIX".*)
    RAW_FILE="${RAW_CANDIDATES[0]:-}"
    if [[ -z "$RAW_FILE" || ! -f "$RAW_FILE" ]]; then
        echo "ERROR: heaptrack did not emit a raw allocation trace" >&2
        exit 1
    fi
    SUMMARY="$(heaptrack --analyze "$RAW_FILE")"
    printf '%s\n' "$SUMMARY" | sed -n \
        -e '/^calls to allocation functions:/p' \
        -e '/^temporary memory allocations:/p' \
        -e '/^peak heap memory consumption:/p' \
        -e '/^peak RSS (including heaptrack overhead):/p' \
        -e '/^total memory leaked:/p' \
        | sed 's/^/ASUPERSYNC_HEAPTRACK_SUMMARY=/'
    printf 'ASUPERSYNC_HEAPTRACK_PATH=%s\n' "$RAW_FILE"
    exit "$TARGET_EXIT"
fi

if [[ "${1:-}" == "--cargo-runner-rss" ]]; then
    shift
    if [[ $# -eq 0 ]]; then
        echo "ERROR: --cargo-runner-rss requires Cargo's test binary and arguments" >&2
        exit 2
    fi
    if [[ "$(uname -s)" == "Darwin" ]]; then
        exec /usr/bin/time -l "$@"
    fi
    exec /usr/bin/time -v "$@"
fi

usage() {
    cat <<'USAGE'
Usage: ./scripts/alloc_census.sh [options]

Options:
  --tool <heaptrack|valgrind>   Allocation tool (default: heaptrack)
  --cmd  "<command>"             Command to profile (required; pass a prebuilt binary path)
  --out  <dir>                   Output directory (default: baselines/alloc_census)
  --flamegraph                   Attempt a flamegraph capture (cargo-flamegraph)
  --cargo-runner-xctrace         Internal macOS Cargo test runner; records Allocations
  --cargo-runner-heaptrack       Internal Linux Cargo test runner; records heap totals
  --cargo-runner-valgrind        Internal Linux Cargo test runner; records heap totals
  --cargo-runner-rss             Internal Cargo test runner; records peak RSS
  -h, --help                     Show help

Examples:
  rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_alloc_census" cargo bench --features criterion-benches --bench scheduler_benchmark --no-run
  ./scripts/alloc_census.sh --tool valgrind --cmd "path/to/prebuilt-benchmark"
  ./scripts/alloc_census.sh --flamegraph
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool) TOOL="$2"; shift 2 ;;
        --cmd) read -r -a CMD <<< "$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --flamegraph) FLAMEGRAPH=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ${#CMD[@]} -eq 0 ]]; then
    echo "ERROR: --cmd is required; prebuild Cargo benchmarks through rch, then profile the binary path." >&2
    exit 2
fi

for token in "${CMD[@]}"; do
    if [[ "$token" == "cargo" && "${ALLOW_LOCAL_CARGO}" != "1" ]]; then
        echo "ERROR: local cargo profiling is disabled by default. Prebuild through rch and pass a binary path, or set ALLOW_LOCAL_CARGO=1 intentionally." >&2
        exit 2
    fi
done

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
        RAW_CANDIDATES=("$OUT_PREFIX".*)
        RAW_FILE="${RAW_CANDIDATES[0]:-}"
        if [[ -z "$RAW_FILE" || ! -f "$RAW_FILE" ]]; then
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
            if [[ "${ALLOW_LOCAL_CARGO}" != "1" ]]; then
                echo "WARN: local cargo flamegraph requires ALLOW_LOCAL_CARGO=1; skipping" >&2
                FLAMEGRAPH_FILE=""
            else
                "$CARGO_BIN" flamegraph --output "$FLAMEGRAPH_FILE" -- "${CMD[@]:1}"
            fi
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
