#!/usr/bin/env bash
# Perf E2E Runner (bd-2nf3x)
#
# Runs selected benchmark suites, captures Criterion baselines,
# optionally compares against a baseline, and writes a structured report.
#
# Usage:
#   ./scripts/run_perf_e2e.sh --list
#   ./scripts/run_perf_e2e.sh --bench phase0_baseline --bench scheduler_benchmark
#   ./scripts/run_perf_e2e.sh --compare baselines/criterion/baseline_latest.json
#   ./scripts/run_perf_e2e.sh --save-baseline baselines/criterion
#
# Environment:
#   PERF_OUTPUT_DIR    - run outputs (default: target/perf-results)
#   PERF_BASELINE_DIR  - default baseline dir (auto: baselines/criterion or baselines)
#   PERF_TIMEOUT       - per-bench timeout seconds (default: 0 = no timeout)
#   PERF_BENCH_ARGS    - extra args passed to cargo bench (default: "-- --noplot")
#   ASUPERSYNC_SEED    - deterministic seed (if benchmark uses it)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DEFAULT_BASELINE_DIR="${PROJECT_ROOT}/baselines/criterion"
if [[ ! -d "$DEFAULT_BASELINE_DIR" ]]; then
    DEFAULT_BASELINE_DIR="${PROJECT_ROOT}/baselines"
fi

OUTPUT_DIR="${PERF_OUTPUT_DIR:-${PROJECT_ROOT}/target/perf-results}"
BASELINE_DIR="${PERF_BASELINE_DIR:-$DEFAULT_BASELINE_DIR}"
TIMEOUT_SEC="${PERF_TIMEOUT:-0}"

DEFAULT_BENCHES=(
    phase0_baseline
    scheduler_benchmark
    protocol_benchmark
    timer_wheel
    tracing_overhead
    reactor_benchmark
    raptorq_benchmark
    cancel_trace_bench
    cancel_drain_bench
    egraph_benchmark
    homology_benchmark
    golden_output
)

BENCHES=()
COMPARE_PATH=""
SAVE_DIR=""
METRIC="median_ns"
MAX_REGRESSION_PCT="10"
BENCH_ARGS_STR="${PERF_BENCH_ARGS:-"-- --noplot"}"
NO_COMPARE=0

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_perf_e2e.sh [options]

Options:
  --list                         List available benchmark suites
  --bench <name>                 Run a specific benchmark suite (repeatable)
  --compare <baseline.json>      Compare against a baseline file
  --no-compare                   Skip baseline comparison
  --save-baseline <dir>          Save baseline JSON into directory
  --metric <mean_ns|median_ns|p95_ns|p99_ns>  Metric for regression check
  --max-regression-pct <pct>     Regression threshold percent (default: 10)
  --timeout <sec>                Per-bench timeout in seconds (default: 0)
  --bench-args "<args>"          Extra args passed to cargo bench
  --seed <value>                 Set ASUPERSYNC_SEED for benches
  -h, --help                     Show help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            printf "Available benchmarks:\n"
            for bench in "${DEFAULT_BENCHES[@]}"; do
                printf "  %s\n" "$bench"
            done
            exit 0
            ;;
        --bench)
            BENCHES+=("$2"); shift 2 ;;
        --compare)
            COMPARE_PATH="$2"; shift 2 ;;
        --no-compare)
            NO_COMPARE=1; shift ;;
        --save-baseline)
            SAVE_DIR="$2"; shift 2 ;;
        --metric)
            METRIC="$2"; shift 2 ;;
        --max-regression-pct)
            MAX_REGRESSION_PCT="$2"; shift 2 ;;
        --timeout)
            TIMEOUT_SEC="$2"; shift 2 ;;
        --bench-args)
            BENCH_ARGS_STR="$2"; shift 2 ;;
        --seed)
            export ASUPERSYNC_SEED="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ${#BENCHES[@]} -eq 0 ]]; then
    BENCHES=("${DEFAULT_BENCHES[@]}")
fi

BASELINE_LATEST="${BASELINE_DIR}/baseline_latest.json"
if [[ -z "$COMPARE_PATH" && "$NO_COMPARE" -eq 0 && -f "$BASELINE_LATEST" ]]; then
    COMPARE_PATH="$BASELINE_LATEST"
fi

# shellcheck disable=SC2206
BENCH_ARGS=($BENCH_ARGS_STR)

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_DIR}/perf_${TIMESTAMP}"
LOG_DIR="${RUN_DIR}/logs"
ARTIFACT_DIR="${RUN_DIR}/artifacts"
REPORT_FILE="${RUN_DIR}/report.json"
COMPARE_LOG="${ARTIFACT_DIR}/compare.log"
COMPARE_STDOUT="${ARTIFACT_DIR}/compare.txt"
BASELINE_CURRENT="${ARTIFACT_DIR}/baseline_current.json"

mkdir -p "$LOG_DIR" "$ARTIFACT_DIR"

echo "==================================================================="
echo "                 Asupersync Perf E2E Runner                        "
echo "==================================================================="
echo ""
echo "Config:"
echo "  Output:            ${RUN_DIR}"
echo "  Baseline dir:      ${BASELINE_DIR}"
echo "  Compare baseline:  ${COMPARE_PATH:-<none>}"
echo "  Save baseline:     ${SAVE_DIR:-<none>}"
echo "  Metric:            ${METRIC}"
echo "  Max regression %:  ${MAX_REGRESSION_PCT}"
echo "  Timeout:           ${TIMEOUT_SEC}s per bench"
echo "  Seed:              ${ASUPERSYNC_SEED:-<unset>}"
echo ""

BENCH_RESULTS_JSON=""
BENCH_FAIL=0

append_result() {
    local entry="$1"
    if [[ -z "$BENCH_RESULTS_JSON" ]]; then
        BENCH_RESULTS_JSON="$entry"
    else
        BENCH_RESULTS_JSON="${BENCH_RESULTS_JSON},${entry}"
    fi
}

for bench in "${BENCHES[@]}"; do
    log_file="${LOG_DIR}/${bench}_${TIMESTAMP}.log"
    cmd=(cargo bench --bench "$bench")
    if [[ ${#BENCH_ARGS[@]} -gt 0 ]]; then
        cmd+=("${BENCH_ARGS[@]}")
    fi

    echo ">>> Running ${bench}"
    echo "    Command: ${cmd[*]}"

    start_ts=$(date +%s)
    set +e
    if [[ "$TIMEOUT_SEC" -gt 0 && -x "$(command -v timeout)" ]]; then
        timeout "$TIMEOUT_SEC" "${cmd[@]}" 2>&1 | tee "$log_file"
        rc=${PIPESTATUS[0]}
    else
        "${cmd[@]}" 2>&1 | tee "$log_file"
        rc=${PIPESTATUS[0]}
    fi
    set -e
    end_ts=$(date +%s)
    duration=$((end_ts - start_ts))

    if [[ "$rc" -ne 0 ]]; then
        BENCH_FAIL=$((BENCH_FAIL + 1))
    fi

    append_result "{\"name\":\"${bench}\",\"exit_code\":${rc},\"duration_sec\":${duration},\"log_file\":\"${log_file}\"}"
done

COMPARE_EXIT=0
if [[ -n "$COMPARE_PATH" ]]; then
    set +e
    ./scripts/capture_baseline.sh \
        --compare "$COMPARE_PATH" \
        --metric "$METRIC" \
        --max-regression-pct "$MAX_REGRESSION_PCT" \
        > /tmp/asupersync_compare_stdout.txt 2> "$COMPARE_LOG"
    COMPARE_EXIT=$?
    set -e
    if [[ -f /tmp/asupersync_compare_stdout.txt ]]; then
        cp /tmp/asupersync_compare_stdout.txt "$COMPARE_STDOUT"
    fi
    if [[ -f /tmp/asupersync_baseline.json ]]; then
        cp /tmp/asupersync_baseline.json "$BASELINE_CURRENT"
    fi
else
    ./scripts/capture_baseline.sh > /tmp/asupersync_compare_stdout.txt
    if [[ -f /tmp/asupersync_compare_stdout.txt ]]; then
        cp /tmp/asupersync_compare_stdout.txt "$COMPARE_STDOUT"
    fi
    if [[ -f /tmp/asupersync_baseline.json ]]; then
        cp /tmp/asupersync_baseline.json "$BASELINE_CURRENT"
    fi
fi

SAVED_BASELINE=""
if [[ -n "$SAVE_DIR" ]]; then
    ./scripts/capture_baseline.sh --save "$SAVE_DIR" > /tmp/asupersync_save_stdout.txt
    if [[ -d "$SAVE_DIR" ]]; then
        SAVED_BASELINE=$(ls -1t "$SAVE_DIR"/baseline_*.json 2>/dev/null | head -n 1 || true)
    fi
fi

GIT_SHA=""
if command -v git &>/dev/null; then
    GIT_SHA=$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || true)
fi
RUSTC_VER=$(rustc -V 2>/dev/null || echo "")
CARGO_VER=$(cargo -V 2>/dev/null || echo "")
OS_NAME=$(uname -s 2>/dev/null || echo "")
OS_ARCH=$(uname -m 2>/dev/null || echo "")
OS_RELEASE=$(uname -r 2>/dev/null || echo "")

cat > "$REPORT_FILE" <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_sha": "${GIT_SHA}",
  "seed": "${ASUPERSYNC_SEED:-}",
  "benchmarks": [${BENCH_RESULTS_JSON}],
  "baseline": {
    "current_path": "${BASELINE_CURRENT}",
    "compare_path": "${COMPARE_PATH}",
    "compare_exit": ${COMPARE_EXIT},
    "compare_log": "${COMPARE_LOG}",
    "compare_stdout": "${COMPARE_STDOUT}",
    "saved_path": "${SAVED_BASELINE}",
    "latest_path": "${BASELINE_LATEST}"
  },
  "config": {
    "metric": "${METRIC}",
    "max_regression_pct": ${MAX_REGRESSION_PCT},
    "timeout_sec": ${TIMEOUT_SEC},
    "bench_args": "${BENCH_ARGS_STR}"
  },
  "env": {
    "CI": "${CI:-}",
    "RUSTFLAGS": "${RUSTFLAGS:-}",
    "RUST_LOG": "${RUST_LOG:-}"
  },
  "system": {
    "os": "${OS_NAME}",
    "arch": "${OS_ARCH}",
    "release": "${OS_RELEASE}",
    "rustc": "${RUSTC_VER}",
    "cargo": "${CARGO_VER}"
  }
}
EOF

echo ""
echo "==================================================================="
echo "                         PERF SUMMARY                              "
echo "==================================================================="
echo "  Report:   ${REPORT_FILE}"
echo "  Baseline: ${BASELINE_CURRENT}"
if [[ -n "$COMPARE_PATH" ]]; then
    echo "  Compare:  ${COMPARE_PATH} (exit ${COMPARE_EXIT})"
fi
if [[ -n "$SAVED_BASELINE" ]]; then
    echo "  Saved:    ${SAVED_BASELINE}"
fi
echo "==================================================================="

if [[ "$BENCH_FAIL" -gt 0 ]]; then
    echo "ERROR: ${BENCH_FAIL} benchmark(s) failed" >&2
    exit 1
fi
if [[ "$COMPARE_EXIT" -ne 0 ]]; then
    echo "ERROR: baseline comparison failed (exit ${COMPARE_EXIT})" >&2
    exit 1
fi
