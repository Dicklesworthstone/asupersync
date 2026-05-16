#!/usr/bin/env bash
# Perf E2E Runner (bd-2nf3x)
#
# Runs selected benchmark suites, captures Criterion baselines,
# optionally compares against a baseline, and writes a structured report.
#
# Usage:
#   ./scripts/run_perf_e2e.sh --list
#   ./scripts/run_perf_e2e.sh --bench phase0_baseline --bench scheduler_benchmark
#   ./scripts/run_perf_e2e.sh --compare baselines/baseline_latest.json
#   ./scripts/run_perf_e2e.sh --save-baseline baselines/
#
# Environment:
#   PERF_OUTPUT_DIR    - run outputs (default: target/perf-results)
#   PERF_BASELINE_DIR  - default baseline dir (default: baselines/)
#   PERF_TIMEOUT       - per-bench timeout seconds (default: 0 = no timeout)
#   PERF_BENCH_ARGS    - extra args passed to cargo bench (default: "-- --noplot")
#   ASUPERSYNC_SEED    - deterministic seed (if benchmark uses it)
#   RCH_BIN            - remote compilation helper executable (default: rch,
#                        required for benchmark execution)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DEFAULT_BASELINE_DIR="${PROJECT_ROOT}/baselines"

OUTPUT_DIR="${PERF_OUTPUT_DIR:-${PROJECT_ROOT}/target/perf-results}"
BASELINE_DIR="${PERF_BASELINE_DIR:-$DEFAULT_BASELINE_DIR}"
TIMEOUT_SEC="${PERF_TIMEOUT:-0}"
RCH_BIN="${RCH_BIN:-rch}"
WORKLOAD_ID="${WORKLOAD_ID:-AA01-WL-CPU-001}"
RUNTIME_PROFILE="${RUNTIME_PROFILE:-bench-release}"
WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/run_perf_e2e.sh::phase0_baseline,scheduler_benchmark}"

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

require_rch_for_benchmark_execution() {
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "ERROR: benchmark execution requires RCH_BIN ('$RCH_BIN') to resolve to a working rch executable; refusing local cargo bench fallback." >&2
        exit 1
    fi
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

require_rch_for_benchmark_execution
RUN_WITH_RCH_BOOL="true"

BASELINE_LATEST="${BASELINE_DIR}/baseline_latest.json"
if [[ -z "$COMPARE_PATH" && "$NO_COMPARE" -eq 0 && -f "$BASELINE_LATEST" ]]; then
    COMPARE_PATH="$BASELINE_LATEST"
fi

# shellcheck disable=SC2206
BENCH_ARGS=($BENCH_ARGS_STR)

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RCH_TARGET_ROOT="${RCH_TARGET_ROOT:-${TMPDIR:-/tmp}/rch_target_perf_e2e_${USER:-unknown}_${TIMESTAMP}}"
RUN_DIR="${OUTPUT_DIR}/perf_${TIMESTAMP}"
LOG_DIR="${RUN_DIR}/logs"
ARTIFACT_DIR="${RUN_DIR}/artifacts"
REPORT_FILE="${RUN_DIR}/report.json"
COMPARE_LOG="${ARTIFACT_DIR}/compare.log"
COMPARE_STDOUT="${ARTIFACT_DIR}/compare.txt"
BASELINE_CURRENT="${ARTIFACT_DIR}/baseline_current.json"
GATE_EVENTS_FILE="${ARTIFACT_DIR}/gate_events.ndjson"
GATE_SCHEMA_VERSION="raptorq-g2-perf-gate-v1"
RUN_REPRO_COMMAND="WORKLOAD_ID=${WORKLOAD_ID} RUNTIME_PROFILE=${RUNTIME_PROFILE} WORKLOAD_CONFIG_REF='${WORKLOAD_CONFIG_REF}' RCH_BIN=${RCH_BIN} RCH_TARGET_ROOT='${RCH_TARGET_ROOT}' PERF_TIMEOUT=${TIMEOUT_SEC} PERF_BENCH_ARGS='${BENCH_ARGS_STR}' ./scripts/run_perf_e2e.sh"

mkdir -p "$LOG_DIR" "$ARTIFACT_DIR"
: > "$GATE_EVENTS_FILE"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

emit_gate_event() {
    local event="$1"
    local status="$2"
    local scenario_id="$3"
    local message="$4"
    local artifact_path="$5"
    local repro_command="$6"
    printf '{"schema_version":"%s","event":"%s","status":"%s","scenario_id":"%s","workload_id":"%s","runtime_profile":"%s","workload_config_ref":"%s","seed":"%s","artifact_path":"%s","repro_command":"%s","message":"%s"}\n' \
        "$GATE_SCHEMA_VERSION" \
        "$(json_escape "$event")" \
        "$(json_escape "$status")" \
        "$(json_escape "$scenario_id")" \
        "$(json_escape "$WORKLOAD_ID")" \
        "$(json_escape "$RUNTIME_PROFILE")" \
        "$(json_escape "$WORKLOAD_CONFIG_REF")" \
        "$(json_escape "${ASUPERSYNC_SEED:-}")" \
        "$(json_escape "$artifact_path")" \
        "$(json_escape "$repro_command")" \
        "$(json_escape "$message")" >> "$GATE_EVENTS_FILE"
}

reject_rch_local_fallback_log() {
    local label="$1"
    local log_file="$2"
    local safe_label="${label//[^A-Za-z0-9_]/_}"
    local marker_file="${ARTIFACT_DIR}/${safe_label}_rch_local_fallback.txt"

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_file" 2>/dev/null; then
        echo "FATAL: rch local fallback detected in ${label}; refusing local cargo execution" >&2
        echo "rch local fallback detected in ${label}; refusing local cargo execution" > "$marker_file"
        emit_gate_event \
            "rch_local_fallback" \
            "fail" \
            "$label" \
            "Refusing local cargo execution after rch local fallback" \
            "$marker_file" \
            "$RUN_REPRO_COMMAND"
        exit 86
    fi
}

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
echo "  Workload:          ${WORKLOAD_ID}"
echo "  Profile:           ${RUNTIME_PROFILE}"
echo "  RCH target root:   ${RCH_TARGET_ROOT}"
echo "  RCH mode:          enabled"
echo ""

emit_gate_event \
    "perf_run_start" \
    "pass" \
    "RQ-G2-PERF-RUN" \
    "Starting deterministic perf gate run" \
    "$RUN_DIR" \
    "$RUN_REPRO_COMMAND"

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
    bench_repro_command="${RUN_REPRO_COMMAND} --bench ${bench}"
    safe_bench="${bench//[^A-Za-z0-9_]/_}"
    bench_target_dir="${RCH_TARGET_ROOT}/${safe_bench}"
    cmd=("$RCH_BIN" exec -- env "CARGO_TARGET_DIR=${bench_target_dir}" cargo bench --bench "$bench")
    if [[ ${#BENCH_ARGS[@]} -gt 0 ]]; then
        cmd+=("${BENCH_ARGS[@]}")
        bench_repro_command="${bench_repro_command} --bench-args '${BENCH_ARGS_STR}'"
    fi

    echo ">>> Running ${bench}"
    echo "    Command: ${cmd[*]}"
    echo "    Target:  ${bench_target_dir}"

    emit_gate_event \
        "bench_start" \
        "pass" \
        "$bench" \
        "Benchmark run started" \
        "$log_file" \
        "$bench_repro_command"

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
    reject_rch_local_fallback_log "$bench" "$log_file"
    end_ts=$(date +%s)
    duration=$((end_ts - start_ts))

    if [[ "$rc" -ne 0 ]]; then
        BENCH_FAIL=$((BENCH_FAIL + 1))
        emit_gate_event \
            "bench_end" \
            "fail" \
            "$bench" \
            "Benchmark run failed with exit code ${rc}" \
            "$log_file" \
            "$bench_repro_command"
    else
        emit_gate_event \
            "bench_end" \
            "pass" \
            "$bench" \
            "Benchmark run completed successfully" \
            "$log_file" \
            "$bench_repro_command"
    fi

    append_result "{\"name\":\"${bench}\",\"exit_code\":${rc},\"duration_sec\":${duration},\"log_file\":\"${log_file}\",\"target_dir\":\"${bench_target_dir}\"}"
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
    if [[ "$COMPARE_EXIT" -eq 0 ]]; then
        emit_gate_event \
            "baseline_compare" \
            "pass" \
            "RQ-G2-PERF-COMPARE" \
            "Baseline comparison passed" \
            "$COMPARE_STDOUT" \
            "${RUN_REPRO_COMMAND} --compare ${COMPARE_PATH} --metric ${METRIC} --max-regression-pct ${MAX_REGRESSION_PCT}"
    else
        emit_gate_event \
            "baseline_compare" \
            "fail" \
            "RQ-G2-PERF-COMPARE" \
            "Baseline comparison failed with exit code ${COMPARE_EXIT}" \
            "$COMPARE_LOG" \
            "${RUN_REPRO_COMMAND} --compare ${COMPARE_PATH} --metric ${METRIC} --max-regression-pct ${MAX_REGRESSION_PCT}"
    fi
else
    ./scripts/capture_baseline.sh > /tmp/asupersync_compare_stdout.txt
    if [[ -f /tmp/asupersync_compare_stdout.txt ]]; then
        cp /tmp/asupersync_compare_stdout.txt "$COMPARE_STDOUT"
    fi
    if [[ -f /tmp/asupersync_baseline.json ]]; then
        cp /tmp/asupersync_baseline.json "$BASELINE_CURRENT"
    fi
    emit_gate_event \
        "baseline_capture" \
        "pass" \
        "RQ-G2-PERF-CAPTURE" \
        "Captured current baseline without comparison" \
        "$BASELINE_CURRENT" \
        "${RUN_REPRO_COMMAND} --no-compare"
fi

SAVED_BASELINE=""
if [[ -n "$SAVE_DIR" ]]; then
    ./scripts/capture_baseline.sh --save "$SAVE_DIR" > /tmp/asupersync_save_stdout.txt
    if [[ -d "$SAVE_DIR" ]]; then
        SAVED_BASELINE=$(find "$SAVE_DIR" -maxdepth 1 -type f -name 'baseline_*.json' -printf '%T@ %p\n' 2>/dev/null \
            | sort -rn \
            | awk 'NR == 1 { sub(/^[^ ]+ /, ""); print }')
    fi
fi

GIT_SHA=""
if command -v git &>/dev/null; then
    GIT_SHA=$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || true)
fi
RUSTC_VER=$(rustc -V 2>/dev/null || echo "")
CARGO_VERSION_LOG="${ARTIFACT_DIR}/cargo_version.log"
set +e
"$RCH_BIN" exec -- env "CARGO_TARGET_DIR=${RCH_TARGET_ROOT}/cargo_version" cargo -V > "$CARGO_VERSION_LOG" 2>&1
CARGO_VERSION_STATUS=$?
set -e
reject_rch_local_fallback_log "cargo-version" "$CARGO_VERSION_LOG"
CARGO_VER=""
if [[ "$CARGO_VERSION_STATUS" -eq 0 ]]; then
    CARGO_VER=$(tail -n 1 "$CARGO_VERSION_LOG" || echo "")
fi
OS_NAME=$(uname -s 2>/dev/null || echo "")
OS_ARCH=$(uname -m 2>/dev/null || echo "")
OS_RELEASE=$(uname -r 2>/dev/null || echo "")

cat > "$REPORT_FILE" <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_sha": "${GIT_SHA}",
  "workload_id": "${WORKLOAD_ID}",
  "runtime_profile": "${RUNTIME_PROFILE}",
  "workload_config_ref": "${WORKLOAD_CONFIG_REF}",
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
    "bench_args": "${BENCH_ARGS_STR}",
    "rch_bin": "${RCH_BIN}",
    "rch_target_root": "${RCH_TARGET_ROOT}",
    "run_with_rch": ${RUN_WITH_RCH_BOOL}
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
  },
  "gate": {
    "schema_version": "${GATE_SCHEMA_VERSION}",
    "event_log": "${GATE_EVENTS_FILE}",
    "repro_command": "${RUN_REPRO_COMMAND}",
    "status": "$(
if [[ "$BENCH_FAIL" -gt 0 || "$COMPARE_EXIT" -ne 0 ]]; then
    printf "fail"
else
    printf "pass"
fi
)"
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
    emit_gate_event \
        "perf_run_end" \
        "fail" \
        "RQ-G2-PERF-RUN" \
        "${BENCH_FAIL} benchmark(s) failed" \
        "$REPORT_FILE" \
        "$RUN_REPRO_COMMAND"
    echo "ERROR: ${BENCH_FAIL} benchmark(s) failed" >&2
    exit 1
fi
if [[ "$COMPARE_EXIT" -ne 0 ]]; then
    emit_gate_event \
        "perf_run_end" \
        "fail" \
        "RQ-G2-PERF-RUN" \
        "Baseline comparison failed with exit ${COMPARE_EXIT}" \
        "$COMPARE_LOG" \
        "${RUN_REPRO_COMMAND} --compare ${COMPARE_PATH} --metric ${METRIC} --max-regression-pct ${MAX_REGRESSION_PCT}"
    echo "ERROR: baseline comparison failed (exit ${COMPARE_EXIT})" >&2
    exit 1
fi

emit_gate_event \
    "perf_run_end" \
    "pass" \
    "RQ-G2-PERF-RUN" \
    "Perf run and optional baseline compare passed" \
    "$REPORT_FILE" \
    "$RUN_REPRO_COMMAND"
