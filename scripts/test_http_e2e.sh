#!/usr/bin/env bash
# HTTP E2E Test Runner (bd-26l3)
#
# Runs the HTTP integration tests with deterministic settings,
# structured logging, seed info, and artifact capture.
#
# Usage:
#   ./scripts/test_http_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)
#   RCH_BIN        - rch executable used for all Cargo commands (default: rch)
#   RCH_TARGET_DIR - remote Cargo target directory
#
# Pass/Fail Semantics:
#   PASS when cargo test exits 0 and no failure patterns are detected.
#   FAIL when cargo test is non-zero or any failure pattern is detected.
#
# Artifact Bundle:
#   summary.json + suite log + extracted seeds/traces under
#   target/e2e-results/http/artifacts_<timestamp>/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/http"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/http_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
TEST_FILTER="${1:-}"
SUITE_TIMEOUT="${SUITE_TIMEOUT:-180}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch-target-http-e2e-${USER:-unknown}-${TIMESTAMP}-$$}"
WORKLOAD_ID="${WORKLOAD_ID:-AA01-WL-IO-HTTP-EX1}"
RUNTIME_PROFILE="${RUNTIME_PROFILE:-native-e2e}"
WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_http_e2e.sh::http_e2e/all_features}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi
RUN_WITH_RCH_BOOL="true"

run_cargo() {
    "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
}

run_timeout_cargo() {
    local timeout_sec="$1"
    shift
    timeout "$timeout_sec" "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
}

reject_rch_local_fallback_log() {
    local log_path="$1"
    if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
        echo "  FATAL: rch local fallback detected; refusing local cargo execution"
        echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
        return 86
    fi
}

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

echo "==================================================================="
echo "                Asupersync HTTP E2E Tests                         "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timeout:         ${SUITE_TIMEOUT}s"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Output:          ${LOG_FILE}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  Workload:        ${WORKLOAD_ID}"
echo "  Profile:         ${RUNTIME_PROFILE}"
echo "  RCH_BIN:         ${RCH_BIN}"
echo "  RCH target dir:  ${RCH_TARGET_DIR}"
echo "  RCH mode:        enabled"
echo ""

# --- [1/4] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! run_cargo check --test http_e2e --all-features >"${ARTIFACT_DIR}/compile_errors.log" 2>&1; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
reject_rch_local_fallback_log "${ARTIFACT_DIR}/compile_errors.log"
echo "  OK"

# --- [2/4] Run tests ---
echo ""
echo ">>> [2/4] Running HTTP E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test http_e2e --all-features)
RUN_ARGS=(--nocapture --test-threads=1)

if [ -n "$TEST_FILTER" ]; then
    RUN_ARGS+=("$TEST_FILTER")
fi

pushd "$PROJECT_ROOT" >/dev/null
if run_timeout_cargo "$SUITE_TIMEOUT" test "${CARGO_ARGS[@]}" -- "${RUN_ARGS[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

# --- [3/4] Failure pattern analysis ---
echo ""
echo ">>> [3/4] Checking output for failure patterns..."

PATTERN_FAILURES=0

check_pattern() {
    local pattern="$1"
    local label="$2"
    if grep -q "$pattern" "$LOG_FILE" 2>/dev/null; then
        echo "  ERROR: ${label}"
        grep -n "$pattern" "$LOG_FILE" | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "panicked at"         "panic detected"
check_pattern "assertion failed"    "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "invalid request"     "invalid request"
check_pattern "malformed"           "malformed input"
check_pattern "connection reset"    "connection reset"
if grep -Eq '^\[RCH\] local \(|falling back to local' "$LOG_FILE" 2>/dev/null; then
    echo "  ERROR: rch local fallback detected"
    echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
    ((PATTERN_FAILURES++)) || true
fi

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4/4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")
SUITE_ID="http_e2e"
SCENARIO_ID="E2E-SUITE-HTTP"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
REPRO_COMMAND="WORKLOAD_ID=${WORKLOAD_ID} RUNTIME_PROFILE=${RUNTIME_PROFILE} WORKLOAD_CONFIG_REF='${WORKLOAD_CONFIG_REF}' TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} RCH_TARGET_DIR='${RCH_TARGET_DIR}' bash ${SCRIPT_DIR}/$(basename "$0")${TEST_FILTER:+ ${TEST_FILTER}}"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi
FAILURE_CLASS="test_or_pattern_failure"
if [ "$SUITE_STATUS" = "passed" ]; then
    FAILURE_CLASS="none"
fi

cat > "${SUMMARY_FILE}" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "workload_id": "${WORKLOAD_ID}",
  "runtime_profile": "${RUNTIME_PROFILE}",
  "workload_config_ref": "${WORKLOAD_CONFIG_REF}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "failure_class": "${FAILURE_CLASS}",
  "repro_command": "${REPRO_COMMAND}",
  "artifact_path": "${SUMMARY_FILE}",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "test_filter": "${TEST_FILTER}",
  "rch_bin": "${RCH_BIN}",
  "rch_target_dir": "${RCH_TARGET_DIR}",
  "run_with_rch": ${RUN_WITH_RCH_BOOL},
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "${LOG_FILE}",
  "artifact_dir": "${ARTIFACT_DIR}"
}
ENDJSON

grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "  Summary: ${SUMMARY_FILE}"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                      HTTP E2E SUMMARY                            "
echo "==================================================================="
echo "  Seed:     ${TEST_SEED}"
echo "  Passed:   ${PASSED}"
echo "  Failed:   ${FAILED}"
echo "  Patterns: ${PATTERN_FAILURES} failure patterns"
echo ""

if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Logs:   ${LOG_FILE}"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
