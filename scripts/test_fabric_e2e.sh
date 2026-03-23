#!/usr/bin/env bash
# FABRIC E2E Test Runner (asupersync-8w83i.17.4)
#
# Runs the FABRIC E2E integration tests with deterministic settings,
# structured logging, scenario-summary extraction, and artifact capture.
#
# Usage:
#   ./scripts/test_fabric_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/fabric"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/fabric_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
TEST_FILTER="${1:-}"
RCH_BIN="${RCH_BIN:-rch}"
WORKLOAD_ID="${WORKLOAD_ID:-AA01-WL-FABRIC-001}"
RUNTIME_PROFILE="${RUNTIME_PROFILE:-fabric-lab-e2e}"
FABRIC_FEATURES="${FABRIC_FEATURES:-messaging-fabric}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/rch-target-fabric-e2e-${USER:-unknown}-${TIMESTAMP}-$$}"
WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_fabric_e2e.sh::fabric_e2e/features=${FABRIC_FEATURES}}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

RUN_WITH_RCH=0
RUN_WITH_RCH_BOOL="false"
if command -v "$RCH_BIN" >/dev/null 2>&1; then
    RUN_WITH_RCH=1
    RUN_WITH_RCH_BOOL="true"
fi

run_cargo() {
    if [ "$RUN_WITH_RCH" -eq 1 ]; then
        "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
    else
        cargo "$@"
    fi
}

run_timeout_cargo() {
    local timeout_sec="$1"
    shift
    if [ "$RUN_WITH_RCH" -eq 1 ]; then
        timeout "$timeout_sec" "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
    else
        timeout "$timeout_sec" cargo "$@"
    fi
}

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

echo "==================================================================="
echo "                 Asupersync FABRIC E2E Tests                       "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Output:          ${LOG_FILE}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  Workload:        ${WORKLOAD_ID}"
echo "  Profile:         ${RUNTIME_PROFILE}"
echo "  Features:        ${FABRIC_FEATURES}"
echo "  RCH target dir:  ${RCH_TARGET_DIR}"
echo "  RCH mode:        $([ "$RUN_WITH_RCH" -eq 1 ] && printf "enabled" || printf "disabled")"
echo ""

echo ">>> [1/4] Pre-flight: checking compilation..."
if ! run_cargo check --test fabric_e2e --features "${FABRIC_FEATURES}" 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
echo "  OK"

echo ""
echo ">>> [2/4] Running FABRIC E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test fabric_e2e --features "${FABRIC_FEATURES}")
RUN_ARGS=(--nocapture --test-threads=1)

if [ -n "$TEST_FILTER" ]; then
    RUN_ARGS+=("$TEST_FILTER")
fi

pushd "$PROJECT_ROOT" >/dev/null
if run_timeout_cargo 180 test "${CARGO_ARGS[@]}" -- "${RUN_ARGS[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

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

check_pattern "panicked at" "panic detected"
check_pattern "assertion failed" "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Task leak detected" "task leak detected"
check_pattern "obligation.*leak" "obligation leak"
check_pattern "oracle_violations" "oracle violations reported"

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")
SUITE_ID="fabric_e2e"
SCENARIO_ID="E2E-SUITE-FABRIC"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
SCENARIO_SUMMARY_LOG="${ARTIFACT_DIR}/scenario_summaries.log"
AGGREGATED_REPORT_LOG="${ARTIFACT_DIR}/aggregated_report.log"
REPRO_COMMAND="WORKLOAD_ID=${WORKLOAD_ID} RUNTIME_PROFILE=${RUNTIME_PROFILE} FABRIC_FEATURES='${FABRIC_FEATURES}' RCH_TARGET_DIR='${RCH_TARGET_DIR}' WORKLOAD_CONFIG_REF='${WORKLOAD_CONFIG_REF}' TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")${TEST_FILTER:+ ${TEST_FILTER}}"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi
FAILURE_CLASS="test_or_pattern_failure"
if [ "$SUITE_STATUS" = "passed" ]; then
    FAILURE_CLASS="none"
fi

grep -n "fabric e2e scenario summary" "$LOG_FILE" > "$SCENARIO_SUMMARY_LOG" 2>/dev/null || true
grep -n "fabric e2e aggregated coverage report" "$LOG_FILE" > "$AGGREGATED_REPORT_LOG" 2>/dev/null || true

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
  "artifact_dir": "${ARTIFACT_DIR}",
  "scenario_summary_log": "${SCENARIO_SUMMARY_LOG}",
  "aggregated_report_log": "${AGGREGATED_REPORT_LOG}"
}
ENDJSON

grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "  Summary: ${SUMMARY_FILE}"

echo ""
echo "==================================================================="
echo "                      FABRIC E2E SUMMARY                           "
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

find "$ARTIFACT_DIR" -name "*.txt" -empty -delete 2>/dev/null || true

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
