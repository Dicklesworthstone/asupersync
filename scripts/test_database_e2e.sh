#!/usr/bin/env bash
# Database/Pool E2E Test Runner (bd-26l3)
#
# Runs the database E2E tests (pool lifecycle, acquire/release, exhaustion,
# concurrent access, health checks) with deterministic settings and artifact
# capture on failure.
#
# Usage:
#   ./scripts/test_database_e2e.sh [--dry-run] [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)
#   RCH_BIN        - remote compilation helper executable (default: rch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/database"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/database_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_database_e2e}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 1 ]]; then
    echo "usage: $0 [--dry-run] [test_filter]" >&2
    exit 2
fi
TEST_FILTER="${1:-}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "${value}"
}

run_or_print() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

echo "==================================================================="
echo "              Asupersync Database/Pool E2E Tests                   "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Output:          ${LOG_FILE}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  Runner:          ${RCH_BIN} exec"
echo "  Target dir:      ${CARGO_TARGET_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Mode:            dry-run"
fi
echo ""

# --- Section: Build Check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
CHECK_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "TEST_SEED=${TEST_SEED}"
    cargo
    check
    --test
    e2e_database
    --all-features
)
if ! run_or_print "${CHECK_COMMAND[@]}" 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
echo "  OK"

# --- Section: Run Tests ---
echo ""
echo ">>> [2/4] Running database E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test e2e_database --all-features)
RUN_ARGS=(--nocapture --test-threads=1)

if [ -n "$TEST_FILTER" ]; then
    RUN_ARGS+=("$TEST_FILTER")
fi

TEST_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "TEST_LOG_LEVEL=${TEST_LOG_LEVEL}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "TEST_SEED=${TEST_SEED}"
    cargo
    test
    "${CARGO_ARGS[@]}"
    --
    "${RUN_ARGS[@]}"
)

pushd "$PROJECT_ROOT" >/dev/null
if [[ "${DRY_RUN}" -eq 1 ]]; then
    format_command "${TEST_COMMAND[@]}" | tee "$LOG_FILE"
    TEST_RESULT=0
elif timeout 120 "${TEST_COMMAND[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

# --- Section: Failure Pattern Analysis ---
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

check_pattern "panicked at"       "panic detected"
check_pattern "assertion failed"  "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "pool exhausted"    "pool exhaustion"
check_pattern "Busy loop detected"  "busy loop detected"
check_pattern "Task leak detected"  "task leak detected"
check_pattern "connection.*timeout" "connection timeout"

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- Section: Artifact Collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$({ grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED=$({ grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="database_e2e"
SCENARIO_ID="E2E-SUITE-DATABASE"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
    SUITE_STATUS="planned"
fi
DRY_RUN_JSON=false
if [[ "${DRY_RUN}" -eq 1 ]]; then
    DRY_RUN_JSON=true
fi
FAILURE_CLASS="test_or_pattern_failure"
if [ "$SUITE_STATUS" = "passed" ]; then
    FAILURE_CLASS="none"
elif [ "$SUITE_STATUS" = "planned" ]; then
    FAILURE_CLASS="none"
fi

cat > "${SUMMARY_FILE}" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "failure_class": "${FAILURE_CLASS}",
  "dry_run": ${DRY_RUN_JSON},
  "runner": "rch exec",
  "all_rch_routed": true,
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "$(json_escape "${TEST_LOG_LEVEL}")",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "$(json_escape "${LOG_FILE}")",
  "artifact_dir": "$(json_escape "${ARTIFACT_DIR}")"
}
ENDJSON

grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "connection_id[= ]+[0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/connections.txt" 2>/dev/null || true

echo "  Summary: ${SUMMARY_FILE}"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                    DATABASE E2E SUMMARY                           "
echo "==================================================================="
echo "  Seed:     ${TEST_SEED}"
echo "  Passed:   ${PASSED}"
echo "  Failed:   ${FAILED}"
echo "  Patterns: ${PATTERN_FAILURES} failure patterns"
echo ""

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Status: PLANNED"
    echo "  Cargo was not executed."
elif [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Logs:   ${LOG_FILE}"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

echo "  Diagnostic artifacts are retained for auditability, including empty files."

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
