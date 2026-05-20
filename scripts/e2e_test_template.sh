#!/usr/bin/env bash
# E2E Test Script Template for Asupersync (bd-26l3)
#
# Copy this template to create a new subsystem E2E test runner.
# Replace SUITE_NAME and TEST_TARGET with the appropriate values.
#
# Standard sections:
#   [1] Pre-flight compilation check
#   [2] Test execution with timeout
#   [3] Failure pattern analysis
#   [4] Artifact collection (seeds, traces, summary.json)
#   [5] Summary report
#
# Usage:
#   ./scripts/test_SUITE_NAME_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)
#   RCH_BIN        - remote compilation helper executable (default: rch)
#   CARGO_BIN      - cargo executable passed to rch (default: cargo)

set -euo pipefail

# ---- CUSTOMIZE THESE ----
SUITE_NAME="SUITE_NAME"           # e.g. "messaging", "transport"
TEST_TARGET="e2e_SUITE_NAME"      # cargo --test target name
SUITE_TIMEOUT=120                 # per-suite timeout in seconds
# --------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/${SUITE_NAME}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/${SUITE_NAME}_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_${SUITE_NAME}_e2e}"
DRY_RUN=0
LOCAL_FALLBACKS=0

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

local_fallback_pattern='^\[RCH\] local \(|local fallback|fallback to local|falling back to local|executing locally'

record_local_fallbacks() {
    local log_path="$1"
    local label="$2"
    local artifact_path="${ARTIFACT_DIR}/${label// /_}.txt"

    if grep -Eiq "$local_fallback_pattern" "$log_path" 2>/dev/null; then
        echo "  ERROR: rch local fallback detected in ${label}"
        grep -Ein "$local_fallback_pattern" "$log_path" | head -5 > "$artifact_path" 2>/dev/null || true
        ((LOCAL_FALLBACKS++)) || true
    fi
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
echo "              Asupersync ${SUITE_NAME} E2E Tests"
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

# --- [1] Pre-flight: compilation check ---
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
    "$CARGO_BIN"
    check
    --test
    "$TEST_TARGET"
    --all-features
)
if ! run_or_print "${CHECK_COMMAND[@]}" 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
record_local_fallbacks "${ARTIFACT_DIR}/compile_errors.log" "compile local fallback"
if [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
    echo "  FATAL: rch local fallback detected during pre-flight; refusing local cargo execution"
    exit 86
fi
echo "  OK"

# --- [2] Run tests ---
echo ""
echo ">>> [2/4] Running ${SUITE_NAME} E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test "$TEST_TARGET" --all-features)
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
    "$CARGO_BIN"
    test
    "${CARGO_ARGS[@]}"
    --
    "${RUN_ARGS[@]}"
)

pushd "$PROJECT_ROOT" >/dev/null
if [[ "${DRY_RUN}" -eq 1 ]]; then
    format_command "${TEST_COMMAND[@]}" | tee "$LOG_FILE"
    TEST_RESULT=0
elif timeout "$SUITE_TIMEOUT" "${TEST_COMMAND[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null
record_local_fallbacks "$LOG_FILE" "test local fallback"
if [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
    TEST_RESULT=86
fi

# --- [3] Failure pattern analysis ---
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

# Core invariant violations
check_pattern "panicked at"         "panic detected"
check_pattern "assertion failed"    "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Busy loop detected"  "busy loop detected"
check_pattern "Task leak detected"  "task leak detected"
check_pattern "leaked registration" "leaked IO registration"
check_pattern "obligation.*leak"    "obligation leak"

# Add subsystem-specific patterns here:
# check_pattern "YOUR_PATTERN"    "your label"

if [ "$PATTERN_FAILURES" -eq 0 ] && [ "$LOCAL_FALLBACKS" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$({ grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED=$({ grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="${SUITE_NAME}_e2e"
SCENARIO_ID="E2E-SUITE-$(printf '%s' "$SUITE_NAME" | tr '[:lower:]' '[:upper:]')"
REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} bash ${SCRIPT_DIR}/$(basename "$0")"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ] && [ "$LOCAL_FALLBACKS" -eq 0 ]; then
    SUITE_STATUS="passed"
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
    SUITE_STATUS="planned"
fi
DRY_RUN_JSON=false
if [[ "${DRY_RUN}" -eq 1 ]]; then
    DRY_RUN_JSON=true
fi
RCH_ROUTED_JSON=true
if [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
    RCH_ROUTED_JSON=false
fi

# Structured summary (machine-readable)
cat > "${SUMMARY_FILE}" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "dry_run": ${DRY_RUN_JSON},
  "runner": "rch exec",
  "all_rch_routed": ${RCH_ROUTED_JSON},
  "rch_local_fallbacks": ${LOCAL_FALLBACKS},
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "$(json_escape "${TEST_LOG_LEVEL}")",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "suite_script": "$(json_escape "${SCRIPT_DIR}/$(basename "$0")")",
  "replay_command": "$(json_escape "${REPRO_COMMAND}")",
  "log_file": "$(json_escape "${LOG_FILE}")",
  "artifact_dir": "$(json_escape "${ARTIFACT_DIR}")"
}
ENDJSON

# Extract repro seeds and trace fingerprints from log
grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "  Summary: ${SUMMARY_FILE}"

# --- [5] Summary ---
echo ""
echo "==================================================================="
echo "                    ${SUITE_NAME} E2E SUMMARY"
echo "==================================================================="
echo "  Seed:     ${TEST_SEED}"
echo "  Passed:   ${PASSED}"
echo "  Failed:   ${FAILED}"
echo "  Patterns: ${PATTERN_FAILURES} failure patterns"
echo ""

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Status: PLANNED"
    echo "  Cargo was not executed."
elif [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ] && [ "$LOCAL_FALLBACKS" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Logs:   ${LOG_FILE}"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

echo "  Diagnostic artifacts are retained for auditability, including empty files."

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ] || [ "$LOCAL_FALLBACKS" -ne 0 ]; then
    exit 1
fi
