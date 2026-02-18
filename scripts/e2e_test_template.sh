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
LOG_FILE="${OUTPUT_DIR}/${SUITE_NAME}_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
TEST_FILTER="${1:-}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

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
echo ""

# --- [1] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! cargo check --test "$TEST_TARGET" --all-features 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
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

pushd "$PROJECT_ROOT" >/dev/null
if timeout "$SUITE_TIMEOUT" cargo test "${CARGO_ARGS[@]}" -- "${RUN_ARGS[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

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

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")

# Structured summary (machine-readable)
cat > "${ARTIFACT_DIR}/summary.json" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v2",
  "suite": "${SUITE_NAME}_e2e",
  "timestamp": "${TIMESTAMP}",
  "seed": "${TEST_SEED}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "suite_script": "${SCRIPT_DIR}/$(basename "$0")",
  "replay_command": "TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} bash ${SCRIPT_DIR}/$(basename "$0")",
  "log_file": "${LOG_FILE}",
  "artifact_dir": "${ARTIFACT_DIR}"
}
ENDJSON

# Extract repro seeds and trace fingerprints from log
grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "  Summary: ${ARTIFACT_DIR}/summary.json"

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

if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Logs:   ${LOG_FILE}"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

# Clean up empty diagnostic files
find "$ARTIFACT_DIR" -name "*.txt" -empty -delete 2>/dev/null || true

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
