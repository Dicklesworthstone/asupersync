#!/usr/bin/env bash
# WebSocket E2E Test Runner (bd-35ld, enriched bd-26l3)
#
# Runs the WebSocket E2E integration tests with deterministic settings,
# structured logging, seed info, and artifact capture on failure.
#
# Usage:
#   ./scripts/test_websocket_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/websocket"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/websocket_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
TEST_FILTER="${1:-}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

echo "==================================================================="
echo "              Asupersync WebSocket E2E Tests                       "
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

# --- Section: Build Check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! cargo check --test e2e_websocket --all-features 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
echo "  OK"

# --- Section: Run Tests ---
echo ""
echo ">>> [2/4] Running WebSocket E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test e2e_websocket --all-features)
RUN_ARGS=(--nocapture --test-threads=1)

if [ -n "$TEST_FILTER" ]; then
    RUN_ARGS+=("$TEST_FILTER")
fi

pushd "$PROJECT_ROOT" >/dev/null
if timeout 180 cargo test "${CARGO_ARGS[@]}" -- "${RUN_ARGS[@]}" 2>&1 | tee "$LOG_FILE"; then
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

check_pattern "panicked at"         "panic detected"
check_pattern "assertion failed"    "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Busy loop detected"  "busy loop detected"
check_pattern "Task leak detected"  "task leak detected"

# WebSocket-specific patterns
check_pattern "deadlock"            "potential deadlock"
check_pattern "hung"                "potential hang"
check_pattern "timed out"           "timeout detected"

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- Section: Artifact Collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")

cat > "${ARTIFACT_DIR}/summary.json" << ENDJSON
{
  "suite": "websocket_e2e",
  "timestamp": "${TIMESTAMP}",
  "seed": "${TEST_SEED}",
  "test_log_level": "${TEST_LOG_LEVEL}",
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

echo "  Summary: ${ARTIFACT_DIR}/summary.json"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                    WEBSOCKET E2E SUMMARY                          "
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
