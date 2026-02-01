#!/usr/bin/env bash
# WebSocket E2E Test Runner (bd-35ld)
#
# Runs the WebSocket E2E integration test crate with deterministic settings
# and saves logs under target/e2e-results/.
#
# Usage:
#   ./scripts/test_websocket_e2e.sh
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)

set -euo pipefail

OUTPUT_DIR="target/e2e-results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/websocket_e2e_${TIMESTAMP}.log"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

mkdir -p "$OUTPUT_DIR"

echo "==================================================================="
echo "                 Asupersync WebSocket E2E Tests                    "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  Output:          ${LOG_FILE}"
echo ""

run_tests() {
  echo ">>> Running: cargo test --test e2e_websocket ..."
  if timeout 180 cargo test --test e2e_websocket -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
    return 0
  fi
  return 1
}

check_failure_patterns() {
  local failures=0

  echo ""
  echo ">>> Checking output for suspicious patterns..."

  if grep -q "test result: FAILED" "$LOG_FILE" 2>/dev/null; then
    echo "  ERROR: cargo reported failures"
    ((failures++))
  fi

  if grep -q "panicked at" "$LOG_FILE" 2>/dev/null; then
    echo "  ERROR: panic detected"
    ((failures++))
  fi

  if grep -qiE "(deadlock|hung|timed out|timeout)" "$LOG_FILE" 2>/dev/null; then
    echo "  WARNING: potential hang/timeout text detected"
    grep -iE "(deadlock|hung|timed out|timeout)" "$LOG_FILE" | head -n 10 || true
    ((failures++))
  fi

  return $failures
}

TEST_RESULT=0
run_tests || TEST_RESULT=$?

PATTERN_RESULT=0
check_failure_patterns || PATTERN_RESULT=$?

echo ""
echo "==================================================================="
echo "                           SUMMARY                                 "
echo "==================================================================="
if [[ "$TEST_RESULT" -eq 0 && "$PATTERN_RESULT" -eq 0 ]]; then
  echo "Status: PASSED"
else
  echo "Status: FAILED"
  echo "See: ${LOG_FILE}"
fi
echo "==================================================================="

if [[ "$TEST_RESULT" -ne 0 || "$PATTERN_RESULT" -ne 0 ]]; then
  exit 1
fi

