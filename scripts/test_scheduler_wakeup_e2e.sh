#!/usr/bin/env bash
# E2E Test Script for Scheduler Wakeup & Race Condition Verification
#
# Runs the full scheduler test pyramid:
#   1. Unit tests (parker, wake state, queues, stealing)
#   2. Lane fairness tests
#   3. Stress tests (high contention, work stealing, backoff)
#   4. Loom systematic concurrency tests (if loom cfg available)
#
# Usage:
#   ./scripts/test_scheduler_wakeup_e2e.sh
#
# Environment Variables:
#   SKIP_STRESS    - Set to 1 to skip stress tests
#   SKIP_LOOM      - Set to 1 to skip Loom tests
#   STRESS_TIMEOUT - Timeout for stress tests in seconds (default: 180)
#   RUST_LOG       - Standard Rust logging level

set -euo pipefail

# Configuration
OUTPUT_DIR="target/e2e-results/scheduler"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$OUTPUT_DIR/$TIMESTAMP"
STRESS_TIMEOUT="${STRESS_TIMEOUT:-180}"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

mkdir -p "$LOG_DIR"

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

echo "==================================================================="
echo "       Scheduler Wakeup E2E Test Suite                             "
echo "==================================================================="
echo ""
echo "Configuration:"
echo "  Log directory:   $LOG_DIR"
echo "  Stress timeout:  ${STRESS_TIMEOUT}s"
echo "  Skip stress:     ${SKIP_STRESS:-no}"
echo "  Skip loom:       ${SKIP_LOOM:-no}"
echo "  Start time:      $(date -Iseconds)"
echo ""

run_suite() {
    local name="$1"
    local log_file="$LOG_DIR/${name}.log"
    shift
    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo "[$TOTAL_SUITES] Running $name..."
    if "$@" 2>&1 | tee "$log_file"; then
        echo "    PASS"
        PASSED_SUITES=$((PASSED_SUITES + 1))
        return 0
    else
        echo "    FAIL (see $log_file)"
        FAILED_SUITES=$((FAILED_SUITES + 1))
        return 1
    fi
}

# --------------------------------------------------------------------------
# 1. Scheduler unit tests (parker, queues, stealing, backoff)
# --------------------------------------------------------------------------
run_suite "scheduler_backoff" \
    cargo test --test scheduler_backoff -- --nocapture || true

# --------------------------------------------------------------------------
# 2. Lane fairness tests
# --------------------------------------------------------------------------
run_suite "scheduler_lane_fairness" \
    cargo test --test scheduler_lane_fairness -- --nocapture || true

# --------------------------------------------------------------------------
# 3. Stress tests (ignored by default, need --ignored flag)
# --------------------------------------------------------------------------
if [ "${SKIP_STRESS:-0}" != "1" ]; then
    run_suite "stress_tests" \
        timeout "${STRESS_TIMEOUT}s" \
        cargo test --release scheduler_stress -- --ignored --nocapture --test-threads=1 || true
else
    echo "[skip] Stress tests (SKIP_STRESS=1)"
fi

# --------------------------------------------------------------------------
# 4. Loom systematic concurrency tests
# --------------------------------------------------------------------------
if [ "${SKIP_LOOM:-0}" != "1" ]; then
    run_suite "loom_tests" \
        cargo test --test scheduler_loom --features loom-tests --release -- --nocapture || true
else
    echo "[skip] Loom tests (SKIP_LOOM=1)"
fi

# --------------------------------------------------------------------------
# Failure pattern analysis
# --------------------------------------------------------------------------
echo ""
echo ">>> Analyzing logs for issues..."
ISSUES=0

for pattern in "timed out" "timeout" "deadlock" "hung" "blocked forever"; do
    if grep -rqi "$pattern" "$LOG_DIR"/*.log 2>/dev/null; then
        echo "  WARNING: '$pattern' detected"
        ISSUES=$((ISSUES + 1))
    fi
done

if grep -rq "lost wakeup" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: Lost wakeup detected"
    ISSUES=$((ISSUES + 1))
fi

if grep -rq "double schedule\|duplicate" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: Double scheduling detected"
    ISSUES=$((ISSUES + 1))
fi

if grep -rq "panicked at" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: Panics detected"
    grep -rh "panicked at" "$LOG_DIR"/*.log | head -5
    ISSUES=$((ISSUES + 1))
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
cat > "$LOG_DIR/summary.md" << EOF
# Scheduler Wakeup E2E Test Report

**Date:** $(date -Iseconds)

## Results

| Suite | Status |
|-------|--------|
| Total | $TOTAL_SUITES |
| Passed | $PASSED_SUITES |
| Failed | $FAILED_SUITES |
| Issues | $ISSUES |

## Test Counts
$(grep -rh "^test result:" "$LOG_DIR"/*.log 2>/dev/null || echo "N/A")

## Failures
$(grep -rhE "(FAILED|panicked)" "$LOG_DIR"/*.log 2>/dev/null | head -20 || echo "None")
EOF

echo ""
echo "==================================================================="
echo "                       SUMMARY                                     "
echo "==================================================================="
echo "  Suites:  $PASSED_SUITES/$TOTAL_SUITES passed"
echo "  Issues:  $ISSUES pattern warnings"
echo "  Logs:    $LOG_DIR/"
echo "  End:     $(date -Iseconds)"
echo "==================================================================="

if [ "$FAILED_SUITES" -gt 0 ] || [ "$ISSUES" -gt 0 ]; then
    exit 1
fi

echo ""
echo "All scheduler wakeup tests passed!"
