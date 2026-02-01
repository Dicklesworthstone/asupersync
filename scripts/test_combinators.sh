#!/bin/bash
# Combinator E2E Test Suite
#
# This script runs the full combinator test suite with structured logging,
# focusing on cancel-correctness and obligation safety verification.
#
# Usage:
#   ./scripts/test_combinators.sh
#
# Environment Variables:
#   RUST_LOG - Log level (default: info)
#   RUST_BACKTRACE - Enable backtraces (default: 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/test_logs/combinators_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

# Default log level
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

echo "=== Combinator E2E Test Suite ==="
echo "Log directory: $LOG_DIR"
echo "Start time: $(date -Iseconds)"
echo "RUST_LOG: $RUST_LOG"
echo ""

# Track test results
UNIT_EXIT=0
CANCEL_EXIT=0
ASYNC_EXIT=0
OVERALL_EXIT=0

# Run combinator unit tests
echo "[1/3] Running combinator unit tests..."
if cargo test --test combinator_tests e2e::combinator::unit -- --nocapture 2>&1 | tee "$LOG_DIR/unit_tests.log"; then
    UNIT_EXIT=0
    echo "    -> PASS"
else
    UNIT_EXIT=1
    echo "    -> FAIL"
fi

# Run cancel-correctness tests (CRITICAL)
echo ""
echo "[2/3] Running cancel-correctness tests (CRITICAL)..."
if cargo test --test combinator_tests e2e::combinator::cancel_correctness -- --nocapture 2>&1 | tee "$LOG_DIR/cancel_tests.log"; then
    CANCEL_EXIT=0
    echo "    -> PASS"
else
    CANCEL_EXIT=1
    echo "    -> FAIL"
fi

# Run async loser drain tests
echo ""
echo "[3/3] Running async loser drain tests..."
if cargo test --test combinator_tests async_loser_drain -- --nocapture 2>&1 | tee "$LOG_DIR/async_tests.log"; then
    ASYNC_EXIT=0
    echo "    -> PASS"
else
    ASYNC_EXIT=1
    echo "    -> FAIL"
fi

# Check for critical oracle violations
echo ""
echo "[Analysis] Checking for oracle violations..."
if grep -qE "(LoserDrainViolation|ObligationLeakViolation)" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "    -> WARNING: Oracle violations detected!"
    grep -hE "(LoserDrainViolation|ObligationLeakViolation)" "$LOG_DIR"/*.log | head -10
    OVERALL_EXIT=1
else
    echo "    -> No oracle violations"
fi

# Check for panics
if grep -qE "(panicked|FAILED)" "$LOG_DIR"/*.log 2>/dev/null; then
    echo ""
    echo "[Analysis] Test failures detected:"
    grep -hE "(panicked|FAILED)" "$LOG_DIR"/*.log | head -20
fi

# Generate summary
echo ""
echo "=== Test Summary ==="
cat > "$LOG_DIR/summary.md" << EOF
# Combinator Test Report

## Date: $(date -Iseconds)

## Results

| Suite | Status |
|-------|--------|
| Unit Tests | $([ $UNIT_EXIT -eq 0 ] && echo "PASS" || echo "FAIL") |
| Cancel-Correctness | $([ $CANCEL_EXIT -eq 0 ] && echo "PASS" || echo "FAIL") |
| Async Loser Drain | $([ $ASYNC_EXIT -eq 0 ] && echo "PASS" || echo "FAIL") |

## Test Counts
$(grep -hE "^test result:" "$LOG_DIR"/*.log 2>/dev/null || echo "N/A")

## Critical Invariants
- Loser Drain: $(grep -c "LoserDrainViolation" "$LOG_DIR"/*.log 2>/dev/null || echo "0") violations
- Obligation Leak: $(grep -c "ObligationLeakViolation" "$LOG_DIR"/*.log 2>/dev/null || echo "0") violations
EOF

cat "$LOG_DIR/summary.md"

echo ""
echo "End time: $(date -Iseconds)"
echo "Logs saved to: $LOG_DIR"
echo "=== Test Complete ==="

# Exit with overall status
if [ $UNIT_EXIT -ne 0 ] || [ $CANCEL_EXIT -ne 0 ] || [ $ASYNC_EXIT -ne 0 ] || [ $OVERALL_EXIT -ne 0 ]; then
    exit 1
fi
exit 0
