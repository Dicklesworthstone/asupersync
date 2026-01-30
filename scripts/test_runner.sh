#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "            Asupersync Unified Test Suite                      "
echo "═══════════════════════════════════════════════════════════════"

echo ""
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE=1

OUTPUT_DIR="target/test-results"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.txt"

run_test_suite() {
    local name="$1"
    local pattern="$2"
    local features="${3:-test-internals}"
    local log_file="$OUTPUT_DIR/${name}_${TIMESTAMP}.log"

    echo ""
    echo "▶ Running ${name} tests..."

    if cargo test "$pattern" --features "$features" -- --nocapture 2>&1 | tee "$log_file"; then
        echo "  ✓ ${name}: PASSED" >> "$SUMMARY_FILE"
        return 0
    else
        echo "  ✗ ${name}: FAILED" >> "$SUMMARY_FILE"
        return 1
    fi
}

FAILURES=0

run_test_suite "unit" "" || ((FAILURES++))
run_test_suite "conformance" "conformance" || ((FAILURES++))
PROPTEST_CASES=${PROPTEST_CASES:-1000} run_test_suite "property" "property_test" || ((FAILURES++))
run_test_suite "tower" "tower_adapter_" "test-internals,tower" || ((FAILURES++))
run_test_suite "e2e" "e2e_" || ((FAILURES++))

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    UNIFIED TEST SUMMARY                        "
echo "═══════════════════════════════════════════════════════════════"
cat "$SUMMARY_FILE"
echo "═══════════════════════════════════════════════════════════════"

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "❌ ${FAILURES} test suite(s) failed"
    echo "See ${OUTPUT_DIR} for detailed logs"
    exit 1
fi

echo ""
echo "✓ All test suites passed!"
