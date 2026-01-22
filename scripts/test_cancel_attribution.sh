#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "          Cancel Attribution Test Suite                        "
echo "═══════════════════════════════════════════════════════════════"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE=1

OUTPUT_DIR="target/test-results/cancel-attribution"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.txt"

echo "" > "$SUMMARY_FILE"

run_test() {
    local name="$1"
    local pattern="$2"
    local log_file="$OUTPUT_DIR/${name}_${TIMESTAMP}.log"

    echo ""
    echo "▶ Running ${name}..."

    if cargo test "$pattern" --test cancel_attribution -- --nocapture 2>&1 | tee "$log_file"; then
        local passed=$(grep -c "test .* ok" "$log_file" || true)
        echo "  ✓ ${name}: PASSED ($passed tests)" >> "$SUMMARY_FILE"
        return 0
    else
        local failed=$(grep -c "test .* FAILED" "$log_file" || true)
        echo "  ✗ ${name}: FAILED ($failed failures)" >> "$SUMMARY_FILE"
        return 1
    fi
}

FAILURES=0

echo ""
echo "▶ Running CancelReason construction tests..."
run_test "cancel_reason_construction" "cancel_reason_basic_construction" || ((FAILURES++))
run_test "cancel_reason_builder" "cancel_reason_builder_methods" || ((FAILURES++))

echo ""
echo "▶ Running cause chain tests..."
run_test "cause_chain_construction" "cancel_reason_cause_chain_construction" || ((FAILURES++))
run_test "root_cause" "cancel_reason_root_cause" || ((FAILURES++))
run_test "any_cause_is" "cancel_reason_any_cause_is" || ((FAILURES++))

echo ""
echo "▶ Running CancelKind tests..."
run_test "cancel_kind_variants" "cancel_kind_all_variants_constructible" || ((FAILURES++))
run_test "cancel_kind_eq_hash" "cancel_kind_eq_and_hash" || ((FAILURES++))

echo ""
echo "▶ Running Cx API tests..."
run_test "cx_cancel_with" "cx_cancel_with_stores_reason" || ((FAILURES++))
run_test "cx_cancel_with_no_msg" "cx_cancel_with_no_message" || ((FAILURES++))
run_test "cx_cancel_chain" "cx_cancel_chain_api" || ((FAILURES++))
run_test "cx_root_cancel_cause" "cx_root_cancel_cause_api" || ((FAILURES++))
run_test "cx_cancelled_by" "cx_cancelled_by_api" || ((FAILURES++))
run_test "cx_any_cause_is" "cx_any_cause_is_api" || ((FAILURES++))
run_test "cx_cancel_fast" "cx_cancel_fast_api" || ((FAILURES++))

echo ""
echo "▶ Running E2E tests..."
run_test "e2e_debugging_workflow" "e2e_debugging_workflow" || ((FAILURES++))
run_test "e2e_metrics_collection" "e2e_metrics_collection" || ((FAILURES++))
run_test "e2e_severity_handling" "e2e_severity_based_handling" || ((FAILURES++))
run_test "integration_handler_usage" "integration_realistic_handler_usage" || ((FAILURES++))

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    TEST SUMMARY                                "
echo "═══════════════════════════════════════════════════════════════"
cat "$SUMMARY_FILE"
echo "═══════════════════════════════════════════════════════════════"

PASSED=$(grep -c "PASSED" "$SUMMARY_FILE" || true)
FAILED=$(grep -c "FAILED" "$SUMMARY_FILE" || true)

echo ""
echo "Tests passed: $PASSED"
echo "Tests failed: $FAILED"

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "❌ ${FAILURES} test(s) failed"
    echo "See ${OUTPUT_DIR} for detailed logs"
    exit 1
fi

echo ""
echo "✓ All cancel attribution tests passed!"
