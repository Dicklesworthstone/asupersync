#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "          Cancel Attribution Test Suite                        "
echo "═══════════════════════════════════════════════════════════════"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE=1
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_cancel_attribution}"
DRY_RUN=0
LOCAL_FALLBACKS=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

OUTPUT_DIR="target/test-results/cancel-attribution"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUMMARY_TEXT_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.txt"
SUMMARY_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.json"
SUITE_ID="cancel-attribution_e2e"
SCENARIO_ID="E2E-SUITE-CANCEL-ATTRIBUTION"
REPRO_COMMAND="TEST_SEED=${TEST_SEED:-0xDEADBEEF} RUST_LOG=${RUST_LOG} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} bash ./scripts/$(basename "$0")"

echo "" > "$SUMMARY_TEXT_FILE"

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

record_local_fallback() {
    local name="$1"
    local log_file="$2"
    local artifact_path="${OUTPUT_DIR}/${name}_rch_local_fallback.txt"

    if grep -Eiq "$local_fallback_pattern" "$log_file" 2>/dev/null; then
        echo "rch local fallback detected; refusing local cargo execution" > "$artifact_path"
        grep -Ein "$local_fallback_pattern" "$log_file" | head -5 >> "$artifact_path" 2>/dev/null || true
        ((LOCAL_FALLBACKS += 1))
        return 0
    fi
    return 1
}

run_test() {
    local name="$1"
    local pattern="$2"
    local log_file="$OUTPUT_DIR/${name}_${TIMESTAMP}.log"
    local test_command=(
        "${RCH_BIN}"
        exec
        --
        env
        "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
        "RUST_LOG=${RUST_LOG}"
        "RUST_BACKTRACE=${RUST_BACKTRACE}"
        "TEST_SEED=${TEST_SEED:-0xDEADBEEF}"
        "${CARGO_BIN}"
        test
        "$pattern"
        --test
        cancel_attribution
        --
        --nocapture
    )

    echo ""
    echo "▶ Running ${name}..."

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "${test_command[@]}" | tee "$log_file"
        echo "  ${name}: PLANNED" >> "$SUMMARY_TEXT_FILE"
        return 0
    fi

    if "${test_command[@]}" 2>&1 | tee "$log_file"; then
        if record_local_fallback "$name" "$log_file"; then
            echo "  ✗ ${name}: RCH LOCAL FALLBACK" >> "$SUMMARY_TEXT_FILE"
            return 86
        fi
        local passed=$(grep -c "test .* ok" "$log_file" || true)
        echo "  ✓ ${name}: PASSED ($passed tests)" >> "$SUMMARY_TEXT_FILE"
        return 0
    else
        if record_local_fallback "$name" "$log_file"; then
            echo "  ✗ ${name}: RCH LOCAL FALLBACK" >> "$SUMMARY_TEXT_FILE"
            return 86
        fi
        local failed=$(grep -c "test .* FAILED" "$log_file" || true)
        echo "  ✗ ${name}: FAILED ($failed failures)" >> "$SUMMARY_TEXT_FILE"
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
cat "$SUMMARY_TEXT_FILE"
echo "═══════════════════════════════════════════════════════════════"

PASSED=$(grep -c "PASSED" "$SUMMARY_TEXT_FILE" || true)
FAILED=$(grep -c "FAILED" "$SUMMARY_TEXT_FILE" || true)
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$FAILURES" -eq 0 ]; then
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
if [[ "${SUITE_STATUS}" == "passed" || "${SUITE_STATUS}" == "planned" ]]; then
    FAILURE_CLASS="none"
elif [ "$LOCAL_FALLBACKS" -ne 0 ]; then
    FAILURE_CLASS="rch_local_fallback"
fi
RCH_ROUTED_JSON=true
if [ "$LOCAL_FALLBACKS" -ne 0 ]; then
    RCH_ROUTED_JSON=false
fi

cat > "$SUMMARY_FILE" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED:-0xDEADBEEF}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "failure_class": "${FAILURE_CLASS}",
  "dry_run": ${DRY_RUN_JSON},
  "runner": "rch exec",
  "all_rch_routed": ${RCH_ROUTED_JSON},
  "rch_local_fallbacks": ${LOCAL_FALLBACKS},
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "failure_groups": ${FAILURES},
  "log_dir": "$(json_escape "${OUTPUT_DIR}")"
}
ENDJSON

echo ""
echo "Tests passed: $PASSED"
echo "Tests failed: $FAILED"
echo "Summary: $SUMMARY_FILE"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo ""
    echo "Cancel attribution tests planned; Cargo was not executed."
    exit 0
fi

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "❌ ${FAILURES} test(s) failed"
    echo "See ${OUTPUT_DIR} for detailed logs"
    exit 1
fi

echo ""
echo "✓ All cancel attribution tests passed!"
