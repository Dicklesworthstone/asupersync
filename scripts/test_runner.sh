#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "            Asupersync Unified Test Suite                      "
echo "═══════════════════════════════════════════════════════════════"

echo ""
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE=1
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_unified_test_runner}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

OUTPUT_DIR="target/test-results"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.txt"

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
}

run_test_suite() {
    local name="$1"
    local pattern="$2"
    local features="${3:-test-internals}"
    local log_file="$OUTPUT_DIR/${name}_${TIMESTAMP}.log"
    local target_dir="${CARGO_TARGET_DIR}_${name}"
    local test_command=(
        "${RCH_BIN}"
        exec
        --
        env
        "CARGO_TARGET_DIR=${target_dir}"
        "RUST_LOG=${RUST_LOG}"
        "RUST_BACKTRACE=${RUST_BACKTRACE}"
        "PROPTEST_CASES=${PROPTEST_CASES:-1000}"
        cargo
        test
    )

    if [[ -n "${pattern}" ]]; then
        test_command+=("${pattern}")
    fi
    test_command+=(--features "${features}" -- --nocapture)

    echo ""
    echo "▶ Running ${name} tests..."

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "${test_command[@]}" | tee "$log_file"
        echo "  ${name}: PLANNED" >> "$SUMMARY_FILE"
        return 0
    fi

    if "${test_command[@]}" 2>&1 | tee "$log_file"; then
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
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "All test suites planned; Cargo was not executed."
else
    echo "✓ All test suites passed!"
fi
