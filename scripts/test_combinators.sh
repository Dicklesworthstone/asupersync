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
#   RCH_BIN - Remote compilation helper executable (default: rch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/test_logs/combinators_$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR_BASE="${CARGO_TARGET_DIR_BASE:-${TMPDIR:-/tmp}/rch_target_combinators_e2e}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"

# Default log level
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

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

run_cargo() {
    local lane="$1"
    shift
    local target_dir="${CARGO_TARGET_DIR_BASE}/${lane}"
    local command=(
        "${RCH_BIN}"
        exec
        --
        env
        "CARGO_TARGET_DIR=${target_dir}"
        "RUST_LOG=${RUST_LOG}"
        "RUST_BACKTRACE=${RUST_BACKTRACE}"
        "TEST_SEED=${TEST_SEED}"
        cargo
        "$@"
    )

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "${command[@]}"
        printf '\n'
        return 0
    fi

    "${command[@]}"
}

echo "=== Combinator E2E Test Suite ==="
echo "Log directory: $LOG_DIR"
echo "Start time: $(date -Iseconds)"
echo "RUST_LOG: $RUST_LOG"
echo "Runner: ${RCH_BIN} exec"
echo "Target base: ${CARGO_TARGET_DIR_BASE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Mode: dry-run"
fi
echo ""

# Track test results
UNIT_EXIT=0
CANCEL_EXIT=0
ASYNC_EXIT=0
OVERALL_EXIT=0

# Run combinator unit tests
echo "[1/3] Running combinator unit tests..."
if run_cargo unit test -p asupersync --test combinator_tests e2e::combinator::unit -- --nocapture 2>&1 | tee "$LOG_DIR/unit_tests.log"; then
    UNIT_EXIT=0
    echo "    -> PASS"
else
    UNIT_EXIT=1
    echo "    -> FAIL"
fi

# Run cancel-correctness tests (CRITICAL)
echo ""
echo "[2/3] Running cancel-correctness tests (CRITICAL)..."
if run_cargo cancel test -p asupersync --test combinator_tests e2e::combinator::cancel_correctness -- --nocapture 2>&1 | tee "$LOG_DIR/cancel_tests.log"; then
    CANCEL_EXIT=0
    echo "    -> PASS"
else
    CANCEL_EXIT=1
    echo "    -> FAIL"
fi

# Run async loser drain tests
echo ""
echo "[3/3] Running async loser drain tests..."
if run_cargo async test -p asupersync --test combinator_tests async_loser_drain -- --nocapture 2>&1 | tee "$LOG_DIR/async_tests.log"; then
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
PASSED_TESTS=$({ grep -h -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$({ grep -h -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
LOSER_DRAIN_VIOLATIONS=$({ grep -h -c "LoserDrainViolation" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
OBLIGATION_LEAK_VIOLATIONS=$({ grep -h -c "ObligationLeakViolation" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="combinators_e2e"
SCENARIO_ID="E2E-SUITE-COMBINATORS"
SUMMARY_FILE="$LOG_DIR/summary.json"
REPRO_COMMAND="TEST_SEED=${TEST_SEED} RUST_LOG=${RUST_LOG} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR_BASE=${CARGO_TARGET_DIR_BASE} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ $UNIT_EXIT -eq 0 ] && [ $CANCEL_EXIT -eq 0 ] && [ $ASYNC_EXIT -eq 0 ] && [ $OVERALL_EXIT -eq 0 ]; then
    SUITE_STATUS="passed"
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
    SUITE_STATUS="planned"
fi
DRY_RUN_JSON=false
if [[ "${DRY_RUN}" -eq 1 ]]; then
    DRY_RUN_JSON=true
fi

cat > "$SUMMARY_FILE" << ENDJSON
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
  "all_rch_routed": true,
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "tests_passed": ${PASSED_TESTS},
  "tests_failed": ${FAILED_TESTS},
  "unit_exit": ${UNIT_EXIT},
  "cancel_exit": ${CANCEL_EXIT},
  "async_exit": ${ASYNC_EXIT},
  "oracle_exit": ${OVERALL_EXIT},
  "loser_drain_violations": ${LOSER_DRAIN_VIOLATIONS},
  "obligation_leak_violations": ${OBLIGATION_LEAK_VIOLATIONS},
  "log_dir": "$(json_escape "${LOG_DIR}")"
}
ENDJSON

echo "Summary: $SUMMARY_FILE"

echo ""
echo "End time: $(date -Iseconds)"
echo "Logs saved to: $LOG_DIR"
echo "=== Test Complete ==="

# Exit with overall status
if [ $UNIT_EXIT -ne 0 ] || [ $CANCEL_EXIT -ne 0 ] || [ $ASYNC_EXIT -ne 0 ] || [ $OVERALL_EXIT -ne 0 ]; then
    exit 1
fi
exit 0
