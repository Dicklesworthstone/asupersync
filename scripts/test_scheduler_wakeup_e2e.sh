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
#   STRESS_TIMEOUT - Timeout for stress tests in seconds (default: 600)
#   RUST_LOG       - Standard Rust logging level
#   RCH_BIN        - rch executable used for all Cargo commands (default: rch)
#   RCH_TARGET_DIR - remote Cargo target directory

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/scheduler"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_DIR="$OUTPUT_DIR/$TIMESTAMP"
STRESS_TIMEOUT="${STRESS_TIMEOUT:-600}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch-target-scheduler-e2e-${USER:-unknown}-${TIMESTAMP}-$$}"
WORKLOAD_ID="${WORKLOAD_ID:-AA01-WL-BURST-001}"
RUNTIME_PROFILE="${RUNTIME_PROFILE:-native-e2e}"
WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_scheduler_wakeup_e2e.sh::scheduler_backoff+scheduler_lane_fairness+scheduler_stress_tests}"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi
RUN_WITH_RCH_BOOL="true"

run_cargo() {
    "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
}

run_timeout_cargo() {
    local timeout_sec="$1"
    shift
    timeout "${timeout_sec}s" "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_TARGET_DIR" cargo "$@"
}

record_rch_local_fallback() {
    echo "rch local fallback detected; refusing local cargo execution" > "$LOG_DIR/rch_local_fallback.txt"
}

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
echo "  Workload:        ${WORKLOAD_ID}"
echo "  Profile:         ${RUNTIME_PROFILE}"
echo "  RCH_BIN:         ${RCH_BIN}"
echo "  RCH target dir:  ${RCH_TARGET_DIR}"
echo "  RCH mode:        enabled"
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
    run_cargo test --test scheduler_backoff -- --nocapture || true

# --------------------------------------------------------------------------
# 2. Lane fairness tests
# --------------------------------------------------------------------------
run_suite "scheduler_lane_fairness" \
    run_cargo test --test scheduler_lane_fairness -- --nocapture || true

# --------------------------------------------------------------------------
# 3. Stress tests (ignored by default, need --ignored flag)
# --------------------------------------------------------------------------
if [ "${SKIP_STRESS:-0}" != "1" ]; then
    # Run the scheduler-only ignored stress tests in one cargo invocation so RCH
    # release-build setup is paid once instead of four separate timeout windows.
    run_suite "scheduler_stress_tests" \
        run_timeout_cargo "${STRESS_TIMEOUT}" test --release --lib 'three_lane::tests::stress_test_' -- --ignored --nocapture --test-threads=1 || true
else
    echo "[skip] Stress tests (SKIP_STRESS=1)"
fi

# --------------------------------------------------------------------------
# 4. Loom systematic concurrency tests
# --------------------------------------------------------------------------
if [ "${SKIP_LOOM:-0}" != "1" ]; then
    run_suite "loom_tests" \
        run_cargo test --test scheduler_loom --features loom-tests --release -- --nocapture || true
else
    echo "[skip] Loom tests (SKIP_LOOM=1)"
fi

# --------------------------------------------------------------------------
# Failure pattern analysis
# --------------------------------------------------------------------------
echo ""
echo ">>> Analyzing logs for issues..."
ISSUES=0

if grep -rEqi "(timed out|timeout( after| while| waiting| reached| expired)|deadline exceeded)" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: timeout-like failure detected"
    ISSUES=$((ISSUES + 1))
fi

for pattern in "deadlock" "hung" "blocked forever"; do
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

if grep -rEq '^\[RCH\] local \(|falling back to local' "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  ERROR: rch local fallback detected"
    record_rch_local_fallback
    ISSUES=$((ISSUES + 1))
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
PASSED_TESTS=$(grep -rh -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$(grep -rh -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null | awk '{s+=$1} END {print s+0}')
SUITE_ID="scheduler_e2e"
SCENARIO_ID="E2E-SUITE-SCHEDULER-WAKEUP"
SUMMARY_FILE="$LOG_DIR/summary.json"
REPRO_COMMAND="WORKLOAD_ID=${WORKLOAD_ID} RUNTIME_PROFILE=${RUNTIME_PROFILE} WORKLOAD_CONFIG_REF='${WORKLOAD_CONFIG_REF}' TEST_SEED=${TEST_SEED} RUST_LOG=${RUST_LOG} RCH_BIN=${RCH_BIN} RCH_TARGET_DIR='${RCH_TARGET_DIR}' bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$FAILED_SUITES" -eq 0 ] && [ "$ISSUES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi

cat > "$SUMMARY_FILE" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "workload_id": "${WORKLOAD_ID}",
  "runtime_profile": "${RUNTIME_PROFILE}",
  "workload_config_ref": "${WORKLOAD_CONFIG_REF}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "repro_command": "${REPRO_COMMAND}",
  "artifact_path": "${SUMMARY_FILE}",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "rch_bin": "${RCH_BIN}",
  "rch_target_dir": "${RCH_TARGET_DIR}",
  "run_with_rch": ${RUN_WITH_RCH_BOOL},
  "tests_passed": ${PASSED_TESTS},
  "tests_failed": ${FAILED_TESTS},
  "suites_total": ${TOTAL_SUITES},
  "suites_passed": ${PASSED_SUITES},
  "suites_failed": ${FAILED_SUITES},
  "pattern_failures": ${ISSUES},
  "log_dir": "${LOG_DIR}"
}
ENDJSON

echo ""
echo "==================================================================="
echo "                       SUMMARY                                     "
echo "==================================================================="
echo "  Suites:  $PASSED_SUITES/$TOTAL_SUITES passed"
echo "  Issues:  $ISSUES pattern warnings"
echo "  Logs:    $LOG_DIR/"
echo "  Summary: $SUMMARY_FILE"
echo "  End:     $(date -Iseconds)"
echo "==================================================================="

if [ "$FAILED_SUITES" -gt 0 ] || [ "$ISSUES" -gt 0 ]; then
    exit 1
fi

echo ""
echo "All scheduler wakeup tests passed!"
