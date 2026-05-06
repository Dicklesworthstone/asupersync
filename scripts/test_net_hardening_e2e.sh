#!/usr/bin/env bash
# E2E Test Script for Network Primitives Hardening Verification
#
# Runs the full network test pyramid:
#   1. TCP inline unit tests
#   2. UDP inline unit tests
#   3. TCP integration tests
#   4. UDP integration tests
#   5. Unix socket integration tests
#   6. Network hardening tests (keepalive, error handling, concurrency)
#   7. Network verification suite
#
# Usage:
#   ./scripts/test_net_hardening_e2e.sh
#
# Environment Variables:
#   RUST_LOG       - Standard Rust logging level
#   RCH_BIN        - Remote compilation helper executable (default: rch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/net_hardening"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_DIR="$OUTPUT_DIR/$TIMESTAMP"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR_BASE="${CARGO_TARGET_DIR_BASE:-${TMPDIR:-/tmp}/rch_target_net_hardening_e2e}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$LOG_DIR"

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

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

echo "==================================================================="
echo "       Network Primitives Hardening E2E Test Suite                  "
echo "==================================================================="
echo ""
echo "  Log directory: $LOG_DIR"
echo "  Start time:    $(date -Iseconds)"
echo "  Runner:        ${RCH_BIN} exec"
echo "  Target base:   ${CARGO_TARGET_DIR_BASE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Mode:          dry-run"
fi
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
# 1. TCP inline unit tests
# --------------------------------------------------------------------------
run_suite "tcp_unit" \
    run_cargo tcp_unit test -p asupersync --lib net::tcp -- --nocapture || true

# --------------------------------------------------------------------------
# 2. UDP inline unit tests
# --------------------------------------------------------------------------
run_suite "udp_unit" \
    run_cargo udp_unit test -p asupersync --lib net::udp -- --nocapture || true

# --------------------------------------------------------------------------
# 3. TCP integration tests
# --------------------------------------------------------------------------
run_suite "tcp_integration" \
    run_cargo tcp_integration test -p asupersync --test net_tcp -- --nocapture || true

# --------------------------------------------------------------------------
# 4. UDP integration tests
# --------------------------------------------------------------------------
run_suite "udp_integration" \
    run_cargo udp_integration test -p asupersync --test net_udp -- --nocapture || true

# --------------------------------------------------------------------------
# 5. Unix socket integration tests
# --------------------------------------------------------------------------
run_suite "unix_integration" \
    run_cargo unix_integration test -p asupersync --test net_unix -- --nocapture || true

# --------------------------------------------------------------------------
# 6. Network hardening tests
# --------------------------------------------------------------------------
run_suite "net_hardening" \
    run_cargo net_hardening test -p asupersync --test net_hardening -- --nocapture || true

# --------------------------------------------------------------------------
# 7. Network verification suite
# --------------------------------------------------------------------------
run_suite "net_verification" \
    run_cargo net_verification test -p asupersync --test net_verification -- --nocapture || true

# --------------------------------------------------------------------------
# Failure pattern analysis
# --------------------------------------------------------------------------
echo ""
echo ">>> Analyzing logs for issues..."
ISSUES=0

for pattern in "timed out" "connection refused" "broken pipe" "reset by peer"; do
    count=$({ grep -rci "$pattern" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk -F: '{s+=$2}END{print s+0}')
    if [ "$count" -gt 0 ]; then
        echo "  NOTE: '$pattern' appeared $count time(s) (may be expected)"
    fi
done

if grep -rq "panicked at" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: Panics detected"
    grep -rh "panicked at" "$LOG_DIR"/*.log | head -5
    ISSUES=$((ISSUES + 1))
fi

if grep -rqi "leak" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  WARNING: Potential leak detected"
    ISSUES=$((ISSUES + 1))
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
PASSED_TESTS=$({ grep -rh -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$({ grep -rh -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="net-hardening_e2e"
SCENARIO_ID="E2E-SUITE-NET-HARDENING"
SUMMARY_FILE="$LOG_DIR/summary.json"
REPRO_COMMAND="TEST_SEED=${TEST_SEED} RUST_LOG=${RUST_LOG} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR_BASE=${CARGO_TARGET_DIR_BASE} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$FAILED_SUITES" -eq 0 ] && [ "$ISSUES" -eq 0 ]; then
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
  "rch_bin": "$(json_escape "${RCH_BIN}")",
  "target_dir_base": "$(json_escape "${CARGO_TARGET_DIR_BASE}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "tests_passed": ${PASSED_TESTS},
  "tests_failed": ${FAILED_TESTS},
  "suites_total": ${TOTAL_SUITES},
  "suites_passed": ${PASSED_SUITES},
  "suites_failed": ${FAILED_SUITES},
  "pattern_failures": ${ISSUES},
  "log_dir": "$(json_escape "${LOG_DIR}")"
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

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo ""
    echo "Dry run planned network hardening suites without executing Cargo."
    exit 0
fi

if [ "$FAILED_SUITES" -gt 0 ] || [ "$ISSUES" -gt 0 ]; then
    exit 1
fi

echo ""
echo "All network hardening tests passed!"
