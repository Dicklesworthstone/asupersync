#!/usr/bin/env bash
# Master E2E Orchestrator (bd-26l3)
#
# Runs all subsystem E2E test suites sequentially, collects per-suite results,
# and produces a unified summary report with seed info and artifact paths.
#
# Usage:
#   ./scripts/run_all_e2e.sh               # run all suites
#   ./scripts/run_all_e2e.sh --suite NAME   # run a single suite
#   ./scripts/run_all_e2e.sh --list         # list available suites
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: info)
#   RUST_LOG       - tracing filter (default: asupersync=info)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed (default: 0xDEADBEEF)
#   E2E_TIMEOUT    - per-suite timeout in seconds (default: 300)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${PROJECT_ROOT}/target/e2e-results/orchestrator_${TIMESTAMP}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
E2E_TIMEOUT="${E2E_TIMEOUT:-300}"

# Suite definitions: name -> script path
declare -A SUITES=(
    [websocket]="test_websocket_e2e.sh"
    [messaging]="test_messaging_e2e.sh"
    [transport]="test_transport_e2e.sh"
    [database]="test_database_e2e.sh"
    [distributed]="test_distributed_e2e.sh"
    [h2-security]="test_h2_security_e2e.sh"
    [net-hardening]="test_net_hardening_e2e.sh"
    [redis]="test_redis_e2e.sh"
    [combinators]="test_combinators.sh"
    [cancel-attribution]="test_cancel_attribution.sh"
    [scheduler]="test_scheduler_wakeup_e2e.sh"
    [phase6]="run_phase6_e2e.sh"
)

# Ordered suite list (core subsystems first, then extended)
SUITE_ORDER=(
    websocket messaging transport database distributed
    h2-security net-hardening redis
    combinators cancel-attribution scheduler
    phase6
)

# --- Argument parsing ---
FILTER=""
if [[ "${1:-}" == "--list" ]]; then
    echo "Available E2E suites:"
    for name in "${SUITE_ORDER[@]}"; do
        script="${SUITES[$name]}"
        if [ -x "${SCRIPT_DIR}/${script}" ]; then
            echo "  ${name}  (${script})"
        else
            echo "  ${name}  (${script}) [not executable]"
        fi
    done
    exit 0
fi

if [[ "${1:-}" == "--suite" && -n "${2:-}" ]]; then
    FILTER="$2"
    if [[ -z "${SUITES[$FILTER]+x}" ]]; then
        echo "Unknown suite: $FILTER"
        echo "Run with --list to see available suites"
        exit 1
    fi
fi

mkdir -p "$REPORT_DIR"

echo "==================================================================="
echo "           Asupersync Master E2E Orchestrator                      "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timeout:         ${E2E_TIMEOUT}s per suite"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Report:          ${REPORT_DIR}"
echo ""
echo "-------------------------------------------------------------------"

TOTAL=0
PASS=0
FAIL=0
SKIP=0

declare -A RESULTS

for name in "${SUITE_ORDER[@]}"; do
    if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
        continue
    fi

    script="${SUITES[$name]}"
    script_path="${SCRIPT_DIR}/${script}"
    suite_log="${REPORT_DIR}/${name}.log"

    TOTAL=$((TOTAL + 1))
    printf "\n>>> %-25s" "[${name}]"

    if [ ! -x "$script_path" ]; then
        echo "SKIP (script not executable)"
        SKIP=$((SKIP + 1))
        RESULTS[$name]="SKIP"
        continue
    fi

    set +e
    timeout "$E2E_TIMEOUT" bash "$script_path" > "$suite_log" 2>&1
    rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        RESULTS[$name]="PASS"
    elif [ "$rc" -eq 124 ]; then
        echo "TIMEOUT (${E2E_TIMEOUT}s)"
        FAIL=$((FAIL + 1))
        RESULTS[$name]="TIMEOUT"
    else
        echo "FAIL (exit $rc)"
        FAIL=$((FAIL + 1))
        RESULTS[$name]="FAIL"
    fi
done

# --- Generate report ---
REPORT_FILE="${REPORT_DIR}/report.json"
{
    echo "{"
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"seed\": \"${TEST_SEED}\","
    echo "  \"test_log_level\": \"${TEST_LOG_LEVEL}\","
    echo "  \"total\": ${TOTAL},"
    echo "  \"passed\": ${PASS},"
    echo "  \"failed\": ${FAIL},"
    echo "  \"skipped\": ${SKIP},"
    echo "  \"suites\": {"
    first=true
    for name in "${SUITE_ORDER[@]}"; do
        if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
            continue
        fi
        result="${RESULTS[$name]:-SKIP}"
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        printf "    \"%s\": \"%s\"" "$name" "$result"
    done
    echo ""
    echo "  }"
    echo "}"
} > "$REPORT_FILE"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                   MASTER E2E SUMMARY                              "
echo "==================================================================="
echo ""
echo "  Seed:     ${TEST_SEED}"
echo "  Suites:   ${TOTAL} total"
echo "  Passed:   ${PASS}"
echo "  Failed:   ${FAIL}"
echo "  Skipped:  ${SKIP}"
echo ""

for name in "${SUITE_ORDER[@]}"; do
    if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
        continue
    fi
    result="${RESULTS[$name]:-SKIP}"
    printf "  %-25s %s\n" "$name" "$result"
done

echo ""
echo "  Report:   ${REPORT_FILE}"
echo "  Logs:     ${REPORT_DIR}/"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "  Status: FAILED"
    echo "==================================================================="
    exit 1
fi

echo "  Status: PASSED"
echo "==================================================================="
