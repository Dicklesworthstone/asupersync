#!/usr/bin/env bash
# Obligation cleanup no-mock E2E runner for asupersync-9u057b.5.
#
# Runs the focused client-disconnect forced-cancel obligation cleanup harness
# with deterministic single-threaded Rust test execution, structured log capture,
# and preserved artifacts for failure triage.
#
# Usage:
#   bash scripts/test_obligation_cleanup_e2e.sh [test_filter]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/obligation-cleanup"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/obligation_cleanup_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
SCENARIO_ID="client_disconnect_forced_cancel_cleanup"
TEST_ARTIFACT_SCENARIO_DIR="${ASUPERSYNC_TEST_ARTIFACTS_DIR:-${ARTIFACT_DIR}/test-artifacts}/${SCENARIO_ID}"
TEST_FILTER="${1:-test_client_disconnect_forced_cancel_cleans_pending_obligations}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch-target-obligation-cleanup-e2e-${USER:-unknown}-${TIMESTAMP}-$$}"
WORKLOAD_ID="${WORKLOAD_ID:-asupersync-9u057b.5}"
RUNTIME_PROFILE="${RUNTIME_PROFILE:-real-service-obligation-chaos}"
WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_obligation_cleanup_e2e.sh::client_disconnect_forced_cancel}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_QUEUE_WHEN_BUSY="${RCH_QUEUE_WHEN_BUSY:-1}"
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-300}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0x90057B5}"
export OBLIGATION_E2E_TESTS="${OBLIGATION_E2E_TESTS:-true}"
export ASUPERSYNC_TEST_ARTIFACTS_DIR="${ASUPERSYNC_TEST_ARTIFACTS_DIR:-${ARTIFACT_DIR}/test-artifacts}"
TEST_ARTIFACT_SCENARIO_DIR="${ASUPERSYNC_TEST_ARTIFACTS_DIR}/${SCENARIO_ID}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR" "$ASUPERSYNC_TEST_ARTIFACTS_DIR"

run_timeout_cargo() {
    local timeout_sec="$1"
    shift
    RCH_REQUIRE_REMOTE="$RCH_REQUIRE_REMOTE" \
    RCH_QUEUE_WHEN_BUSY="$RCH_QUEUE_WHEN_BUSY" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS" \
    timeout "$timeout_sec" "$RCH_BIN" exec -- env \
        CARGO_TARGET_DIR="$RCH_TARGET_DIR" \
        TEST_LOG_LEVEL="$TEST_LOG_LEVEL" \
        RUST_LOG="$RUST_LOG" \
        RUST_BACKTRACE="$RUST_BACKTRACE" \
        TEST_SEED="$TEST_SEED" \
        OBLIGATION_E2E_TESTS="$OBLIGATION_E2E_TESTS" \
        ASUPERSYNC_TEST_ARTIFACTS_DIR="$ASUPERSYNC_TEST_ARTIFACTS_DIR" \
        cargo "$@"
}

reject_rch_local_fallback_log() {
    local log_path="$1"
    if grep -Eq '^\[RCH\] local \(|falling back to local|local fallback' "$log_path" 2>/dev/null; then
        echo "  FATAL: rch local fallback detected; refusing local cargo execution"
        echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
        return 86
    fi
}

echo "==================================================================="
echo "          Asupersync Obligation Cleanup No-Mock E2E"
echo "==================================================================="
echo "  Test filter:      ${TEST_FILTER}"
echo "  Output:           ${LOG_FILE}"
echo "  Artifacts:        ${ARTIFACT_DIR}"
echo "  Test artifacts:   ${ASUPERSYNC_TEST_ARTIFACTS_DIR}"
echo "  RCH target dir:   ${RCH_TARGET_DIR}"
echo "  RCH remote only:  ${RCH_REQUIRE_REMOTE}"
echo ""

TEST_RESULT=0
pushd "$PROJECT_ROOT" >/dev/null
if run_timeout_cargo 900 test -p asupersync --no-default-features --features obligation-cleanup-e2e --test obligation_cleanup_e2e --message-format=short "${TEST_FILTER}" -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

if ! reject_rch_local_fallback_log "$LOG_FILE"; then
    TEST_RESULT=86
fi

materialize_test_artifacts_from_log() {
    mkdir -p "$TEST_ARTIFACT_SCENARIO_DIR"

    awk '
        /^ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_BEGIN / { capture = 1; next }
        /^ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_END / { capture = 0; next }
        capture { print }
    ' "$LOG_FILE" > "${TEST_ARTIFACT_SCENARIO_DIR}/events.ndjson"

    sed -n 's/^ASUPERSYNC_OBLIGATION_CLEANUP_SUMMARY_JSON //p' "$LOG_FILE" \
        | tail -1 > "${TEST_ARTIFACT_SCENARIO_DIR}/summary.json"
}

materialize_test_artifacts_from_log

PATTERN_FAILURES=0
check_pattern() {
    local pattern="$1"
    local label="$2"
    if grep -Eq "$pattern" "$LOG_FILE" 2>/dev/null; then
        echo "  ERROR: ${label}"
        grep -En "$pattern" "$LOG_FILE" | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "panicked at" "panic detected"
check_pattern "assertion failed" "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Task leak detected" "task leak detected"
check_pattern 'Leak detected: [1-9][0-9]* obligations leaked|obligation leak detected|"zero_leaks":[[:space:]]*false|"leaked_after":[[:space:]]*[1-9]' "obligation leak"

if [ "$TEST_RESULT" -eq 0 ]; then
    if [ ! -s "${TEST_ARTIFACT_SCENARIO_DIR}/events.ndjson" ] || [ ! -s "${TEST_ARTIFACT_SCENARIO_DIR}/summary.json" ]; then
        echo "  ERROR: test artifact materialization failed"
        ((PATTERN_FAILURES++)) || true
    fi
fi

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || true)
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || true)
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi

cat > "$SUMMARY_FILE" << ENDJSON
{
  "schema_version": "obligation-cleanup-e2e-runner-summary-v1",
  "suite_id": "obligation_cleanup_e2e",
  "scenario_id": "client_disconnect_forced_cancel_cleanup",
  "workload_id": "${WORKLOAD_ID}",
  "runtime_profile": "${RUNTIME_PROFILE}",
  "workload_config_ref": "${WORKLOAD_CONFIG_REF}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "test_filter": "${TEST_FILTER}",
  "rch_bin": "${RCH_BIN}",
  "rch_target_dir": "${RCH_TARGET_DIR}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "${LOG_FILE}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "test_artifact_dir": "${ASUPERSYNC_TEST_ARTIFACTS_DIR}",
  "repro_command": "RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=300 RCH_TARGET_DIR='${RCH_TARGET_DIR}' ASUPERSYNC_TEST_ARTIFACTS_DIR='${ASUPERSYNC_TEST_ARTIFACTS_DIR}' bash scripts/test_obligation_cleanup_e2e.sh ${TEST_FILTER}"
}
ENDJSON

echo ""
echo "Summary: ${SUMMARY_FILE}"
echo "Status: ${SUITE_STATUS}"

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
