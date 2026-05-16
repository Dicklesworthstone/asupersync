#!/usr/bin/env bash
# HTTP/2 Security E2E Test Runner (bd-26l3)
#
# Runs the HTTP/2 security test pyramid with deterministic settings and
# structured artifacts for repro.
#
# Usage:
#   ./scripts/test_h2_security_e2e.sh
#
# Environment Variables:
#   SKIP_FUZZ      - Set to 1 to skip fuzz seed validation
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)
#   SUITE_TIMEOUT  - per-suite timeout in seconds (default: 180)
#   RCH_BIN        - rch executable used for all Cargo commands (default: rch)
#   RCH_TARGET_ROOT - base target directory for remote Cargo builds

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/h2_security"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
LOG_DIR="${ARTIFACT_DIR}/logs"
SUITE_TIMEOUT="${SUITE_TIMEOUT:-180}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_ROOT="${RCH_TARGET_ROOT:-${TMPDIR:-/tmp}/rch_target_h2_security_${TIMESTAMP}}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR" "$LOG_DIR"

echo "==================================================================="
echo "              HTTP/2 Security E2E Test Suite                       "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timeout:         ${SUITE_TIMEOUT}s"
echo "  RCH_BIN:         ${RCH_BIN}"
echo "  RCH_TARGET_ROOT: ${RCH_TARGET_ROOT}"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  SKIP_FUZZ:       ${SKIP_FUZZ:-0}"
echo ""

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

run_cargo() {
    local label="$1"
    shift
    local safe_label="${label//[^A-Za-z0-9_]/_}"
    local target_dir="${RCH_TARGET_ROOT}/${safe_label}"

    timeout "$SUITE_TIMEOUT" "$RCH_BIN" exec -- env \
        "CARGO_TARGET_DIR=${target_dir}" \
        cargo "$@"
}

reject_rch_local_fallback_log() {
    local log_path="$1"
    if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
        echo "  FATAL: rch local fallback detected; refusing local cargo execution"
        echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
        return 86
    fi
}

# --- [1/4] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! run_cargo compile_check check --tests --all-features >"${ARTIFACT_DIR}/compile_errors.log" 2>&1; then
    reject_rch_local_fallback_log "${ARTIFACT_DIR}/compile_errors.log" || exit $?
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
reject_rch_local_fallback_log "${ARTIFACT_DIR}/compile_errors.log"
echo "  OK"

# --- [2/4] Run suites ---
echo ""
echo ">>> [2/4] Running HTTP/2 security suites..."

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

run_suite() {
    local name="$1"
    shift
    local log_file="$LOG_DIR/${name}.log"
    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo "[$TOTAL_SUITES] Running ${name}..."
    set +e
    run_cargo "$name" "$@" 2>&1 | tee "$log_file"
    local rc=${PIPESTATUS[0]}
    set -e

    if [ "$rc" -eq 0 ]; then
        echo "    PASS"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        echo "    FAIL (exit $rc)"
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
}

run_suite "hpack_unit" test --lib http::h2::hpack -- --nocapture
run_suite "h2_frame_unit" test --lib http::h2::frame -- --nocapture
run_suite "h2_settings_unit" test --lib http::h2::settings -- --nocapture
run_suite "h2_security_integration" test --test h2_security --all-features -- --nocapture --test-threads=1
run_suite "http_verification" test --test http_verification --all-features -- --nocapture --test-threads=1

if [ "${SKIP_FUZZ:-0}" != "1" ] && [ -d "${PROJECT_ROOT}/fuzz/seeds" ]; then
    run_suite "fuzz_seed_hpack" test --lib stress_test_hpack -- --nocapture
    run_suite "fuzz_seed_huffman" test --lib stress_test_huffman -- --nocapture
else
    echo "[skip] Fuzz seed validation"
fi

# --- [3/4] Failure pattern analysis ---
echo ""
echo ">>> [3/4] Checking output for failure patterns..."

PATTERN_FAILURES=0

check_pattern() {
    local pattern="$1"
    local label="$2"
    if grep -rqi "$pattern" "$LOG_DIR"/*.log 2>/dev/null; then
        echo "  ERROR: ${label}"
        grep -rni "$pattern" "$LOG_DIR"/*.log | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "panicked at"     "panic detected"
check_pattern "assertion failed" "assertion failure"
check_pattern "overflow"         "overflow detected"
check_pattern "out of bounds"    "out of bounds"
check_pattern "index out of range" "index out of range"
check_pattern "stack overflow"   "stack overflow"

if grep -rEq '^\[RCH\] local \(|falling back to local' "$LOG_DIR"/*.log 2>/dev/null; then
    echo "  ERROR: rch local fallback detected"
    echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
    ((PATTERN_FAILURES++)) || true
fi

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4/4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED_TESTS=$({ grep -h -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$({ grep -h -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="h2-security_e2e"
SCENARIO_ID="E2E-SUITE-H2-SECURITY"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$FAILED_SUITES" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi

cat > "${SUMMARY_FILE}" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "repro_command": "${REPRO_COMMAND}",
  "artifact_path": "${SUMMARY_FILE}",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "suite_timeout": ${SUITE_TIMEOUT},
  "suites_total": ${TOTAL_SUITES},
  "suites_passed": ${PASSED_SUITES},
  "suites_failed": ${FAILED_SUITES},
  "tests_passed": ${PASSED_TESTS},
  "tests_failed": ${FAILED_TESTS},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_dir": "${LOG_DIR}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "skip_fuzz": ${SKIP_FUZZ:-0}
}
ENDJSON

grep -r -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_DIR"/*.log > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -r -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_DIR"/*.log > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "  Summary: ${SUMMARY_FILE}"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                    HTTP/2 SECURITY SUMMARY                        "
echo "==================================================================="
echo "  Seed:     ${TEST_SEED}"
echo "  Suites:   ${PASSED_SUITES}/${TOTAL_SUITES} passed"
echo "  Tests:    ${PASSED_TESTS} passed, ${FAILED_TESTS} failed"
echo "  Patterns: ${PATTERN_FAILURES} failure patterns"
echo "  Logs:     ${LOG_DIR}"
echo ""

if [ "$FAILED_SUITES" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

if [ "$FAILED_SUITES" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
