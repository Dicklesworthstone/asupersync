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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/h2_security"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
LOG_DIR="${ARTIFACT_DIR}/logs"
SUITE_TIMEOUT="${SUITE_TIMEOUT:-180}"

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
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  SKIP_FUZZ:       ${SKIP_FUZZ:-0}"
echo ""

# --- [1/4] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! cargo check --tests --all-features 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
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
    timeout "$SUITE_TIMEOUT" "$@" 2>&1 | tee "$log_file"
    local rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        echo "    PASS"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        echo "    FAIL (exit $rc)"
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
}

run_suite "hpack_unit" cargo test --lib http::h2::hpack -- --nocapture
run_suite "h2_frame_unit" cargo test --lib http::h2::frame -- --nocapture
run_suite "h2_settings_unit" cargo test --lib http::h2::settings -- --nocapture
run_suite "h2_security_integration" cargo test --test h2_security --all-features -- --nocapture --test-threads=1
run_suite "http_verification" cargo test --test http_verification --all-features -- --nocapture --test-threads=1

if [ "${SKIP_FUZZ:-0}" != "1" ] && [ -d "${PROJECT_ROOT}/fuzz/seeds" ]; then
    run_suite "fuzz_seed_hpack" cargo test --lib stress_test_hpack -- --nocapture
    run_suite "fuzz_seed_huffman" cargo test --lib stress_test_huffman -- --nocapture
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

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4/4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED_TESTS=$(grep -h -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$(grep -h -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null | awk '{s+=$1} END {print s+0}')

cat > "${ARTIFACT_DIR}/summary.json" << ENDJSON
{
  "suite": "h2_security_e2e",
  "timestamp": "${TIMESTAMP}",
  "seed": "${TEST_SEED}",
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

echo "  Summary: ${ARTIFACT_DIR}/summary.json"

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

find "$ARTIFACT_DIR" -name "*.txt" -empty -delete 2>/dev/null || true

if [ "$FAILED_SUITES" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
