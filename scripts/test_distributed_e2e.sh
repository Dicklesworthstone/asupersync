#!/usr/bin/env bash
# Distributed E2E Test Runner (bd-26l3)
#
# Runs the distributed subsystem E2E tests (RaptorQ encode/distribute/recover,
# snapshot serialization, bridge state machine, hash ring, region recovery)
# with deterministic settings and artifact capture on failure.
#
# Usage:
#   ./scripts/test_distributed_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/distributed"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/distributed_e2e_${TIMESTAMP}.log"
INVARIANT_LOG="${OUTPUT_DIR}/distributed_invariants_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
TEST_FILTER="${1:-}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

echo "==================================================================="
echo "              Asupersync Distributed E2E Tests                     "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Output:          ${LOG_FILE}"
echo "  Invariants:      ${INVARIANT_LOG}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo ""

# --- Section: Build Check ---
echo ">>> [1/5] Pre-flight: checking compilation..."
if ! cargo check --test e2e_distributed --test distributed_trace_remote_invariants --all-features 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
echo "  OK"

# --- Section: Run E2E tests ---
echo ""
echo ">>> [2/5] Running distributed E2E tests..."

TEST_RESULT=0
CARGO_ARGS=(--test e2e_distributed --all-features)
RUN_ARGS=(--nocapture --test-threads=1)

if [ -n "$TEST_FILTER" ]; then
    RUN_ARGS+=("$TEST_FILTER")
fi

pushd "$PROJECT_ROOT" >/dev/null
if timeout 180 cargo test "${CARGO_ARGS[@]}" -- "${RUN_ARGS[@]}" 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi

# --- Section: Run invariant tests ---
echo ""
echo ">>> [3/5] Running distributed/trace/remote invariant tests..."

INVARIANT_RESULT=0
if timeout 120 cargo test --test distributed_trace_remote_invariants --all-features -- --nocapture --test-threads=1 2>&1 | tee "$INVARIANT_LOG"; then
    INVARIANT_RESULT=0
else
    INVARIANT_RESULT=$?
fi
popd >/dev/null

# --- Section: Failure Pattern Analysis ---
echo ""
echo ">>> [4/5] Checking output for failure patterns..."

PATTERN_FAILURES=0

check_pattern() {
    local pattern="$1"
    local label="$2"
    local found=0
    for f in "$LOG_FILE" "$INVARIANT_LOG"; do
        if grep -q "$pattern" "$f" 2>/dev/null; then
            found=1
        fi
    done
    if [ "$found" -eq 1 ]; then
        echo "  ERROR: ${label}"
        grep -hn "$pattern" "$LOG_FILE" "$INVARIANT_LOG" | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "panicked at"         "panic detected"
check_pattern "assertion failed"    "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Busy loop detected"  "busy loop detected"
check_pattern "SnapshotError"       "snapshot error"
check_pattern "RecoveryError"       "recovery error"
check_pattern "obligation.*leak"    "obligation leak"
check_pattern "causality.*violation" "causality violation"

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- Section: Artifact Collection ---
echo ""
echo ">>> [5/5] Collecting artifacts..."

E2E_PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
E2E_FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")
INV_PASSED=$(grep -c "^test .* ok$" "$INVARIANT_LOG" 2>/dev/null || echo "0")
INV_FAILED=$(grep -c "^test .* FAILED$" "$INVARIANT_LOG" 2>/dev/null || echo "0")

TOTAL_PASSED=$((E2E_PASSED + INV_PASSED))
TOTAL_FAILED=$((E2E_FAILED + INV_FAILED))

cat > "${ARTIFACT_DIR}/summary.json" << ENDJSON
{
  "suite": "distributed_e2e",
  "timestamp": "${TIMESTAMP}",
  "seed": "${TEST_SEED}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "suites": {
    "e2e": { "passed": ${E2E_PASSED}, "failed": ${E2E_FAILED}, "exit_code": ${TEST_RESULT} },
    "invariants": { "passed": ${INV_PASSED}, "failed": ${INV_FAILED}, "exit_code": ${INVARIANT_RESULT} }
  },
  "total_passed": ${TOTAL_PASSED},
  "total_failed": ${TOTAL_FAILED},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "${LOG_FILE}",
  "invariant_log": "${INVARIANT_LOG}",
  "artifact_dir": "${ARTIFACT_DIR}"
}
ENDJSON

for f in "$LOG_FILE" "$INVARIANT_LOG"; do
    grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$f" >> "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
    grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$f" >> "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true
    grep -oE "content_hash[= ]+[a-f0-9]+" "$f" >> "${ARTIFACT_DIR}/hashes.txt" 2>/dev/null || true
done

echo "  Summary: ${ARTIFACT_DIR}/summary.json"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                   DISTRIBUTED E2E SUMMARY                         "
echo "==================================================================="
echo "  Seed:       ${TEST_SEED}"
echo "  E2E:        ${E2E_PASSED} passed, ${E2E_FAILED} failed"
echo "  Invariants: ${INV_PASSED} passed, ${INV_FAILED} failed"
echo "  Total:      ${TOTAL_PASSED} passed, ${TOTAL_FAILED} failed"
echo "  Patterns:   ${PATTERN_FAILURES} failure patterns"
echo ""

OVERALL=0
if [ "$TEST_RESULT" -ne 0 ] || [ "$INVARIANT_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    OVERALL=1
fi

if [ "$OVERALL" -eq 0 ]; then
    echo "  Status: PASSED"
else
    echo "  Status: FAILED"
    echo "  Logs:      ${LOG_FILE}"
    echo "  Invariant: ${INVARIANT_LOG}"
    echo "  Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

find "$ARTIFACT_DIR" -name "*.txt" -empty -delete 2>/dev/null || true

exit $OVERALL
