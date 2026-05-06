#!/usr/bin/env bash
# Tokio Interop E2E Test Runner (asupersync-2oh2u.7.11)
#
# Runs end-to-end interoperability validation for all adapter modules in
# asupersync-tokio-compat, with structured compatibility logging and
# deterministic artifact capture.
#
# Usage:
#   ./scripts/test_tokio_interop_e2e.sh [test_filter]
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: info)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0x7011C0DE)
#   SKIP_CLIPPY    - set to 1 to skip clippy gate (default: 0)
#   RCH_BIN        - remote compilation helper executable (default: rch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/tokio-interop"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/tokio_interop_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
COMPAT_LOG="${ARTIFACT_DIR}/compatibility_log.jsonl"
SUMMARY_FILE="${ARTIFACT_DIR}/e2e_summary.md"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR_BASE="${CARGO_TARGET_DIR_BASE:-${TMPDIR:-/tmp}/rch_target_tokio_interop_e2e}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 1 ]]; then
    echo "usage: $0 [--dry-run] [test_filter]" >&2
    exit 2
fi
TEST_FILTER="${1:-}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0x7011C0DE}"
SKIP_CLIPPY="${SKIP_CLIPPY:-0}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

# ─── helpers ────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_SCENARIOS=0
CORRELATION_ID="e2e-$(uuidgen 2>/dev/null || echo "${TIMESTAMP}")"

log_compat() {
    local status="$1"
    local scenario="$2"
    local adapter="$3"
    local message="$4"
    local duration_ms="${5:-0}"

    printf '{"ts":"%s","correlation_id":"%s","scenario":"%s","adapter":"%s","status":"%s","message":"%s","duration_ms":%s,"seed":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        "$CORRELATION_ID" \
        "$scenario" \
        "$adapter" \
        "$status" \
        "$message" \
        "$duration_ms" \
        "$TEST_SEED" >> "$COMPAT_LOG"
}

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
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
        "TEST_LOG_LEVEL=${TEST_LOG_LEVEL}"
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

run_scenario() {
    local name="$1"
    local test_target="$2"
    local test_pattern="$3"
    local adapter="$4"

    TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
    local start_ms
    start_ms=$(date +%s%3N 2>/dev/null || date +%s)

    printf "  [%02d] %-60s " "$TOTAL_SCENARIOS" "$name"

    local scenario_log="${ARTIFACT_DIR}/scenario_${TOTAL_SCENARIOS}_${name// /_}.log"
    local run_args=(--nocapture)
    if [[ -n "$test_pattern" ]]; then
        run_args=("$test_pattern" --nocapture)
    fi

    if run_cargo "scenario_${TOTAL_SCENARIOS}" test -p asupersync --test "$test_target" -- "${run_args[@]}" > "$scenario_log" 2>&1; then
        local end_ms
        end_ms=$(date +%s%3N 2>/dev/null || date +%s)
        local duration=$((end_ms - start_ms))
        echo "PASS (${duration}ms)"
        log_compat "PASS" "$name" "$adapter" "all assertions passed" "$duration"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        local end_ms
        end_ms=$(date +%s%3N 2>/dev/null || date +%s)
        local duration=$((end_ms - start_ms))
        echo "FAIL (${duration}ms)"
        log_compat "FAIL" "$name" "$adapter" "see ${scenario_log}" "$duration"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ─── header ─────────────────────────────────────────────────────────

{
echo "==================================================================="
echo "          Asupersync Tokio Interop E2E Test Runner                 "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  RUST_BACKTRACE:  ${RUST_BACKTRACE}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  CORRELATION_ID:  ${CORRELATION_ID}"
echo "  TIMESTAMP:       ${TIMESTAMP}"
echo "  OUTPUT_DIR:      ${OUTPUT_DIR}"
echo "  ARTIFACT_DIR:    ${ARTIFACT_DIR}"
echo "  RUNNER:          ${RCH_BIN} exec"
echo "  TARGET_BASE:     ${CARGO_TARGET_DIR_BASE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  MODE:            dry-run"
fi
echo ""
} | tee "$LOG_FILE"

# ─── Phase 1: Quality Gates ────────────────────────────────────────

echo "Phase 1: Quality Gates" | tee -a "$LOG_FILE"
echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"

echo "  [QG] rch cargo check -p asupersync-tokio-compat --all-targets" | tee -a "$LOG_FILE"
if ! run_cargo qg_check check -p asupersync-tokio-compat --all-targets >> "$LOG_FILE" 2>&1; then
    echo "  FAIL: cargo check failed. See ${LOG_FILE}" | tee -a "$LOG_FILE"
    log_compat "FAIL" "quality-gate-check" "all" "cargo check failed" "0"
    exit 1
fi
echo "        PASS" | tee -a "$LOG_FILE"
log_compat "PASS" "quality-gate-check" "all" "cargo check passed" "0"

if [ "$SKIP_CLIPPY" != "1" ]; then
    echo "  [QG] rch cargo clippy -p asupersync-tokio-compat --all-targets -- -D warnings" | tee -a "$LOG_FILE"
    if ! run_cargo qg_clippy clippy -p asupersync-tokio-compat --all-targets -- -D warnings >> "$LOG_FILE" 2>&1; then
        echo "  FAIL: clippy failed. See ${LOG_FILE}" | tee -a "$LOG_FILE"
        log_compat "FAIL" "quality-gate-clippy" "all" "clippy failed" "0"
        exit 1
    fi
    echo "        PASS" | tee -a "$LOG_FILE"
    log_compat "PASS" "quality-gate-clippy" "all" "clippy passed" "0"
fi

echo "  [QG] rch cargo fmt --check -p asupersync-tokio-compat" | tee -a "$LOG_FILE"
if ! run_cargo qg_fmt fmt --check -p asupersync-tokio-compat >> "$LOG_FILE" 2>&1; then
    echo "  FAIL: fmt check failed. See ${LOG_FILE}" | tee -a "$LOG_FILE"
    log_compat "FAIL" "quality-gate-fmt" "all" "fmt check failed" "0"
    exit 1
fi
echo "        PASS" | tee -a "$LOG_FILE"
log_compat "PASS" "quality-gate-fmt" "all" "fmt check passed" "0"

echo "" | tee -a "$LOG_FILE"

# ─── Phase 2: Adapter Unit Tests (in-crate) ────────────────────────

echo "Phase 2: Adapter Unit Tests (asupersync-tokio-compat)" | tee -a "$LOG_FILE"
echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"

echo "  [UT] cargo test -p asupersync-tokio-compat" | tee -a "$LOG_FILE"
UNIT_LOG="${ARTIFACT_DIR}/unit_tests.log"
if run_cargo unit test -p asupersync-tokio-compat --no-fail-fast -- --nocapture > "$UNIT_LOG" 2>&1; then
    UNIT_COUNT=$({ grep -c "^test .* ok$" "$UNIT_LOG" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
    echo "        PASS (${UNIT_COUNT} tests)" | tee -a "$LOG_FILE"
    log_compat "PASS" "adapter-unit-tests" "all" "${UNIT_COUNT} unit tests passed" "0"
else
    echo "        FAIL: see ${UNIT_LOG}" | tee -a "$LOG_FILE"
    log_compat "FAIL" "adapter-unit-tests" "all" "unit tests failed" "0"
fi

echo "" | tee -a "$LOG_FILE"

# ─── Phase 3: E2E Scenario Suites ──────────────────────────────────

echo "Phase 3: E2E Interop Scenarios" | tee -a "$LOG_FILE"
echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"

# 3a: Boundary architecture conformance (T7.2)
run_scenario "boundary architecture conformance" \
    "tokio_adapter_boundary_architecture" "" "boundary"

# 3b: Interop conformance suites (T7.7)
run_scenario "interop conformance suites" \
    "tokio_interop_conformance_suites" "${TEST_FILTER}" "conformance"

# 3c: Performance budget contracts (T7.8)
run_scenario "performance budget contracts" \
    "tokio_adapter_performance_budgets" "${TEST_FILTER}" "budgets"

# 3d: Boundary correctness contracts (T7.10)
run_scenario "boundary correctness contracts" \
    "tokio_adapter_boundary_correctness" "${TEST_FILTER}" "correctness"

# 3e: E2E scenarios (this bead)
run_scenario "e2e interop scenarios" \
    "tokio_interop_e2e_scenarios" "${TEST_FILTER}" "e2e"

echo "" | tee -a "$LOG_FILE"

# ─── Phase 4: Incompatibility Drills ───────────────────────────────

echo "Phase 4: Incompatibility Drills" | tee -a "$LOG_FILE"
echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"

# Drill: Verify no Tokio runtime leaks
TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
printf "  [%02d] %-60s " "$TOTAL_SCENARIOS" "no tokio runtime in adapter code"
COMPAT_DIR="${PROJECT_ROOT}/asupersync-tokio-compat/src"
LEAK_FOUND=0
for f in "$COMPAT_DIR"/*.rs; do
    if grep -q "tokio::runtime::Runtime\|#\[tokio::main\]\|#\[tokio::test\]" "$f" 2>/dev/null; then
        LEAK_FOUND=1
        log_compat "FAIL" "no-runtime-leak" "all" "found tokio runtime in $(basename "$f")" "0"
    fi
done
if [ "$LEAK_FOUND" -eq 0 ]; then
    echo "PASS"
    log_compat "PASS" "no-runtime-leak" "all" "no tokio runtime found" "0"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Drill: Verify deny(unsafe_code) in lib.rs
TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
printf "  [%02d] %-60s " "$TOTAL_SCENARIOS" "deny(unsafe_code) enforced"
if grep -q "deny(unsafe_code)" "$COMPAT_DIR/lib.rs" 2>/dev/null; then
    echo "PASS"
    log_compat "PASS" "deny-unsafe" "all" "deny(unsafe_code) present" "0"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    log_compat "FAIL" "deny-unsafe" "all" "deny(unsafe_code) missing" "0"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Drill: Verify all 7 adapter source files exist
TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
printf "  [%02d] %-60s " "$TOTAL_SCENARIOS" "all adapter modules present"
MISSING=0
for mod in lib.rs hyper_bridge.rs body_bridge.rs tower_bridge.rs io.rs cancel.rs blocking.rs; do
    if [ ! -f "$COMPAT_DIR/$mod" ]; then
        MISSING=$((MISSING + 1))
        log_compat "FAIL" "modules-present" "$mod" "missing module" "0"
    fi
done
if [ "$MISSING" -eq 0 ]; then
    echo "PASS"
    log_compat "PASS" "modules-present" "all" "all 7 modules present" "0"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL ($MISSING missing)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo "" | tee -a "$LOG_FILE"

# ─── Summary ───────────────────────────────────────────────────────

RUN_FINISHED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))

{
echo "==================================================================="
echo "                        E2E Summary                                "
echo "==================================================================="
echo ""
echo "  Correlation ID:  ${CORRELATION_ID}"
echo "  Started:         ${RUN_STARTED_TS}"
echo "  Finished:        ${RUN_FINISHED_TS}"
echo "  Seed:            ${TEST_SEED}"
echo "  Runner:          ${RCH_BIN} exec"
echo "  Target base:     ${CARGO_TARGET_DIR_BASE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Mode:            dry-run"
fi
echo ""
echo "  Scenarios:       ${TOTAL}"
echo "  Passed:          ${PASS_COUNT}"
echo "  Failed:          ${FAIL_COUNT}"
echo "  Skipped:         ${SKIP_COUNT}"
echo ""
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  Compat Log:      ${COMPAT_LOG}"
echo "  Full Log:        ${LOG_FILE}"
echo ""
} | tee -a "$LOG_FILE"

# Generate summary artifact
cat > "$SUMMARY_FILE" <<EOFMD
# Tokio Interop E2E Summary

**Bead**: asupersync-2oh2u.7.11
**Correlation ID**: ${CORRELATION_ID}
**Run**: ${RUN_STARTED_TS} → ${RUN_FINISHED_TS}
**Seed**: ${TEST_SEED}
**Runner**: ${RCH_BIN} exec
**Target Base**: ${CARGO_TARGET_DIR_BASE}
**Dry Run**: ${DRY_RUN}

## Results

| Metric | Value |
|--------|-------|
| Total Scenarios | ${TOTAL} |
| Passed | ${PASS_COUNT} |
| Failed | ${FAIL_COUNT} |
| Skipped | ${SKIP_COUNT} |

## Artifacts

- \`compatibility_log.jsonl\`: structured JSONL compat log
- \`e2e_summary.md\`: this file
- \`scenario_*.log\`: per-scenario output logs
- \`unit_tests.log\`: adapter unit test output

## Repro Command

\`\`\`bash
TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR_BASE=${CARGO_TARGET_DIR_BASE} ./scripts/test_tokio_interop_e2e.sh
\`\`\`
EOFMD

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  RESULT: PLANNED (cargo was not executed)" | tee -a "$LOG_FILE"
    exit 0
elif [ "$FAIL_COUNT" -gt 0 ]; then
    echo "  RESULT: FAIL (${FAIL_COUNT} scenario(s) failed)" | tee -a "$LOG_FILE"
    exit 1
else
    echo "  RESULT: PASS (all ${PASS_COUNT} scenarios passed)" | tee -a "$LOG_FILE"
    exit 0
fi
