#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/target/proptest-results"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_property_tests}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/proptest_${TIMESTAMP}.log"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

PROPTEST_SEED="${PROPTEST_SEED:-$(date +%s)}"
PROPTEST_CASES="${PROPTEST_CASES:-1000}"
PROPTEST_MAX_SHRINK_ITERS="${PROPTEST_MAX_SHRINK_ITERS:-100000}"

export PROPTEST_CASES
export PROPTEST_SEED
export PROPTEST_MAX_SHRINK_ITERS
export ASUPERSYNC_PROPTEST_SEED="${ASUPERSYNC_PROPTEST_SEED:-$PROPTEST_SEED}"
export ASUPERSYNC_PROPTEST_MAX_SHRINK_ITERS="${ASUPERSYNC_PROPTEST_MAX_SHRINK_ITERS:-$PROPTEST_MAX_SHRINK_ITERS}"

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
}

reject_rch_local_fallback_log() {
    if grep -Eq '^\[RCH\] local \(|falling back to local' "${LOG_FILE}" 2>/dev/null; then
        echo ""
        echo "FATAL: rch local fallback detected; refusing local cargo execution" >&2
        echo "rch local fallback detected; refusing local cargo execution" > "${OUTPUT_DIR}/rch_local_fallback_${TIMESTAMP}.txt"
        exit 86
    fi
}

echo "==== Asupersync Property Test Suite ===="
echo "Cases: ${PROPTEST_CASES}"
echo "Seed:  ${PROPTEST_SEED}"
echo "Log:   ${LOG_FILE}"
echo "Runner: ${RCH_BIN} exec"
echo "Target: ${CARGO_TARGET_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Mode:  dry-run"
fi
echo ""

TEST_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "PROPTEST_CASES=${PROPTEST_CASES}"
    "PROPTEST_SEED=${PROPTEST_SEED}"
    "PROPTEST_MAX_SHRINK_ITERS=${PROPTEST_MAX_SHRINK_ITERS}"
    "ASUPERSYNC_PROPTEST_SEED=${ASUPERSYNC_PROPTEST_SEED}"
    "ASUPERSYNC_PROPTEST_MAX_SHRINK_ITERS=${ASUPERSYNC_PROPTEST_MAX_SHRINK_ITERS}"
    "${CARGO_BIN}"
    test
    --test
    algebraic_laws
    --test
    property_region_ops
    --test
    security/property_tests
    --all-features
    --
    --nocapture
)

set +e
pushd "${ROOT_DIR}" >/dev/null
if [[ "${DRY_RUN}" -eq 1 ]]; then
    format_command "${TEST_COMMAND[@]}" | tee "${LOG_FILE}"
    STATUS=${PIPESTATUS[0]}
else
    "${TEST_COMMAND[@]}" 2>&1 | tee "${LOG_FILE}"
    STATUS=${PIPESTATUS[0]}
fi
popd >/dev/null
set -e

reject_rch_local_fallback_log

if grep -q "FAILED" "${LOG_FILE}"; then
    echo ""
    echo "Property tests reported failures."
    echo "Log: ${LOG_FILE}"
    exit 1
fi

if [ "${STATUS}" -ne 0 ]; then
    echo ""
    echo "Property test command failed."
    echo "Log: ${LOG_FILE}"
    exit 1
fi

PASSED=$({ grep -c "test .* ok" "${LOG_FILE}" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')

echo ""
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Property tests planned; Cargo was not executed."
else
    echo "Property tests passed"
fi
echo "Total test functions: ${PASSED}"
echo "Cases per test (requested): ${PROPTEST_CASES}"
echo "Seed: ${PROPTEST_SEED}"
