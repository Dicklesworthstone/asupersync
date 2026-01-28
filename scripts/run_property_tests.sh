#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/target/proptest-results"

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

echo "==== Asupersync Property Test Suite ===="
echo "Cases: ${PROPTEST_CASES}"
echo "Seed:  ${PROPTEST_SEED}"
echo "Log:   ${LOG_FILE}"
echo ""

set +e
pushd "${ROOT_DIR}" >/dev/null
cargo test --test algebraic_laws --test property_region_ops --test security/property_tests --all-features -- --nocapture 2>&1 | tee "${LOG_FILE}"
STATUS=${PIPESTATUS[0]}
popd >/dev/null
set -e

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

PASSED=$(grep -c "test .* ok" "${LOG_FILE}" 2>/dev/null || echo "0")

echo ""
echo "✓ Property tests passed"
echo "Total test functions: ${PASSED}"
echo "Cases per test (requested): ${PROPTEST_CASES}"
echo "Seed: ${PROPTEST_SEED}"
