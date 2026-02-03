#!/usr/bin/env bash
set -euo pipefail

# Phase 6 End-to-End Test Runner
#
# Runs all five Phase 6 E2E suites and produces a summary report.
# Exit code is non-zero if any required suite fails.
#
# Usage:
#   ./scripts/run_phase6_e2e.sh              # run all suites
#   ./scripts/run_phase6_e2e.sh --suite geo  # run a single suite

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/target/phase6-e2e"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${OUTPUT_DIR}/report_${TIMESTAMP}.txt"

export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Suite definitions: name, test target, required (1) or advisory (0)
declare -a SUITE_NAMES=(geo homo lyap raptorq plan)
declare -A SUITE_TARGETS=(
    [geo]=e2e_geodesic_normalization
    [homo]=topology_benchmark
    [lyap]=e2e_governor_vs_baseline
    [raptorq]=raptorq_conformance
    [plan]=golden_outputs
)
declare -A SUITE_LABELS=(
    [geo]="GEO  - Geodesic normalization"
    [homo]="HOMO - Topology-guided exploration"
    [lyap]="LYAP - Governor vs baseline"
    [raptorq]="RAPTORQ - Encode/decode conformance"
    [plan]="PLAN - Certified rewrite pipeline"
)

# Parse args
FILTER=""
if [[ "${1:-}" == "--suite" && -n "${2:-}" ]]; then
    FILTER="$2"
    if [[ -z "${SUITE_TARGETS[$FILTER]+x}" ]]; then
        echo "Unknown suite: $FILTER"
        echo "Available: ${SUITE_NAMES[*]}"
        exit 1
    fi
fi

echo "==== Phase 6 End-to-End Test Suites ===="
echo "Output: ${REPORT_FILE}"
echo ""

PASS=0
FAIL=0
TOTAL=0

pushd "${ROOT_DIR}" >/dev/null

for name in "${SUITE_NAMES[@]}"; do
    if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
        continue
    fi

    target="${SUITE_TARGETS[$name]}"
    label="${SUITE_LABELS[$name]}"
    log_file="${OUTPUT_DIR}/${name}_${TIMESTAMP}.log"

    printf "%-45s" "$label"
    TOTAL=$((TOTAL + 1))

    set +e
    cargo test --test "$target" --all-features -- --nocapture > "$log_file" 2>&1
    rc=$?
    set -e

    passed=$(grep -c "^test .* ok$" "$log_file" 2>/dev/null || echo "0")
    failed=$(grep -c "^test .* FAILED$" "$log_file" 2>/dev/null || echo "0")

    if [ "$rc" -eq 0 ]; then
        echo "PASS  ($passed tests)"
        PASS=$((PASS + 1))
        echo "PASS  $label  ($passed tests)" >> "$REPORT_FILE"
    else
        echo "FAIL  ($passed passed, $failed failed)"
        FAIL=$((FAIL + 1))
        echo "FAIL  $label  ($passed passed, $failed failed)" >> "$REPORT_FILE"
        echo "  Log: $log_file" >> "$REPORT_FILE"
    fi
done

popd >/dev/null

echo ""
echo "---- Summary ----"
echo "Suites: $TOTAL  Pass: $PASS  Fail: $FAIL"
echo "Report: ${REPORT_FILE}"
echo "Logs:   ${OUTPUT_DIR}/"

{
    echo ""
    echo "Summary: $TOTAL suites, $PASS passed, $FAIL failed"
    echo "Timestamp: $TIMESTAMP"
} >> "$REPORT_FILE"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
