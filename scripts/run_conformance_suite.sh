#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/target/conformance-results"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/conformance_${TIMESTAMP}.log"
JSON_FILE="${OUTPUT_DIR}/conformance_${TIMESTAMP}.json"
LATEST_LOG="${OUTPUT_DIR}/latest.log"
LATEST_JSON="${OUTPUT_DIR}/latest.json"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

echo "==== Asupersync Conformance Suite ===="
echo "Log:  ${LOG_FILE}"
echo "JSON: ${JSON_FILE}"
echo ""

set +e
pushd "${ROOT_DIR}/conformance" >/dev/null
cargo test -- --nocapture 2>&1 | tee "${LOG_FILE}"
STATUS=${PIPESTATUS[0]}
popd >/dev/null
set -e

PASSED=$(grep -c "test .* ok" "${LOG_FILE}" 2>/dev/null || echo "0")
FAILED=$(grep -c "test .* FAILED" "${LOG_FILE}" 2>/dev/null || echo "0")
IGNORED=$(grep -c "test .* ignored" "${LOG_FILE}" 2>/dev/null || echo "0")
TOTAL=$((PASSED + FAILED + IGNORED))

STATUS_LABEL="passed"
if [ "${STATUS}" -ne 0 ] || [ "${FAILED}" -gt 0 ]; then
    STATUS_LABEL="failed"
fi

cat > "${JSON_FILE}" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "suite": "asupersync-conformance",
  "results": {
    "total": ${TOTAL},
    "passed": ${PASSED},
    "failed": ${FAILED},
    "ignored": ${IGNORED}
  },
  "log_file": "${LOG_FILE}",
  "status": "${STATUS_LABEL}"
}
EOF

cp "${LOG_FILE}" "${LATEST_LOG}"
cp "${JSON_FILE}" "${LATEST_JSON}"

echo ""
echo "Total:   ${TOTAL}"
echo "Passed:  ${PASSED}"
echo "Failed:  ${FAILED}"
echo "Ignored: ${IGNORED}"

if [ "${STATUS}" -ne 0 ] || [ "${FAILED}" -gt 0 ]; then
    echo "Conformance suite failed."
    exit 1
fi

echo "Conformance suite passed."
