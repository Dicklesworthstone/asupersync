#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/target/conformance-results"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_asupersync_conformance_suite}"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "${value}"
}

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/conformance_${TIMESTAMP}.log"
JSON_FILE="${OUTPUT_DIR}/conformance_${TIMESTAMP}.json"
LATEST_LOG="${OUTPUT_DIR}/latest.log"
LATEST_JSON="${OUTPUT_DIR}/latest.json"

reject_rch_local_fallback_log() {
    if grep -Eq '^\[RCH\] local \(|falling back to local' "${LOG_FILE}" 2>/dev/null; then
        echo "FATAL: rch local fallback detected; refusing local cargo execution" >&2
        echo "rch local fallback detected; refusing local cargo execution" > "${OUTPUT_DIR}/rch_local_fallback_${TIMESTAMP}.txt"
        cat > "${JSON_FILE}" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "suite": "asupersync-conformance",
  "runner": "rch exec",
  "replay_command": "$(json_escape "${REPLAY_COMMAND}")",
  "target_dir": "$(json_escape "${CARGO_TARGET_DIR}")",
  "log_file": "$(json_escape "${LOG_FILE}")",
  "status": "rch_local_fallback"
}
EOF
        cp "${JSON_FILE}" "${LATEST_JSON}"
        exit 86
    fi
}

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

TEST_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync-conformance
    --
    --nocapture
)

printf -v REPLAY_COMMAND "%q " "${TEST_COMMAND[@]}"
REPLAY_COMMAND="${REPLAY_COMMAND% }"

echo "==== Asupersync Conformance Suite ===="
echo "Log:  ${LOG_FILE}"
echo "JSON: ${JSON_FILE}"
echo "Command: ${REPLAY_COMMAND}"
echo ""

if [[ "${DRY_RUN}" -eq 1 ]]; then
    cat > "${JSON_FILE}" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "suite": "asupersync-conformance",
  "dry_run": true,
  "runner": "rch exec",
  "replay_command": "$(json_escape "${REPLAY_COMMAND}")",
  "target_dir": "$(json_escape "${CARGO_TARGET_DIR}")",
  "status": "planned"
}
EOF
    cp "${JSON_FILE}" "${LATEST_JSON}"
    echo "Dry run planned without executing Cargo."
    exit 0
fi

set +e
"${TEST_COMMAND[@]}" 2>&1 | tee "${LOG_FILE}"
STATUS=${PIPESTATUS[0]}
set -e

reject_rch_local_fallback_log

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
  "log_file": "$(json_escape "${LOG_FILE}")",
  "runner": "rch exec",
  "replay_command": "$(json_escape "${REPLAY_COMMAND}")",
  "target_dir": "$(json_escape "${CARGO_TARGET_DIR}")",
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
