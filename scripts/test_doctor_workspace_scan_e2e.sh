#!/usr/bin/env bash
# Doctor Workspace Scanner E2E Runner (asupersync-2b4jj.2.1)
#
# Runs deterministic scanner E2E validation against a synthetic Cargo workspace
# fixture and verifies:
# - stable schema/taxonomy versions
# - deterministic output across repeated runs
# - golden member/edge/warning expectations
#
# Usage:
#   ./scripts/test_doctor_workspace_scan_e2e.sh
#
# Environment Variables:
#   RCH_BIN         - path to rch binary (default: ~/.local/bin/rch)
#   TEST_LOG_LEVEL  - informational label (default: info)
#   RUST_LOG        - cargo/runtime log filter (default: asupersync=info)
#   TEST_SEED       - deterministic seed label for summary metadata

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_workspace_scan"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
SCAN1_JSON="${ARTIFACT_DIR}/scan_run1.json"
SCAN2_JSON="${ARTIFACT_DIR}/scan_run2.json"
SCAN1_NORM_JSON="${ARTIFACT_DIR}/scan_run1.normalized.json"
SCAN2_NORM_JSON="${ARTIFACT_DIR}/scan_run2.normalized.json"
SCAN1_LOG="${ARTIFACT_DIR}/scan1.log"
SCAN2_LOG="${ARTIFACT_DIR}/scan2.log"
FIXTURE_ROOT="${PROJECT_ROOT}/tests/fixtures/doctor_workspace_scan_e2e"
SUITE_ID="doctor_workspace_scan_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-WORKSPACE-SCAN"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-240}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "$RCH_BIN" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}"

echo "==================================================================="
echo "           Asupersync Doctor Workspace Scanner E2E                "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo "  Fixture root:     ${FIXTURE_ROOT}"
echo ""

if [[ ! -f "${FIXTURE_ROOT}/Cargo.toml" ]]; then
    echo "FATAL: fixture workspace missing at ${FIXTURE_ROOT}" >&2
    exit 1
fi

SCAN_CMD=(
    env "CARGO_TARGET_DIR=/tmp/rch-doctor-workspace-scan-${TIMESTAMP}" \
    cargo run --quiet --features cli --bin asupersync --
    --format json
    --color never
    doctor scan-workspace
    --root "${FIXTURE_ROOT}"
)

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0

run_scan_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local rc=0

    if ! timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${SCAN_CMD[@]}" >"${run_log}" 2>&1; then
        rc=$?
    fi

    local payload
    payload="$(grep -F '"scanner_version":"doctor-workspace-scan-v1"' "${run_log}" | tail -n1 || true)"
    if [[ -z "${payload}" ]]; then
        echo "  ERROR: ${run_label} failed (exit=${rc}) and produced no JSON payload (see ${run_log})"
        return 1
    fi

    if ! printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
        echo "  ERROR: ${run_label} emitted invalid JSON payload (see ${run_log})"
        return 1
    fi

    printf '%s\n' "${payload}" > "${run_json}"
    if [[ ${rc} -ne 0 ]]; then
        echo "  WARN: ${run_label} exited ${rc}; proceeding with captured JSON payload"
    fi

    return 0
}

echo ">>> [1/4] Running scan command (run 1) via rch..."
if ! run_scan_call "scan run 1" "${SCAN1_LOG}" "${SCAN1_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [2/4] Running scan command (run 2) via rch..."
if ! run_scan_call "scan run 2" "${SCAN2_LOG}" "${SCAN2_JSON}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/4] Verifying deterministic output..."
    jq 'del(.root, .workspace_manifest)' "${SCAN1_JSON}" > "${SCAN1_NORM_JSON}"
    jq 'del(.root, .workspace_manifest)' "${SCAN2_JSON}" > "${SCAN2_NORM_JSON}"
    if diff -u "${SCAN1_NORM_JSON}" "${SCAN2_NORM_JSON}" > "${ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: deterministic output check failed (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/4] Validating schema + golden expectations..."
    if jq -e '
        .scanner_version == "doctor-workspace-scan-v1" and
        .taxonomy_version == "capability-surfaces-v1" and
        .members == [
          {
            "name": "alpha",
            "relative_path": "alpha",
            "manifest_path": "alpha/Cargo.toml",
            "rust_file_count": 1,
            "capability_surfaces": ["cx", "runtime"]
          },
          {
            "name": "beta",
            "relative_path": "beta",
            "manifest_path": "beta/Cargo.toml",
            "rust_file_count": 1,
            "capability_surfaces": ["channel", "lab"]
          }
        ] and
        .capability_edges == [
          {
            "member": "alpha",
            "surface": "cx",
            "evidence_count": 1,
            "sample_files": ["alpha/src/lib.rs"]
          },
          {
            "member": "alpha",
            "surface": "runtime",
            "evidence_count": 1,
            "sample_files": ["alpha/src/lib.rs"]
          },
          {
            "member": "beta",
            "surface": "channel",
            "evidence_count": 1,
            "sample_files": ["beta/src/lib.rs"]
          },
          {
            "member": "beta",
            "surface": "lab",
            "evidence_count": 1,
            "sample_files": ["beta/src/lib.rs"]
          }
        ] and
        (.warnings | sort) == [
          "malformed package name field in Cargo.toml",
          "malformed package name field in Cargo.toml",
          "member missing Cargo.toml: missing_member"
          ,
          "missing package name in Cargo.toml"
        ] and
        (.events | map(.phase) | index("scan_start")) != null and
        (.events | map(.phase) | index("scan_complete")) != null and
        ((.events | map(select(.level == "warn")) | length) >= 4)
    ' "${SCAN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: golden/schema validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi
fi

RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
FAILURE_CLASS="test_or_pattern_failure"

if [[ ${EXIT_CODE} -eq 0 && ${CHECK_FAILURES} -eq 0 ]]; then
    SUITE_STATUS="passed"
    FAILURE_CLASS="none"
fi

TESTS_PASSED=0
TESTS_FAILED=1
if [[ "${SUITE_STATUS}" == "passed" ]]; then
    TESTS_PASSED=1
    TESTS_FAILED=0
fi

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

cat > "${SUMMARY_FILE}" <<ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "failure_class": "${FAILURE_CLASS}",
  "repro_command": "${REPRO_COMMAND}",
  "artifact_path": "${SUMMARY_FILE}",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "tests_passed": ${TESTS_PASSED},
  "tests_failed": ${TESTS_FAILED},
  "exit_code": ${EXIT_CODE},
  "pattern_failures": ${CHECK_FAILURES},
  "log_file": "${SCAN1_LOG}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
ENDJSON

echo ""
echo "==================================================================="
echo "            Doctor Workspace Scanner E2E Summary                  "
echo "==================================================================="
echo "  Status:         ${SUITE_STATUS}"
echo "  Exit code:      ${EXIT_CODE}"
echo "  Check failures: ${CHECK_FAILURES}"
echo "  Checks passed:  ${CHECKS_PASSED}"
echo "  Summary:        ${SUMMARY_FILE}"
echo "==================================================================="

if [[ ${EXIT_CODE} -ne 0 || ${CHECK_FAILURES} -ne 0 ]]; then
    exit 1
fi
