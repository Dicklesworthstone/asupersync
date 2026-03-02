#!/usr/bin/env bash
# Doctor Report Export E2E Runner (asupersync-2b4jj.5.4)
#
# Validates deterministic markdown/json export generation for advanced diagnostics
# report fixtures and verifies required troubleshooting/provenance sections.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_report_export"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${ARTIFACT_DIR}/report_export_run1.json"
RUN2_JSON="${ARTIFACT_DIR}/report_export_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
EXPORT_ROOT="${ARTIFACT_DIR}/export_bundle"
FIXTURE_ID="${FIXTURE_ID:-advanced_failure_path}"
SUITE_ID="doctor_report_export_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-REPORT-EXPORT"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-360}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/rch-doctor-report-export-${TIMESTAMP}}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}" "${EXPORT_ROOT}"

echo "==================================================================="
echo "          Asupersync Doctor Report Export E2E                      "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:        ${RCH_BIN}"
echo "  TEST_LOG_LEVEL: ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:       ${RUST_LOG}"
echo "  TEST_SEED:      ${TEST_SEED}"
echo "  FIXTURE_ID:     ${FIXTURE_ID}"
echo "  Artifact dir:   ${ARTIFACT_DIR}"
echo "  Export root:    ${EXPORT_ROOT}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0

run_export_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local rc=0
    local attempt_log=""

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local -a export_cmd=(
            env "CARGO_TARGET_DIR=${RCH_TARGET_DIR}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor report-export
            --fixture-id "${FIXTURE_ID}"
            --out-dir "${EXPORT_ROOT}"
            --format markdown,json
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${export_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        local payload=""
        payload="$(grep -E '"schema_version"[[:space:]]*:[[:space:]]*"doctor-report-export-v1"' "${attempt_log}" | tail -n1 || true)"
        if [[ -n "${payload}" ]] && printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
            cp "${attempt_log}" "${run_log}"
            printf '%s\n' "${payload}" > "${run_json}"
            if [[ ${rc} -ne 0 ]]; then
                echo "  WARN: ${run_label} exited ${rc}; proceeding with captured JSON payload"
            fi
            return 0
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} produced no valid JSON payload (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

echo ">>> [1/6] Running report export command (run 1) via rch..."
if ! run_export_call "export run 1" "${RUN1_LOG}" "${RUN1_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [2/6] Running report export command (run 2) via rch..."
if ! run_export_call "export run 2" "${RUN2_LOG}" "${RUN2_JSON}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/6] Verifying deterministic top-level export payload..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: export payload mismatch across runs (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/6] Validating payload contract and artifact paths..."
    if jq -e --arg fixture "${FIXTURE_ID}" '
        .schema_version == "doctor-report-export-v1" and
        .core_schema_version == "doctor-core-report-v1" and
        .extension_schema_version == "doctor-advanced-report-v1" and
        (.formats | type == "array" and length == 2) and
        (.formats | index("json") != null) and
        (.formats | index("markdown") != null) and
        (.exports | type == "array" and length == 1) and
        .exports[0].fixture_id == $fixture and
        .exports[0].validation_status == "valid" and
        (.exports[0].output_files | type == "array" and length == 2) and
        (. as $root | .exports[0].output_files[] | startswith($root.export_root)) and
        (.exports[0].remediation_outcome_count | type == "number" and . > 0) and
        (.rerun_commands | type == "array" and length >= 2)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: export payload contract validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/6] Validating export metadata includes required report sections..."
    if jq -e '
        .exports[0].finding_count >= 1 and
        .exports[0].evidence_count >= 1 and
        .exports[0].command_count >= 1 and
        .exports[0].remediation_outcome_count >= 1 and
        (.exports[0].output_files | map(endswith(".json")) | any) and
        (.exports[0].output_files | map(endswith(".md")) | any) and
        (.rerun_commands | map(contains("doctor report-export")) | any) and
        (.rerun_commands | map(contains("doctor report-contract")) | any)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: export metadata validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [6/6] Validating cross-run file references..."
    if jq -e --argjson run1 "$(cat "${RUN1_JSON}")" '
        .export_root == $run1.export_root and
        .exports[0].output_files == $run1.exports[0].output_files and
        .exports[0].report_id == $run1.exports[0].report_id
    ' "${RUN2_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: exported file references changed across runs"
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

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} FIXTURE_ID=${FIXTURE_ID} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

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
  "log_file": "${RUN1_LOG}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
ENDJSON

echo ""
echo "==================================================================="
echo "           Doctor Report Export E2E Summary                        "
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
