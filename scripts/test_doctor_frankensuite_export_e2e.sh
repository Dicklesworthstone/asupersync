#!/usr/bin/env bash
# Doctor FrankenSuite Export E2E Runner (asupersync-2b4jj.5.3)
#
# Runs deterministic doctor export validation and verifies:
# - stable export payloads across repeated runs with same inputs
# - FrankenSuite evidence/decision artifacts are emitted and parseable
# - artifact counts and references match command output contract
#
# Usage:
#   ./scripts/test_doctor_frankensuite_export_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_frankensuite_export"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${ARTIFACT_DIR}/export_run1.json"
RUN2_JSON="${ARTIFACT_DIR}/export_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
REPORT_EXPORT_JSON="${ARTIFACT_DIR}/report_export_cross_system.json"
REPORT_EXPORT_LOG="${ARTIFACT_DIR}/report_export_cross_system.log"
EXPORT_ROOT="${ARTIFACT_DIR}/export_bundle"
FIXTURE_ID="${FIXTURE_ID:-baseline_failure_path}"
REPORT_EXPORT_FIXTURE_ID="${REPORT_EXPORT_FIXTURE_ID:-advanced_cross_system_mismatch_path}"
SUITE_ID="doctor_frankensuite_export_e2e"
E2E_SCENARIO_ID="E2E-SUITE-DOCTOR-FRANKENSUITE-EXPORT"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-240}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}" "${EXPORT_ROOT}"

echo "==================================================================="
echo "         Asupersync Doctor FrankenSuite Export E2E                "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:        ${RCH_BIN}"
echo "  TEST_LOG_LEVEL: ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:       ${RUST_LOG}"
echo "  TEST_SEED:      ${TEST_SEED}"
echo "  FIXTURE_ID:     ${FIXTURE_ID}"
echo "  REPORT_EXPORT_FIXTURE_ID: ${REPORT_EXPORT_FIXTURE_ID}"
echo "  Artifact dir:   ${ARTIFACT_DIR}"
echo "  Export root:    ${EXPORT_ROOT}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0
RUN_FAILURE_CLASS="none"

rch_attempt_went_local() {
    local log_path=""
    for log_path in "$@"; do
        [[ -f "${log_path}" ]] || continue
        if grep -Eq '\[RCH\] local \(|falling back to local' "${log_path}"; then
            return 0
        fi
    done
    return 1
}

update_run_failure_class() {
    local failure_class="${1:-}"
    if [[ "${failure_class}" == "rch_local_fallback" ]]; then
        RUN_FAILURE_CLASS="rch_local_fallback"
    fi
}

run_export_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local run_id="$4"
    local rc=0
    local payload=""
    local attempt_log=""
    local fell_back_local=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-frankensuite-export-${TIMESTAMP}-${run_id}-attempt${attempt}"
        local -a export_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor franken-export
            --fixture-id "${FIXTURE_ID}"
            --out-dir "${EXPORT_ROOT}"
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${export_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        fell_back_local=0
        if rch_attempt_went_local "${attempt_log}"; then
            echo "  ERROR: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} fell back to local execution; rejecting captured payload"
            fell_back_local=1
            rc=86
            update_run_failure_class "rch_local_fallback"
        fi

        payload="$(grep -E "\"schema_version\"[[:space:]]*:[[:space:]]*\"doctor-frankensuite-export-v1\"" "${attempt_log}" | tail -n1 || true)"
        if [[ -n "${payload}" ]] && printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
            if [[ ${fell_back_local} -eq 0 ]]; then
                cp "${attempt_log}" "${run_log}"
                printf '%s\n' "${payload}" > "${run_json}"
                if [[ ${rc} -ne 0 ]]; then
                    echo "  WARN: ${run_label} exited ${rc}; proceeding with captured JSON payload"
                fi
                return 0
            fi
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} produced no valid JSON payload (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (last exit=${rc}) and produced no valid JSON payload (see ${run_log})"
    return 1
}

run_report_export_call() {
    local run_log="$1"
    local run_json="$2"
    local rc=0
    local payload=""
    local attempt_log=""
    local fell_back_local=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-integration-export-${TIMESTAMP}-attempt${attempt}"
        local -a export_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor report-export
            --fixture-id "${REPORT_EXPORT_FIXTURE_ID}"
            --out-dir "${EXPORT_ROOT}"
            --format json
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${export_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        fell_back_local=0
        if rch_attempt_went_local "${attempt_log}"; then
            echo "  ERROR: report-export attempt ${attempt}/${RCH_RETRY_ATTEMPTS} fell back to local execution; rejecting captured payload"
            fell_back_local=1
            rc=86
            update_run_failure_class "rch_local_fallback"
        fi

        payload="$(grep -E "\"schema_version\"[[:space:]]*:[[:space:]]*\"doctor-report-export-v1\"" "${attempt_log}" | tail -n1 || true)"
        if [[ -n "${payload}" ]] && printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
            if [[ ${fell_back_local} -eq 0 ]]; then
                cp "${attempt_log}" "${run_log}"
                printf '%s\n' "${payload}" > "${run_json}"
                if [[ ${rc} -ne 0 ]]; then
                    echo "  WARN: report-export exited ${rc}; proceeding with captured JSON payload"
                fi
                return 0
            fi
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: report-export attempt ${attempt}/${RCH_RETRY_ATTEMPTS} produced no valid JSON payload (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: report-export failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (last exit=${rc}) and produced no valid JSON payload (see ${run_log})"
    return 1
}

echo ">>> [1/7] Running export command (run 1) via rch..."
if ! run_export_call "export run 1" "${RUN1_LOG}" "${RUN1_JSON}" "run1"; then
    EXIT_CODE=1
fi

echo ">>> [2/7] Running export command (run 2) via rch..."
if ! run_export_call "export run 2" "${RUN2_LOG}" "${RUN2_JSON}" "run2"; then
    EXIT_CODE=1
fi

echo ">>> [3/7] Running cross-system report export via rch..."
if ! run_report_export_call "${REPORT_EXPORT_LOG}" "${REPORT_EXPORT_JSON}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [4/7] Verifying deterministic top-level export payload..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: export payload mismatch across runs (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/7] Validating payload contract and artifact integrity..."
    if jq -e \
        --arg fixture "${FIXTURE_ID}" '
        .schema_version == "doctor-frankensuite-export-v1" and
        .source_schema_version == "doctor-core-report-v1" and
        (.exports | type == "array" and length == 1) and
        .exports[0].fixture_id == $fixture and
        (.exports[0].evidence_count | type == "number" and . > 0) and
        (.exports[0].decision_count | type == "number" and . > 0) and
        .exports[0].validation_status == "valid" and
        (.exports[0].evidence_jsonl | type == "string" and length > 0) and
        (.exports[0].decision_json | type == "string" and length > 0) and
        (. as $root | .exports[0] as $entry |
            ($entry.evidence_jsonl | startswith($root.export_root)) and
            ($entry.decision_json | startswith($root.export_root)) and
            ($entry.evidence_jsonl | endswith("_evidence.jsonl")) and
            ($entry.decision_json | endswith("_decision.json"))
        ) and
        (.rerun_commands | type == "array" and length >= 2) and
        (.rerun_commands[0] | contains("asupersync doctor franken-export")) and
        (.rerun_commands[1] | contains("asupersync doctor report-contract"))
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: export payload contract validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    if jq -e '
        .exports[0].evidence_count == 2 and
        .exports[0].decision_count == 2
    ' "${RUN2_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: deterministic artifact count check failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [6/7] Validating cross-system report/franken interoperability assertions..."
    if jq -e --arg report_fixture "${REPORT_EXPORT_FIXTURE_ID}" --argjson report "$(cat "${REPORT_EXPORT_JSON}")" '
        .schema_version == "doctor-frankensuite-export-v1" and
        .source_schema_version == "doctor-core-report-v1" and
        ($report.schema_version == "doctor-report-export-v1") and
        ($report.core_schema_version == .source_schema_version) and
        ($report.extension_schema_version == "doctor-advanced-report-v1") and
        ($report.exports | type == "array" and length == 1) and
        ($report.exports[0].fixture_id == $report_fixture) and
        ($report.exports[0].collaboration_channel_count == 3) and
        ($report.exports[0].collaboration_channels == ["agent_mail", "beads", "frankensuite"]) and
        ($report.exports[0].has_mismatch_diagnostics == true) and
        ($report.exports[0].validation_status == "valid") and
        ($report.rerun_commands | map(contains("doctor report-contract")) | any) and
        (.rerun_commands | map(contains("doctor report-contract")) | any)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: cross-system interoperability contract validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [7/7] Verifying cross-run export-root and link stability..."
    if jq -e --argjson run1 "$(cat "${RUN1_JSON}")" '
        .export_root == $run1.export_root and
        .exports[0].evidence_jsonl == $run1.exports[0].evidence_jsonl and
        .exports[0].decision_json == $run1.exports[0].decision_json and
        .exports[0].report_id == $run1.exports[0].report_id
    ' "${RUN2_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: exported link metadata changed across runs"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi
fi

RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
FAILURE_CLASS="test_or_pattern_failure"

if [[ ${EXIT_CODE} -eq 0 && ${CHECK_FAILURES} -eq 0 ]]; then
    SUITE_STATUS="passed"
    FAILURE_CLASS="none"
elif [[ "${RUN_FAILURE_CLASS}" == "rch_local_fallback" ]]; then
    FAILURE_CLASS="rch_local_fallback"
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
  "scenario_id": "${E2E_SCENARIO_ID}",
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
echo "           Doctor FrankenSuite Export E2E Summary                 "
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
