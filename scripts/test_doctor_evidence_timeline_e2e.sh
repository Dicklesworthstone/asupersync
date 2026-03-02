#!/usr/bin/env bash
# Doctor Evidence Timeline E2E Runner (asupersync-2b4jj.3.4)
#
# Validates timeline drill-down contract + keyboard smoke flow through the CLI:
# - deterministic contract and smoke transcript output across repeated runs
# - required timeline event taxonomy and node-schema fields
# - keyboard transition expectations for evidence-panel drill-down
# - unit-test slice covering ordering/group/filter + causal traversal behavior
#
# Usage:
#   ./scripts/test_doctor_evidence_timeline_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_evidence_timeline"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_CONTRACT_JSON="${ARTIFACT_DIR}/contract_run1.json"
RUN2_CONTRACT_JSON="${ARTIFACT_DIR}/contract_run2.json"
RUN1_SMOKE_JSON="${ARTIFACT_DIR}/smoke_run1.json"
RUN2_SMOKE_JSON="${ARTIFACT_DIR}/smoke_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
UNIT_LOG="${ARTIFACT_DIR}/unit.log"
UNIT_JSON="${ARTIFACT_DIR}/unit_summary.json"
SUITE_ID="doctor_evidence_timeline_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-EVIDENCE-TIMELINE"
UNIT_FILTER="evidence_timeline_"
EXPECTED_MIN_TESTS=5

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-360}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}"

echo "==================================================================="
echo "          Asupersync Doctor Evidence Timeline E2E                 "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  UNIT_FILTER:      ${UNIT_FILTER}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0

run_export_call() {
    local run_label="$1"
    local run_log="$2"
    local contract_json="$3"
    local smoke_json="$4"

    local rc_contract=0
    local rc_smoke=0
    local attempt_log=""

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-timeline-${TIMESTAMP}-${run_label}-attempt${attempt}"
        local contract_tmp="${contract_json}.attempt${attempt}"
        local smoke_tmp="${smoke_json}.attempt${attempt}"
        attempt_log="${run_log%.log}.attempt${attempt}.log"
        : > "${attempt_log}"

        local -a contract_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor evidence-timeline-contract
        )
        local -a smoke_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor evidence-timeline-smoke
        )

        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${contract_cmd[@]}" >"${contract_tmp}" 2>>"${attempt_log}"; then
            rc_contract=0
        else
            rc_contract=$?
        fi

        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${smoke_cmd[@]}" >"${smoke_tmp}" 2>>"${attempt_log}"; then
            rc_smoke=0
        else
            rc_smoke=$?
        fi

        if [[ ${rc_contract} -eq 0 && ${rc_smoke} -eq 0 ]] \
            && jq -e . "${contract_tmp}" >/dev/null 2>&1 \
            && jq -e . "${smoke_tmp}" >/dev/null 2>&1; then
            mv "${contract_tmp}" "${contract_json}"
            mv "${smoke_tmp}" "${smoke_json}"
            cp "${attempt_log}" "${run_log}"
            return 0
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} failed (contract_exit=${rc_contract}, smoke_exit=${rc_smoke}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

run_unit_slice() {
    local run_log="$1"
    local run_json="$2"
    local attempt_log=""
    local rc=0
    local running_count=""
    local passed_count=""

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-timeline-unit-${TIMESTAMP}-attempt${attempt}"
        local -a unit_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo test --quiet --features cli --lib "${UNIT_FILTER}" -- --nocapture
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${unit_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        running_count="$(
            grep -Eo 'running [0-9]+ tests' "${attempt_log}" \
                | tail -n1 \
                | awk '{print $2}' \
                || true
        )"
        passed_count="$(
            sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "${attempt_log}" \
                | tail -n1 \
                || true
        )"

        if [[ ${rc} -eq 0 && -n "${running_count}" && -n "${passed_count}" ]]; then
            cp "${attempt_log}" "${run_log}"
            jq -n \
                --arg schema_version "doctor-evidence-timeline-unit-v1" \
                --arg filter "${UNIT_FILTER}" \
                --arg status "passed" \
                --argjson running_tests "${running_count}" \
                --argjson passed_tests "${passed_count}" \
                '{
                  schema_version: $schema_version,
                  test_filter: $filter,
                  status: $status,
                  running_tests: $running_tests,
                  passed_tests: $passed_tests
                }' > "${run_json}"
            return 0
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: unit-slice attempt ${attempt}/${RCH_RETRY_ATTEMPTS} failed (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: unit-slice failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

echo ">>> [1/6] Running timeline contract + smoke export (run 1) via rch..."
if ! run_export_call "run1" "${RUN1_LOG}" "${RUN1_CONTRACT_JSON}" "${RUN1_SMOKE_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [2/6] Running timeline contract + smoke export (run 2) via rch..."
if ! run_export_call "run2" "${RUN2_LOG}" "${RUN2_CONTRACT_JSON}" "${RUN2_SMOKE_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [3/6] Running timeline unit-test slice via rch..."
if ! run_unit_slice "${UNIT_LOG}" "${UNIT_JSON}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [4/6] Verifying deterministic contract + smoke outputs..."
    if diff -u "${RUN1_CONTRACT_JSON}" "${RUN2_CONTRACT_JSON}" > "${ARTIFACT_DIR}/contract_determinism.diff" \
        && diff -u "${RUN1_SMOKE_JSON}" "${RUN2_SMOKE_JSON}" > "${ARTIFACT_DIR}/smoke_determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/contract_determinism.diff" "${ARTIFACT_DIR}/smoke_determinism.diff"
    else
        echo "  ERROR: deterministic output mismatch (see *_determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/6] Validating contract + smoke schema and keyboard transitions..."
    if jq -e '
        .contract_version == "doctor-evidence-timeline-v1" and
        .core_report_contract_version == "doctor-core-report-v1" and
        (.required_node_fields | index("node_id") != null) and
        (.required_node_fields | index("missing_causal_refs") != null) and
        (.event_taxonomy | index("timeline_interaction") != null) and
        (.event_taxonomy | index("causal_expansion_decision") != null) and
        (.event_taxonomy | index("missing_link_diagnostic") != null)
    ' "${RUN1_CONTRACT_JSON}" >/dev/null \
        && jq -e '
        .scenario_id == "doctor-evidence-timeline-keyboard-smoke" and
        (.steps | type == "array" and length == 5) and
        .steps[0].focused_panel == "context_panel" and
        .steps[1].focused_panel == "primary_panel" and
        .steps[2].selected_node == "timeline-002" and
        .steps[3].focused_panel == "evidence_panel" and
        .steps[3].evidence_panel_node == "timeline-002" and
        .steps[4].focused_panel == "primary_panel" and
        .steps[4].evidence_panel_node == null and
        (.steps[3].snapshot.events | map(.event_kind) | index("timeline_interaction") != null) and
        (.steps[3].snapshot.events | map(.event_kind) | index("causal_expansion_decision") != null)
    ' "${RUN1_SMOKE_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: contract/smoke schema validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [6/6] Validating unit-test coverage floor and canonical test names..."
    if jq -e \
        --arg filter "${UNIT_FILTER}" \
        --argjson min_tests "${EXPECTED_MIN_TESTS}" '
        .schema_version == "doctor-evidence-timeline-unit-v1" and
        .test_filter == $filter and
        .status == "passed" and
        (.running_tests | type == "number") and
        .running_tests >= $min_tests and
        (.passed_tests | type == "number") and
        .passed_tests == .running_tests
    ' "${UNIT_JSON}" >/dev/null \
        && grep -q "evidence_timeline_contract_validates" "${UNIT_LOG}" \
        && grep -q "build_evidence_timeline_snapshot_orders_groups_and_filters" "${UNIT_LOG}" \
        && grep -q "build_evidence_timeline_snapshot_emits_missing_link_and_causal_events" "${UNIT_LOG}" \
        && grep -q "evidence_timeline_keyboard_flow_smoke_is_deterministic" "${UNIT_LOG}"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: unit-test slice validation failed"
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
  "log_file": "${RUN1_LOG}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
ENDJSON

echo ""
echo "==================================================================="
echo "         Doctor Evidence Timeline E2E Summary                     "
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
