#!/usr/bin/env bash
# Doctor Scenario Coverage Packs E2E Runner (asupersync-2b4jj.3.5)
#
# Validates deterministic scenario coverage packs for doctor Track 3:
# - deterministic contract + smoke report outputs across repeated runs
# - required workflow variants (cancellation/retry/degraded_dependency/recovery)
# - transcript terminal-state expectations and artifact-index schema
# - unit-test slice coverage for pack contract/selection/oracle invariants
#
# Usage:
#   ./scripts/test_doctor_scenario_coverage_packs_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET_OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_scenario_coverage_packs"
STAGING_ROOT="${TMPDIR:-/tmp}/asupersync-e2e-staging/doctor_scenario_coverage_packs"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_BASENAME="artifacts_${TIMESTAMP}"
ARTIFACT_DIR="${STAGING_ROOT}/${ARTIFACT_BASENAME}"
PUBLISHED_ARTIFACT_DIR="${TARGET_OUTPUT_DIR}/${ARTIFACT_BASENAME}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_CONTRACT_JSON="${ARTIFACT_DIR}/contract_run1.json"
RUN2_CONTRACT_JSON="${ARTIFACT_DIR}/contract_run2.json"
RUN1_SMOKE_JSON="${ARTIFACT_DIR}/smoke_run1.json"
RUN2_SMOKE_JSON="${ARTIFACT_DIR}/smoke_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
UNIT_LOG="${ARTIFACT_DIR}/unit.log"
UNIT_JSON="${ARTIFACT_DIR}/unit_summary.json"
SUITE_ID="doctor_scenario_coverage_packs_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-SCENARIO-COVERAGE-PACKS"
UNIT_FILTER="doctor_scenario_coverage"
EXPECTED_MIN_TESTS=6
SELECTION_MODE="all"
SMOKE_SEED="${SMOKE_SEED:-seed-4242}"

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

if ! [[ "${SMOKE_SEED}" =~ ^[a-z0-9._:/-]+$ ]]; then
    echo "FATAL: SMOKE_SEED must be slug-like; got '${SMOKE_SEED}'" >&2
    exit 1
fi

ensure_artifact_dirs() {
    mkdir -p "${ARTIFACT_DIR}"
}

publish_artifacts() {
    mkdir -p "${TARGET_OUTPUT_DIR}" "${PUBLISHED_ARTIFACT_DIR}" \
        && cp -a "${ARTIFACT_DIR}/." "${PUBLISHED_ARTIFACT_DIR}/"
}

ensure_artifact_dirs

echo "==================================================================="
echo "     Asupersync Doctor Scenario Coverage Packs E2E                "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  SMOKE_SEED:       ${SMOKE_SEED}"
echo "  UNIT_FILTER:      ${UNIT_FILTER}"
echo "  Artifact staging: ${ARTIFACT_DIR}"
echo "  Artifact output:  ${PUBLISHED_ARTIFACT_DIR}"
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
    local contract_ready=0

    if jq -e . "${contract_json}" >/dev/null 2>&1; then
        contract_ready=1
    fi

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        ensure_artifact_dirs
        local target_dir="/tmp/rch-doctor-scenario-packs-${TIMESTAMP}-${run_label}-attempt${attempt}"
        local contract_tmp="${contract_json}.attempt${attempt}"
        local smoke_tmp="${smoke_json}.attempt${attempt}"
        attempt_log="${run_log%.log}.attempt${attempt}.log"
        : > "${attempt_log}"

        local -a contract_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor scenario-coverage-pack-contract
        )
        local -a smoke_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor scenario-coverage-pack-smoke
            --selection-mode "${SELECTION_MODE}"
            --seed "${SMOKE_SEED}"
        )

        if [[ ${contract_ready} -eq 1 ]]; then
            cp "${contract_json}" "${contract_tmp}"
            rc_contract=0
        else
            if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${contract_cmd[@]}" >"${contract_tmp}" 2>>"${attempt_log}"; then
                rc_contract=0
            else
                rc_contract=$?
            fi
        fi

        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${smoke_cmd[@]}" >"${smoke_tmp}" 2>>"${attempt_log}"; then
            rc_smoke=0
        else
            rc_smoke=$?
        fi

        if ! jq -e . "${contract_tmp}" >/dev/null 2>&1; then
            local contract_payload=""
            contract_payload="$(grep -E 'doctor-scenario-coverage-packs-v1' "${attempt_log}" | tail -n1 || true)"
            if [[ -n "${contract_payload}" ]] && printf '%s\n' "${contract_payload}" | jq -e . >/dev/null 2>&1; then
                printf '%s\n' "${contract_payload}" > "${contract_tmp}"
            fi
        fi

        if ! jq -e . "${smoke_tmp}" >/dev/null 2>&1; then
            local smoke_payload=""
            smoke_payload="$(grep -E 'doctor-scenario-coverage-pack-report-v1' "${attempt_log}" | tail -n1 || true)"
            if [[ -n "${smoke_payload}" ]] && printf '%s\n' "${smoke_payload}" | jq -e . >/dev/null 2>&1; then
                printf '%s\n' "${smoke_payload}" > "${smoke_tmp}"
            fi
        fi

        if [[ ${rc_contract} -eq 0 ]] \
            && jq -e . "${contract_tmp}" >/dev/null 2>&1; then
            mv "${contract_tmp}" "${contract_json}"
            contract_ready=1
        fi

        if [[ ${contract_ready} -eq 1 && ${rc_smoke} -eq 0 ]] \
            && jq -e . "${contract_json}" >/dev/null 2>&1 \
            && jq -e . "${smoke_tmp}" >/dev/null 2>&1; then
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
        ensure_artifact_dirs
        local target_dir="/tmp/rch-doctor-scenario-packs-unit-${TIMESTAMP}-attempt${attempt}"
        local -a unit_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo test --features cli --lib "${UNIT_FILTER}" -- --nocapture
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
                --arg schema_version "doctor-scenario-coverage-pack-unit-v1" \
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

echo ">>> [1/6] Running scenario-pack contract + smoke export (run 1) via rch..."
if ! run_export_call "run1" "${RUN1_LOG}" "${RUN1_CONTRACT_JSON}" "${RUN1_SMOKE_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [2/6] Running scenario-pack contract + smoke export (run 2) via rch..."
if ! run_export_call "run2" "${RUN2_LOG}" "${RUN2_CONTRACT_JSON}" "${RUN2_SMOKE_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [3/6] Running scenario-pack unit-test slice via rch..."
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

    echo ">>> [5/6] Validating contract + smoke schema and outcome oracles..."
    if jq -e '
        (.contract // .) as $contract |
        $contract.contract_version == "doctor-scenario-coverage-packs-v1" and
        $contract.e2e_harness_contract_version == "doctor-e2e-harness-v1" and
        ($contract.selection_modes | index("all") != null) and
        ($contract.selection_modes | index("cancellation") != null) and
        ($contract.selection_modes | index("retry") != null) and
        ($contract.selection_modes | index("degraded_dependency") != null) and
        ($contract.selection_modes | index("recovery") != null) and
        ($contract.required_pack_fields | index("workflow_variant") != null) and
        ($contract.required_run_fields | index("terminal_state") != null) and
        ($contract.required_run_fields | index("artifact_manifest") != null) and
        ($contract.required_run_fields | index("visual_snapshot") != null) and
        ($contract.required_log_fields | index("failure_cluster") != null) and
        ($contract.required_log_fields | index("snapshot_path") != null) and
        ($contract.required_log_fields | index("metrics_path") != null) and
        ($contract.required_log_fields | index("replay_metadata_path") != null) and
        ($contract.minimum_required_pack_ids | length >= 4) and
        ($contract.coverage_packs | length >= 4)
    ' "${RUN1_CONTRACT_JSON}" >/dev/null \
        && jq -e '
        (.report // .) as $report |
        $report.schema_version == "doctor-scenario-coverage-pack-report-v1" and
        $report.selection_mode == "all" and
        ($report.runs | type == "array" and length == 4) and
        (($report.runs | map(.workflow_variant) | sort) == ["cancellation","degraded_dependency","recovery","retry"]) and
        ($report.runs | all(
            (.expected_outcome == "cancelled" and .terminal_state == "cancelled") or
            (.expected_outcome == "failed" and .terminal_state == "failed") or
            (.expected_outcome == "success" and .terminal_state == "completed")
        )) and
        ($report.runs | all(.status == "passed")) and
        ($report.runs | all((.artifact_index | map(.artifact_class) | sort) == ["structured_log","summary","transcript"])) and
        ($report.runs | all((.artifact_manifest.records | map(.artifact_class) | sort) == ["metrics","replay_metadata","snapshot","structured_log","summary","transcript"])) and
        ($report.runs | all(.artifact_manifest.schema_version == "doctor-visual-harness-manifest-v1")) and
        ($report.runs | all(.visual_snapshot.stage_digest | startswith("len:"))) and
        ($report.runs | all(.structured_log_summary.failure_cluster != "")) and
        ($report.runs | all(.structured_log_summary.transcript_path | startswith("artifacts/"))) and
        ($report.runs | all(.structured_log_summary.snapshot_path | startswith("artifacts/"))) and
        ($report.runs | all(.structured_log_summary.metrics_path | startswith("artifacts/"))) and
        ($report.runs | all(.structured_log_summary.replay_metadata_path | startswith("artifacts/"))) and
        ($report.failure_clusters | type == "array" and length >= 4)
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
        .schema_version == "doctor-scenario-coverage-pack-unit-v1" and
        .test_filter == $filter and
        .status == "passed" and
        (.running_tests | type == "number") and
        .running_tests >= $min_tests and
        (.passed_tests | type == "number") and
        .passed_tests == .running_tests
    ' "${UNIT_JSON}" >/dev/null \
        && grep -q "doctor_scenario_coverage_packs_contract_validates" "${UNIT_LOG}" \
        && grep -q "select_doctor_scenario_coverage_packs_filters_variants" "${UNIT_LOG}" \
        && grep -q "doctor_scenario_coverage_pack_smoke_report_is_deterministic" "${UNIT_LOG}" \
        && grep -q "doctor_scenario_coverage_pack_smoke_report_aligns_terminal_outcomes" "${UNIT_LOG}" \
        && grep -q "doctor_scenario_coverage_pack_visual_harness_manifest_is_complete" "${UNIT_LOG}"; then
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

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} SMOKE_SEED=${SMOKE_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

ensure_artifact_dirs
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
  "artifact_path": "${PUBLISHED_ARTIFACT_DIR}/summary.json",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "tests_passed": ${TESTS_PASSED},
  "tests_failed": ${TESTS_FAILED},
  "exit_code": ${EXIT_CODE},
  "pattern_failures": ${CHECK_FAILURES},
  "log_file": "${PUBLISHED_ARTIFACT_DIR}/run1.log",
  "artifact_dir": "${PUBLISHED_ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
ENDJSON

if publish_artifacts; then
    SUMMARY_FILE="${PUBLISHED_ARTIFACT_DIR}/summary.json"
else
    echo "  ERROR: failed to publish artifacts to ${PUBLISHED_ARTIFACT_DIR}" >&2
    EXIT_CODE=1
fi

echo ""
echo "==================================================================="
echo "    Doctor Scenario Coverage Packs E2E Summary                    "
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
