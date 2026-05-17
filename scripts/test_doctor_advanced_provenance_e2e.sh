#!/usr/bin/env bash
# Doctor Advanced Provenance E2E Runner (asupersync-2b4jj.5.9)
#
# Exercises advanced diagnostics report export across the full fixture corpus and
# validates cross-system provenance scenarios:
# - rollback
# - partial-success
# - conflicting-signal
# - beads/bv + Agent Mail + FrankenSuite mismatch diagnostics
#
# Usage:
#   ./scripts/test_doctor_advanced_provenance_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_advanced_provenance"
STAGING_ROOT="$(mktemp -d "/tmp/asupersync-doctor-advanced-provenance-${TIMESTAMP}-XXXXXX")"
STAGING_ARTIFACT_DIR="${STAGING_ROOT}/artifacts_${TIMESTAMP}"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${STAGING_ARTIFACT_DIR}/report_export_run1.json"
RUN2_JSON="${STAGING_ARTIFACT_DIR}/report_export_run2.json"
RUN1_LOG="${STAGING_ARTIFACT_DIR}/run1.log"
RUN2_LOG="${STAGING_ARTIFACT_DIR}/run2.log"
EXPORT_ROOT="${STAGING_ARTIFACT_DIR}/export_bundle"
SUITE_ID="doctor_advanced_provenance_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-ADVANCED-PROVENANCE"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-5150}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-420}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${STAGING_ARTIFACT_DIR}" "${EXPORT_ROOT}"

echo "==================================================================="
echo "        Asupersync Doctor Advanced Provenance E2E                 "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:        ${RCH_BIN}"
echo "  TEST_LOG_LEVEL: ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:       ${RUST_LOG}"
echo "  TEST_SEED:      ${TEST_SEED}"
echo "  Staging dir:    ${STAGING_ARTIFACT_DIR}"
echo "  Artifact dir:   ${ARTIFACT_DIR}"
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
    local rc=0
    local attempt_log=""
    local fell_back_local=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-advanced-provenance-${TIMESTAMP}-${run_label}-attempt${attempt}"
        local -a export_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor report-export
            --out-dir "${EXPORT_ROOT}"
            --format markdown,json
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        mkdir -p "$(dirname "${attempt_log}")"
        if "${RCH_BIN}" exec -- "${export_cmd[@]}" >"${attempt_log}" 2>&1; then
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

        local payload=""
        payload="$(grep -E '"schema_version"[[:space:]]*:[[:space:]]*"doctor-report-export-v1"' "${attempt_log}" | tail -n1 || true)"
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
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

echo ">>> [1/6] Running full advanced report export (run 1) via rch..."
if ! run_export_call "run1" "${RUN1_LOG}" "${RUN1_JSON}"; then
    EXIT_CODE=1
fi

echo ">>> [2/6] Running full advanced report export (run 2) via rch..."
if ! run_export_call "run2" "${RUN2_LOG}" "${RUN2_JSON}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/6] Verifying deterministic export payload..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${STAGING_ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${STAGING_ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: export payload mismatch across runs (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/6] Validating fixture corpus coverage and output schema..."
    if jq -e '
        .schema_version == "doctor-report-export-v1" and
        (.exports | length >= 6) and
        ([.exports[].fixture_id] | sort) == [
          "advanced_conflicting_signal_path",
          "advanced_cross_system_mismatch_path",
          "advanced_failure_path",
          "advanced_happy_path",
          "advanced_partial_success_path",
          "advanced_rollback_path"
        ] and
        (.exports[] | .output_files | map(endswith(".json")) | any) and
        (.exports[] | .output_files | map(endswith(".md")) | any) and
        (.rerun_commands | map(contains("doctor report-export")) | any) and
        (.rerun_commands | map(contains("doctor report-contract")) | any)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: fixture corpus/schema validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/6] Validating cross-system mismatch diagnostics metadata..."
    if jq -e '
        .exports[]
        | select(.fixture_id=="advanced_cross_system_mismatch_path")
        | (.collaboration_channels == ["agent_mail", "beads", "frankensuite"]) and
          (.has_mismatch_diagnostics == true)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: cross-system mismatch diagnostics validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [6/6] Validating rollback + partial-success metadata..."
    if jq -e '
        (.exports[] | select(.fixture_id=="advanced_rollback_path") | .has_rollback_signal == true) and
        (.exports[] | select(.fixture_id=="advanced_partial_success_path") | .has_partial_success_mix == true)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: rollback/partial-success validation failed"
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

mkdir -p "${ARTIFACT_DIR}"
cp -a "${STAGING_ARTIFACT_DIR}/." "${ARTIFACT_DIR}/"

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
  "log_file": "${ARTIFACT_DIR}/run1.log",
  "artifact_dir": "${ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
ENDJSON

echo ""
echo "==================================================================="
echo "        Doctor Advanced Provenance E2E Summary                    "
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
