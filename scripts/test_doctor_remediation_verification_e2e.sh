#!/usr/bin/env bash
# Doctor Remediation Verification E2E Runner (asupersync-2b4jj.4.3)
#
# Runs deterministic post-remediation verification-loop checks and asserts:
# - trust-scorecard verification tests execute and pass under rch
# - scorecard-focused test slice is stable across repeated runs
# - required recommendation/evidence assertions remain in the test surface
#
# Usage:
#   ./scripts/test_doctor_remediation_verification_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_remediation_verification"
STAGING_ROOT="$(mktemp -d "/tmp/asupersync-doctor-remediation-verification-${TIMESTAMP}-XXXXXX")"
STAGING_ARTIFACT_DIR="${STAGING_ROOT}/artifacts_${TIMESTAMP}"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_LOG="${STAGING_ARTIFACT_DIR}/run1.log"
RUN2_LOG="${STAGING_ARTIFACT_DIR}/run2.log"
RUN1_PASS_LIST="${STAGING_ARTIFACT_DIR}/run1.passlist"
RUN2_PASS_LIST="${STAGING_ARTIFACT_DIR}/run2.passlist"
UNIT_FILTER="verification_"
SUITE_ID="doctor_remediation_verification_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-REMEDIATION-VERIFICATION"

REQUIRED_TESTS=(
    "verification_loop_smoke_is_deterministic_and_emits_scorecards"
    "verification_scorecard_computes_trust_delta_and_recommendations"
    "verification_scorecard_logs_capture_before_after_unresolved_and_shift"
    "verification_scorecard_thresholds_are_sane"
)

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-300}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${STAGING_ARTIFACT_DIR}"

echo "==================================================================="
echo "    Asupersync Doctor Remediation Verification E2E                 "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  UNIT_FILTER:      ${UNIT_FILTER}"
echo "  Retry attempts:   ${RCH_RETRY_ATTEMPTS}"
echo "  Staging dir:      ${STAGING_ARTIFACT_DIR}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0

run_verification_slice() {
    local run_label="$1"
    local run_log="$2"
    local run_pass_list="$3"
    local attempt_log=""
    local rc=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-remediation-verification-${TIMESTAMP}-${run_label}-attempt${attempt}"
        local -a run_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo test --quiet -p asupersync --features cli --test doctor_remediation_unit_harness "${UNIT_FILTER}" -- --nocapture
        )
        attempt_log="${run_log%.log}.attempt${attempt}.log"
        mkdir -p "$(dirname "${attempt_log}")"

        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${run_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if [[ ${rc} -eq 0 ]] && grep -q "test result: ok" "${attempt_log}"; then
            cp "${attempt_log}" "${run_log}"
            sed -nE 's/^test (verification_[[:alnum:]_]+) \.\.\. ok$/\1/p' "${run_log}" \
                | sort -u > "${run_pass_list}"
            return 0
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} failed (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

echo ">>> [1/5] Running verification scorecard test slice (run 1) via rch..."
if ! run_verification_slice "run1" "${RUN1_LOG}" "${RUN1_PASS_LIST}"; then
    EXIT_CODE=1
fi

echo ">>> [2/5] Running verification scorecard test slice (run 2) via rch..."
if ! run_verification_slice "run2" "${RUN2_LOG}" "${RUN2_PASS_LIST}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/5] Verifying deterministic pass-set across runs..."
    if diff -u "${RUN1_PASS_LIST}" "${RUN2_PASS_LIST}" > "${STAGING_ARTIFACT_DIR}/verification_passset.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${STAGING_ARTIFACT_DIR}/verification_passset.diff"
    else
        echo "  ERROR: verification pass-set mismatch across runs (see verification_passset.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/5] Validating required scorecard tests executed..."
    for test_name in "${REQUIRED_TESTS[@]}"; do
        if grep -Fxq "${test_name}" "${RUN1_PASS_LIST}"; then
            CHECKS_PASSED=$((CHECKS_PASSED + 1))
        else
            echo "  ERROR: required scorecard test missing from run output: ${test_name}"
            CHECK_FAILURES=$((CHECK_FAILURES + 1))
        fi
    done

    echo ">>> [5/5] Validating minimum executed test count..."
    RUNNING_COUNT="$(
        grep -Eo 'running [0-9]+ tests' "${RUN1_LOG}" \
            | tail -n1 \
            | awk '{print $2}' \
            || true
    )"
    if [[ -n "${RUNNING_COUNT}" && "${RUNNING_COUNT}" -ge 4 ]]; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: expected at least 4 verification tests; saw '${RUNNING_COUNT:-missing}'"
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

mkdir -p "${ARTIFACT_DIR}"
cp -a "${STAGING_ARTIFACT_DIR}/." "${ARTIFACT_DIR}/"

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
echo "    Doctor Remediation Verification E2E Summary                   "
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
