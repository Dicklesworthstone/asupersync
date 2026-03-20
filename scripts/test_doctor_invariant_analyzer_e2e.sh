#!/usr/bin/env bash
# Doctor Invariant Analyzer E2E Runner (asupersync-2b4jj.2.3)
#
# Runs deterministic invariant analysis against a synthetic workspace fixture and
# verifies:
# - stable analyzer/scanner schema versions
# - deterministic analyzer output across repeated runs
# - golden finding/rule-trace expectations
#
# Usage:
#   ./scripts/test_doctor_invariant_analyzer_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_invariant_analyzer"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${ARTIFACT_DIR}/analysis_run1.json"
RUN2_JSON="${ARTIFACT_DIR}/analysis_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
FIXTURE_TEMPLATE_ROOT="${PROJECT_ROOT}/tests/fixtures/doctor_workspace_scan_e2e"
STAGED_FIXTURE_ROOT="${ARTIFACT_DIR}/fixture_workspace"
SUITE_ID="doctor_invariant_analyzer_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-INVARIANT-ANALYZER"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
DOCTOR_FULLSTACK_SINGLE_RUN="${DOCTOR_FULLSTACK_SINGLE_RUN:-0}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-900}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}"

stage_workspace_fixture() {
    mkdir -p "${STAGED_FIXTURE_ROOT}"
    cp -R "${FIXTURE_TEMPLATE_ROOT}/." "${STAGED_FIXTURE_ROOT}/"
    cat > "${STAGED_FIXTURE_ROOT}/beta/Cargo.toml" <<'ENDMANIFEST'
[package]
name = beta
version = "0.1.0"
edition = "2024"
ENDMANIFEST
}

echo "==================================================================="
echo "            Asupersync Doctor Invariant Analyzer E2E              "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  Retry attempts:   ${RCH_RETRY_ATTEMPTS}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo "  Fixture template: ${FIXTURE_TEMPLATE_ROOT}"
echo "  Fixture root:     ${STAGED_FIXTURE_ROOT}"
echo ""

if [[ ! -f "${FIXTURE_TEMPLATE_ROOT}/Cargo.toml" ]]; then
    echo "FATAL: fixture workspace missing at ${FIXTURE_TEMPLATE_ROOT}" >&2
    exit 1
fi

stage_workspace_fixture

if [[ ! -f "${STAGED_FIXTURE_ROOT}/Cargo.toml" ]]; then
    echo "FATAL: staged fixture workspace missing at ${STAGED_FIXTURE_ROOT}" >&2
    exit 1
fi

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

run_analysis_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local run_id="$4"
    local rc=0
    local payload=""
    local attempt_log=""
    local fell_back_local=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        # Keep one deterministic target dir per script invocation so run1/run2
        # and retries reuse compiled artifacts instead of cold-compiling each call.
        local target_dir="/tmp/rch-doctor-invariant-analyzer-${TIMESTAMP}"
        local -a run_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            cargo run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor analyze-invariants
            --root "${STAGED_FIXTURE_ROOT}"
        )
        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${run_cmd[@]}" >"${attempt_log}" 2>&1; then
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

        payload="$(grep -E '"analyzer_version"[[:space:]]*:[[:space:]]*"doctor-invariant-analyzer-v1"' "${attempt_log}" | tail -n1 || true)"
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

echo ">>> [1/4] Running invariant analysis (run 1) via rch..."
if ! run_analysis_call "analysis run 1" "${RUN1_LOG}" "${RUN1_JSON}" "run1"; then
    EXIT_CODE=1
fi

if [[ "${DOCTOR_FULLSTACK_SINGLE_RUN}" == "1" ]]; then
    cp "${RUN1_LOG}" "${RUN2_LOG}"
    cp "${RUN1_JSON}" "${RUN2_JSON}"
else
    echo ">>> [2/4] Running invariant analysis (run 2) via rch..."
    if ! run_analysis_call "analysis run 2" "${RUN2_LOG}" "${RUN2_JSON}" "run2"; then
        EXIT_CODE=1
    fi
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/4] Verifying deterministic output..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: deterministic output check failed (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/4] Validating schema + golden expectations..."
    if jq -e '
        .analyzer_version == "doctor-invariant-analyzer-v1" and
        .scanner_version == "doctor-workspace-scan-v1" and
        .taxonomy_version == "capability-surfaces-v1" and
        (.correlation_id | type == "string" and length > 0) and
        .finding_count == (.findings | length) and
        (.findings | map(.rule_id) | sort) == [
          "cancel_phase_surface",
          "obligation_surface",
          "scanner_warning_integrity",
          "structured_concurrency_surface"
        ] and
        (.rule_traces | map(.rule_id) | sort) == [
          "cancel_phase_surface",
          "obligation_surface",
          "scan_lifecycle_events",
          "scanner_warning_integrity",
          "structured_concurrency_surface"
        ] and
        ((.rule_traces[] | select(.rule_id == "scan_lifecycle_events")).outcome == "pass") and
        ((.rule_traces | map(.correlation_id) | unique | length) == 1) and
        ((.findings[] | select(.rule_id == "scanner_warning_integrity")).severity == "warn")
    ' "${RUN1_JSON}" >/dev/null; then
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
elif [[ "${RUN_FAILURE_CLASS}" == "rch_local_fallback" ]]; then
    FAILURE_CLASS="rch_local_fallback"
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
echo "           Doctor Invariant Analyzer E2E Summary                  "
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
