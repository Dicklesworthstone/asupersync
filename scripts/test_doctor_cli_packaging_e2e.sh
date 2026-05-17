#!/usr/bin/env bash
# Doctor CLI Packaging E2E Runner (asupersync-2b4jj.6.3)
#
# Validates deterministic doctor_asupersync packaging payloads, config template
# materialization metadata, and packaged install/run smoke behavior.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_cli_package"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${ARTIFACT_DIR}/package_run1.json"
RUN2_JSON="${ARTIFACT_DIR}/package_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/package_run1.log"
RUN2_LOG="${ARTIFACT_DIR}/package_run2.log"
RUN1_OUTDIR="${ARTIFACT_DIR}/package_run1"
RUN2_OUTDIR="${ARTIFACT_DIR}/package_run2"
SUITE_ID="doctor_cli_packaging_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-CLI-PACKAGING"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-480}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/rch-doctor-cli-package-${TIMESTAMP}}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"

if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

rch_attempt_went_local() {
    local attempt_log="$1"

    grep -Eq '^\[RCH\] local \(|falling back to local' "${attempt_log}"
}

update_run_failure_class() {
    local candidate="$1"

    if [[ "${candidate}" == "rch_local_fallback" || "${RUN_FAILURE_CLASS}" == "none" ]]; then
        RUN_FAILURE_CLASS="${candidate}"
    fi
}

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}" "${RUN1_OUTDIR}" "${RUN2_OUTDIR}"

echo "==================================================================="
echo "          Asupersync Doctor CLI Packaging E2E                      "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:        ${RCH_BIN}"
echo "  TEST_LOG_LEVEL: ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:       ${RUST_LOG}"
echo "  TEST_SEED:      ${TEST_SEED}"
echo "  Artifact dir:   ${ARTIFACT_DIR}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0
RUN_FAILURE_CLASS="none"

run_packaging_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local package_out_dir="$4"
    local rc=0
    local attempt_log=""
    local last_failure_reason="test_or_pattern_failure"

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local -a package_cmd=(
            env "CARGO_TARGET_DIR=${RCH_TARGET_DIR}" \
            "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
            --format json
            --color never
            doctor package-cli
            --out-dir "${package_out_dir}"
            --binary-name "doctor_asupersync"
            --default-profile "ci"
            --smoke
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${package_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if rch_attempt_went_local "${attempt_log}"; then
            rc=86
            last_failure_reason="rch_local_fallback"
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} fell back to local cargo; rejecting attempt"
        fi

        local payload=""
        payload="$(grep -E '"schema_version"[[:space:]]*:[[:space:]]*"doctor-cli-package-v1"' "${attempt_log}" | tail -n1 || true)"
        if [[ -n "${payload}" ]] && printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
            cp "${attempt_log}" "${run_log}"
            printf '%s\n' "${payload}" > "${run_json}"
            if [[ ${rc} -ne 0 ]]; then
                if [[ "${last_failure_reason}" == "rch_local_fallback" ]]; then
                    rm -f "${run_json}"
                else
                    echo "  WARN: ${run_label} exited ${rc}; proceeding with captured JSON payload"
                    return 0
                fi
            else
                return 0
            fi
        fi

        if [[ ${attempt} -lt ${RCH_RETRY_ATTEMPTS} ]]; then
            update_run_failure_class "${last_failure_reason}"
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} produced no valid JSON payload (exit=${rc}); retrying"
            sleep 1
        fi
    done

    if [[ -n "${attempt_log}" && -f "${attempt_log}" ]]; then
        cp "${attempt_log}" "${run_log}"
    fi
    update_run_failure_class "${last_failure_reason}"
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (see ${run_log})"
    return 1
}

echo ">>> [1/5] Running package-cli flow (run 1) via rch..."
if ! run_packaging_call "package-cli run 1" "${RUN1_LOG}" "${RUN1_JSON}" "${RUN1_OUTDIR}"; then
    EXIT_CODE=1
fi

echo ">>> [2/5] Running package-cli flow (run 2) via rch..."
if ! run_packaging_call "package-cli run 2" "${RUN2_LOG}" "${RUN2_JSON}" "${RUN2_OUTDIR}"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/5] Validating packaging payload contract and smoke fields..."
    if jq -e '
        .schema_version == "doctor-cli-package-v1" and
        (.package_version | type == "string" and length > 0) and
        .binary_name == "doctor_asupersync" and
        (.packaged_binary_sha256 | type == "string" and length == 64) and
        (.packaged_binary_size_bytes | type == "number" and . > 0) and
        .default_profile == "ci" and
        (.config_templates | type == "array" and length == 2) and
        (.config_templates | map(.profile) | sort == ["ci", "local"]) and
        (.config_templates | map(.command_preview | contains("--format")) | all) and
        (.install_smoke != null) and
        .install_smoke.startup_status == "ok" and
        .install_smoke.command_status == "ok" and
        .install_smoke.observed_contract_version == "doctor-core-report-v1" and
        (.install_smoke.command_output_sha256 | type == "string" and length == 64) and
        (.structured_logs | type == "array" and length >= 4) and
        (.structured_logs | map(.event) | index("release_manifest_written") != null) and
        (.rerun_commands | type == "array" and length >= 2)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: package-cli payload contract validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/5] Validating deterministic metadata across runs..."
    if jq -e --argjson run1 "$(cat "${RUN1_JSON}")" '
        .schema_version == $run1.schema_version and
        .package_version == $run1.package_version and
        .binary_name == $run1.binary_name and
        .default_profile == $run1.default_profile and
        (.config_templates | map(.profile) | sort) == ($run1.config_templates | map(.profile) | sort) and
        (.config_templates | map(.command_preview) | sort) == ($run1.config_templates | map(.command_preview) | sort) and
        .install_smoke.command_output_sha256 == $run1.install_smoke.command_output_sha256 and
        .install_smoke.observed_contract_version == $run1.install_smoke.observed_contract_version
    ' "${RUN2_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: deterministic metadata mismatch across package runs"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/5] Validating log quality and remediation coverage..."
    if jq -e '
        (.structured_logs | map(.event) | index("package_started") != null) and
        (.structured_logs | map(.event) | index("config_template_materialized") != null) and
        (.structured_logs | map(.event) | index("package_completed") != null) and
        (.structured_logs | map(select(.event == "install_smoke_passed")) | length == 1) and
        (.structured_logs | map(select(.event == "install_smoke_passed"))[0].remediation_guidance | type == "string")
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: structured log coverage/remediation validation failed"
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
echo "         Doctor CLI Packaging E2E Summary                          "
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
