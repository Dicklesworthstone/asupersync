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
FIXTURE_TEMPLATE_ROOT="${PROJECT_ROOT}/tests/fixtures/doctor_workspace_scan_e2e"
FIXTURE_TEMPLATE_REL="tests/fixtures/doctor_workspace_scan_e2e"
SUITE_ID="doctor_workspace_scan_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-WORKSPACE-SCAN"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
DOCTOR_FULLSTACK_SINGLE_RUN="${DOCTOR_FULLSTACK_SINGLE_RUN:-0}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-900}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "$RCH_BIN" ]]; then
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

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}"

echo "==================================================================="
echo "           Asupersync Doctor Workspace Scanner E2E                "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  Retry attempts:   ${RCH_RETRY_ATTEMPTS}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo "  Fixture template: ${FIXTURE_TEMPLATE_ROOT}"
echo "  Remote fixture:   /tmp/asupersync-doctor-workspace-scan-${TIMESTAMP}-<run>"
echo ""

if [[ ! -f "${FIXTURE_TEMPLATE_ROOT}/Cargo.toml" ]]; then
    echo "FATAL: fixture workspace missing at ${FIXTURE_TEMPLATE_ROOT}" >&2
    exit 1
fi

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0
RUN_FAILURE_CLASS="none"

run_scan_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local run_id="$4"
    local rc=0
    local payload=""
    local attempt_log=""
    local last_failure_reason="test_or_pattern_failure"
    local remote_stage_root="/tmp/asupersync-doctor-workspace-scan-${TIMESTAMP}-${run_id}"
    local remote_target_dir="/tmp/rch-doctor-workspace-scan-${TIMESTAMP}"
    local remote_scan_script="set -euo pipefail; stage_root='${remote_stage_root}'; \
mkdir -p \"\${stage_root}\"; \
cp -R '${FIXTURE_TEMPLATE_REL}/.' \"\${stage_root}/\"; \
printf '%s\\n' '[package]' 'name = beta' 'version = \"0.1.0\"' 'edition = \"2024\"' > \"\${stage_root}/beta/Cargo.toml\"; \
env CARGO_TARGET_DIR='${remote_target_dir}' cargo run --quiet --features cli --bin asupersync -- --format json --color never doctor scan-workspace --root \"\${stage_root}\""

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        # Keep one deterministic target dir per script invocation so run1/run2
        # and retries reuse compiled artifacts instead of cold-compiling each call.
        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if (
            cd "${PROJECT_ROOT}"
            timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- bash -lc "${remote_scan_script}"
        ) >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if rch_attempt_went_local "${attempt_log}"; then
            rc=86
            last_failure_reason="rch_local_fallback"
            echo "  WARN: ${run_label} attempt ${attempt}/${RCH_RETRY_ATTEMPTS} fell back to local cargo; rejecting attempt"
        fi

        payload="$(grep -E '"scanner_version"[[:space:]]*:[[:space:]]*"doctor-workspace-scan-v1"' "${attempt_log}" | tail -n1 || true)"
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
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (last exit=${rc}) and produced no valid JSON payload (see ${run_log})"
    return 1
}

echo ">>> [1/4] Running scan command (run 1) via rch..."
if ! run_scan_call "scan run 1" "${SCAN1_LOG}" "${SCAN1_JSON}" "run1"; then
    EXIT_CODE=1
fi

if [[ "${DOCTOR_FULLSTACK_SINGLE_RUN}" == "1" ]]; then
    if [[ -f "${SCAN1_LOG}" ]]; then
        cp "${SCAN1_LOG}" "${SCAN2_LOG}"
    fi
    if [[ -f "${SCAN1_JSON}" ]]; then
        cp "${SCAN1_JSON}" "${SCAN2_JSON}"
    fi
else
    echo ">>> [2/4] Running scan command (run 2) via rch..."
    if ! run_scan_call "scan run 2" "${SCAN2_LOG}" "${SCAN2_JSON}" "run2"; then
        EXIT_CODE=1
    fi
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
