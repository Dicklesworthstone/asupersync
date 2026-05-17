#!/usr/bin/env bash
# Doctor Replay Launcher E2E Runner (asupersync-2b4jj.3.3)
#
# Runs deterministic replay-launcher validation against a real scenario fixture
# and verifies:
# - stable replay output across repeated runs with the same seed
# - required replay provenance fields and rerun command payloads
# - replay-window parameter handling and structured output shape
#
# Usage:
#   ./scripts/test_doctor_replay_launcher_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_replay_launcher"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
RUN1_JSON="${ARTIFACT_DIR}/replay_run1.json"
RUN2_JSON="${ARTIFACT_DIR}/replay_run2.json"
RUN1_LOG="${ARTIFACT_DIR}/run1.log"
RUN2_LOG="${ARTIFACT_DIR}/run2.log"
REPLAY_REPORT_PATH="${ARTIFACT_DIR}/replay_report.json"
SCENARIO_PATH="examples/scenarios/smoke_happy_path.yaml"
SCENARIO_ID="smoke-happy-path"
ARTIFACT_POINTER="artifacts/replay/doctor-smoke-happy-4242.json"
WINDOW_START="${WINDOW_START:-1}"
WINDOW_EVENTS="${WINDOW_EVENTS:-8}"
SUITE_ID="doctor_replay_launcher_e2e"
E2E_SCENARIO_ID="E2E-SUITE-DOCTOR-REPLAY-LAUNCHER"

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

if [[ ! -f "${PROJECT_ROOT}/${SCENARIO_PATH}" ]]; then
    echo "FATAL: scenario fixture missing at ${PROJECT_ROOT}/${SCENARIO_PATH}" >&2
    exit 1
fi

if ! [[ "${TEST_SEED}" =~ ^[0-9]+$ ]]; then
    echo "FATAL: TEST_SEED must be an unsigned integer for replay CLI; got '${TEST_SEED}'" >&2
    exit 1
fi

if ! [[ "${WINDOW_START}" =~ ^[0-9]+$ ]]; then
    echo "FATAL: WINDOW_START must be a non-negative integer; got '${WINDOW_START}'" >&2
    exit 1
fi

if ! [[ "${WINDOW_EVENTS}" =~ ^[0-9]+$ ]] || [[ "${WINDOW_EVENTS}" -eq 0 ]]; then
    echo "FATAL: WINDOW_EVENTS must be a positive integer; got '${WINDOW_EVENTS}'" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}"

echo "==================================================================="
echo "           Asupersync Doctor Replay Launcher E2E                  "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  WINDOW_START:     ${WINDOW_START}"
echo "  WINDOW_EVENTS:    ${WINDOW_EVENTS}"
echo "  Artifact pointer: ${ARTIFACT_POINTER}"
echo "  Artifact dir:     ${ARTIFACT_DIR}"
echo "  Scenario:         ${SCENARIO_PATH}"
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

run_replay_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local run_id="$4"
    local rc=0
    local payload=""
    local attempt_log=""
    local fell_back_local=0

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-doctor-replay-launcher-${TIMESTAMP}-${run_id}-attempt${attempt}"
        local -a replay_cmd=(
            env "CARGO_TARGET_DIR=${target_dir}" \
            "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
            --format json
            --color never
            lab replay "${SCENARIO_PATH}"
            --seed "${TEST_SEED}"
            --artifact-pointer "${ARTIFACT_POINTER}"
            --artifact-output "${REPLAY_REPORT_PATH}"
            --window-start "${WINDOW_START}"
            --window-events "${WINDOW_EVENTS}"
        )

        attempt_log="${run_log%.log}.attempt${attempt}.log"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${replay_cmd[@]}" >"${attempt_log}" 2>&1; then
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

        payload="$(grep -E "\"scenario_id\"[[:space:]]*:[[:space:]]*\"${SCENARIO_ID}\"" "${attempt_log}" | tail -n1 || true)"
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

echo ">>> [1/4] Running replay command (run 1) via rch..."
if ! run_replay_call "replay run 1" "${RUN1_LOG}" "${RUN1_JSON}" "run1"; then
    EXIT_CODE=1
fi

echo ">>> [2/4] Running replay command (run 2) via rch..."
if ! run_replay_call "replay run 2" "${RUN2_LOG}" "${RUN2_JSON}" "run2"; then
    EXIT_CODE=1
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/4] Verifying deterministic replay output..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${ARTIFACT_DIR}/determinism.diff"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        rm -f "${ARTIFACT_DIR}/determinism.diff"
    else
        echo "  ERROR: deterministic replay output mismatch (see determinism.diff)"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/4] Validating replay provenance and schema invariants..."
    if jq -e \
        --arg scenario "${SCENARIO_PATH}" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg pointer "${ARTIFACT_POINTER}" \
        --arg report_path "${REPLAY_REPORT_PATH}" \
        --argjson seed "${TEST_SEED}" \
        --argjson window_start "${WINDOW_START}" \
        --argjson window_events "${WINDOW_EVENTS}" '
        .scenario == $scenario and
        .scenario_id == $scenario_id and
        .deterministic == true and
        .seed == $seed and
        (.trace_fingerprint | type == "number") and
        (.steps | type == "number") and
        (.replay_events | type == "number" and . >= 1) and
        .window.start == $window_start and
        .window.requested_events == $window_events and
        (.window as $w | ($w.total_events | type == "number") and $w.total_events >= $w.resolved_events) and
        (.window.end_exclusive | type == "number") and
        .window.end_exclusive >= .window.start and
        .provenance.scenario_path == $scenario and
        .provenance.artifact_pointer == $pointer and
        (.provenance.rerun_commands | type == "array" and length >= 2) and
        (.provenance.rerun_commands[0] | contains("asupersync lab replay")) and
        (.provenance.rerun_commands[0] | contains("--seed \($seed)")) and
        (.provenance.rerun_commands[0] | contains("--window-start \($window_start)")) and
        (.provenance.rerun_commands[0] | contains("--window-events \($window_events)")) and
        (.provenance.rerun_commands[0] | contains("--artifact-pointer \($pointer)")) and
        (.provenance.rerun_commands[0] | contains("--artifact-output \($report_path)")) and
        (.provenance.rerun_commands[1] | contains("asupersync lab run")) and
        (.divergence == null)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: replay provenance/schema validation failed"
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

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} WINDOW_START=${WINDOW_START} WINDOW_EVENTS=${WINDOW_EVENTS} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

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
echo "             Doctor Replay Launcher E2E Summary                   "
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
