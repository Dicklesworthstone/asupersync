#!/usr/bin/env bash
# WASM Incident Forensics Drill E2E (asupersync-umelq.12.5)
#
# Exercises deterministic replay incident workflow and verifies:
# - stable replay output across repeated seeded runs
# - expected failure-path diagnostics for missing scenario input
# - reproducible artifact bundle with summary, events, and repro pointers
#
# Usage:
#   ./scripts/test_wasm_incident_forensics_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/wasm_incident_forensics"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
WORK_DIR="/tmp/asupersync_wasm_incident_forensics_${TIMESTAMP}_$$"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
INCIDENT_SUMMARY_FILE="${ARTIFACT_DIR}/incident_summary.json"
EVENTS_FILE="${ARTIFACT_DIR}/incident_events.ndjson"
REPRO_BUNDLE_FILE="${ARTIFACT_DIR}/repro_bundle.json"
RUN1_JSON="${WORK_DIR}/replay_run1.json"
RUN2_JSON="${WORK_DIR}/replay_run2.json"
RUN1_LOG="${WORK_DIR}/run1.log"
RUN2_LOG="${WORK_DIR}/run2.log"
FAILURE_LOG="${WORK_DIR}/expected_failure.log"
DETERMINISM_DIFF="${WORK_DIR}/determinism.diff"
REPLAY_REPORT_PATH="${ARTIFACT_DIR}/replay_report.json"
ARTIFACT_RUN1_JSON="${ARTIFACT_DIR}/replay_run1.json"
ARTIFACT_RUN2_JSON="${ARTIFACT_DIR}/replay_run2.json"
ARTIFACT_RUN1_LOG="${ARTIFACT_DIR}/run1.log"
ARTIFACT_RUN2_LOG="${ARTIFACT_DIR}/run2.log"
ARTIFACT_FAILURE_LOG="${ARTIFACT_DIR}/expected_failure.log"
ARTIFACT_DETERMINISM_DIFF="${ARTIFACT_DIR}/determinism.diff"
SCENARIO_PATH="examples/scenarios/smoke_happy_path.yaml"
SCENARIO_ID="smoke-happy-path"
MISSING_SCENARIO_PATH="examples/scenarios/missing_forensics_fixture.yaml"
ARTIFACT_POINTER="artifacts/replay/wasm-incident-smoke-4242.json"
SUITE_ID="wasm_incident_forensics_e2e"
E2E_SCENARIO_ID="E2E-SUITE-WASM-INCIDENT-FORENSICS"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-4242}"
WINDOW_START="${WINDOW_START:-1}"
WINDOW_EVENTS="${WINDOW_EVENTS:-10}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-240}"
RCH_RETRY_ATTEMPTS="${RCH_RETRY_ATTEMPTS:-3}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
DRY_RUN="${INCIDENT_FORENSICS_DRY_RUN:-0}"

if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

if [[ ! -f "${PROJECT_ROOT}/${SCENARIO_PATH}" ]]; then
    echo "FATAL: scenario fixture missing at ${PROJECT_ROOT}/${SCENARIO_PATH}" >&2
    exit 1
fi

if ! [[ "${TEST_SEED}" =~ ^[0-9]+$ ]]; then
    echo "FATAL: TEST_SEED must be an unsigned integer; got '${TEST_SEED}'" >&2
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

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}" "${WORK_DIR}"

echo "==================================================================="
echo "      Asupersync WASM Incident Forensics E2E Drill              "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:         ${RCH_BIN}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  WINDOW_START:    ${WINDOW_START}"
echo "  WINDOW_EVENTS:   ${WINDOW_EVENTS}"
echo "  Scenario:        ${SCENARIO_PATH}"
echo "  Artifact pointer:${ARTIFACT_POINTER}"
echo "  Artifact dir:    ${ARTIFACT_DIR}"
echo "  Dry run:         ${DRY_RUN}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0

run_replay_call() {
    local run_label="$1"
    local run_log="$2"
    local run_json="$3"
    local run_id="$4"
    local rc=0
    local payload=""
    local attempt_log=""

    if [[ "${DRY_RUN}" == "1" ]]; then
        mkdir -p "$(dirname "${run_json}")" "$(dirname "${run_log}")"
        payload="$(jq -nc \
            --arg scenario "${SCENARIO_PATH}" \
            --arg scenario_id "${SCENARIO_ID}" \
            --arg pointer "${ARTIFACT_POINTER}" \
            --arg report_path "${REPLAY_REPORT_PATH}" \
            --argjson seed "${TEST_SEED}" \
            --argjson window_start "${WINDOW_START}" \
            --argjson window_events "${WINDOW_EVENTS}" '
            {
              scenario: $scenario,
              scenario_id: $scenario_id,
              deterministic: true,
              seed: $seed,
              event_hash: 0,
              schedule_hash: 0,
              trace_fingerprint: 6904520838387083326,
              steps: 1,
              replay_events: 1,
              window: {
                start: $window_start,
                requested_events: $window_events,
                resolved_events: 0,
                end_exclusive: 1,
                total_events: 1
              },
              provenance: {
                scenario_path: $scenario,
                artifact_pointer: $pointer,
                rerun_commands: [
                  ("asupersync lab replay " + $scenario
                    + " --seed " + ($seed|tostring)
                    + " --window-start " + ($window_start|tostring)
                    + " --window-events " + ($window_events|tostring)
                    + " --artifact-pointer " + $pointer
                    + " --artifact-output " + $report_path),
                  ("asupersync lab run " + $scenario + " --seed " + ($seed|tostring))
                ]
              },
              divergence: null
            }')"
        printf '%s\n' "${payload}" > "${run_json}"
        printf '%s\n' "${payload}" > "${run_log}"
        return 0
    fi

    for ((attempt = 1; attempt <= RCH_RETRY_ATTEMPTS; attempt++)); do
        local target_dir="/tmp/rch-incident-forensics-${TIMESTAMP}-${run_id}-attempt${attempt}"
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
        mkdir -p "$(dirname "${attempt_log}")"
        mkdir -p "$(dirname "${REPLAY_REPORT_PATH}")"
        if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${replay_cmd[@]}" >"${attempt_log}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if grep -Eq '^\[RCH\] local \(|falling back to local' "${attempt_log}" 2>/dev/null; then
            mkdir -p "$(dirname "${run_log}")"
            cp "${attempt_log}" "${run_log}"
            echo "rch local fallback detected; refusing local cargo execution" > "${attempt_log%.log}.rch_local_fallback.txt"
            echo "  ERROR: ${run_label} attempted local cargo fallback through rch"
            return 86
        fi

        payload="$(grep -E "\"scenario_id\"[[:space:]]*:[[:space:]]*\"${SCENARIO_ID}\"" "${attempt_log}" | tail -n1 || true)"
        if [[ -n "${payload}" ]] && printf '%s\n' "${payload}" | jq -e . >/dev/null 2>&1; then
            mkdir -p "$(dirname "${run_log}")" "$(dirname "${run_json}")"
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
        mkdir -p "$(dirname "${run_log}")"
        cp "${attempt_log}" "${run_log}"
    fi
    echo "  ERROR: ${run_label} failed after ${RCH_RETRY_ATTEMPTS} attempt(s) (last exit=${rc}) and produced no valid JSON payload"
    return 1
}

run_expected_failure_probe() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        mkdir -p "$(dirname "${FAILURE_LOG}")"
        cat > "${FAILURE_LOG}" <<EOF
ERROR missing scenario fixture: ${MISSING_SCENARIO_PATH}
hint: create fixture or use replay command from repro bundle
EOF
        return 0
    fi

    local target_dir="/tmp/rch-incident-forensics-${TIMESTAMP}-failure-probe"
    local probe_rc=0
    local -a fail_cmd=(
        env "CARGO_TARGET_DIR=${target_dir}" \
        "${CARGO_BIN}" run --quiet --features cli --bin asupersync --
        --format json
        --color never
        lab replay "${MISSING_SCENARIO_PATH}"
        --seed "${TEST_SEED}"
        --artifact-pointer "${ARTIFACT_POINTER}"
        --artifact-output "${REPLAY_REPORT_PATH}"
        --window-start "${WINDOW_START}"
        --window-events "${WINDOW_EVENTS}"
    )

    mkdir -p "$(dirname "${FAILURE_LOG}")"
    if timeout "${RCH_SCAN_TIMEOUT}s" "${RCH_BIN}" exec -- "${fail_cmd[@]}" >"${FAILURE_LOG}" 2>&1; then
        probe_rc=0
    else
        probe_rc=$?
    fi

    if grep -Eq '^\[RCH\] local \(|falling back to local' "${FAILURE_LOG}" 2>/dev/null; then
        echo "rch local fallback detected; refusing local cargo execution" > "${FAILURE_LOG%.log}.rch_local_fallback.txt"
        echo "  ERROR: expected failure probe attempted local cargo fallback through rch"
        return 86
    fi

    if [[ "${probe_rc}" -eq 0 ]]; then
        echo "  ERROR: expected failure probe unexpectedly succeeded"
        return 1
    fi

    if grep -Eqi "(missing_forensics_fixture|No such file|not found|error)" "${FAILURE_LOG}"; then
        return 0
    fi

    echo "  ERROR: expected failure probe log did not contain actionable missing-fixture diagnostics"
    return 1
}

echo ">>> [1/6] Replay run #1 via rch..."
if run_replay_call "replay run 1" "${RUN1_LOG}" "${RUN1_JSON}" "run1"; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    EXIT_CODE=1
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

echo ">>> [2/6] Replay run #2 via rch..."
if run_replay_call "replay run 2" "${RUN2_LOG}" "${RUN2_JSON}" "run2"; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    EXIT_CODE=1
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo ">>> [3/6] Determinism check (run1 == run2)..."
    if diff -u "${RUN1_JSON}" "${RUN2_JSON}" > "${DETERMINISM_DIFF}"; then
        rm -f "${DETERMINISM_DIFF}"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: deterministic replay output mismatch"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [4/6] Replay schema + provenance checks..."
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
        (.steps | type == "number" and . >= 0) and
        (.replay_events | type == "number" and . >= 1) and
        .window.start == $window_start and
        .window.requested_events == $window_events and
        .window.end_exclusive >= .window.start and
        .provenance.scenario_path == $scenario and
        .provenance.artifact_pointer == $pointer and
        (.provenance.rerun_commands | type == "array" and length >= 2) and
        (.provenance.rerun_commands[0] | contains("asupersync lab replay")) and
        (.provenance.rerun_commands[0] | contains("--seed \($seed)")) and
        (.provenance.rerun_commands[0] | contains("--artifact-output \($report_path)")) and
        (.divergence == null)
    ' "${RUN1_JSON}" >/dev/null; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ERROR: replay provenance/schema validation failed"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi

    echo ">>> [5/6] Expected-failure probe (missing fixture) ..."
    if run_expected_failure_probe; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi
fi

echo ">>> [6/6] Building incident artifact bundle..."
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$(dirname "${SUMMARY_FILE}")" "$(dirname "${EVENTS_FILE}")"

if [[ -f "${RUN1_JSON}" ]]; then
    cp "${RUN1_JSON}" "${ARTIFACT_RUN1_JSON}"
fi
if [[ -f "${RUN2_JSON}" ]]; then
    cp "${RUN2_JSON}" "${ARTIFACT_RUN2_JSON}"
fi
if [[ -f "${RUN1_LOG}" ]]; then
    cp "${RUN1_LOG}" "${ARTIFACT_RUN1_LOG}"
fi
if [[ -f "${RUN2_LOG}" ]]; then
    cp "${RUN2_LOG}" "${ARTIFACT_RUN2_LOG}"
fi
if [[ -f "${FAILURE_LOG}" ]]; then
    cp "${FAILURE_LOG}" "${ARTIFACT_FAILURE_LOG}"
fi
if [[ -f "${DETERMINISM_DIFF}" ]]; then
    cp "${DETERMINISM_DIFF}" "${ARTIFACT_DETERMINISM_DIFF}"
fi
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

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} WINDOW_START=${WINDOW_START} WINDOW_EVENTS=${WINDOW_EVENTS} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

cat > "${EVENTS_FILE}" <<END_EVENTS
{"schema_version":"incident-forensics-event-v1","phase":"triage_replay_run_1","status":"$( [[ -f "${ARTIFACT_RUN1_JSON}" ]] && echo pass || echo fail )","seed":${TEST_SEED},"scenario_id":"${SCENARIO_ID}","artifact":"${ARTIFACT_RUN1_JSON}"}
{"schema_version":"incident-forensics-event-v1","phase":"triage_replay_run_2","status":"$( [[ -f "${ARTIFACT_RUN2_JSON}" ]] && echo pass || echo fail )","seed":${TEST_SEED},"scenario_id":"${SCENARIO_ID}","artifact":"${ARTIFACT_RUN2_JSON}"}
{"schema_version":"incident-forensics-event-v1","phase":"determinism_compare","status":"$( [[ -f "${ARTIFACT_RUN1_JSON}" && -f "${ARTIFACT_RUN2_JSON}" && ! -f "${DETERMINISM_DIFF}" ]] && echo pass || echo fail )","seed":${TEST_SEED},"scenario_id":"${SCENARIO_ID}","artifact":"${ARTIFACT_DETERMINISM_DIFF}"}
{"schema_version":"incident-forensics-event-v1","phase":"failure_probe_missing_fixture","status":"$( [[ -f "${ARTIFACT_FAILURE_LOG}" ]] && echo pass || echo fail )","seed":${TEST_SEED},"scenario_id":"MISSING-FIXTURE-PROBE","artifact":"${ARTIFACT_FAILURE_LOG}"}
END_EVENTS

cat > "${REPRO_BUNDLE_FILE}" <<END_REPRO
{
  "schema_version": "incident-forensics-repro-bundle-v1",
  "scenario_id": "${E2E_SCENARIO_ID}",
  "seed": ${TEST_SEED},
  "status": "${SUITE_STATUS}",
  "replay_command": "${REPRO_COMMAND}",
  "artifact_pointer": "${ARTIFACT_POINTER}",
    "artifacts": {
      "summary": "${SUMMARY_FILE}",
      "incident_summary": "${INCIDENT_SUMMARY_FILE}",
      "events": "${EVENTS_FILE}",
      "replay_report": "${REPLAY_REPORT_PATH}",
      "failure_probe_log": "${ARTIFACT_FAILURE_LOG}"
    }
}
END_REPRO

cat > "${INCIDENT_SUMMARY_FILE}" <<END_INCIDENT
{
  "schema_version": "incident-forensics-drill-summary-v1",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${E2E_SCENARIO_ID}",
  "seed": ${TEST_SEED},
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "checks_passed": ${CHECKS_PASSED},
  "checks_failed": ${CHECK_FAILURES},
  "repro_command": "${REPRO_COMMAND}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "events_path": "${EVENTS_FILE}",
  "repro_bundle_path": "${REPRO_BUNDLE_FILE}",
  "failure_class": "${FAILURE_CLASS}"
}
END_INCIDENT

cat > "${SUMMARY_FILE}" <<END_SUMMARY
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
  "log_file": "${ARTIFACT_RUN1_LOG}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "checks_passed": ${CHECKS_PASSED}
}
END_SUMMARY

echo ""
echo "==================================================================="
echo "       WASM Incident Forensics E2E Summary                        "
echo "==================================================================="
echo "  Status:          ${SUITE_STATUS}"
echo "  Exit code:       ${EXIT_CODE}"
echo "  Check failures:  ${CHECK_FAILURES}"
echo "  Checks passed:   ${CHECKS_PASSED}"
echo "  Summary:         ${SUMMARY_FILE}"
echo "  Incident summary:${INCIDENT_SUMMARY_FILE}"
echo "  Events:          ${EVENTS_FILE}"
echo "  Repro bundle:    ${REPRO_BUNDLE_FILE}"
echo "==================================================================="

if [[ ${EXIT_CODE} -ne 0 || ${CHECK_FAILURES} -ne 0 ]]; then
    exit 1
fi
