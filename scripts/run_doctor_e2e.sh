#!/usr/bin/env bash
# Aggregate Doctor E2E proof lane (asupersync-idea-wizard-fifth-wave-3gaiun.1.4).
#
# This runner ties the existing doctor E2E surfaces into one evidence lane:
# workspace fixture scans and malformed input, report schema export, CLI smoke,
# and analyzer fixture rehearsals for redaction and stale evidence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_e2e_proof_lane"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
EVENTS_FILE="${ARTIFACT_DIR}/events.ndjson"
STAGES_FILE="${ARTIFACT_DIR}/stages.json"
OPERATOR_REPORT="${ARTIFACT_DIR}/operator_report.md"
SUITE_ID="doctor_e2e_proof_lane"
SCENARIO_ID="E2E-SUITE-DOCTOR-E2E-PROOF-LANE"
NO_CLAIM_TEXT="doctor diagnoses evidence but does not certify broad workspace health"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export TEST_SEED="${TEST_SEED:-0xD0C70E2E}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

if [[ ! -x "$RCH_BIN" ]]; then
    RCH_BIN="$(command -v rch || true)"
fi

if [[ -z "$RCH_BIN" || ! -x "$RCH_BIN" ]]; then
    echo "FATAL: rch is required and was not found/executable" >&2
    exit 1
fi

mkdir -p "$ARTIFACT_DIR"
: > "$EVENTS_FILE"

json_event() {
    local event="$1"
    local stage_id="$2"
    local coverage_family="$3"
    local status="$4"
    local failure_class="$5"
    local exit_code="$6"
    local started_ts="$7"
    local ended_ts="$8"
    local command="$9"
    local log_path="${10}"

    jq -cn \
        --arg schema_version "doctor-e2e-proof-lane-event-v1" \
        --arg event "$event" \
        --arg suite_id "$SUITE_ID" \
        --arg scenario_id "$SCENARIO_ID" \
        --arg stage_id "$stage_id" \
        --arg coverage_family "$coverage_family" \
        --arg status "$status" \
        --arg failure_class "$failure_class" \
        --arg exit_code "$exit_code" \
        --arg started_ts "$started_ts" \
        --arg ended_ts "$ended_ts" \
        --arg command "$command" \
        --arg log_path "$log_path" \
        --arg no_claim "$NO_CLAIM_TEXT" \
        '{
          schema_version: $schema_version,
          event: $event,
          suite_id: $suite_id,
          scenario_id: $scenario_id,
          stage_id: $stage_id,
          coverage_family: $coverage_family,
          status: $status,
          failure_class: $failure_class,
          exit_code: ($exit_code | tonumber),
          started_ts: $started_ts,
          ended_ts: $ended_ts,
          command: $command,
          log_path: $log_path,
          no_claim: $no_claim
        }' >> "$EVENTS_FILE"
}

rch_attempt_went_local() {
    local attempt_log="$1"

    grep -Eq '^\[RCH\] local \(|falling back to local|local fallback marker|no-local-fallback violation' "$attempt_log"
}

run_stage() {
    local stage_id="$1"
    local coverage_family="$2"
    local command_display="$3"
    shift 3

    local log_file="${ARTIFACT_DIR}/${stage_id}.log"
    local started_ts
    local ended_ts
    local rc
    local status="passed"
    local failure_class="none"

    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ">>> [${stage_id}] ${coverage_family}"

    set +e
    "$@" > "$log_file" 2>&1
    rc=$?
    set -e

    if rch_attempt_went_local "$log_file"; then
        status="failed"
        failure_class="rch_local_fallback"
        rc=1
    elif [[ "$rc" -ne 0 ]]; then
        status="failed"
        failure_class="stage_failure"
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    json_event "stage_complete" "$stage_id" "$coverage_family" "$status" "$failure_class" "$rc" "$started_ts" "$ended_ts" "$command_display" "$log_file"

    if [[ "$status" == "passed" ]]; then
        echo "    PASS"
    else
        echo "    FAIL (${failure_class}, exit ${rc})"
    fi

    return "$rc"
}

OVERALL_RC=0
FALLBACK_DETECTED=0
STAGE_FAILURES=0
TESTS_PASSED=0
TESTS_FAILED=0

run_and_count() {
    if run_stage "$@"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        OVERALL_RC=1
        TESTS_FAILED=$((TESTS_FAILED + 1))
        STAGE_FAILURES=$((STAGE_FAILURES + 1))
        if tail -n 1 "$EVENTS_FILE" | grep -q '"failure_class":"rch_local_fallback"'; then
            FALLBACK_DETECTED=1
        fi
    fi
}

WORKSPACE_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/test_doctor_workspace_scan_e2e.sh"
REPORT_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/test_doctor_report_export_e2e.sh"
CLI_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/test_doctor_cli_packaging_e2e.sh"
ANALYZER_COMMAND="RCH_REQUIRE_REMOTE=1 ${RCH_BIN} exec -- env CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_doctor_e2e_proof_lane_analyzer CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --features cli --test doctor_analyzer_fixture_harness -- --nocapture"

run_and_count \
    "workspace-fixtures-malformed-input" \
    "representative fixture scans and malformed-input failure cases" \
    "$WORKSPACE_COMMAND" \
    env TEST_LOG_LEVEL="$TEST_LOG_LEVEL" RUST_LOG="$RUST_LOG" TEST_SEED="$TEST_SEED" RCH_BIN="$RCH_BIN" \
    bash "${SCRIPT_DIR}/test_doctor_workspace_scan_e2e.sh"

run_and_count \
    "report-schema-export" \
    "report schema checks and deterministic export metadata" \
    "$REPORT_COMMAND" \
    env TEST_LOG_LEVEL="$TEST_LOG_LEVEL" RUST_LOG="$RUST_LOG" TEST_SEED="$TEST_SEED" RCH_BIN="$RCH_BIN" \
    bash "${SCRIPT_DIR}/test_doctor_report_export_e2e.sh"

run_and_count \
    "cli-packaging-smoke" \
    "CLI smoke packaging and install-run evidence" \
    "$CLI_COMMAND" \
    env TEST_LOG_LEVEL="$TEST_LOG_LEVEL" RUST_LOG="$RUST_LOG" TEST_SEED="$TEST_SEED" RCH_BIN="$RCH_BIN" \
    bash "${SCRIPT_DIR}/test_doctor_cli_packaging_e2e.sh"

run_and_count \
    "analyzer-redaction-stale-evidence" \
    "redaction checks, malformed proof artifacts, and stale-evidence rehearsals" \
    "$ANALYZER_COMMAND" \
    env RCH_REQUIRE_REMOTE=1 "$RCH_BIN" exec -- env \
    CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_doctor_e2e_proof_lane_analyzer" \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_TEST_DEBUG=0 \
    RUSTFLAGS="-D warnings -C debuginfo=0" \
    cargo test -p asupersync --features cli --test doctor_analyzer_fixture_harness -- --nocapture

jq -s '[.[] | select(.event == "stage_complete") | {
    stage_id,
    coverage_family,
    status,
    failure_class,
    exit_code,
    command,
    log_path
}]' "$EVENTS_FILE" > "$STAGES_FILE"

RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="passed"
FAILURE_CLASS="none"
if [[ "$FALLBACK_DETECTED" -eq 1 ]]; then
    SUITE_STATUS="failed"
    FAILURE_CLASS="rch_local_fallback"
elif [[ "$OVERALL_RC" -ne 0 ]]; then
    SUITE_STATUS="failed"
    FAILURE_CLASS="stage_failure"
fi

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")"

jq -n \
    --slurpfile stages "$STAGES_FILE" \
    --arg schema_version "e2e-suite-summary-v3" \
    --arg suite_id "$SUITE_ID" \
    --arg scenario_id "$SCENARIO_ID" \
    --arg seed "$TEST_SEED" \
    --arg started_ts "$RUN_STARTED_TS" \
    --arg ended_ts "$RUN_ENDED_TS" \
    --arg status "$SUITE_STATUS" \
    --arg failure_class "$FAILURE_CLASS" \
    --arg repro_command "$REPRO_COMMAND" \
    --arg artifact_path "$SUMMARY_FILE" \
    --arg events_path "$EVENTS_FILE" \
    --arg operator_report "$OPERATOR_REPORT" \
    --arg artifact_dir "$ARTIFACT_DIR" \
    --arg no_claim "$NO_CLAIM_TEXT" \
    --arg tests_passed "$TESTS_PASSED" \
    --arg tests_failed "$TESTS_FAILED" \
    --arg exit_code "$OVERALL_RC" \
    '{
      schema_version: $schema_version,
      suite_id: $suite_id,
      scenario_id: $scenario_id,
      seed: $seed,
      started_ts: $started_ts,
      ended_ts: $ended_ts,
      status: $status,
      failure_class: $failure_class,
      repro_command: $repro_command,
      artifact_path: $artifact_path,
      events_path: $events_path,
      operator_report: $operator_report,
      artifact_dir: $artifact_dir,
      tests_passed: ($tests_passed | tonumber),
      tests_failed: ($tests_failed | tonumber),
      exit_code: ($exit_code | tonumber),
      coverage_families: [
        "representative fixture scans",
        "malformed-input failure cases",
        "redaction checks",
        "report schema checks",
        "CLI smoke",
        "stale-evidence rehearsal"
      ],
      no_claim: $no_claim,
      no_claim_boundaries: [
        "broad workspace health",
        "release readiness",
        "live RCH fleet availability",
        "performance",
        "source correctness outside the doctor proof lane"
      ],
      stages: $stages[0]
    }' > "$SUMMARY_FILE"

{
    echo "# Doctor E2E Proof Lane Operator Report"
    echo
    echo "- Suite: ${SUITE_ID}"
    echo "- Scenario: ${SCENARIO_ID}"
    echo "- Status: ${SUITE_STATUS}"
    echo "- Failure class: ${FAILURE_CLASS}"
    echo "- Summary: ${SUMMARY_FILE}"
    echo "- Events: ${EVENTS_FILE}"
    echo "- Repro command: \`${REPRO_COMMAND}\`"
    echo
    echo "No-claim boundary: ${NO_CLAIM_TEXT}. This lane does not certify release readiness, live RCH fleet availability, performance, or broad workspace health."
    echo
    echo "## Stage Commands"
    jq -r '.[] | "- " + .stage_id + " (" + .status + "): `" + .command + "`"' "$STAGES_FILE"
} > "$OPERATOR_REPORT"

echo ""
echo "==================================================================="
echo "          Doctor E2E Proof Lane Summary                           "
echo "==================================================================="
echo "  Status:         ${SUITE_STATUS}"
echo "  Failure class:  ${FAILURE_CLASS}"
echo "  Tests passed:   ${TESTS_PASSED}"
echo "  Tests failed:   ${TESTS_FAILED}"
echo "  Summary:        ${SUMMARY_FILE}"
echo "  Events:         ${EVENTS_FILE}"
echo "  Report:         ${OPERATOR_REPORT}"
echo "  Artifacts:      ${ARTIFACT_DIR}"
echo "==================================================================="

exit "$OVERALL_RC"
