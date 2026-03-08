#!/usr/bin/env bash
# WASM QA evidence matrix smoke runner (WASM-QA 3qv04.8.1)
#
# Usage:
#   bash ./scripts/run_wasm_qa_evidence_smoke.sh --list
#   bash ./scripts/run_wasm_qa_evidence_smoke.sh --scenario WASM-QA-SMOKE-LAYERS --dry-run
#   bash ./scripts/run_wasm_qa_evidence_smoke.sh --scenario WASM-QA-SMOKE-LAYERS --execute
#   bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute
#
# Bundle schema: wasm-qa-evidence-smoke-bundle-v1
# Report schema: wasm-qa-evidence-smoke-run-report-v1

set -euo pipefail

ARTIFACT="artifacts/wasm_qa_evidence_matrix_v1.json"
RCH_BIN="${RCH_BIN:-rch}"
MODE=""
SCENARIO=""
RUN_ALL=0
WASM_PROFILE="${WASM_PROFILE:-wasm-browser-dev}"
BROWSER_ID="${BROWSER_ID:-headless-smoke}"
PACKAGE_NAME="${PACKAGE_NAME:-@asupersync/browser-core}"
MODULE_FINGERPRINT="${WASM_MODULE_FINGERPRINT:-unknown}"
EVIDENCE_ID="${EVIDENCE_ID:-L8-REPRO-COMMAND}"
LAYER_ID="${LAYER_ID:-L8}"
TOOL_NAME="${TOOL_NAME:-smoke-runner}"
TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
SINGLE_ROOT="target/wasm-qa-evidence-smoke"
SUITE_ROOT="target/e2e-results/wasm_qa_evidence_smoke"
SUITE_NAME="wasm-qa-evidence-smoke"
SUITE_ID="${SUITE_NAME}_e2e"
SUITE_SCENARIO_ID="E2E-SUITE-WASM-QA-EVIDENCE-SMOKE"

usage() {
  echo "Usage: $0 --list | --all (--dry-run | --execute) | --scenario <ID> (--dry-run | --execute)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)   MODE="list"; shift ;;
    --all)    RUN_ALL=1; shift ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --dry-run)  MODE="dry-run"; shift ;;
    --execute)  MODE="execute"; shift ;;
    *) usage ;;
  esac
done

[[ -z "$MODE" ]] && usage

BUNDLE_SCHEMA=$(jq -r '.runner_bundle_schema_version // "wasm-qa-evidence-smoke-bundle-v1"' "$ARTIFACT")
REPORT_SCHEMA=$(jq -r '.runner_report_schema_version // "wasm-qa-evidence-smoke-run-report-v1"' "$ARTIFACT")
ARTIFACT_BUNDLE_SCHEMA=$(jq -r '.artifact_bundle_schema_version // "wasm-qa-artifact-bundle-v1"' "$ARTIFACT")
LOG_SCHEMA=$(jq -r '.e2e_log_schema_version // "wasm-qa-e2e-log-v1"' "$ARTIFACT")
RETENTION_SCHEMA=$(jq -r '.retention_policy.schema_version // "wasm-qa-artifact-retention-v1"' "$ARTIFACT")

retention_days_for_class() {
  local cls="$1"
  local days
  days=$(jq -r --arg cls "$cls" '.retention_policy.classes[]? | select(.class == $cls) | .min_days' "$ARTIFACT" | head -n1)
  if [[ -z "${days}" || "${days}" == "null" ]]; then
    case "$cls" in
      hot) days=30 ;;
      warm) days=14 ;;
      cold) days=7 ;;
      *) days=7 ;;
    esac
  fi
  printf '%s' "$days"
}

retention_until_utc() {
  local cls="$1"
  local days
  days=$(retention_days_for_class "$cls")
  date -u -d "+${days} days" +%Y-%m-%dT%H:%M:%SZ
}

scenario_field() {
  local sid="$1"
  local field="$2"
  jq -r \
    --arg sid "$sid" \
    --arg field "$field" \
    '.smoke_scenarios[] | select(.scenario_id == $sid) | .[$field]' \
    "$ARTIFACT"
}

load_scenario() {
  local sid="$1"
  COMMAND="$(scenario_field "$sid" command)"
  DESCRIPTION="$(scenario_field "$sid" description)"
  if [[ -z "$COMMAND" || "$COMMAND" == "null" || -z "$DESCRIPTION" || "$DESCRIPTION" == "null" ]]; then
    echo "error: unknown scenario $sid" >&2
    exit 1
  fi
}

if [[ "$MODE" == "list" ]]; then
  echo "=== WASM QA Evidence Matrix Smoke Scenarios ==="
  jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.description)"' "$ARTIFACT"
  exit 0
fi

if [[ "$RUN_ALL" -eq 1 && -n "$SCENARIO" ]]; then
  echo "error: choose either --all or --scenario" >&2
  exit 1
fi

if [[ "$RUN_ALL" -eq 0 && -z "$SCENARIO" ]]; then
  echo "error: --scenario required with --dry-run/--execute" >&2
  exit 1
fi

emit_event() {
  local event_kind="$1"
  local verdict="$2"
  local exit_code="$3"
  local failure_reason="$4"
  local retention_class="$5"
  local retention_until="$6"
  jq -nc \
    --arg schema_version "$LOG_SCHEMA" \
    --arg event_kind "$event_kind" \
    --arg scenario_id "$SCENARIO" \
    --arg run_id "$RUN_ID" \
    --arg timestamp_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg evidence_id "$EVIDENCE_ID" \
    --arg layer "$LAYER_ID" \
    --arg tool "$TOOL_NAME" \
    --arg wasm_profile "$WASM_PROFILE" \
    --arg browser "$BROWSER_ID" \
    --arg package_name "$PACKAGE_NAME" \
    --arg module_fingerprint "$MODULE_FINGERPRINT" \
    --arg verdict "$verdict" \
    --argjson command_exit_code "$exit_code" \
    --arg failure_reason "$failure_reason" \
    --arg repro_command "$COMMAND" \
    --arg bundle_manifest_path "$BUNDLE_MANIFEST_PATH" \
    --arg artifact_path "$OUTDIR" \
    --arg retention_class "$retention_class" \
    --arg retention_until_utc "$retention_until" \
    '{
      schema_version,
      event_kind,
      scenario_id,
      run_id,
      timestamp_utc,
      evidence_id,
      layer,
      tool,
      wasm_profile,
      browser,
      package_name,
      module_fingerprint,
      verdict,
      command_exit_code,
      failure_reason,
      repro_command,
      bundle_manifest_path,
      artifact_path,
      retention_class,
      retention_until_utc
    }' >> "$EVENTS_PATH"
}

write_bundle_manifest() {
  local retention_class="$1"
  local retention_until="$2"
  jq -nc \
    --arg schema "$BUNDLE_SCHEMA" \
    --arg artifact_bundle_schema_version "$ARTIFACT_BUNDLE_SCHEMA" \
    --arg log_schema_version "$LOG_SCHEMA" \
    --arg retention_schema_version "$RETENTION_SCHEMA" \
    --arg scenario_id "$SCENARIO" \
    --arg description "$DESCRIPTION" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg command "$COMMAND" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg bundle_manifest_path "$BUNDLE_MANIFEST_PATH" \
    --arg run_report_path "$RUN_REPORT_PATH" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg events_path "$EVENTS_PATH" \
    --arg retention_class "$retention_class" \
    --arg retention_until_utc "$retention_until" \
    '{
      schema,
      artifact_bundle_schema_version,
      log_schema_version,
      retention_schema_version,
      scenario_id,
      description,
      run_id,
      mode,
      command,
      timestamp,
      bundle_manifest_path,
      run_report_path,
      run_log_path,
      events_path,
      retention_class,
      retention_until_utc,
      required_layout: ["bundle_manifest.json", "run_report.json", "run.log", "events.ndjson"]
    }' > "$BUNDLE_MANIFEST_PATH"
}

write_run_report() {
  local exit_code="$1"
  local verdict="$2"
  local failure_reason="$3"
  local retention_class="$4"
  local retention_until="$5"
  jq -nc \
    --arg scenario_id "$SCENARIO" \
    --arg schema "$REPORT_SCHEMA" \
    --arg run_id "$RUN_ID" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg verdict "$verdict" \
    --arg failure_reason "$failure_reason" \
    --arg artifact_path "$OUTDIR" \
    --arg events_path "$EVENTS_PATH" \
    --arg retention_class "$retention_class" \
    --arg retention_until_utc "$retention_until" \
    --argjson exit_code "$exit_code" \
    '{
      schema,
      scenario_id,
      run_id,
      exit_code,
      verdict,
      failure_reason,
      artifact_path,
      events_path,
      retention_class,
      retention_until_utc,
      timestamp
    }' > "$RUN_REPORT_PATH"
}

write_suite_summary() {
  local suite_run_dir="$1"
  local suite_run_id="$2"
  local suite_started_ts="$3"
  local suite_ended_ts="$4"
  local suite_status="$5"
  local suite_log_path="$6"
  local tests_passed="$7"
  local tests_failed="$8"
  local suite_exit_code="$9"
  local summary_path="${10}"
  jq -nc \
    --arg schema_version "e2e-suite-summary-v3" \
    --arg suite_id "$SUITE_ID" \
    --arg scenario_id "$SUITE_SCENARIO_ID" \
    --arg seed "$TEST_SEED" \
    --arg started_ts "$suite_started_ts" \
    --arg ended_ts "$suite_ended_ts" \
    --arg status "$suite_status" \
    --arg repro_command "bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute" \
    --arg artifact_path "$summary_path" \
    --arg suite "$SUITE_ID" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg test_log_level "$TEST_LOG_LEVEL" \
    --arg log_file "$suite_log_path" \
    --arg artifact_dir "$suite_run_dir" \
    --arg run_id "$suite_run_id" \
    --arg mode "$MODE" \
    --argjson tests_passed "$tests_passed" \
    --argjson tests_failed "$tests_failed" \
    --argjson exit_code "$suite_exit_code" \
    --argjson pattern_failures "$tests_failed" \
    --argjson checks_passed "$tests_passed" \
    '{
      schema_version,
      suite_id,
      scenario_id,
      seed,
      started_ts,
      ended_ts,
      status,
      repro_command,
      artifact_path,
      suite,
      timestamp,
      test_log_level,
      tests_passed,
      tests_failed,
      exit_code,
      pattern_failures,
      log_file,
      artifact_dir,
      checks_passed,
      run_id,
      mode,
      suite_name: $suite_id
    }' > "$summary_path"
}

run_scenario_bundle() {
  local RUN_ID="$1"
  local SCENARIO="$2"
  local OUTDIR="$3"
  local MODE="$4"
  local COMMAND=""
  local DESCRIPTION=""
  local BUNDLE_MANIFEST_PATH="$OUTDIR/bundle_manifest.json"
  local RUN_REPORT_PATH="$OUTDIR/run_report.json"
  local RUN_LOG_PATH="$OUTDIR/run.log"
  local EVENTS_PATH="$OUTDIR/events.ndjson"

  load_scenario "$SCENARIO"
  mkdir -p "$OUTDIR"
  : > "$EVENTS_PATH"

  if [[ "$MODE" == "dry-run" ]]; then
    local RETENTION_CLASS="cold"
    local RETENTION_UNTIL
    RETENTION_UNTIL="$(retention_until_utc "$RETENTION_CLASS")"
    : > "$RUN_LOG_PATH"
    write_bundle_manifest "$RETENTION_CLASS" "$RETENTION_UNTIL"
    write_run_report 0 "skip" "dry-run mode" "$RETENTION_CLASS" "$RETENTION_UNTIL"
    emit_event "dry_run" "skip" 0 "dry-run mode" "$RETENTION_CLASS" "$RETENTION_UNTIL"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$SCENARIO" \
      "skip" \
      "0" \
      "$RUN_REPORT_PATH" \
      "$BUNDLE_MANIFEST_PATH" \
      "$OUTDIR"
    return 0
  fi

  emit_event "scenario_start" "blocked" -1 "" "warm" "$(retention_until_utc warm)"
  local EXITCODE=0
  eval "$COMMAND" > "$RUN_LOG_PATH" 2>&1 || EXITCODE=$?

  local VERDICT="pass"
  local FAILURE_REASON=""
  local RETENTION_CLASS="warm"
  if [[ $EXITCODE -ne 0 ]]; then
    VERDICT="fail"
    FAILURE_REASON="command exited with status $EXITCODE"
    RETENTION_CLASS="hot"
  fi
  local RETENTION_UNTIL
  RETENTION_UNTIL="$(retention_until_utc "$RETENTION_CLASS")"

  write_bundle_manifest "$RETENTION_CLASS" "$RETENTION_UNTIL"
  write_run_report "$EXITCODE" "$VERDICT" "$FAILURE_REASON" "$RETENTION_CLASS" "$RETENTION_UNTIL"
  emit_event "scenario_finish" "$VERDICT" "$EXITCODE" "$FAILURE_REASON" "$RETENTION_CLASS" "$RETENTION_UNTIL"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$SCENARIO" \
    "$VERDICT" \
    "$EXITCODE" \
    "$RUN_REPORT_PATH" \
    "$BUNDLE_MANIFEST_PATH" \
    "$OUTDIR"
  return "$EXITCODE"
}

if [[ "$RUN_ALL" -eq 1 ]]; then
  SUITE_RUN_ID="run_$(date +%Y%m%d_%H%M%S)"
  SUITE_RUN_DIR="${SUITE_ROOT}/${SUITE_RUN_ID}"
  SUITE_LOG_PATH="${SUITE_RUN_DIR}/suite.log"
  SUITE_EVENTS_PATH="${SUITE_RUN_DIR}/suite_events.ndjson"
  SUMMARY_FILE="${SUITE_RUN_DIR}/summary.json"
  SUITE_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SUITE_START_EPOCH="$(date +%s)"
  TESTS_PASSED=0
  TESTS_FAILED=0
  TESTS_SKIPPED=0
  mkdir -p "$SUITE_RUN_DIR"
  : > "$SUITE_LOG_PATH"
  : > "$SUITE_EVENTS_PATH"

  echo "=== Executing all WASM QA smoke scenarios ==="
  echo "  mode: ${MODE}"
  echo "  run:  ${SUITE_RUN_ID}"
  echo "  dir:  ${SUITE_RUN_DIR}"

  mapfile -t SCENARIO_IDS < <(jq -r '.smoke_scenarios[].scenario_id' "$ARTIFACT")
  for scenario_id in "${SCENARIO_IDS[@]}"; do
    scenario_dir="${SUITE_RUN_DIR}/${scenario_id}"
    echo ">>> [${scenario_id}]"
    set +e
    scenario_result="$(run_scenario_bundle "$SUITE_RUN_ID" "$scenario_id" "$scenario_dir" "$MODE")"
    scenario_rc=$?
    set -e
    IFS=$'\t' read -r sid verdict exit_code run_report bundle_manifest artifact_dir <<< "$scenario_result"

    if [[ "$verdict" == "pass" ]]; then
      TESTS_PASSED=$((TESTS_PASSED + 1))
    elif [[ "$verdict" == "skip" ]]; then
      TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    else
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    jq -nc \
      --arg scenario_id "$sid" \
      --arg verdict "$verdict" \
      --arg run_report "$run_report" \
      --arg bundle_manifest "$bundle_manifest" \
      --arg artifact_dir "$artifact_dir" \
      --argjson exit_code "$exit_code" \
      '{
        scenario_id: $scenario_id,
        verdict: $verdict,
        exit_code: $exit_code,
        run_report,
        bundle_manifest,
        artifact_dir
      }' >> "$SUITE_EVENTS_PATH"

    printf '%s\t%s\t%s\t%s\n' "$sid" "$verdict" "$exit_code" "$artifact_dir" >> "$SUITE_LOG_PATH"
    if [[ "$scenario_rc" -eq 0 ]]; then
      echo "  PASS (exit 0)"
    else
      echo "  FAIL (exit ${scenario_rc})"
    fi
  done

  SUITE_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SUITE_END_EPOCH="$(date +%s)"
  SUITE_STATUS="passed"
  SUITE_EXIT_CODE=0
  if [[ "$TESTS_FAILED" -gt 0 ]]; then
    SUITE_STATUS="failed"
    SUITE_EXIT_CODE=1
  fi

  write_suite_summary \
    "$SUITE_RUN_DIR" \
    "$SUITE_RUN_ID" \
    "$SUITE_STARTED_TS" \
    "$SUITE_ENDED_TS" \
    "$SUITE_STATUS" \
    "$SUITE_LOG_PATH" \
    "$TESTS_PASSED" \
    "$TESTS_FAILED" \
    "$SUITE_EXIT_CODE" \
    "$SUMMARY_FILE"

  echo "Summary: ${SUMMARY_FILE}"
  echo "Artifacts: ${SUITE_RUN_DIR}"
  exit "$SUITE_EXIT_CODE"
fi

RUN_ID="run_$(date +%Y%m%d_%H%M%S)"
OUTDIR="${SINGLE_ROOT}/${RUN_ID}/${SCENARIO}"
load_scenario "$SCENARIO"
echo "=== Executing $SCENARIO ==="
echo "  $DESCRIPTION"
echo "  command: $COMMAND"

set +e
scenario_result="$(run_scenario_bundle "$RUN_ID" "$SCENARIO" "$OUTDIR" "$MODE")"
EXITCODE=$?
set -e
IFS=$'\t' read -r _ verdict _ run_report _ _ <<< "$scenario_result"

if [[ $EXITCODE -eq 0 ]]; then
  echo "  PASS (exit 0)"
else
  echo "  FAIL (exit $EXITCODE)"
  tail -20 "${OUTDIR}/run.log"
fi
echo "  report: ${run_report}"

exit "$EXITCODE"
