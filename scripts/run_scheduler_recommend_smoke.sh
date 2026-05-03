#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/scheduler_recommend_smoke_contract_v1.json"
MODE="execute"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${SCHEDULER_RECOMMEND_SMOKE_OUTPUT_DIR:-}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_scheduler_recommend_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  --dry-run               Emit manifests without executing offline_tuner
  --execute               Execute the offline_tuner smoke path (default)
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for scheduler recommend smoke runner" >&2
        exit 1
    fi
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
        exit 1
    fi
}

artifact_value() {
    local query="$1"
    jq -r "$query" "$ARTIFACT"
}

default_scenario_id() {
    artifact_value '.smoke_scenarios[0].scenario_id'
}

load_scenario_json() {
    local scenario_id="$1"
    jq -c --arg sid "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $sid)' "$ARTIFACT"
}

list_scenarios() {
    echo "=== Scheduler Recommend Smoke Scenarios ==="
    jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.description)"' "$ARTIFACT"
}

write_bundle_manifest() {
    local bundle_path="$1"
    local scenario_id="$2"
    local description="$3"
    local run_id="$4"
    local mode="$5"
    local run_log_path="$6"
    local evidence_file="$7"
    local report_file="$8"
    local command="$9"
    local expected_report_json="${10}"
    local command_exit_code="${11}"
    local script_exit_code="${12}"
    local validation_passed="${13}"
    local status="${14}"
    local started_ts="${15}"
    local ended_ts="${16}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg scenario_id "$scenario_id" \
        --arg description "$description" \
        --arg run_id "$run_id" \
        --arg mode "$mode" \
        --arg artifact_path "$bundle_path" \
        --arg run_log_path "$run_log_path" \
        --arg evidence_file "$evidence_file" \
        --arg report_file "$report_file" \
        --arg command "$command" \
        --arg expected_profile_name "$(jq -r '.profile_name' <<<"$expected_report_json")" \
        --argjson expected_reason_codes "$(jq '.reason_codes' <<<"$expected_report_json")" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
        --arg status "$status" \
        --arg started_ts "$started_ts" \
        --arg ended_ts "$ended_ts" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            scenario_id: $scenario_id,
            description: $description,
            run_id: $run_id,
            mode: $mode,
            artifact_path: $artifact_path,
            run_log_path: $run_log_path,
            evidence_file: $evidence_file,
            report_file: $report_file,
            command: $command,
            expected_profile_name: $expected_profile_name,
            expected_reason_codes: $expected_reason_codes,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            started_ts: $started_ts,
            ended_ts: $ended_ts
        }' >"$bundle_path"
}

write_run_report() {
    local run_report_path="$1"
    local bundle_manifest_path="$2"
    local run_id="$3"
    local scenario_id="$4"
    local mode="$5"
    local command_exit_code="$6"
    local script_exit_code="$7"
    local validation_passed="$8"
    local status="$9"
    local message="${10}"
    local expected_report_json="${11}"
    local actual_report_json="${12}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_report_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg artifact_path "$run_report_path" \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_id "$run_id" \
        --arg scenario_id "$scenario_id" \
        --arg mode "$mode" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
        --arg status "$status" \
        --arg message "$message" \
        --argjson expected_report_projection "$expected_report_json" \
        --argjson actual_report_projection "$actual_report_json" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            artifact_path: $artifact_path,
            bundle_manifest_path: $bundle_manifest_path,
            run_id: $run_id,
            scenario_id: $scenario_id,
            mode: $mode,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            message: $message,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection
        }' >"$run_report_path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SCENARIO="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT_OVERRIDE="${2:-}"
            shift 2
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_tools

if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_scenarios
    exit 0
fi

if [[ -z "$SCENARIO" ]]; then
    SCENARIO="$(default_scenario_id)"
fi

SCENARIO_JSON="$(load_scenario_json "$SCENARIO")"
if [[ -z "$SCENARIO_JSON" ]]; then
    echo "FATAL: unknown scenario: ${SCENARIO}" >&2
    exit 1
fi

SCENARIO_DESCRIPTION="$(jq -r '.description' <<<"$SCENARIO_JSON")"
SCENARIO_OUTPUT_ROOT="$(jq -r '.output_root' <<<"$SCENARIO_JSON")"
COMMAND_PREFIX="$(jq -r '.command_prefix' <<<"$SCENARIO_JSON")"
EXPECTED_REPORT_JSON="$(jq -c '.expected_report' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/${SCENARIO_OUTPUT_ROOT}}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_ID="run_${TIMESTAMP}"
RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}/${SCENARIO}"
EVIDENCE_FILE="${RUN_DIR}/scheduler_evidence.json"
REPORT_FILE="${RUN_DIR}/scheduler_report.json"
LOG_FILE="${RUN_DIR}/run.log"
BUNDLE_MANIFEST="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT="${RUN_DIR}/run_report.json"
COMMAND="${COMMAND_PREFIX} --evidence-file ${EVIDENCE_FILE} --output-file ${REPORT_FILE}"

mkdir -p "$RUN_DIR"
jq '.evidence_artifact' <<<"$SCENARIO_JSON" >"$EVIDENCE_FILE"

echo "==================================================================="
echo "           SCHEDULER RECOMMEND SMOKE: INPUT EVIDENCE               "
echo "==================================================================="
cat "$EVIDENCE_FILE"
echo ""

STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
VALIDATION_PASSED=true
STATUS="dry_run"
MESSAGE="dry-run mode: command not executed"
ACTUAL_REPORT_JSON='{}'

if [[ "$MODE" == "dry-run" ]]; then
    printf 'DRY_RUN %s\n' "$COMMAND" >"$LOG_FILE"
else
    set +e
    pushd "$PROJECT_ROOT" >/dev/null
    bash -lc "$COMMAND" 2>&1 | tee "$LOG_FILE"
    COMMAND_EXIT_CODE=${PIPESTATUS[0]}
    popd >/dev/null
    set -e

    STATUS="failed"
    VALIDATION_PASSED=false
    MESSAGE="offline_tuner exited ${COMMAND_EXIT_CODE}"

    if [[ "$COMMAND_EXIT_CODE" -eq 0 && -f "$REPORT_FILE" ]]; then
        ACTUAL_REPORT_JSON="$(
            jq -c '{
                schema_version,
                source_run_label,
                workload_class,
                profile_name,
                recommended_knobs,
                global_queue_limit_hint,
                fallback_profile,
                confidence_percent,
                reason_codes
            }' "$REPORT_FILE"
        )"

        if jq -e --argjson expected "$EXPECTED_REPORT_JSON" '{
                schema_version,
                source_run_label,
                workload_class,
                profile_name,
                recommended_knobs,
                global_queue_limit_hint,
                fallback_profile,
                confidence_percent,
                reason_codes
            } == $expected' "$REPORT_FILE" >/dev/null; then
            STATUS="passed"
            VALIDATION_PASSED=true
            MESSAGE="report matched expected projection"
        else
            MESSAGE="report projection diverged from contract"
            echo "FATAL: scheduler report diverged from expected projection" >&2
            echo "Expected:" >&2
            jq '.' <<<"$EXPECTED_REPORT_JSON" >&2
            echo "Actual:" >&2
            jq '.' <<<"$ACTUAL_REPORT_JSON" >&2
        fi
    fi
fi

if [[ "$MODE" == "execute" ]]; then
    if [[ "$COMMAND_EXIT_CODE" -ne 0 ]]; then
        SCRIPT_EXIT_CODE="$COMMAND_EXIT_CODE"
    elif [[ "$VALIDATION_PASSED" != "true" ]]; then
        SCRIPT_EXIT_CODE=1
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

write_bundle_manifest \
    "$BUNDLE_MANIFEST" \
    "$SCENARIO" \
    "$SCENARIO_DESCRIPTION" \
    "$RUN_ID" \
    "$MODE" \
    "$LOG_FILE" \
    "$EVIDENCE_FILE" \
    "$REPORT_FILE" \
    "$COMMAND" \
    "$EXPECTED_REPORT_JSON" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$STARTED_TS" \
    "$ENDED_TS"

write_run_report \
    "$RUN_REPORT" \
    "$BUNDLE_MANIFEST" \
    "$RUN_ID" \
    "$SCENARIO" \
    "$MODE" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE" \
    "$EXPECTED_REPORT_JSON" \
    "$ACTUAL_REPORT_JSON"

if [[ -f "$REPORT_FILE" ]]; then
    echo ""
    echo "==================================================================="
    echo "         SCHEDULER RECOMMEND SMOKE: GENERATED REPORT               "
    echo "==================================================================="
    cat "$REPORT_FILE"
    echo ""
fi

echo "Smoke run artifacts:"
echo "  bundle:   $BUNDLE_MANIFEST"
echo "  evidence: $EVIDENCE_FILE"
echo "  report:   $REPORT_FILE"
echo "  status:   $STATUS"
echo "  summary:  $RUN_REPORT"

exit "$SCRIPT_EXIT_CODE"
