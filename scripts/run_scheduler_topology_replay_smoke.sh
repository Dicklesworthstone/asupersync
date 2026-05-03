#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/scheduler_topology_replay_smoke_contract_v1.json"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${SCHEDULER_TOPOLOGY_REPLAY_OUTPUT_DIR:-}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_scheduler_topology_replay_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for topology replay smoke runner" >&2
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
    echo "=== Scheduler Topology Replay Smoke Scenarios ==="
    jq -r '.smoke_scenarios[] | "  \(.scenario_id) [\(.scenario_class)/\(.execution_policy)]: \(.description)"' "$ARTIFACT"
}

write_bundle_manifest() {
    local bundle_path="$1"
    local scenario_id="$2"
    local description="$3"
    local scenario_class="$4"
    local execution_policy="$5"
    local run_id="$6"
    local mode="$7"
    local run_log_path="$8"
    local topology_manifest_file="$9"
    local topology_trace_file="${10}"
    local command="${11}"
    local expected_first_hash="${12}"
    local expected_second_hash="${13}"
    local command_exit_code="${14}"
    local script_exit_code="${15}"
    local validation_passed="${16}"
    local status="${17}"
    local started_ts="${18}"
    local ended_ts="${19}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg scenario_id "$scenario_id" \
        --arg description "$description" \
        --arg scenario_class "$scenario_class" \
        --arg execution_policy "$execution_policy" \
        --arg run_id "$run_id" \
        --arg mode "$mode" \
        --arg artifact_path "$bundle_path" \
        --arg run_log_path "$run_log_path" \
        --arg topology_manifest_file "$topology_manifest_file" \
        --arg topology_trace_file "$topology_trace_file" \
        --arg command "$command" \
        --argjson expected_first_hash "$expected_first_hash" \
        --argjson expected_second_hash "$expected_second_hash" \
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
            scenario_class: $scenario_class,
            execution_policy: $execution_policy,
            run_id: $run_id,
            mode: $mode,
            artifact_path: $artifact_path,
            run_log_path: $run_log_path,
            topology_manifest_file: $topology_manifest_file,
            topology_trace_file: $topology_trace_file,
            command: $command,
            expected_first_hash: $expected_first_hash,
            expected_second_hash: $expected_second_hash,
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
    local expected_trace_json="${11}"
    local actual_trace_json="${12}"

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
        --argjson expected_trace_projection "$expected_trace_json" \
        --argjson actual_trace_projection "$actual_trace_json" \
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
            expected_trace_projection: $expected_trace_projection,
            actual_trace_projection: $actual_trace_projection
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
SCENARIO_CLASS="$(jq -r '.scenario_class' <<<"$SCENARIO_JSON")"
EXECUTION_POLICY="$(jq -r '.execution_policy' <<<"$SCENARIO_JSON")"
COMMAND_PREFIX="$(jq -r '.command_prefix' <<<"$SCENARIO_JSON")"
EXPECTED_TRACE_JSON="$(jq -c '.expected_trace' <<<"$SCENARIO_JSON")"
EXPECTED_FIRST_HASH="$(jq -r '.expected_trace.first_hash' <<<"$SCENARIO_JSON")"
EXPECTED_SECOND_HASH="$(jq -r '.expected_trace.second_hash' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/${SCENARIO_OUTPUT_ROOT}}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_ID="run_${TIMESTAMP}"
SCENARIO_DIR="${OUTPUT_ROOT}/${RUN_ID}/${SCENARIO}"
RUN_LOG="${SCENARIO_DIR}/run.log"
TOPOLOGY_MANIFEST="${SCENARIO_DIR}/topology_manifest.json"
TOPOLOGY_TRACE="${SCENARIO_DIR}/topology_trace.json"
BUNDLE_MANIFEST="${SCENARIO_DIR}/bundle_manifest.json"
RUN_REPORT="${SCENARIO_DIR}/run_report.json"
COMMAND="${COMMAND_PREFIX}"
STARTED_TS="$(date --iso-8601=seconds)"

mkdir -p "$SCENARIO_DIR"

set +e
ASUPERSYNC_TOPOLOGY_REPLAY_SCENARIO="$SCENARIO" \
ASUPERSYNC_TOPOLOGY_REPLAY_OUTPUT_DIR="$SCENARIO_DIR" \
    $COMMAND >"$RUN_LOG" 2>&1
COMMAND_EXIT_CODE=$?
set -e

SCRIPT_EXIT_CODE=0
STATUS="passed"
VALIDATION_PASSED=true
MESSAGE="topology replay smoke validation passed"

if [[ "$COMMAND_EXIT_CODE" -ne 0 ]]; then
    STATUS="failed"
    VALIDATION_PASSED=false
    SCRIPT_EXIT_CODE=1
    MESSAGE="topology replay test command failed"
fi

if [[ ! -f "$TOPOLOGY_MANIFEST" || ! -f "$TOPOLOGY_TRACE" ]]; then
    STATUS="failed"
    VALIDATION_PASSED=false
    SCRIPT_EXIT_CODE=1
    MESSAGE="expected topology artifact files were not emitted"
fi

ACTUAL_TRACE_JSON='{}'
if [[ -f "$TOPOLOGY_TRACE" ]]; then
    ACTUAL_TRACE_JSON="$(jq -c '{first_hash: .first_trace_hash, second_hash: .second_trace_hash, event_count, remote_spill_count, locality_sequence}' "$TOPOLOGY_TRACE")"

    ACTUAL_FIRST_HASH="$(jq -r '.first_trace_hash' "$TOPOLOGY_TRACE")"
    ACTUAL_SECOND_HASH="$(jq -r '.second_trace_hash' "$TOPOLOGY_TRACE")"
    ACTUAL_EVENT_COUNT="$(jq -r '.event_count' "$TOPOLOGY_TRACE")"
    ACTUAL_REMOTE_SPILLS="$(jq -r '.remote_spill_count' "$TOPOLOGY_TRACE")"
    ACTUAL_LOCALITY_SEQUENCE="$(jq -c '.locality_sequence' "$TOPOLOGY_TRACE")"
    EXPECTED_EVENT_COUNT="$(jq -r '.expected_trace.event_count' <<<"$SCENARIO_JSON")"
    EXPECTED_REMOTE_SPILLS="$(jq -r '.expected_trace.remote_spill_count' <<<"$SCENARIO_JSON")"
    EXPECTED_LOCALITY_SEQUENCE="$(jq -c '.expected_trace.locality_sequence' <<<"$SCENARIO_JSON")"

    if [[ "$ACTUAL_FIRST_HASH" != "$EXPECTED_FIRST_HASH" || "$ACTUAL_SECOND_HASH" != "$EXPECTED_SECOND_HASH" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="topology replay stable hash mismatch"
    fi
    if [[ "$ACTUAL_EVENT_COUNT" != "$EXPECTED_EVENT_COUNT" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="topology replay event count mismatch"
    fi
    if [[ "$ACTUAL_REMOTE_SPILLS" != "$EXPECTED_REMOTE_SPILLS" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="topology replay remote spill mismatch"
    fi
    if [[ "$EXPECTED_LOCALITY_SEQUENCE" != "[]" && "$ACTUAL_LOCALITY_SEQUENCE" != "$EXPECTED_LOCALITY_SEQUENCE" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="topology replay locality sequence mismatch"
    fi
    if [[ "$(jq -r '.hashes_match' "$TOPOLOGY_TRACE")" != "true" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="topology replay hashes did not match across reruns"
    fi
fi

ENDED_TS="$(date --iso-8601=seconds)"

write_bundle_manifest \
    "$BUNDLE_MANIFEST" \
    "$SCENARIO" \
    "$SCENARIO_DESCRIPTION" \
    "$SCENARIO_CLASS" \
    "$EXECUTION_POLICY" \
    "$RUN_ID" \
    "execute" \
    "$RUN_LOG" \
    "$TOPOLOGY_MANIFEST" \
    "$TOPOLOGY_TRACE" \
    "$COMMAND" \
    "$EXPECTED_FIRST_HASH" \
    "$EXPECTED_SECOND_HASH" \
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
    "execute" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE" \
    "$EXPECTED_TRACE_JSON" \
    "$ACTUAL_TRACE_JSON"

echo "=== Scheduler Topology Replay Smoke Result ==="
echo "scenario_id: ${SCENARIO}"
echo "status: ${STATUS}"
echo "bundle_manifest: ${BUNDLE_MANIFEST}"
echo "run_report: ${RUN_REPORT}"
echo "topology_manifest: ${TOPOLOGY_MANIFEST}"
echo "topology_trace: ${TOPOLOGY_TRACE}"

exit "$SCRIPT_EXIT_CODE"
