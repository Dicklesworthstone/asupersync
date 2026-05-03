#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/scheduler_global_ready_contention_smoke_contract_v1.json"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${SCHEDULER_GLOBAL_READY_CONTENTION_OUTPUT_DIR:-}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_scheduler_global_ready_contention_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  -h, --help              Show help

Environment:
  SCHEDULER_GLOBAL_READY_CONTENTION_USE_RCH=0
      Run the contract command directly instead of through rch. Agent workflows
      should leave this unset so Rust validation is remote-executed.
  SCHEDULER_GLOBAL_READY_CONTENTION_CARGO_TARGET_DIR=<dir>
      Override the remote Cargo target dir used by rch.
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for scheduler global-ready contention runner" >&2
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
    echo "=== Scheduler Global Ready Contention Smoke Scenarios ==="
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
    local contention_manifest_file="$9"
    local contention_metrics_file="${10}"
    local command="${11}"
    local command_exit_code="${12}"
    local script_exit_code="${13}"
    local validation_passed="${14}"
    local status="${15}"
    local started_ts="${16}"
    local ended_ts="${17}"

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
        --arg contention_manifest_file "$contention_manifest_file" \
        --arg contention_metrics_file "$contention_metrics_file" \
        --arg command "$command" \
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
            contention_manifest_file: $contention_manifest_file,
            contention_metrics_file: $contention_metrics_file,
            command: $command,
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
    local expected_metrics_json="${11}"
    local actual_metrics_json="${12}"

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
        --argjson expected_metrics_projection "$expected_metrics_json" \
        --argjson actual_metrics_projection "$actual_metrics_json" \
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
            expected_metrics_projection: $expected_metrics_projection,
            actual_metrics_projection: $actual_metrics_projection
        }' >"$run_report_path"
}

summary_field() {
    local line="$1"
    local field="$2"
    sed -nE "s/.*(^|[[:space:]])${field}=([^[:space:]]+).*/\\2/p" <<<"$line"
}

summary_latency_field() {
    local line="$1"
    local field="$2"
    sed -nE "s/.*${field}:([0-9]+).*/\\1/p" <<<"$line"
}

recover_contention_artifacts_from_run_log() {
    if [[ -f "$CONTENTION_MANIFEST" && -f "$CONTENTION_METRICS" ]]; then
        return 0
    fi

    local summary_line
    summary_line="$(grep 'selected scenario summary:' "$RUN_LOG" | tail -n 1 || true)"
    if [[ -z "$summary_line" ]]; then
        return 0
    fi

    local summary_scenario_id
    summary_scenario_id="$(summary_field "$summary_line" "id")"
    if [[ "$summary_scenario_id" != "$SCENARIO" ]]; then
        return 0
    fi

    local producer_count tasks_per_producer total_injected ready_before_drain
    local drains drain_tasks fallback batch_mode duplicates lost p50 p95 p99 pmax
    producer_count="$(summary_field "$summary_line" "producers")"
    tasks_per_producer="$(summary_field "$summary_line" "tasks_per_producer")"
    total_injected="$(summary_field "$summary_line" "total_injected")"
    ready_before_drain="$(summary_field "$summary_line" "ready_before_drain")"
    drains="$(summary_field "$summary_line" "drains")"
    drain_tasks="$(summary_field "$summary_line" "drain_tasks")"
    fallback="$(summary_field "$summary_line" "fallback")"
    batch_mode="$(summary_field "$summary_line" "batch_mode")"
    duplicates="$(summary_field "$summary_line" "duplicates")"
    lost="$(summary_field "$summary_line" "lost")"
    p50="$(summary_latency_field "$summary_line" "p50")"
    p95="$(summary_latency_field "$summary_line" "p95")"
    p99="$(summary_latency_field "$summary_line" "p99")"
    pmax="$(summary_latency_field "$summary_line" "max")"

    if [[ -z "$producer_count" || -z "$tasks_per_producer" || -z "$total_injected" || -z "$drains" || -z "$drain_tasks" || -z "$p50" || -z "$p95" || -z "$p99" || -z "$pmax" ]]; then
        return 0
    fi

    jq -n \
        --arg scenario_id "$SCENARIO" \
        --argjson producer_count "$producer_count" \
        --argjson tasks_per_producer "$tasks_per_producer" \
        --argjson priority "$(jq -r '.fixture.priority' <<<"$SCENARIO_JSON")" \
        '{
            scenario_id: $scenario_id,
            fixture: {
                producer_count: $producer_count,
                tasks_per_producer: $tasks_per_producer,
                priority: $priority
            },
            recovered_from_run_log: true
        }' >"$CONTENTION_MANIFEST"

    jq -n \
        --arg scenario_id "$SCENARIO" \
        --argjson producer_count "$producer_count" \
        --argjson tasks_per_producer "$tasks_per_producer" \
        --argjson total_injected "$total_injected" \
        --argjson ready_before_drain "$ready_before_drain" \
        --argjson total_dispatched "$total_injected" \
        --argjson duplicate_dispatches "$duplicates" \
        --argjson lost_tasks "$lost" \
        --argjson batch_mode_activated "$batch_mode" \
        --argjson fallback_to_baseline "$fallback" \
        --argjson global_ready_batch_drains "$drains" \
        --argjson global_ready_batch_tasks "$drain_tasks" \
        --argjson configured_batch_size "$(jq -r '.expected_metrics.configured_batch_size' <<<"$SCENARIO_JSON")" \
        --argjson activation_threshold "$(jq -r '.expected_metrics.activation_threshold' <<<"$SCENARIO_JSON")" \
        --argjson p50 "$p50" \
        --argjson p95 "$p95" \
        --argjson p99 "$p99" \
        --argjson pmax "$pmax" \
        '{
            scenario_id: $scenario_id,
            producer_count: $producer_count,
            tasks_per_producer: $tasks_per_producer,
            total_injected: $total_injected,
            ready_count_before_drain: $ready_before_drain,
            total_dispatched: $total_dispatched,
            unique_dispatched: ($total_dispatched - $duplicate_dispatches),
            duplicate_dispatches: $duplicate_dispatches,
            lost_tasks: $lost_tasks,
            batch_mode_activated: $batch_mode_activated,
            fallback_to_baseline: $fallback_to_baseline,
            global_ready_batch_drains: $global_ready_batch_drains,
            global_ready_batch_tasks: $global_ready_batch_tasks,
            configured_batch_size: $configured_batch_size,
            activation_threshold: $activation_threshold,
            mean_batch_size: (if $global_ready_batch_drains > 0 then ($global_ready_batch_tasks / $global_ready_batch_drains) else 0 end),
            enqueue_latency_ns: {
                p50: $p50,
                p95: $p95,
                p99: $p99,
                max: $pmax
            },
            contention_counters: {
                available: false,
                retry_count: 0,
                cas_failures: 0,
                notes: [
                    "GlobalQueue currently exposes batch-drain counters but not internal CAS retry counters.",
                    "This artifact was recovered from the rch run log because target/ outputs are ignored during retrieval."
                ]
            },
            recovered_from_run_log: true
        }' >"$CONTENTION_METRICS"
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
EXPECTED_METRICS_JSON="$(jq -cS '.expected_metrics' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/${SCENARIO_OUTPUT_ROOT}}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_ID="run_${TIMESTAMP}"
SCENARIO_DIR="${OUTPUT_ROOT}/${RUN_ID}/${SCENARIO}"
RUN_LOG="${SCENARIO_DIR}/run.log"
CONTENTION_MANIFEST="${SCENARIO_DIR}/contention_manifest.json"
CONTENTION_METRICS="${SCENARIO_DIR}/contention_metrics.json"
BUNDLE_MANIFEST="${SCENARIO_DIR}/bundle_manifest.json"
RUN_REPORT="${SCENARIO_DIR}/run_report.json"
COMMAND="${COMMAND_PREFIX}"
DEFAULT_RCH_TMP="${TMPDIR:-}"
if [[ (-z "$DEFAULT_RCH_TMP" || "$DEFAULT_RCH_TMP" == "/tmp") && -d /data/tmp ]]; then
    DEFAULT_RCH_TMP="/data/tmp"
fi
DEFAULT_RCH_TMP="${DEFAULT_RCH_TMP:-/tmp}"
RCH_CARGO_TARGET_DIR="${SCHEDULER_GLOBAL_READY_CONTENTION_CARGO_TARGET_DIR:-${DEFAULT_RCH_TMP}/rch_target_scheduler_global_ready_contention}"
EXECUTED_COMMAND="$COMMAND"
STARTED_TS="$(date --iso-8601=seconds)"

mkdir -p "$SCENARIO_DIR"

set +e
if [[ "${SCHEDULER_GLOBAL_READY_CONTENTION_USE_RCH:-1}" == "1" ]]; then
    EXECUTED_COMMAND="rch exec -- env CARGO_TARGET_DIR=${RCH_CARGO_TARGET_DIR} ASUPERSYNC_GLOBAL_READY_CONTENTION_SCENARIO=${SCENARIO} ASUPERSYNC_GLOBAL_READY_CONTENTION_OUTPUT_DIR=${SCENARIO_DIR} ${COMMAND}"
    rch exec -- env \
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        ASUPERSYNC_GLOBAL_READY_CONTENTION_SCENARIO="$SCENARIO" \
        ASUPERSYNC_GLOBAL_READY_CONTENTION_OUTPUT_DIR="$SCENARIO_DIR" \
        $COMMAND >"$RUN_LOG" 2>&1
else
    ASUPERSYNC_GLOBAL_READY_CONTENTION_SCENARIO="$SCENARIO" \
    ASUPERSYNC_GLOBAL_READY_CONTENTION_OUTPUT_DIR="$SCENARIO_DIR" \
        $COMMAND >"$RUN_LOG" 2>&1
fi
COMMAND_EXIT_CODE=$?
set -e

recover_contention_artifacts_from_run_log

SCRIPT_EXIT_CODE=0
STATUS="passed"
VALIDATION_PASSED=true
MESSAGE="scheduler global-ready contention validation passed"

if [[ "$COMMAND_EXIT_CODE" -ne 0 ]]; then
    STATUS="failed"
    VALIDATION_PASSED=false
    SCRIPT_EXIT_CODE=1
    MESSAGE="scheduler global-ready contention test command failed"
fi

if [[ ! -f "$CONTENTION_MANIFEST" || ! -f "$CONTENTION_METRICS" ]]; then
    STATUS="failed"
    VALIDATION_PASSED=false
    SCRIPT_EXIT_CODE=1
    MESSAGE="expected contention artifact files were not emitted"
fi

ACTUAL_METRICS_JSON='{}'
if [[ -f "$CONTENTION_METRICS" ]]; then
    ACTUAL_METRICS_JSON="$(jq -cS '{total_injected, batch_mode_activated, fallback_to_baseline, global_ready_batch_drains, global_ready_batch_tasks, duplicate_dispatches, lost_tasks, configured_batch_size, activation_threshold}' "$CONTENTION_METRICS")"

    ACTUAL_TOTAL_INJECTED="$(jq -r '.total_injected' "$CONTENTION_METRICS")"
    ACTUAL_BATCH_MODE_ACTIVATED="$(jq -r '.batch_mode_activated' "$CONTENTION_METRICS")"
    ACTUAL_FALLBACK_TO_BASELINE="$(jq -r '.fallback_to_baseline' "$CONTENTION_METRICS")"
    ACTUAL_BATCH_DRAINS="$(jq -r '.global_ready_batch_drains' "$CONTENTION_METRICS")"
    ACTUAL_BATCH_TASKS="$(jq -r '.global_ready_batch_tasks' "$CONTENTION_METRICS")"
    ACTUAL_DUPLICATES="$(jq -r '.duplicate_dispatches' "$CONTENTION_METRICS")"
    ACTUAL_LOST_TASKS="$(jq -r '.lost_tasks' "$CONTENTION_METRICS")"
    ACTUAL_CONFIGURED_BATCH_SIZE="$(jq -r '.configured_batch_size' "$CONTENTION_METRICS")"
    ACTUAL_ACTIVATION_THRESHOLD="$(jq -r '.activation_threshold' "$CONTENTION_METRICS")"
    ACTUAL_P50="$(jq -r '.enqueue_latency_ns.p50' "$CONTENTION_METRICS")"
    ACTUAL_P95="$(jq -r '.enqueue_latency_ns.p95' "$CONTENTION_METRICS")"
    ACTUAL_P99="$(jq -r '.enqueue_latency_ns.p99' "$CONTENTION_METRICS")"

    EXPECTED_TOTAL_INJECTED="$(jq -r '.expected_metrics.total_injected' <<<"$SCENARIO_JSON")"
    EXPECTED_BATCH_MODE_ACTIVATED="$(jq -r '.expected_metrics.batch_mode_activated' <<<"$SCENARIO_JSON")"
    EXPECTED_FALLBACK_TO_BASELINE="$(jq -r '.expected_metrics.fallback_to_baseline' <<<"$SCENARIO_JSON")"
    EXPECTED_MIN_BATCH_DRAINS="$(jq -r '.expected_metrics.min_batch_drains' <<<"$SCENARIO_JSON")"
    EXPECTED_MIN_BATCH_TASKS="$(jq -r '.expected_metrics.min_batch_tasks' <<<"$SCENARIO_JSON")"
    EXPECTED_MAX_DUPLICATES="$(jq -r '.expected_metrics.max_duplicate_dispatches' <<<"$SCENARIO_JSON")"
    EXPECTED_MAX_LOST_TASKS="$(jq -r '.expected_metrics.max_lost_tasks' <<<"$SCENARIO_JSON")"
    EXPECTED_CONFIGURED_BATCH_SIZE="$(jq -r '.expected_metrics.configured_batch_size' <<<"$SCENARIO_JSON")"
    EXPECTED_ACTIVATION_THRESHOLD="$(jq -r '.expected_metrics.activation_threshold' <<<"$SCENARIO_JSON")"

    if [[ "$ACTUAL_TOTAL_INJECTED" != "$EXPECTED_TOTAL_INJECTED" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention total_injected mismatch"
    fi
    if [[ "$ACTUAL_BATCH_MODE_ACTIVATED" != "$EXPECTED_BATCH_MODE_ACTIVATED" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention batch-mode activation mismatch"
    fi
    if [[ "$ACTUAL_FALLBACK_TO_BASELINE" != "$EXPECTED_FALLBACK_TO_BASELINE" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention fallback mismatch"
    fi
    if (( ACTUAL_BATCH_DRAINS < EXPECTED_MIN_BATCH_DRAINS )); then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention batch drain count below minimum"
    fi
    if (( ACTUAL_BATCH_TASKS < EXPECTED_MIN_BATCH_TASKS )); then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention batch task count below minimum"
    fi
    if (( ACTUAL_DUPLICATES > EXPECTED_MAX_DUPLICATES )); then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention duplicate dispatches exceeded maximum"
    fi
    if (( ACTUAL_LOST_TASKS > EXPECTED_MAX_LOST_TASKS )); then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention lost task count exceeded maximum"
    fi
    if [[ "$ACTUAL_CONFIGURED_BATCH_SIZE" != "$EXPECTED_CONFIGURED_BATCH_SIZE" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention configured batch size mismatch"
    fi
    if [[ "$ACTUAL_ACTIVATION_THRESHOLD" != "$EXPECTED_ACTIVATION_THRESHOLD" ]]; then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention activation threshold mismatch"
    fi
    if (( ACTUAL_P95 < ACTUAL_P50 || ACTUAL_P99 < ACTUAL_P95 )); then
        STATUS="failed"
        VALIDATION_PASSED=false
        SCRIPT_EXIT_CODE=1
        MESSAGE="scheduler global-ready contention latency percentiles were not monotone"
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
    "$CONTENTION_MANIFEST" \
    "$CONTENTION_METRICS" \
    "$EXECUTED_COMMAND" \
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
    "$EXPECTED_METRICS_JSON" \
    "$ACTUAL_METRICS_JSON"

echo "=== Scheduler Global Ready Contention Smoke Result ==="
echo "scenario_id: ${SCENARIO}"
echo "status: ${STATUS}"
echo "bundle_manifest: ${BUNDLE_MANIFEST}"
echo "run_report: ${RUN_REPORT}"
echo "contention_manifest: ${CONTENTION_MANIFEST}"
echo "contention_metrics: ${CONTENTION_METRICS}"

exit "$SCRIPT_EXIT_CODE"
