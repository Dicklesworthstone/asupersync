#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/scheduler_recommend_smoke_contract_v1.json"
MODE="execute"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${SCHEDULER_RECOMMEND_SMOKE_OUTPUT_DIR:-}"
RUN_ID_OVERRIDE="${SCHEDULER_RECOMMEND_SMOKE_RUN_ID:-}"

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
    jq -r '.smoke_scenarios[] | "  \(.scenario_id) [\(.scenario_class // "deterministic_lab_safe")/\(.execution_policy // "execute_or_dry_run")]: \(.description)"' "$ARTIFACT"
}

split_command_words() {
    local command_string="$1"
    local output_name="$2"
    local -n output_ref="$output_name"

    output_ref=()
    if [[ -z "$command_string" ]]; then
        return 0
    fi

    case "$command_string" in
        *"'"*|*\"*|*\\*|*'`'*|*'$'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
            echo "FATAL: command string requires shell parsing: ${command_string}" >&2
            return 1
            ;;
    esac

    read -r -a output_ref <<<"$command_string"
}

host_fingerprint_json() {
    local host="unknown"
    local os="unknown"
    local kernel_release="unknown"
    local arch="unknown"
    local cpu_threads=0
    local mem_total_kib=0

    host="$(hostname 2>/dev/null || printf 'unknown')"
    os="$(uname -s 2>/dev/null || printf 'unknown')"
    kernel_release="$(uname -r 2>/dev/null || printf 'unknown')"
    arch="$(uname -m 2>/dev/null || printf 'unknown')"
    cpu_threads="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '0')"
    mem_total_kib="$(awk '/MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || printf '0')"

    jq -nc \
        --arg hostname "$host" \
        --arg os "$os" \
        --arg kernel_release "$kernel_release" \
        --arg arch "$arch" \
        --argjson cpu_threads "${cpu_threads:-0}" \
        --argjson mem_total_kib "${mem_total_kib:-0}" \
        '{
            hostname: $hostname,
            os: $os,
            kernel_release: $kernel_release,
            arch: $arch,
            cpu_threads: $cpu_threads,
            mem_total_kib: $mem_total_kib
        }'
}

evidence_latency_summary_json() {
    local evidence_file="$1"
    jq -c '{
        wake_to_run_ns: {
            p50: .metrics.wake_to_run_p50_ns,
            p95: .metrics.wake_to_run_p95_ns,
            p99: .metrics.wake_to_run_p99_ns
        },
        queue_residency_ns: {
            p50: .metrics.queue_residency_p50_ns,
            p95: .metrics.queue_residency_p95_ns,
            p99: .metrics.queue_residency_p99_ns
        },
        ready_backlog: {
            p95: .metrics.ready_backlog_p95,
            p99: .metrics.ready_backlog_p99
        },
        cancel_debt: {
            p95: .metrics.cancel_debt_p95,
            p99: .metrics.cancel_debt_p99
        }
    }' "$evidence_file"
}

report_fallback_activations_json() {
    local report_file="$1"
    jq -c '{
        activated: (.profile_name == "conservative_baseline" or (.recommended_knobs == .fallback_profile)),
        active_profile_names: (
            if (.profile_name == "conservative_baseline" or (.recommended_knobs == .fallback_profile))
            then [.profile_name]
            else []
            end
        ),
        fallback_profile: .fallback_profile,
        reason_codes: .reason_codes
    }' "$report_file"
}

evidence_config_snapshot_json() {
    local evidence_file="$1"
    jq -c '{
        source: "scheduler_evidence.current_knobs",
        run_label: .run_label,
        workload_class: .workload_class,
        topology: .topology,
        current_knobs: .current_knobs
    }' "$evidence_file"
}

merged_config_snapshot_json() {
    local evidence_file="$1"
    local report_file="$2"
    jq -cn \
        --slurpfile evidence "$evidence_file" \
        --slurpfile report "$report_file" \
        '{
            source: "scheduler_evidence.current_knobs + scheduler_report",
            run_label: $evidence[0].run_label,
            workload_class: $evidence[0].workload_class,
            topology: $evidence[0].topology,
            current_knobs: $evidence[0].current_knobs,
            recommended_knobs: $report[0].recommended_knobs,
            fallback_profile: $report[0].fallback_profile
        }'
}

verdict_summary_json() {
    local status="$1"
    local message="$2"
    local validation_passed="$3"
    local command_exit_code="$4"
    local script_exit_code="$5"
    local scenario_class="$6"
    local execution_policy="$7"
    local expected_profile_name="$8"
    local actual_profile_name="$9"
    jq -nc \
        --arg status "$status" \
        --arg message "$message" \
        --argjson validation_passed "$validation_passed" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --arg scenario_class "$scenario_class" \
        --arg execution_policy "$execution_policy" \
        --arg expected_profile_name "$expected_profile_name" \
        --arg actual_profile_name "$actual_profile_name" \
        '{
            status: $status,
            message: $message,
            validation_passed: $validation_passed,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            scenario_class: $scenario_class,
            execution_policy: $execution_policy,
            expected_profile_name: $expected_profile_name,
            actual_profile_name: (if $actual_profile_name == "" then null else $actual_profile_name end)
        }'
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
    local evidence_file="$9"
    local report_file="${10}"
    local command="${11}"
    local host_requirements_json="${12}"
    local template_env_json="${13}"
    local capture_plan_json="${14}"
    local expected_profile_name="${15}"
    local expected_reason_codes_json="${16}"
    local command_exit_code="${17}"
    local script_exit_code="${18}"
    local validation_passed="${19}"
    local status="${20}"
    local started_ts="${21}"
    local ended_ts="${22}"
    local capture_mode="${23}"
    local capture_command="${24}"
    local capture_command_exit_code="${25}"

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
        --arg evidence_file "$evidence_file" \
        --arg report_file "$report_file" \
        --arg command "$command" \
        --argjson host_requirements "$host_requirements_json" \
        --argjson template_env "$template_env_json" \
        --argjson capture_plan "$capture_plan_json" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson topology_profile "$TOPOLOGY_PROFILE_JSON" \
        --argjson memory_profile "$MEMORY_PROFILE_JSON" \
        --argjson workload_seed "$WORKLOAD_SEED_JSON" \
        --argjson queue_storm_shape "$QUEUE_STORM_SHAPE_JSON" \
        --argjson cancel_storm_shape "$CANCEL_STORM_SHAPE_JSON" \
        --argjson latency_summary "$LATENCY_SUMMARY_JSON" \
        --argjson throughput_summary "$THROUGHPUT_SUMMARY_JSON" \
        --argjson fallback_activations "$FALLBACK_ACTIVATIONS_JSON" \
        --argjson controller_state_references "$CONTROLLER_STATE_REFERENCES_JSON" \
        --argjson config_snapshot "$CONFIG_SNAPSHOT_JSON" \
        --argjson verdict_summary "$VERDICT_SUMMARY_JSON" \
        --arg expected_profile_name "$expected_profile_name" \
        --argjson expected_reason_codes "$expected_reason_codes_json" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
        --arg status "$status" \
        --arg started_ts "$started_ts" \
        --arg ended_ts "$ended_ts" \
        --arg capture_mode "$capture_mode" \
        --arg capture_command "$capture_command" \
        --argjson capture_command_exit_code "$capture_command_exit_code" \
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
            evidence_file: $evidence_file,
            report_file: $report_file,
            command: $command,
            host_requirements: $host_requirements,
            template_env: $template_env,
            capture_plan: $capture_plan,
            host_fingerprint: $host_fingerprint,
            topology_profile: $topology_profile,
            memory_profile: $memory_profile,
            workload_seed: $workload_seed,
            queue_storm_shape: $queue_storm_shape,
            cancel_storm_shape: $cancel_storm_shape,
            latency_summary: $latency_summary,
            throughput_summary: $throughput_summary,
            fallback_activations: $fallback_activations,
            controller_state_references: $controller_state_references,
            config_snapshot: $config_snapshot,
            verdict_summary: $verdict_summary,
            expected_profile_name: $expected_profile_name,
            expected_reason_codes: $expected_reason_codes,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            started_ts: $started_ts,
            ended_ts: $ended_ts,
            capture_mode: $capture_mode,
            capture_command: $capture_command,
            capture_command_exit_code: $capture_command_exit_code
        }' >"$bundle_path"
}

write_run_report() {
    local run_report_path="$1"
    local bundle_manifest_path="$2"
    local run_id="$3"
    local scenario_id="$4"
    local scenario_class="$5"
    local execution_policy="$6"
    local mode="$7"
    local command_exit_code="$8"
    local script_exit_code="$9"
    local validation_passed="${10}"
    local status="${11}"
    local message="${12}"
    local host_requirements_json="${13}"
    local template_env_json="${14}"
    local capture_plan_json="${15}"
    local expected_report_json="${16}"
    local actual_report_json="${17}"
    local capture_mode="${18}"
    local capture_command="${19}"
    local capture_command_exit_code="${20}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_report_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg artifact_path "$run_report_path" \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_id "$run_id" \
        --arg scenario_id "$scenario_id" \
        --arg scenario_class "$scenario_class" \
        --arg execution_policy "$execution_policy" \
        --arg mode "$mode" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
        --arg status "$status" \
        --arg message "$message" \
        --argjson host_requirements "$host_requirements_json" \
        --argjson template_env "$template_env_json" \
        --argjson capture_plan "$capture_plan_json" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson topology_profile "$TOPOLOGY_PROFILE_JSON" \
        --argjson memory_profile "$MEMORY_PROFILE_JSON" \
        --argjson workload_seed "$WORKLOAD_SEED_JSON" \
        --argjson queue_storm_shape "$QUEUE_STORM_SHAPE_JSON" \
        --argjson cancel_storm_shape "$CANCEL_STORM_SHAPE_JSON" \
        --argjson latency_summary "$LATENCY_SUMMARY_JSON" \
        --argjson throughput_summary "$THROUGHPUT_SUMMARY_JSON" \
        --argjson fallback_activations "$FALLBACK_ACTIVATIONS_JSON" \
        --argjson controller_state_references "$CONTROLLER_STATE_REFERENCES_JSON" \
        --argjson config_snapshot "$CONFIG_SNAPSHOT_JSON" \
        --argjson verdict_summary "$VERDICT_SUMMARY_JSON" \
        --argjson expected_report_projection "$expected_report_json" \
        --argjson actual_report_projection "$actual_report_json" \
        --arg capture_mode "$capture_mode" \
        --arg capture_command "$capture_command" \
        --argjson capture_command_exit_code "$capture_command_exit_code" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            artifact_path: $artifact_path,
            bundle_manifest_path: $bundle_manifest_path,
            run_id: $run_id,
            scenario_id: $scenario_id,
            scenario_class: $scenario_class,
            execution_policy: $execution_policy,
            mode: $mode,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            message: $message,
            host_requirements: $host_requirements,
            template_env: $template_env,
            capture_plan: $capture_plan,
            host_fingerprint: $host_fingerprint,
            topology_profile: $topology_profile,
            memory_profile: $memory_profile,
            workload_seed: $workload_seed,
            queue_storm_shape: $queue_storm_shape,
            cancel_storm_shape: $cancel_storm_shape,
            latency_summary: $latency_summary,
            throughput_summary: $throughput_summary,
            fallback_activations: $fallback_activations,
            controller_state_references: $controller_state_references,
            config_snapshot: $config_snapshot,
            verdict_summary: $verdict_summary,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
            capture_mode: $capture_mode,
            capture_command: $capture_command,
            capture_command_exit_code: $capture_command_exit_code
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
SCENARIO_CLASS="$(jq -r '.scenario_class // "deterministic_lab_safe"' <<<"$SCENARIO_JSON")"
EXECUTION_POLICY="$(jq -r '.execution_policy // "execute_or_dry_run"' <<<"$SCENARIO_JSON")"
COMMAND_PREFIX="$(jq -r '.command_prefix // empty' <<<"$SCENARIO_JSON")"
HOST_REQUIREMENTS_JSON="$(jq -c '.host_requirements // {}' <<<"$SCENARIO_JSON")"
TEMPLATE_ENV_JSON="$(jq -c '.template_env // {}' <<<"$SCENARIO_JSON")"
CAPTURE_PLAN_JSON="$(jq -c '.capture_plan // []' <<<"$SCENARIO_JSON")"
EXPECTED_REPORT_JSON="$(jq -c '.expected_report // {}' <<<"$SCENARIO_JSON")"
HAS_EXPECTED_REPORT="$(jq -r 'if .expected_report == null then "false" else "true" end' <<<"$SCENARIO_JSON")"
EXPECTED_PROFILE_NAME="$(jq -r 'if .expected_report != null then (.expected_report.profile_name // "") else (.expected_profile_name_hint // "") end' <<<"$SCENARIO_JSON")"
EXPECTED_REASON_CODES_JSON="$(jq -c 'if .expected_report != null then (.expected_report.reason_codes // []) else (.expected_reason_codes_hint // []) end' <<<"$SCENARIO_JSON")"
CAPTURE_MODE="$(jq -r '.capture_mode // "embedded_contract_artifact"' <<<"$SCENARIO_JSON")"
CAPTURE_COMMAND="$(jq -r '.capture_command // empty' <<<"$SCENARIO_JSON")"
TOPOLOGY_PROFILE_JSON="$(jq -c '.topology_profile // (.evidence_artifact.topology // {})' <<<"$SCENARIO_JSON")"
MEMORY_PROFILE_JSON="$(jq -c '.memory_profile // { name: "derived_from_evidence", budget_gib: (.evidence_artifact.topology.memory_budget_gib // null) }' <<<"$SCENARIO_JSON")"
WORKLOAD_SEED_JSON="$(jq -c '.workload_seed // null' <<<"$SCENARIO_JSON")"
QUEUE_STORM_SHAPE_JSON="$(jq -c '.queue_storm_shape // {}' <<<"$SCENARIO_JSON")"
CANCEL_STORM_SHAPE_JSON="$(jq -c '.cancel_storm_shape // {}' <<<"$SCENARIO_JSON")"
THROUGHPUT_SUMMARY_JSON="$(jq -c '.throughput_summary // { units: "evidence_owned", observed: null, source: "unspecified", note: "throughput is owned by upstream evidence capture rather than this replay step" }' <<<"$SCENARIO_JSON")"
FALLBACK_ACTIVATIONS_JSON="$(jq -c '.fallback_activations_hint // { activated: false, active_profile_names: [] }' <<<"$SCENARIO_JSON")"
CONTROLLER_STATE_REFERENCES_JSON="$(jq -c '.controller_state_references // ["scheduler_report.profile_name","scheduler_report.recommended_knobs","scheduler_report.fallback_profile","scheduler_report.reason_codes"]' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/${SCENARIO_OUTPUT_ROOT}}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_ID="${RUN_ID_OVERRIDE:-run_${TIMESTAMP}}"
RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}/${SCENARIO}"
EVIDENCE_FILE="${RUN_DIR}/scheduler_evidence.json"
REPORT_FILE="${RUN_DIR}/scheduler_report.json"
LOG_FILE="${RUN_DIR}/run.log"
BUNDLE_MANIFEST="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT="${RUN_DIR}/run_report.json"
COMMAND_ARGS=()
split_command_words "$COMMAND_PREFIX" COMMAND_ARGS
COMMAND_ARGS+=(--evidence-file "$EVIDENCE_FILE" --output-file "$REPORT_FILE")
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND%" "}"

mkdir -p "$RUN_DIR"

capture_evidence() {
    local mode="$1"
    local command="$2"
    local command_args=()
    local exit_code=0

    case "$mode" in
        embedded_contract_artifact)
            jq '.evidence_artifact // .evidence_template' <<<"$SCENARIO_JSON" >"$EVIDENCE_FILE"
            printf 'CAPTURE_EMBEDDED %s\n' "$EVIDENCE_FILE" >>"$LOG_FILE"
            ;;
        runtime_test_capture)
            if [[ -z "$command" ]]; then
                echo "FATAL: runtime_test_capture requires capture_command" >&2
                return 1
            fi
            printf 'CAPTURE_COMMAND %s\n' "$command" >>"$LOG_FILE"
            split_command_words "$command" command_args
            set +e
            pushd "$PROJECT_ROOT" >/dev/null
            ASUPERSYNC_SCHEDULER_EVIDENCE_CAPTURE_PATH="$EVIDENCE_FILE" \
                "${command_args[@]}" 2>&1 | tee -a "$LOG_FILE"
            exit_code=${PIPESTATUS[0]}
            popd >/dev/null
            set -e
            if [[ "$exit_code" -ne 0 ]]; then
                return "$exit_code"
            fi
            if [[ ! -f "$EVIDENCE_FILE" ]]; then
                echo "FATAL: capture command succeeded but did not emit ${EVIDENCE_FILE}" >&2
                return 1
            fi
            ;;
        *)
            echo "FATAL: unsupported capture_mode=${mode}" >&2
            return 1
            ;;
    esac

    return 0
}

printf '' >"$LOG_FILE"

echo "==================================================================="
echo "           SCHEDULER RECOMMEND SMOKE: INPUT EVIDENCE               "
echo "==================================================================="

STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMAND_EXIT_CODE=0
CAPTURE_COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
VALIDATION_PASSED=true
STATUS="dry_run"
MESSAGE="dry-run mode: command not executed"
ACTUAL_REPORT_JSON='{}'
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
LATENCY_SUMMARY_JSON='{}'
CONFIG_SNAPSHOT_JSON='{}'
VERDICT_SUMMARY_JSON='{}'
ACTUAL_PROFILE_NAME=""

set +e
capture_evidence "$CAPTURE_MODE" "$CAPTURE_COMMAND"
CAPTURE_COMMAND_EXIT_CODE=$?
set -e

if [[ "$CAPTURE_COMMAND_EXIT_CODE" -ne 0 ]]; then
    STATUS="failed"
    VALIDATION_PASSED=false
    MESSAGE="evidence capture failed with exit ${CAPTURE_COMMAND_EXIT_CODE}"
    SCRIPT_EXIT_CODE="$CAPTURE_COMMAND_EXIT_CODE"
else
    cat "$EVIDENCE_FILE"
    echo ""
    LATENCY_SUMMARY_JSON="$(evidence_latency_summary_json "$EVIDENCE_FILE")"
    CONFIG_SNAPSHOT_JSON="$(evidence_config_snapshot_json "$EVIDENCE_FILE")"
fi

if [[ "$CAPTURE_COMMAND_EXIT_CODE" -ne 0 ]]; then
    :
elif [[ "$MODE" == "dry-run" ]]; then
    printf 'DRY_RUN %s\n' "$COMMAND" >>"$LOG_FILE"
    MESSAGE="dry-run mode: evidence captured; offline_tuner not executed"
elif [[ "$EXECUTION_POLICY" == "dry_run_only" ]]; then
    printf 'REFUSED_EXECUTE %s\n' "$COMMAND" >>"$LOG_FILE"
    STATUS="blocked"
    VALIDATION_PASSED=false
    MESSAGE="scenario execution_policy=dry_run_only; use --dry-run to emit the real-host template bundle"
    SCRIPT_EXIT_CODE=1
else
    set +e
    pushd "$PROJECT_ROOT" >/dev/null
    "${COMMAND_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"
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
        FALLBACK_ACTIVATIONS_JSON="$(report_fallback_activations_json "$REPORT_FILE")"
        CONFIG_SNAPSHOT_JSON="$(merged_config_snapshot_json "$EVIDENCE_FILE" "$REPORT_FILE")"
        ACTUAL_PROFILE_NAME="$(jq -r '.profile_name // ""' "$REPORT_FILE")"

        if [[ "$HAS_EXPECTED_REPORT" == "true" ]] && jq -e --argjson expected "$EXPECTED_REPORT_JSON" '{
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
        elif [[ "$HAS_EXPECTED_REPORT" != "true" ]]; then
            STATUS="passed"
            VALIDATION_PASSED=true
            MESSAGE="command completed; scenario has no fixed report projection contract"
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

VERDICT_SUMMARY_JSON="$(
    verdict_summary_json \
        "$STATUS" \
        "$MESSAGE" \
        "$VALIDATION_PASSED" \
        "$COMMAND_EXIT_CODE" \
        "$SCRIPT_EXIT_CODE" \
        "$SCENARIO_CLASS" \
        "$EXECUTION_POLICY" \
        "$EXPECTED_PROFILE_NAME" \
        "$ACTUAL_PROFILE_NAME"
)"

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

write_bundle_manifest \
    "$BUNDLE_MANIFEST" \
    "$SCENARIO" \
    "$SCENARIO_DESCRIPTION" \
    "$SCENARIO_CLASS" \
    "$EXECUTION_POLICY" \
    "$RUN_ID" \
    "$MODE" \
    "$LOG_FILE" \
    "$EVIDENCE_FILE" \
    "$REPORT_FILE" \
    "$COMMAND" \
    "$HOST_REQUIREMENTS_JSON" \
    "$TEMPLATE_ENV_JSON" \
    "$CAPTURE_PLAN_JSON" \
    "$EXPECTED_PROFILE_NAME" \
    "$EXPECTED_REASON_CODES_JSON" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$STARTED_TS" \
    "$ENDED_TS" \
    "$CAPTURE_MODE" \
    "$CAPTURE_COMMAND" \
    "$CAPTURE_COMMAND_EXIT_CODE"

write_run_report \
    "$RUN_REPORT" \
    "$BUNDLE_MANIFEST" \
    "$RUN_ID" \
    "$SCENARIO" \
    "$SCENARIO_CLASS" \
    "$EXECUTION_POLICY" \
    "$MODE" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE" \
    "$HOST_REQUIREMENTS_JSON" \
    "$TEMPLATE_ENV_JSON" \
    "$CAPTURE_PLAN_JSON" \
    "$EXPECTED_REPORT_JSON" \
    "$ACTUAL_REPORT_JSON" \
    "$CAPTURE_MODE" \
    "$CAPTURE_COMMAND" \
    "$CAPTURE_COMMAND_EXIT_CODE"

if [[ -f "$REPORT_FILE" ]]; then
    {
        echo ""
        echo "==================================================================="
        echo "         SCHEDULER RECOMMEND SMOKE: GENERATED REPORT               "
        echo "==================================================================="
        cat "$REPORT_FILE"
        echo ""
    } | tee -a "$LOG_FILE"
fi

echo "Smoke run artifacts:"
echo "  bundle:   $BUNDLE_MANIFEST"
echo "  evidence: $EVIDENCE_FILE"
echo "  report:   $REPORT_FILE"
echo "  class:    $SCENARIO_CLASS"
echo "  policy:   $EXECUTION_POLICY"
echo "  status:   $STATUS"
echo "  summary:  $RUN_REPORT"

exit "$SCRIPT_EXIT_CODE"
