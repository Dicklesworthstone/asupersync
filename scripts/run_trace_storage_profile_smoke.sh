#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/trace_storage_profile_smoke_contract_v1.json"
MODE="execute"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${TRACE_STORAGE_PROFILE_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${TRACE_STORAGE_PROFILE_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${TRACE_STORAGE_PROFILE_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_trace_storage_profile_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  --dry-run               Emit manifests without executing the trace-storage comparison proof
  --execute               Execute the trace-storage comparison proof (default)
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for trace storage smoke runner" >&2
        exit 1
    fi
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
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
    echo "=== Trace Storage Profile Smoke Scenarios ==="
    jq -r '.smoke_scenarios[] | "  \(.scenario_id) [\(.execution_policy // "execute_or_dry_run")]: \(.description)"' "$ARTIFACT"
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

write_bundle_manifest() {
    local bundle_path="$1"
    local run_report_path="$2"
    local comparison_report_path="$3"
    local run_log_path="$4"
    local command="$5"
    local command_exit_code="$6"
    local script_exit_code="$7"
    local validation_passed="$8"
    local status="$9"
    local started_ts="${10}"
    local ended_ts="${11}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$DESCRIPTION" \
        --arg run_id "$RUN_ID" \
        --arg mode "$MODE" \
        --arg artifact_path "$bundle_path" \
        --arg comparison_report_path "$comparison_report_path" \
        --arg run_log_path "$run_log_path" \
        --arg command "$command" \
        --argjson host_requirements "$HOST_REQUIREMENTS_JSON" \
        --argjson workload_model "$WORKLOAD_MODEL_JSON" \
        --argjson operator_notes "$OPERATOR_NOTES_JSON" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
        --argjson verdict_summary "$VERDICT_SUMMARY_JSON" \
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
            comparison_report_path: $comparison_report_path,
            run_log_path: $run_log_path,
            command: $command,
            host_requirements: $host_requirements,
            workload_model: $workload_model,
            operator_notes: $operator_notes,
            host_fingerprint: $host_fingerprint,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
            verdict_summary: $verdict_summary,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            started_ts: $started_ts,
            ended_ts: $ended_ts
        }' >"$bundle_path"
}

write_run_report() {
    local report_path="$1"
    local bundle_manifest_path="$2"
    local comparison_report_path="$3"
    local command="$4"
    local command_exit_code="$5"
    local script_exit_code="$6"
    local validation_passed="$7"
    local status="$8"
    local message="$9"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_report_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg artifact_path "$report_path" \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_id "$RUN_ID" \
        --arg scenario_id "$SCENARIO" \
        --arg mode "$MODE" \
        --arg status "$status" \
        --arg message "$message" \
        --arg command "$command" \
        --arg comparison_report_path "$comparison_report_path" \
        --argjson host_requirements "$HOST_REQUIREMENTS_JSON" \
        --argjson workload_model "$WORKLOAD_MODEL_JSON" \
        --argjson operator_notes "$OPERATOR_NOTES_JSON" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
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
            command: $command,
            host_requirements: $host_requirements,
            workload_model: $workload_model,
            operator_notes: $operator_notes,
            host_fingerprint: $host_fingerprint,
            comparison_report_path: $comparison_report_path,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection
        }' >"$report_path"
}

extract_report_from_log() {
    local log_path="$1"
    local output_path="$2"
    local output_dir
    output_dir="$(dirname "$output_path")"
    mkdir -p "$output_dir"
    awk '
        /TRACE_STORAGE_REPORT_JSON_BEGIN/ { capture=1; next }
        /TRACE_STORAGE_REPORT_JSON_END/ { capture=0; exit }
        capture { print }
    ' "$log_path" >"$output_path"
    [ -s "$output_path" ]
}

while [ $# -gt 0 ]; do
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
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_tools

if [ "$LIST_ONLY" -eq 1 ]; then
    list_scenarios
    exit 0
fi

if [ -z "$SCENARIO" ]; then
    SCENARIO="$(default_scenario_id)"
fi

SCENARIO_JSON="$(load_scenario_json "$SCENARIO")"
if [ -z "$SCENARIO_JSON" ]; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 1
fi

DESCRIPTION="$(jq -r '.description' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-$(jq -r '.output_root' <<<"$SCENARIO_JSON")}"
RUN_ID="${RUN_ID_OVERRIDE:-run_$(date '+%Y%m%d_%H%M%S')}"
SCENARIO_DIR="${OUTPUT_ROOT}/${RUN_ID}/${SCENARIO}"
mkdir -p "$SCENARIO_DIR"
REPORT_ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-.trace-storage-profile-smoke-artifacts}"
REPORT_ARTIFACT_DIR="${REPORT_ARTIFACT_ROOT}/${RUN_ID}/${SCENARIO}"
mkdir -p "$REPORT_ARTIFACT_DIR"

BUNDLE_MANIFEST_PATH="${SCENARIO_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${SCENARIO_DIR}/run_report.json"
COMPARISON_REPORT_PATH="${REPORT_ARTIFACT_DIR}/trace_storage_profile_comparison.json"
RUN_LOG_PATH="${SCENARIO_DIR}/run.log"

HOST_REQUIREMENTS_JSON="$(jq -c '.host_requirements' <<<"$SCENARIO_JSON")"
WORKLOAD_MODEL_JSON="$(jq -c '.workload_model' <<<"$SCENARIO_JSON")"
OPERATOR_NOTES_JSON="$(jq -c '.operator_notes' <<<"$SCENARIO_JSON")"
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"

printf -v RCH_INVOCATION '%q' "$RCH_BIN"
COMMAND="${RCH_INVOCATION} exec -- env ASUPERSYNC_TRACE_STORAGE_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_TRACE_STORAGE_SCENARIO_ID=${SCENARIO} ASUPERSYNC_TRACE_STORAGE_REPORT_PATH=${COMPARISON_REPORT_PATH} CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_trace_storage_profile_smoke cargo test -p asupersync --test trace_storage_profile trace_storage_profile_smoke_contract_emits_operator_cost_report -- --nocapture"

STARTED_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
VALIDATION_PASSED=false
STATUS="dry_run"
MESSAGE="dry-run only; expected projection emitted without executing the trace storage comparison proof"
ACTUAL_REPORT_PROJECTION_JSON='null'

if [ "$MODE" = "execute" ]; then
    COMMAND_EXIT_CODE=-1
    set +e
    eval "$COMMAND" >"$RUN_LOG_PATH" 2>&1 &
    COMMAND_PID=$!
    set -e

    POLL_SECONDS=0
    MAX_POLL_SECONDS=300

    while kill -0 "$COMMAND_PID" 2>/dev/null; do
        if grep -q 'TRACE_STORAGE_REPORT_JSON_END' "$RUN_LOG_PATH" 2>/dev/null \
            && grep -q 'Remote command finished: exit=0' "$RUN_LOG_PATH" 2>/dev/null; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=0
            break
        fi
        if grep -Eq 'Remote command finished: exit=[1-9][0-9]*' "$RUN_LOG_PATH" 2>/dev/null; then
            break
        fi
        if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=86
            printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
            break
        fi
        sleep 1
        POLL_SECONDS=$((POLL_SECONDS + 1))
        if [ "$POLL_SECONDS" -ge "$MAX_POLL_SECONDS" ]; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=124
            printf 'FATAL: timed out waiting for trace storage smoke proof markers\n' >>"$RUN_LOG_PATH"
            break
        fi
    done

    if [ "$COMMAND_EXIT_CODE" -eq -1 ]; then
        set +e
        wait "$COMMAND_PID"
        COMMAND_EXIT_CODE=$?
        set -e
    fi

    if [ "$COMMAND_EXIT_CODE" -ne 86 ] \
        && grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ] && extract_report_from_log "$RUN_LOG_PATH" "$COMPARISON_REPORT_PATH"; then
        ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$COMPARISON_REPORT_PATH")"
        VALIDATION_PASSED=true
        STATUS="passed"
        MESSAGE="trace storage comparison proof passed and emitted operator-cost report"
    else
        SCRIPT_EXIT_CODE=$COMMAND_EXIT_CODE
        VALIDATION_PASSED=false
        STATUS="failed"
        if [ "$COMMAND_EXIT_CODE" -eq 86 ]; then
            MESSAGE="rch local fallback detected; refusing local cargo execution"
        else
            MESSAGE="trace storage comparison proof failed"
        fi
    fi
else
    printf 'dry-run: skipped execution for scenario %s\n' "$SCENARIO" >"$RUN_LOG_PATH"
    VALIDATION_PASSED=true
fi

VERDICT_SUMMARY_JSON="$(jq -nc \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --arg mode "$MODE" \
    '{status: $status, message: $message, validation_passed: $validation_passed, command_exit_code: $command_exit_code, mode: $mode}')"

ENDED_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

write_bundle_manifest \
    "$BUNDLE_MANIFEST_PATH" \
    "$RUN_REPORT_PATH" \
    "$COMPARISON_REPORT_PATH" \
    "$RUN_LOG_PATH" \
    "$COMMAND" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$STARTED_TS" \
    "$ENDED_TS"

write_run_report \
    "$RUN_REPORT_PATH" \
    "$BUNDLE_MANIFEST_PATH" \
    "$COMPARISON_REPORT_PATH" \
    "$COMMAND" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

if [ "$STATUS" = "failed" ]; then
    exit "$COMMAND_EXIT_CODE"
fi

printf 'bundle_manifest=%s\n' "$BUNDLE_MANIFEST_PATH"
printf 'run_report=%s\n' "$RUN_REPORT_PATH"
if [ -f "$COMPARISON_REPORT_PATH" ]; then
    printf 'comparison_report=%s\n' "$COMPARISON_REPORT_PATH"
fi
