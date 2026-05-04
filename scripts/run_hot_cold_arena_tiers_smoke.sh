#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/hot_cold_arena_tiers_smoke_contract_v1.json"
MODE="execute"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_RUN_ID:-}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_hot_cold_arena_tiers_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  --dry-run               Emit manifests without executing the hot/cold arena proof
  --execute               Execute the hot/cold arena proof (default)
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for hot/cold arena smoke runner" >&2
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
    echo "=== Hot/Cold Arena Tier Smoke Scenarios ==="
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
    local report_path="$2"
    local run_log_path="$3"
    local command="$4"
    local command_exit_code="$5"
    local script_exit_code="$6"
    local validation_passed="$7"
    local status="$8"
    local started_ts="$9"
    local ended_ts="${10}"

    jq -n \
        --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$DESCRIPTION" \
        --arg run_id "$RUN_ID" \
        --arg mode "$MODE" \
        --arg artifact_path "$bundle_path" \
        --arg report_path "$report_path" \
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
            report_path: $report_path,
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
    local command_exit_code="$4"
    local script_exit_code="$5"
    local validation_passed="$6"
    local status="$7"
    local message="$8"

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
            host_requirements: $host_requirements,
            workload_model: $workload_model,
            operator_notes: $operator_notes,
            host_fingerprint: $host_fingerprint,
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
        /HOT_COLD_ARENA_REPORT_JSON_BEGIN/ { capture=1; next }
        /HOT_COLD_ARENA_REPORT_JSON_END/ { capture=0; exit }
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
HOST_REQUIREMENTS_JSON="$(jq -c '.host_requirements' <<<"$SCENARIO_JSON")"
WORKLOAD_MODEL_JSON="$(jq -c '.workload_model' <<<"$SCENARIO_JSON")"
OPERATOR_NOTES_JSON="$(jq -c '.operator_notes' <<<"$SCENARIO_JSON")"
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.hot-cold-arena-tiers-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
SCENARIO_REPORT_PATH="${ARTIFACT_ROOT}/hot_cold_arena_tiers_report.json"
RCH_TAIL_TIMEOUT_SECONDS="${HOT_COLD_ARENA_TIERS_RCH_TIMEOUT_SECONDS:-300}"

mkdir -p "$RUN_DIR"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

COMMAND="rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_hot_cold_arena ASUPERSYNC_HOT_COLD_ARENA_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_HOT_COLD_ARENA_SCENARIO=${SCENARIO} ASUPERSYNC_HOT_COLD_ARENA_REPORT_PATH=${SCENARIO_REPORT_PATH} cargo test -p asupersync --test hot_cold_arena_tiers hot_cold_arena_tiers_smoke_contract_emits_operator_report --features test-internals -- --nocapture"

COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
STATUS="passed"
VALIDATION_PASSED=false
MESSAGE="runner completed"
ACTUAL_REPORT_PROJECTION_JSON="null"
VERDICT_SUMMARY_JSON='{}'

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN scenario=%s\n' "$SCENARIO" >"$RUN_LOG_PATH"
    STATUS="dry_run"
    VALIDATION_PASSED=true
    MESSAGE="dry run emitted manifests only"
else
    if timeout "${RCH_TAIL_TIMEOUT_SECONDS}s" bash -lc "$COMMAND" >"$RUN_LOG_PATH" 2>&1; then
        COMMAND_EXIT_CODE=0
        MESSAGE="rch proof command completed"
    else
        COMMAND_EXIT_CODE=$?
        if [ "$COMMAND_EXIT_CODE" -eq 124 ] && grep -q 'Remote command finished: exit=0' "$RUN_LOG_PATH"; then
            COMMAND_EXIT_CODE=0
            MESSAGE="rch proof passed before retrieval tail timeout"
        else
            SCRIPT_EXIT_CODE=$COMMAND_EXIT_CODE
            STATUS="failed"
            MESSAGE="rch proof command failed"
        fi
    fi

    if [ "$STATUS" = "passed" ]; then
        if ! extract_report_from_log "$RUN_LOG_PATH" "$SCENARIO_REPORT_PATH"; then
            SCRIPT_EXIT_CODE=1
            STATUS="failed"
            MESSAGE="hot/cold arena report JSON markers missing from run.log"
        else
            ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$SCENARIO_REPORT_PATH")"
            VERDICT_SUMMARY_JSON="$(jq -c '.comparison' "$SCENARIO_REPORT_PATH")"
            if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ] || jq -en \
                --argjson expected "$EXPECTED_REPORT_PROJECTION_JSON" \
                --argjson actual "$ACTUAL_REPORT_PROJECTION_JSON" \
                '$expected == $actual' >/dev/null; then
                VALIDATION_PASSED=true
                if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ]; then
                    MESSAGE="report projection emitted for contract freeze"
                elif [ "$MESSAGE" = "rch proof command completed" ]; then
                    MESSAGE="report projection matched the contract"
                else
                    MESSAGE="report projection matched the contract after retrieval tail timeout"
                fi
            else
                SCRIPT_EXIT_CODE=1
                STATUS="failed"
                MESSAGE="report projection diverged from the contract"
            fi
        fi
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

write_bundle_manifest \
    "$BUNDLE_MANIFEST_PATH" \
    "$SCENARIO_REPORT_PATH" \
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
    "$SCENARIO_REPORT_PATH" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

cat "$RUN_REPORT_PATH"

if [ "$SCRIPT_EXIT_CODE" -ne 0 ]; then
    exit "$SCRIPT_EXIT_CODE"
fi
