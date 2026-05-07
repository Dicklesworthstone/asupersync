#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/host_profile_planner_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${HOST_PROFILE_PLANNER_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${HOST_PROFILE_PLANNER_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${HOST_PROFILE_PLANNER_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_host_profile_planner_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing the rch proof
  --execute                  Execute the rch proof and validate the report projection
  --output-root <path>       Override scenario output_root
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq awk date uname timeout; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        missing=1
    fi
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
}

artifact_value() {
    jq -r "$1" "$ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$ARTIFACT"
}

default_scenario_id() {
    jq -r '.smoke_scenarios[0].scenario_id' "$ARTIFACT"
}

load_scenario_json() {
    local scenario_id="$1"
    jq -c --arg scenario_id "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$ARTIFACT"
}

host_fingerprint_json() {
    local host os kernel_release arch cpu_threads mem_total_kib
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

extract_report_from_log() {
    local log_path="$1"
    local output_path="$2"
    local output_dir
    output_dir="$(dirname "$output_path")"
    mkdir -p "$output_dir"
    awk '
        /HOST_PROFILE_PLANNER_REPORT_JSON_BEGIN/ { capture=1; next }
        /HOST_PROFILE_PLANNER_REPORT_JSON_END/ { capture=0; exit }
        capture { print }
    ' "$log_path" | awk '
        BEGIN { json_started=0 }
        /^[[:space:]]*{/ { json_started=1 }
        json_started { print }
    ' >"$output_path"
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
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.host-profile-planner-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
SCENARIO_REPORT_PATH="${ARTIFACT_ROOT}/host_profile_planner_report.json"
RCH_TAIL_TIMEOUT_SECONDS="${HOST_PROFILE_PLANNER_RCH_TIMEOUT_SECONDS:-300}"

mkdir -p "$RUN_DIR"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

RCH_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_host_profile_planner"
COMMAND_ARGS=(
    "$RCH_BIN"
    exec
    --
    env
    CARGO_INCREMENTAL=0
    "CARGO_TARGET_DIR=${RCH_TARGET_DIR}"
    "ASUPERSYNC_HOST_PROFILE_PLANNER_CONTRACT_PATH=${ARTIFACT}"
    "ASUPERSYNC_HOST_PROFILE_PLANNER_SCENARIO=${SCENARIO}"
    "ASUPERSYNC_HOST_PROFILE_PLANNER_REPORT_PATH=${SCENARIO_REPORT_PATH}"
    cargo
    test
    -p
    asupersync
    --test
    host_profile_planner_contract
    host_profile_planner_smoke_contract_emits_report
    --features
    test-internals
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND%" "}"

COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
STATUS="passed"
VALIDATION_PASSED=false
MESSAGE="runner completed"
ACTUAL_REPORT_PROJECTION_JSON="null"

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN scenario=%s\n' "$SCENARIO" >"$RUN_LOG_PATH"
    STATUS="dry_run"
    VALIDATION_PASSED=true
    MESSAGE="dry run emitted manifests only"
else
    if timeout "${RCH_TAIL_TIMEOUT_SECONDS}s" "${COMMAND_ARGS[@]}" >"$RUN_LOG_PATH" 2>&1; then
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

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    fi

    if [ "$STATUS" = "passed" ]; then
        if ! extract_report_from_log "$RUN_LOG_PATH" "$SCENARIO_REPORT_PATH"; then
            SCRIPT_EXIT_CODE=1
            STATUS="failed"
            MESSAGE="host profile planner report JSON markers missing from run.log"
        else
            ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$SCENARIO_REPORT_PATH")"
            if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ] || jq -en \
                --argjson expected "$EXPECTED_REPORT_PROJECTION_JSON" \
                --argjson actual "$ACTUAL_REPORT_PROJECTION_JSON" \
                '$expected == $actual' >/dev/null; then
                VALIDATION_PASSED=true
                if [ "$MESSAGE" = "rch proof command completed" ]; then
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

jq -n \
    --arg schema_version "host-profile-planner-smoke-bundle-v1" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg scenario_id "$SCENARIO" \
    --arg description "$DESCRIPTION" \
    --arg mode "$MODE" \
    --arg started_at "$STARTED_TS" \
    --arg ended_at "$ENDED_TS" \
    --arg report_path "$SCENARIO_REPORT_PATH" \
    --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
    '{
        schema_version: $schema_version,
        contract_version: $contract_version,
        scenario_id: $scenario_id,
        description: $description,
        mode: $mode,
        started_at: $started_at,
        ended_at: $ended_at,
        host_fingerprint: $host_fingerprint,
        report_artifact_path: $report_path
    }' >"$BUNDLE_MANIFEST_PATH"

jq -n \
    --arg schema_version "host-profile-planner-run-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --arg mode "$MODE" \
    --arg command "$COMMAND" \
    --arg report_path "$SCENARIO_REPORT_PATH" \
    --arg bundle_manifest_path "$BUNDLE_MANIFEST_PATH" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson expected_report_projection "${EXPECTED_REPORT_PROJECTION_JSON}" \
    --argjson actual_report_projection "${ACTUAL_REPORT_PROJECTION_JSON}" \
    '{
        schema_version: $schema_version,
        scenario_id: $scenario_id,
        status: $status,
        message: $message,
        mode: $mode,
        command: $command,
        validation_passed: $validation_passed,
        command_exit_code: $command_exit_code,
        script_exit_code: $script_exit_code,
        bundle_manifest_path: $bundle_manifest_path,
        report_artifact_path: $report_path,
        run_log_path: $run_log_path,
        expected_report_projection: $expected_report_projection,
        actual_report_projection: $actual_report_projection
    }' >"$RUN_REPORT_PATH"

printf 'Scenario: %s\n' "$SCENARIO"
printf 'Mode: %s\n' "$MODE"
printf 'Status: %s\n' "$STATUS"
printf 'Validation: %s\n' "$VALIDATION_PASSED"
printf 'Bundle manifest: %s\n' "$BUNDLE_MANIFEST_PATH"
printf 'Run report: %s\n' "$RUN_REPORT_PATH"
printf 'Scenario report: %s\n' "$SCENARIO_REPORT_PATH"

exit "$SCRIPT_EXIT_CODE"
