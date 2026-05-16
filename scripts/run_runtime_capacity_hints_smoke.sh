#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_capacity_hints_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${RUNTIME_CAPACITY_HINTS_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${RUNTIME_CAPACITY_HINTS_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${RUNTIME_CAPACITY_HINTS_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'EOF'
Usage: ./scripts/run_runtime_capacity_hints_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing the rch proof
  --execute                  Execute the rch proof and validate the report projection
  --output-root <path>       Override scenario output root
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
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
        missing=1
    fi
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
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
        /RUNTIME_CAPACITY_HINTS_REPORT_JSON_BEGIN/ { armed=1; next }
        /RUNTIME_CAPACITY_HINTS_REPORT_JSON_END/ { capture=0; exit }
        armed && /^\{/ { capture=1; armed=0 }
        capture { print }
    ' "$log_path" >"$output_path"
    [ -s "$output_path" ]
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
        --arg schema_version "$(jq -r '.runner_bundle_schema_version' "$ARTIFACT")" \
        --arg contract_version "$(jq -r '.contract_version' "$ARTIFACT")" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$DESCRIPTION" \
        --arg run_id "$RUN_ID" \
        --arg mode "$MODE" \
        --arg report_path "$report_path" \
        --arg run_log_path "$run_log_path" \
        --arg command "$command" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson scenario_contract "$SCENARIO_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
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
            report_path: $report_path,
            run_log_path: $run_log_path,
            command: $command,
            host_fingerprint: $host_fingerprint,
            scenario_contract: $scenario_contract,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
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
    local command="$3"
    local command_exit_code="$4"
    local script_exit_code="$5"
    local validation_passed="$6"
    local status="$7"
    local message="$8"

    jq -n \
        --arg schema_version "$(jq -r '.runner_report_schema_version' "$ARTIFACT")" \
        --arg contract_version "$(jq -r '.contract_version' "$ARTIFACT")" \
        --arg artifact_path "$report_path" \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_id "$RUN_ID" \
        --arg scenario_id "$SCENARIO" \
        --arg mode "$MODE" \
        --arg status "$status" \
        --arg message "$message" \
        --arg command "$command" \
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
            host_fingerprint: $host_fingerprint,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection
        }' >"$report_path"
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
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/target/runtime-capacity-hints-smoke}"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.runtime-capacity-hints-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
SCENARIO_REPORT_PATH="${ARTIFACT_ROOT}/runtime_capacity_hints_report.json"
RCH_TAIL_TIMEOUT_SECONDS="${RUNTIME_CAPACITY_HINTS_RCH_TIMEOUT_SECONDS:-300}"

mkdir -p "$RUN_DIR"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

COMMAND_ARGS=(
    "$RCH_BIN"
    exec
    --
    env
    "CARGO_INCREMENTAL=0"
    "CARGO_PROFILE_TEST_DEBUG=0"
    "RUSTFLAGS=-D warnings -C debuginfo=0"
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_runtime_capacity_hints"
    "ASUPERSYNC_RUNTIME_CAPACITY_HINTS_CONTRACT_PATH=${ARTIFACT}"
    "ASUPERSYNC_RUNTIME_CAPACITY_HINTS_SCENARIO_ID=${SCENARIO}"
    "ASUPERSYNC_RUNTIME_CAPACITY_HINTS_REPORT_PATH=${SCENARIO_REPORT_PATH}"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync
    --test
    runtime_capacity_hints_contract
    runtime_capacity_hints_smoke_contract_emits_report
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"

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
    COMMAND_EXIT_CODE=-1
    EARLY_SUCCESS=0
    set +e
    (
        cd "$PROJECT_ROOT"
        "${COMMAND_ARGS[@]}"
    ) >"$RUN_LOG_PATH" 2>&1 &
    COMMAND_PID=$!
    set -e

    POLL_SECONDS=0
    while kill -0 "$COMMAND_PID" 2>/dev/null; do
        if grep -q 'RUNTIME_CAPACITY_HINTS_REPORT_JSON_END' "$RUN_LOG_PATH" 2>/dev/null \
            && grep -q 'Remote command finished: exit=0' "$RUN_LOG_PATH" 2>/dev/null; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=0
            EARLY_SUCCESS=1
            break
        fi
        if grep -Eq 'Remote command finished: exit=[1-9][0-9]*' "$RUN_LOG_PATH" 2>/dev/null; then
            break
        fi
        if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RUN_LOG_PATH" 2>/dev/null; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=86
            printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
            break
        fi
        sleep 1
        POLL_SECONDS=$((POLL_SECONDS + 1))
        if [ "$POLL_SECONDS" -ge "$RCH_TAIL_TIMEOUT_SECONDS" ]; then
            kill "$COMMAND_PID" 2>/dev/null || true
            wait "$COMMAND_PID" 2>/dev/null || true
            COMMAND_EXIT_CODE=124
            printf 'FATAL: timed out waiting for runtime capacity hints proof markers\n' >>"$RUN_LOG_PATH"
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
        && grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ]; then
        if [ "$EARLY_SUCCESS" -eq 1 ]; then
            MESSAGE="rch proof passed before retrieval tail timeout"
        else
            MESSAGE="rch proof command completed"
        fi
    else
        SCRIPT_EXIT_CODE=$COMMAND_EXIT_CODE
        STATUS="failed"
        if [ "$COMMAND_EXIT_CODE" -eq 86 ]; then
            MESSAGE="rch local fallback detected; refusing local cargo execution"
        else
            MESSAGE="rch proof command failed"
        fi
    fi

    if [ "$STATUS" = "passed" ]; then
        if ! extract_report_from_log "$RUN_LOG_PATH" "$SCENARIO_REPORT_PATH"; then
            SCRIPT_EXIT_CODE=1
            STATUS="failed"
            MESSAGE="runtime capacity hints report JSON markers missing from run.log"
        else
            ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$SCENARIO_REPORT_PATH")"
            if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ] || jq -en \
                --argjson expected "$EXPECTED_REPORT_PROJECTION_JSON" \
                --argjson actual "$ACTUAL_REPORT_PROJECTION_JSON" \
                '$expected == $actual' >/dev/null; then
                VALIDATION_PASSED=true
                if [ "$EARLY_SUCCESS" -eq 1 ]; then
                    MESSAGE="report projection matched the contract after marker completion"
                else
                    MESSAGE="report projection matched the contract"
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
    "$COMMAND" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

printf 'scenario=%s\n' "$SCENARIO"
printf 'mode=%s\n' "$MODE"
printf 'status=%s\n' "$STATUS"
printf 'validation_passed=%s\n' "$VALIDATION_PASSED"
printf 'run_report=%s\n' "$RUN_REPORT_PATH"
printf 'bundle_manifest=%s\n' "$BUNDLE_MANIFEST_PATH"
if [ -f "$SCENARIO_REPORT_PATH" ]; then
    printf 'report=%s\n' "$SCENARIO_REPORT_PATH"
fi

if [ "$SCRIPT_EXIT_CODE" -ne 0 ]; then
    exit "$SCRIPT_EXIT_CODE"
fi
