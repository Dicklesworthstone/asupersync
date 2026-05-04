#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/task_record_pool_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${TASK_RECORD_POOL_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${TASK_RECORD_POOL_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${TASK_RECORD_POOL_SMOKE_RUN_ID:-}"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_task_record_pool_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing the rch proof
  --execute                  Execute the rch proof twice and validate repeat stability
  --output-root <path>       Override scenario output root
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq awk date uname timeout rch; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
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
        /TASK_RECORD_POOL_REPORT_JSON_BEGIN/ { armed=1; next }
        /TASK_RECORD_POOL_REPORT_JSON_END/ { capture=0; exit }
        armed && /^\{/ { capture=1; armed=0 }
        capture { print }
    ' "$log_path" >"$output_path"
    [ -s "$output_path" ]
}

write_bundle_manifest() {
    local bundle_path="$1"
    local command="$2"
    local command_exit_code="$3"
    local script_exit_code="$4"
    local validation_passed="$5"
    local status="$6"
    local started_ts="$7"
    local ended_ts="$8"

    jq -n \
        --arg schema_version "$(jq -r '.runner_bundle_schema_version' "$ARTIFACT")" \
        --arg contract_version "$(jq -r '.contract_version' "$ARTIFACT")" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$DESCRIPTION" \
        --arg run_id "$RUN_ID" \
        --arg mode "$MODE" \
        --arg report_path "$REPORT_PATH" \
        --arg report_path_repeat_2 "$REPORT_PATH_REPEAT_2" \
        --arg run_log_path "$RUN_LOG_PATH" \
        --arg run_log_path_repeat_2 "$RUN_LOG_PATH_REPEAT_2" \
        --arg command "$command" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson scenario_contract "$SCENARIO_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection_repeat_2 "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" \
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
            report_path_repeat_2: $report_path_repeat_2,
            run_log_path: $run_log_path,
            run_log_path_repeat_2: $run_log_path_repeat_2,
            command: $command,
            host_fingerprint: $host_fingerprint,
            scenario_contract: $scenario_contract,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
            actual_report_projection_repeat_2: $actual_report_projection_repeat_2,
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
    local command_exit_code="$3"
    local script_exit_code="$4"
    local validation_passed="$5"
    local status="$6"
    local message="$7"

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
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection_repeat_2 "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" \
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
            host_fingerprint: $host_fingerprint,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
            actual_report_projection_repeat_2: $actual_report_projection_repeat_2
        }' >"$report_path"
}

run_once() {
    local run_label="$1"
    local report_path="$2"
    local log_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_task_record_pool_${run_label}"
    local tail_timeout_seconds="${TASK_RECORD_POOL_RCH_TIMEOUT_SECONDS:-300}"
    local poll_seconds=0
    local command_exit_code=-1

    local command="
        rch exec -- env \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR=${target_dir} \
        ASUPERSYNC_TASK_RECORD_POOL_CONTRACT_PATH=${ARTIFACT} \
        ASUPERSYNC_TASK_RECORD_POOL_SCENARIO_ID=${SCENARIO} \
        ASUPERSYNC_TASK_RECORD_POOL_REPORT_PATH=${report_path} \
        cargo test -p asupersync --test task_record_pool_contract task_record_pool_smoke_contract_emits_report --features test-internals -- --nocapture
    "

    RUN_ONCE_EARLY_SUCCESS=0
    (
        cd "$PROJECT_ROOT"
        bash -lc "$command"
    ) >"$log_path" 2>&1 &
    local command_pid=$!

    while kill -0 "$command_pid" 2>/dev/null; do
        if grep -q 'TASK_RECORD_POOL_REPORT_JSON_END' "$log_path" 2>/dev/null \
            && grep -q 'Remote command finished: exit=0' "$log_path" 2>/dev/null; then
            kill "$command_pid" 2>/dev/null || true
            wait "$command_pid" 2>/dev/null || true
            command_exit_code=0
            RUN_ONCE_EARLY_SUCCESS=1
            break
        fi
        if grep -Eq 'Remote command finished: exit=[1-9][0-9]*' "$log_path" 2>/dev/null; then
            break
        fi
        sleep 1
        poll_seconds=$((poll_seconds + 1))
        if [ "$poll_seconds" -ge "$tail_timeout_seconds" ]; then
            kill "$command_pid" 2>/dev/null || true
            wait "$command_pid" 2>/dev/null || true
            command_exit_code=124
            printf 'FATAL: timed out waiting for task record pool proof markers\n' >>"$log_path"
            break
        fi
    done

    if [ "$command_exit_code" -eq -1 ]; then
        set +e
        wait "$command_pid"
        command_exit_code=$?
        set -e
    fi

    if [ ! -s "$report_path" ]; then
        extract_report_from_log "$log_path" "$report_path" || true
    fi

    if [ "$command_exit_code" -eq 124 ] \
        && grep -q 'TASK_RECORD_POOL_REPORT_JSON_END' "$log_path" 2>/dev/null \
        && grep -q 'Remote command finished: exit=0' "$log_path" 2>/dev/null; then
        RUN_ONCE_EARLY_SUCCESS=1
        return 0
    fi

    return "$command_exit_code"
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
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/target/task-record-pool-smoke}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.task-record-pool-smoke-artifacts}"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_DIR="${ARTIFACT_ROOT}/run_${RUN_ID}/${SCENARIO}"
mkdir -p "$RUN_DIR" "$ARTIFACT_DIR"

REPORT_PATH="${ARTIFACT_DIR}/task_record_pool_report.json"
REPORT_PATH_REPEAT_2="${ARTIFACT_DIR}/task_record_pool_report_repeat_2.json"
RUN_LOG_PATH="${ARTIFACT_DIR}/task_record_pool_run.log"
RUN_LOG_PATH_REPEAT_2="${ARTIFACT_DIR}/task_record_pool_run_repeat_2.log"
BUNDLE_PATH="${ARTIFACT_DIR}/task_record_pool_bundle.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"

ACTUAL_REPORT_PROJECTION_JSON='null'
ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON='null'

STARTED_TS="$(date --iso-8601=seconds)"

if [ "$MODE" = "dry-run" ]; then
    write_bundle_manifest \
        "$BUNDLE_PATH" \
        "dry-run" \
        0 \
        0 \
        true \
        "dry_run" \
        "$STARTED_TS" \
        "$STARTED_TS"
    write_run_report \
        "$RUN_REPORT_PATH" \
        "$BUNDLE_PATH" \
        0 \
        0 \
        true \
        "dry_run" \
        "dry-run manifest emitted"
    exit 0
fi

if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ]; then
    write_bundle_manifest \
        "$BUNDLE_PATH" \
        "expected projection missing" \
        1 \
        1 \
        false \
        "failed" \
        "$STARTED_TS" \
        "$(date --iso-8601=seconds)"
    write_run_report \
        "$RUN_REPORT_PATH" \
        "$BUNDLE_PATH" \
        1 \
        1 \
        false \
        "failed" \
        "expected_report_projection is not pinned yet"
    exit 1
fi

COMMAND_STRING="rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_task_record_pool_<run> ASUPERSYNC_TASK_RECORD_POOL_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_TASK_RECORD_POOL_SCENARIO_ID=${SCENARIO} ASUPERSYNC_TASK_RECORD_POOL_REPORT_PATH=<report> cargo test -p asupersync --test task_record_pool_contract task_record_pool_smoke_contract_emits_report --features test-internals -- --nocapture"

set +e
run_once "run1" "$REPORT_PATH" "$RUN_LOG_PATH"
COMMAND_EXIT_CODE=$?
RUN1_EARLY_SUCCESS=$RUN_ONCE_EARLY_SUCCESS
if [ "$COMMAND_EXIT_CODE" -eq 0 ]; then
    run_once "run2" "$REPORT_PATH_REPEAT_2" "$RUN_LOG_PATH_REPEAT_2"
    COMMAND_EXIT_CODE=$?
    RUN2_EARLY_SUCCESS=$RUN_ONCE_EARLY_SUCCESS
else
    RUN2_EARLY_SUCCESS=0
fi
set -e

STATUS="passed"
MESSAGE="report projection matched the contract across repeated runs"
VALIDATION_PASSED=true

if [ "$COMMAND_EXIT_CODE" -ne 0 ]; then
    STATUS="failed"
    MESSAGE="rch command failed"
    VALIDATION_PASSED=false
elif [ ! -s "$REPORT_PATH" ] || [ ! -s "$REPORT_PATH_REPEAT_2" ]; then
    STATUS="failed"
    MESSAGE="report markers were not recoverable from rch output"
    VALIDATION_PASSED=false
else
    ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$REPORT_PATH")"
    ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON="$(jq -c '.report_projection' "$REPORT_PATH_REPEAT_2")"
    if [ "$ACTUAL_REPORT_PROJECTION_JSON" != "$EXPECTED_REPORT_PROJECTION_JSON" ]; then
        STATUS="failed"
        MESSAGE="first run projection diverged from the contract"
        VALIDATION_PASSED=false
    elif [ "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" != "$EXPECTED_REPORT_PROJECTION_JSON" ]; then
        STATUS="failed"
        MESSAGE="second run projection diverged from the contract"
        VALIDATION_PASSED=false
    elif [ "$ACTUAL_REPORT_PROJECTION_JSON" != "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" ]; then
        STATUS="failed"
        MESSAGE="repeated run projection mismatch"
        VALIDATION_PASSED=false
    elif [ "$RUN1_EARLY_SUCCESS" -eq 1 ] || [ "$RUN2_EARLY_SUCCESS" -eq 1 ]; then
        MESSAGE="report projection matched the contract after marker completion"
    fi
fi

ENDED_TS="$(date --iso-8601=seconds)"
SCRIPT_EXIT_CODE=0
if [ "$VALIDATION_PASSED" != true ]; then
    SCRIPT_EXIT_CODE=1
fi

write_bundle_manifest \
    "$BUNDLE_PATH" \
    "$COMMAND_STRING" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$STARTED_TS" \
    "$ENDED_TS"
write_run_report \
    "$RUN_REPORT_PATH" \
    "$BUNDLE_PATH" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

if [ "$SCRIPT_EXIT_CODE" -ne 0 ]; then
    exit "$SCRIPT_EXIT_CODE"
fi
