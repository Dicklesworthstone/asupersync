#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/hot_cold_arena_tiers_smoke_contract_v1.json"

MODE="execute"
SCENARIO=""
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${HOT_COLD_ARENA_TIERS_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_hot_cold_arena_tiers_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (defaults to the first artifact scenario)
  --output-root <dir>     Override output root
  --dry-run               Emit manifests without executing the hot/cold arena proof
  --execute               Execute the hot/cold arena proof twice and validate repeat stability
  -h, --help              Show help
USAGE
}

require_tools() {
    local missing=0
    for tool in jq awk date uname; do
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

extract_report_from_log() {
    local log_path="$1"
    local output_path="$2"
    local output_dir
    output_dir="$(dirname "$output_path")"
    mkdir -p "$output_dir"
    awk '
        /HOT_COLD_ARENA_REPORT_JSON_BEGIN/ { armed=1; next }
        /HOT_COLD_ARENA_REPORT_JSON_END/ { capture=0; exit }
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
        --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
        --arg contract_version "$(artifact_value '.contract_version')" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$DESCRIPTION" \
        --arg run_id "$RUN_ID" \
        --arg mode "$MODE" \
        --arg report_path "$REPORT_PATH" \
        --arg report_path_repeat_2 "$REPORT_PATH_REPEAT_2" \
        --arg run_log_path "$RUN_LOG_PATH" \
        --arg run_log_path_repeat_2 "$RUN_LOG_PATH_REPEAT_2" \
        --arg command "$command" \
        --argjson host_requirements "$HOST_REQUIREMENTS_JSON" \
        --argjson workload_model "$WORKLOAD_MODEL_JSON" \
        --argjson operator_notes "$OPERATOR_NOTES_JSON" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson scenario_contract "$SCENARIO_JSON" \
        --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
        --argjson actual_report_projection_repeat_2 "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" \
        --argjson verdict_summary "$VERDICT_SUMMARY_JSON" \
        --argjson verdict_summary_repeat_2 "$VERDICT_SUMMARY_REPEAT_2_JSON" \
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
            host_requirements: $host_requirements,
            workload_model: $workload_model,
            operator_notes: $operator_notes,
            host_fingerprint: $host_fingerprint,
            scenario_contract: $scenario_contract,
            expected_report_projection: $expected_report_projection,
            actual_report_projection: $actual_report_projection,
            actual_report_projection_repeat_2: $actual_report_projection_repeat_2,
            verdict_summary: $verdict_summary,
            verdict_summary_repeat_2: $verdict_summary_repeat_2,
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
            host_requirements: $host_requirements,
            workload_model: $workload_model,
            operator_notes: $operator_notes,
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
    local target_dir="${TMPDIR:-/tmp}/rch_target_hot_cold_arena_${run_label}"
    local tail_timeout_seconds="${HOT_COLD_ARENA_TIERS_RCH_TIMEOUT_SECONDS:-300}"
    local poll_seconds=0
    local command_exit_code=-1
    local had_errexit=0
    local -a command_args=()

    case $- in
        *e*) had_errexit=1 ;;
    esac

    command_args=(
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=-D warnings -C debuginfo=0"
        "CARGO_TARGET_DIR=${target_dir}"
        "ASUPERSYNC_HOT_COLD_ARENA_CONTRACT_PATH=${ARTIFACT}"
        "ASUPERSYNC_HOT_COLD_ARENA_SCENARIO=${SCENARIO}"
        "ASUPERSYNC_HOT_COLD_ARENA_REPORT_PATH=${report_path}"
        "${CARGO_BIN:-cargo}"
        test
        -p
        asupersync
        --test
        hot_cold_arena_tiers
        hot_cold_arena_tiers_smoke_contract_emits_operator_report
        --features
        test-internals
        --
        --nocapture
    )

    RUN_ONCE_EARLY_SUCCESS=0
    (
        cd "$PROJECT_ROOT"
        "${command_args[@]}"
    ) >"$log_path" 2>&1 &
    local command_pid=$!

    while kill -0 "$command_pid" 2>/dev/null; do
        if grep -q 'HOT_COLD_ARENA_REPORT_JSON_END' "$log_path" 2>/dev/null \
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
        if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$log_path" 2>/dev/null; then
            kill "$command_pid" 2>/dev/null || true
            wait "$command_pid" 2>/dev/null || true
            command_exit_code=86
            printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_path"
            break
        fi
        sleep 1
        poll_seconds=$((poll_seconds + 1))
        if [ "$poll_seconds" -ge "$tail_timeout_seconds" ]; then
            kill "$command_pid" 2>/dev/null || true
            wait "$command_pid" 2>/dev/null || true
            command_exit_code=124
            printf 'FATAL: timed out waiting for hot/cold arena proof markers\n' >>"$log_path"
            break
        fi
    done

    if [ "$command_exit_code" -eq -1 ]; then
        set +e
        wait "$command_pid"
        command_exit_code=$?
        if [ "$had_errexit" -eq 1 ]; then
            set -e
        else
            set +e
        fi
    fi

    if [ "$command_exit_code" -ne 86 ] && grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$log_path" 2>/dev/null; then
        command_exit_code=86
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_path"
    fi

    if [ ! -s "$report_path" ]; then
        extract_report_from_log "$log_path" "$report_path" || true
    fi

    if [ "$command_exit_code" -eq 124 ] \
        && grep -q 'HOT_COLD_ARENA_REPORT_JSON_END' "$log_path" 2>/dev/null \
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
ARTIFACT_DIR="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.hot-cold-arena-tiers-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_LOG_PATH_REPEAT_2="${RUN_DIR}/run_repeat_2.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_PATH="${ARTIFACT_DIR}/hot_cold_arena_tiers_report.json"
REPORT_PATH_REPEAT_2="${ARTIFACT_DIR}/hot_cold_arena_tiers_report_repeat_2.json"

mkdir -p "$RUN_DIR" "$ARTIFACT_DIR"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"

COMMAND_STRING="${RCH_BIN} exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_hot_cold_arena_<run> ASUPERSYNC_HOT_COLD_ARENA_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_HOT_COLD_ARENA_SCENARIO=${SCENARIO} ASUPERSYNC_HOT_COLD_ARENA_REPORT_PATH=<report> cargo test -p asupersync --test hot_cold_arena_tiers hot_cold_arena_tiers_smoke_contract_emits_operator_report --features test-internals -- --nocapture"

ACTUAL_REPORT_PROJECTION_JSON='null'
ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON='null'
VERDICT_SUMMARY_JSON='{}'
VERDICT_SUMMARY_REPEAT_2_JSON='{}'

STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN scenario=%s\n' "$SCENARIO" >"$RUN_LOG_PATH"
    write_bundle_manifest \
        "$BUNDLE_MANIFEST_PATH" \
        "dry-run" \
        0 \
        0 \
        true \
        "dry_run" \
        "$STARTED_TS" \
        "$STARTED_TS"
    write_run_report \
        "$RUN_REPORT_PATH" \
        "$BUNDLE_MANIFEST_PATH" \
        0 \
        0 \
        true \
        "dry_run" \
        "dry run emitted manifests only"
    cat "$RUN_REPORT_PATH"
    exit 0
fi

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
    MESSAGE="rch proof command failed"
    VALIDATION_PASSED=false
elif [ ! -s "$REPORT_PATH" ] || [ ! -s "$REPORT_PATH_REPEAT_2" ]; then
    STATUS="failed"
    MESSAGE="report markers were not recoverable from rch output"
    VALIDATION_PASSED=false
else
    ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$REPORT_PATH")"
    ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON="$(jq -c '.report_projection' "$REPORT_PATH_REPEAT_2")"
    VERDICT_SUMMARY_JSON="$(jq -c '.comparison' "$REPORT_PATH")"
    VERDICT_SUMMARY_REPEAT_2_JSON="$(jq -c '.comparison' "$REPORT_PATH_REPEAT_2")"
    if [ "$ACTUAL_REPORT_PROJECTION_JSON" != "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" ]; then
        STATUS="repeat_mismatch"
        MESSAGE="repeated run projection mismatch"
        VALIDATION_PASSED=false
    elif [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ]; then
        MESSAGE="report projection emitted for contract freeze"
    elif [ "$ACTUAL_REPORT_PROJECTION_JSON" != "$EXPECTED_REPORT_PROJECTION_JSON" ]; then
        STATUS="projection_mismatch"
        MESSAGE="first run projection diverged from the contract"
        VALIDATION_PASSED=false
    elif [ "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" != "$EXPECTED_REPORT_PROJECTION_JSON" ]; then
        STATUS="projection_mismatch"
        MESSAGE="second run projection diverged from the contract"
        VALIDATION_PASSED=false
    elif [ "$RUN1_EARLY_SUCCESS" -eq 1 ] || [ "$RUN2_EARLY_SUCCESS" -eq 1 ]; then
        MESSAGE="report projection matched the contract after marker completion"
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT_EXIT_CODE=0
if [ "$VALIDATION_PASSED" != true ]; then
    SCRIPT_EXIT_CODE=1
fi

write_bundle_manifest \
    "$BUNDLE_MANIFEST_PATH" \
    "$COMMAND_STRING" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$STARTED_TS" \
    "$ENDED_TS"

write_run_report \
    "$RUN_REPORT_PATH" \
    "$BUNDLE_MANIFEST_PATH" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

cat "$RUN_REPORT_PATH"

if [ "$SCRIPT_EXIT_CODE" -ne 0 ]; then
    exit "$SCRIPT_EXIT_CODE"
fi
