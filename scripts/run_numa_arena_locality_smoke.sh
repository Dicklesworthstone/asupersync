#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/numa_arena_locality_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${NUMA_ARENA_LOCALITY_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${NUMA_ARENA_LOCALITY_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${NUMA_ARENA_LOCALITY_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_numa_arena_locality_smoke.sh [options]

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
    local host os kernel_release arch cpu_threads mem_total_kib numa_nodes
    host="$(hostname 2>/dev/null || printf 'unknown')"
    os="$(uname -s 2>/dev/null || printf 'unknown')"
    kernel_release="$(uname -r 2>/dev/null || printf 'unknown')"
    arch="$(uname -m 2>/dev/null || printf 'unknown')"
    cpu_threads="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '0')"
    mem_total_kib="$(awk '/MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || printf '0')"
    numa_nodes="$(find /sys/devices/system/node -maxdepth 1 -type d -name 'node*' 2>/dev/null | wc -l | tr -d ' ')"

    jq -nc \
        --arg hostname "$host" \
        --arg os "$os" \
        --arg kernel_release "$kernel_release" \
        --arg arch "$arch" \
        --argjson cpu_threads "${cpu_threads:-0}" \
        --argjson mem_total_kib "${mem_total_kib:-0}" \
        --argjson numa_nodes "${numa_nodes:-0}" \
        '{
            hostname: $hostname,
            os: $os,
            kernel_release: $kernel_release,
            arch: $arch,
            cpu_threads: $cpu_threads,
            mem_total_kib: $mem_total_kib,
            numa_nodes: $numa_nodes
        }'
}

extract_report_from_log() {
    local log_path="$1"
    local output_path="$2"
    mkdir -p "$(dirname "$output_path")"
    awk '
        /NUMA_ARENA_LOCALITY_REPORT_JSON_BEGIN/ { armed=1; next }
        /NUMA_ARENA_LOCALITY_REPORT_JSON_END/ { capture=0; exit }
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
    local target_dir="${TMPDIR:-/tmp}/rch_target_numa_arena_locality_${run_label}"
    local tail_timeout_seconds="${NUMA_ARENA_LOCALITY_RCH_TIMEOUT_SECONDS:-300}"
    local poll_seconds=0
    local command_exit_code=-1
    local -a command_args=(
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=-D warnings -C debuginfo=0"
        "CARGO_TARGET_DIR=${target_dir}"
        "ASUPERSYNC_NUMA_ARENA_LOCALITY_CONTRACT_PATH=${ARTIFACT}"
        "ASUPERSYNC_NUMA_ARENA_LOCALITY_SCENARIO=${SCENARIO}"
        "ASUPERSYNC_NUMA_ARENA_LOCALITY_REPORT_PATH=${report_path}"
        cargo
        test
        -p
        asupersync
        --test
        numa_arena_locality_contract
        numa_arena_locality_smoke_contract_emits_report
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
        if grep -q 'NUMA_ARENA_LOCALITY_REPORT_JSON_END' "$log_path" 2>/dev/null \
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
        if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
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
            printf 'FATAL: timed out waiting for NUMA arena locality proof markers\n' >>"$log_path"
            break
        fi
    done

    if [ "$command_exit_code" -eq -1 ]; then
        set +e
        wait "$command_pid"
        command_exit_code=$?
        set -e
    fi

    if [ "$command_exit_code" -ne 86 ] && grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
        command_exit_code=86
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_path"
    fi

    if [ ! -s "$report_path" ]; then
        extract_report_from_log "$log_path" "$report_path" || true
    fi

    if [ "$command_exit_code" -eq 124 ] \
        && grep -q 'NUMA_ARENA_LOCALITY_REPORT_JSON_END' "$log_path" 2>/dev/null \
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
RUN_ID="${RUN_ID_OVERRIDE:-$(date -u +%Y%m%d_%H%M%S)}"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/target/numa-arena-locality-smoke}"
SCENARIO_OUTPUT_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.numa-arena-locality-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
REPORT_PATH="${ARTIFACT_ROOT}/numa_arena_locality_report.json"
REPORT_PATH_REPEAT_2="${ARTIFACT_ROOT}/numa_arena_locality_report_repeat_2.json"
RUN_LOG_PATH="${SCENARIO_OUTPUT_DIR}/run.log"
RUN_LOG_PATH_REPEAT_2="${SCENARIO_OUTPUT_DIR}/run_repeat_2.log"
BUNDLE_MANIFEST_PATH="${SCENARIO_OUTPUT_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${SCENARIO_OUTPUT_DIR}/run_report.json"

mkdir -p "$SCENARIO_OUTPUT_DIR" "$ARTIFACT_ROOT"

ACTUAL_REPORT_PROJECTION_JSON='null'
ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON='null'
SCRIPT_EXIT_CODE=0
COMMAND_EXIT_CODE=0
VALIDATION_PASSED=false
STATUS="dry_run_only"
MESSAGE="dry-run manifest emitted without executing the NUMA arena locality proof"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$MODE" = "dry-run" ]; then
    ACTUAL_REPORT_PROJECTION_JSON="$EXPECTED_REPORT_PROJECTION_JSON"
    ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON="$EXPECTED_REPORT_PROJECTION_JSON"
    VALIDATION_PASSED=true
else
    if run_once "primary" "$REPORT_PATH" "$RUN_LOG_PATH"; then
        COMMAND_EXIT_CODE=0
    else
        COMMAND_EXIT_CODE=$?
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ] && [ -s "$REPORT_PATH" ]; then
        ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$REPORT_PATH")"
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ]; then
        if run_once "repeat2" "$REPORT_PATH_REPEAT_2" "$RUN_LOG_PATH_REPEAT_2"; then
            :
        else
            COMMAND_EXIT_CODE=$?
        fi
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ] && [ -s "$REPORT_PATH_REPEAT_2" ]; then
        ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON="$(jq -c '.report_projection' "$REPORT_PATH_REPEAT_2")"
    fi

    if [ "$COMMAND_EXIT_CODE" -eq 0 ] && [ "$ACTUAL_REPORT_PROJECTION_JSON" = "$ACTUAL_REPORT_PROJECTION_REPEAT_2_JSON" ]; then
        if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ] || [ "$ACTUAL_REPORT_PROJECTION_JSON" = "$EXPECTED_REPORT_PROJECTION_JSON" ]; then
            VALIDATION_PASSED=true
            STATUS="passed"
            MESSAGE="NUMA arena locality proof passed and emitted a stable repeated projection"
        else
            SCRIPT_EXIT_CODE=1
            STATUS="projection_mismatch"
            MESSAGE="NUMA arena locality projection diverged from the contract"
        fi
    elif [ "$COMMAND_EXIT_CODE" -eq 0 ]; then
        SCRIPT_EXIT_CODE=1
        STATUS="repeat_mismatch"
        MESSAGE="NUMA arena locality repeated projection drifted across execute runs"
    else
        SCRIPT_EXIT_CODE="$COMMAND_EXIT_CODE"
        STATUS="command_failed"
        MESSAGE="NUMA arena locality proof command failed"
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_bundle_manifest \
    "$BUNDLE_MANIFEST_PATH" \
    "${RCH_BIN} exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_numa_arena_locality_<run> ASUPERSYNC_NUMA_ARENA_LOCALITY_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_NUMA_ARENA_LOCALITY_SCENARIO=${SCENARIO} ASUPERSYNC_NUMA_ARENA_LOCALITY_REPORT_PATH=<report> cargo test -p asupersync --test numa_arena_locality_contract numa_arena_locality_smoke_contract_emits_report --features test-internals -- --nocapture" \
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

if [ "$SCRIPT_EXIT_CODE" -ne 0 ]; then
    echo "FATAL: ${MESSAGE}" >&2
    exit "$SCRIPT_EXIT_CODE"
fi

printf 'numa arena locality smoke: %s (%s)\n' "$SCENARIO" "$STATUS"
