#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/unified_admission_brownout_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${UNIFIED_ADMISSION_BROWNOUT_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${UNIFIED_ADMISSION_BROWNOUT_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${UNIFIED_ADMISSION_BROWNOUT_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_unified_admission_brownout_smoke.sh [options]

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
        /UNIFIED_ADMISSION_BROWNOUT_REPORT_JSON_BEGIN/ { capture=1; next }
        /UNIFIED_ADMISSION_BROWNOUT_REPORT_JSON_END/ { capture=0; exit }
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
WORKLOAD_SEED="$(jq -r '.workload_seed' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-$(jq -r '.output_root' <<<"$SCENARIO_JSON")}"
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.unified-admission-brownout-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
SCENARIO_REPORT_PATH="${ARTIFACT_ROOT}/unified_admission_brownout_report.json"

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
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_unified_admission_brownout"
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_CONTRACT_PATH=${ARTIFACT}"
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_SCENARIO=${SCENARIO}"
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_REPORT_PATH=${SCENARIO_REPORT_PATH}"
    cargo
    test
    -p
    asupersync
    --test
    unified_admission_brownout_contract
    unified_admission_brownout_smoke_contract_emits_report
    --features
    test-internals
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
    set +e
    "${COMMAND_ARGS[@]}" >"$RUN_LOG_PATH" 2>&1
    COMMAND_EXIT_CODE=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH"; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    elif [ "$COMMAND_EXIT_CODE" -ne 0 ]; then
        SCRIPT_EXIT_CODE="$COMMAND_EXIT_CODE"
        STATUS="failed"
        MESSAGE="rch proof command failed"
    else
        if ! extract_report_from_log "$RUN_LOG_PATH" "$SCENARIO_REPORT_PATH"; then
            SCRIPT_EXIT_CODE=1
            STATUS="failed"
            MESSAGE="unified admission/brownout report JSON markers missing from run.log"
        else
            ACTUAL_REPORT_PROJECTION_JSON="$(jq -c '.report_projection' "$SCENARIO_REPORT_PATH")"
            if [ "$EXPECTED_REPORT_PROJECTION_JSON" = "null" ] || jq -en \
                --argjson expected "$EXPECTED_REPORT_PROJECTION_JSON" \
                --argjson actual "$ACTUAL_REPORT_PROJECTION_JSON" \
                '$expected == $actual' >/dev/null; then
                VALIDATION_PASSED=true
                MESSAGE="report projection matched the contract"
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
    --arg schema_version "unified-admission-brownout-smoke-bundle-v1" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg scenario_id "$SCENARIO" \
    --arg description "$DESCRIPTION" \
    --arg workload_seed "$WORKLOAD_SEED" \
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
        workload_seed: ($workload_seed | tonumber),
        mode: $mode,
        started_at: $started_at,
        ended_at: $ended_at,
        host_fingerprint: $host_fingerprint,
        report_artifact_path: $report_path
    }' >"$BUNDLE_MANIFEST_PATH"

jq -n \
    --arg schema_version "unified-admission-brownout-smoke-run-report-v1" \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg run_id "$RUN_ID" \
    --arg command "$COMMAND" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg bundle_manifest_path "$BUNDLE_MANIFEST_PATH" \
    --arg report_artifact_path "$SCENARIO_REPORT_PATH" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
    --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
    '{
        schema_version: $schema_version,
        status: $status,
        message: $message,
        scenario_id: $scenario_id,
        mode: $mode,
        run_id: $run_id,
        command_exit_code: $command_exit_code,
        script_exit_code: $script_exit_code,
        validation_passed: $validation_passed,
        command: $command,
        replay_command: $command,
        run_log_path: $run_log_path,
        bundle_manifest_path: $bundle_manifest_path,
        report_artifact_path: $report_artifact_path,
        expected_report_projection: $expected_report_projection,
        actual_report_projection: $actual_report_projection,
        policy_phase_sequence: ($actual_report_projection.policy_phase_sequence // []),
        reason_code_sequence: ($actual_report_projection.reason_code_sequence // []),
        admitted_units: ($actual_report_projection.admitted_units // 0),
        refused_units: ($actual_report_projection.refused_units // 0),
        preserved_telemetry_units: ($actual_report_projection.preserved_telemetry_units // 0),
        restoration_trigger_windows: ($actual_report_projection.restored_windows // []),
        fallback_reasons: ($actual_report_projection.fallback_reasons // []),
        no_win_decision_count: ($actual_report_projection.no_win_decision_count // 0)
    }' >"$RUN_REPORT_PATH"

echo "Unified admission/brownout smoke ${STATUS}: ${SCENARIO}"
echo "  run_report=${RUN_REPORT_PATH}"
echo "  bundle_manifest=${BUNDLE_MANIFEST_PATH}"
echo "  report_artifact=${SCENARIO_REPORT_PATH}"
echo "  replay_command=${COMMAND}"

exit "$SCRIPT_EXIT_CODE"
