#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/cohort_admission_steering_smoke_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${COHORT_ADMISSION_STEERING_SMOKE_OUTPUT_DIR:-}"
ARTIFACT_ROOT_OVERRIDE="${COHORT_ADMISSION_STEERING_SMOKE_ARTIFACT_ROOT:-}"
RUN_ID_OVERRIDE="${COHORT_ADMISSION_STEERING_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_cohort_admission_steering_smoke.sh [options]

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
        /COHORT_ADMISSION_STEERING_REPORT_JSON_BEGIN/ { capture=1; next }
        /COHORT_ADMISSION_STEERING_REPORT_JSON_END/ { capture=0; exit }
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
FIXTURE_JSON="$(jq -c '.fixture' <<<"$SCENARIO_JSON")"
STEERING_PROFILE_JSON="$(jq -c '.steering_profile' <<<"$SCENARIO_JSON")"
EXPECTED_REPORT_PROJECTION_JSON="$(jq -c '.expected_report_projection' <<<"$SCENARIO_JSON")"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-$(jq -r '.output_root' <<<"$SCENARIO_JSON")}"

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date +%Y%m%d_%H%M%S)"
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${ARTIFACT_ROOT_OVERRIDE:-${PROJECT_ROOT}/.cohort-admission-steering-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
BUNDLE_MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
SCENARIO_REPORT_PATH="${ARTIFACT_ROOT}/cohort_admission_steering_report.json"

mkdir -p "$RUN_DIR"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf -v RCH_INVOCATION '%q' "$RCH_BIN"
COMMAND="${RCH_INVOCATION} exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_cohort_admission_steering ASUPERSYNC_COHORT_ADMISSION_STEERING_CONTRACT_PATH=${ARTIFACT} ASUPERSYNC_COHORT_ADMISSION_STEERING_SCENARIO=${SCENARIO} ASUPERSYNC_COHORT_ADMISSION_STEERING_REPORT_PATH=${SCENARIO_REPORT_PATH} cargo test -p asupersync --test cohort_admission_steering_contract cohort_admission_steering_smoke_contract_emits_report --features test-internals -- --nocapture"

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
    eval "$COMMAND" >"$RUN_LOG_PATH" 2>&1
    COMMAND_EXIT_CODE=$?
    set -e

    if [ "$COMMAND_EXIT_CODE" -ne 0 ]; then
        SCRIPT_EXIT_CODE=$COMMAND_EXIT_CODE
        STATUS="failed"
        MESSAGE="rch proof command failed"
    elif grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    else
        if ! extract_report_from_log "$RUN_LOG_PATH" "$SCENARIO_REPORT_PATH"; then
            SCRIPT_EXIT_CODE=1
            STATUS="failed"
            MESSAGE="cohort steering report JSON markers missing from run.log"
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
    if [ "$COMMAND_EXIT_CODE" -ne 86 ] \
        && grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg schema_version "$(artifact_value '.runner_bundle_schema_version')" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg scenario_id "$SCENARIO" \
    --arg description "$DESCRIPTION" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg artifact_path "$BUNDLE_MANIFEST_PATH" \
    --arg report_path "$SCENARIO_REPORT_PATH" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg command "$COMMAND" \
    --argjson workload_seed "$WORKLOAD_SEED" \
    --argjson fixture "$FIXTURE_JSON" \
    --argjson steering_profile "$STEERING_PROFILE_JSON" \
    --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
    --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
    --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --arg status "$STATUS" \
    --arg started_ts "$STARTED_TS" \
    --arg ended_ts "$ENDED_TS" \
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
        workload_seed: $workload_seed,
        fixture: $fixture,
        steering_profile: $steering_profile,
        host_fingerprint: $host_fingerprint,
        expected_report_projection: $expected_report_projection,
        actual_report_projection: $actual_report_projection,
        command_exit_code: $command_exit_code,
        script_exit_code: $script_exit_code,
        validation_passed: $validation_passed,
        status: $status,
        started_ts: $started_ts,
        ended_ts: $ended_ts
    }' >"$BUNDLE_MANIFEST_PATH"

jq -n \
    --arg schema_version "$(artifact_value '.runner_report_schema_version')" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg artifact_path "$RUN_REPORT_PATH" \
    --arg bundle_manifest_path "$BUNDLE_MANIFEST_PATH" \
    --arg run_id "$RUN_ID" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --arg command "$COMMAND" \
    --arg report_path "$SCENARIO_REPORT_PATH" \
    --argjson workload_seed "$WORKLOAD_SEED" \
    --argjson fixture "$FIXTURE_JSON" \
    --argjson steering_profile "$STEERING_PROFILE_JSON" \
    --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
    --argjson expected_report_projection "$EXPECTED_REPORT_PROJECTION_JSON" \
    --argjson actual_report_projection "$ACTUAL_REPORT_PROJECTION_JSON" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson validation_passed "$VALIDATION_PASSED" \
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
        workload_seed: $workload_seed,
        fixture: $fixture,
        steering_profile: $steering_profile,
        host_fingerprint: $host_fingerprint,
        report_path: $report_path,
        expected_report_projection: $expected_report_projection,
        actual_report_projection: $actual_report_projection
    }' >"$RUN_REPORT_PATH"

echo ""
echo "==================================================================="
echo "   COHORT ADMISSION STEERING SMOKE SUMMARY                         "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Mode:      $([ "$MODE" = "dry-run" ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $STATUS"
echo "==================================================================="

exit "$SCRIPT_EXIT_CODE"
