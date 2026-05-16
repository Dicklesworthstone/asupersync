#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SCENARIO="RM-PLATFORM-GAP-HOST-TEMPLATE"
MODE="execute"
LIST_ONLY=0
OUTPUT_ROOT_OVERRIDE="${RESOURCE_MONITOR_PLATFORM_GAP_SMOKE_OUTPUT_DIR:-}"
RUN_ID_OVERRIDE="${RESOURCE_MONITOR_PLATFORM_GAP_SMOKE_RUN_ID:-}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_resource_monitor_platform_gap_smoke.sh [options]

Options:
  --list                  List scenario IDs and exit
  --scenario <id>         Run one scenario (only RM-PLATFORM-GAP-HOST-TEMPLATE)
  --output-root <dir>     Override output root
  --dry-run               Emit manifests without executing the rch proof
  --execute               Execute the rch proof (default)
  -h, --help              Show help
USAGE
}

require_tools() {
    local missing=0
    for tool in awk date jq timeout uname; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
}

list_scenarios() {
    printf '%s\t%s\n' \
        "RM-PLATFORM-GAP-HOST-TEMPLATE" \
        "Host-template resource monitor probe report with supported, unavailable, fallback, sampled, error, and verdict fields"
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
    mkdir -p "$(dirname "$output_path")"
    awk '
        /RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_BEGIN/ { capture=1; next }
        /RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_END/ { capture=0; exit }
        capture { print }
    ' "$log_path" >"$output_path"
    [ -s "$output_path" ]
}

validate_report() {
    local report_path="$1"
    jq -e '
        .schema_version == "asupersync.resource-monitor-platform-gaps.v1"
        and (.platform_fingerprint | type == "string")
        and (.probe_list | length >= 4)
        and .supported_count >= 1
        and .unavailable_count >= 1
        and .fallback_count >= 1
        and .disabled_count >= 1
        and (.sampled_values | length >= 1)
        and (.error_messages | length >= 1)
        and .final_operator_verdict == "degraded_with_unavailable_probes"
    ' "$report_path" >/dev/null
}

write_manifest() {
    local manifest_path="$1"
    local report_path="$2"
    local run_log_path="$3"
    local command="$4"
    local command_exit_code="$5"
    local script_exit_code="$6"
    local validation_passed="$7"
    local status="$8"
    local message="$9"

    jq -n \
        --arg schema_version "asupersync.resource-monitor-platform-gap-smoke-runner.v1" \
        --arg scenario_id "$SCENARIO" \
        --arg mode "$MODE" \
        --arg run_id "$RUN_ID" \
        --arg report_path "$report_path" \
        --arg run_log_path "$run_log_path" \
        --arg command "$command" \
        --arg status "$status" \
        --arg message "$message" \
        --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
        --argjson report_projection "$REPORT_PROJECTION_JSON" \
        --argjson command_exit_code "$command_exit_code" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson validation_passed "$validation_passed" \
        '{
            schema_version: $schema_version,
            scenario_id: $scenario_id,
            mode: $mode,
            run_id: $run_id,
            report_path: $report_path,
            run_log_path: $run_log_path,
            command: $command,
            command_exit_code: $command_exit_code,
            script_exit_code: $script_exit_code,
            validation_passed: $validation_passed,
            status: $status,
            message: $message,
            host_fingerprint: $host_fingerprint,
            report_projection: $report_projection
        }' >"$manifest_path"
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

if [ "$SCENARIO" != "RM-PLATFORM-GAP-HOST-TEMPLATE" ]; then
    echo "FATAL: unknown scenario: ${SCENARIO}" >&2
    exit 1
fi

if [ -n "$RUN_ID_OVERRIDE" ]; then
    RUN_ID="$RUN_ID_OVERRIDE"
else
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
fi

OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${PROJECT_ROOT}/target/resource-monitor-platform-gap-smoke}"
RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
ARTIFACT_ROOT="${RESOURCE_MONITOR_PLATFORM_GAP_SMOKE_ARTIFACT_ROOT:-${PROJECT_ROOT}/.resource-monitor-platform-gap-smoke-artifacts/run_${RUN_ID}/${SCENARIO}}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
REPORT_PATH="${ARTIFACT_ROOT}/resource_monitor_platform_gap_report.json"
MANIFEST_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
COMMAND_ARGS=(
    "$RCH_BIN"
    exec
    --
    env
    "CARGO_INCREMENTAL=0"
    "CARGO_PROFILE_TEST_DEBUG=0"
    "RUSTFLAGS=-D warnings -C debuginfo=0"
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_resource_monitor_platform_gap"
    "ASUPERSYNC_RESOURCE_MONITOR_PLATFORM_GAP_REPORT=1"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync
    --lib
    m4oxsk_resource_monitor_platform_gap_smoke_emits_operator_report
    --features
    test-internals
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"
RCH_TIMEOUT_SECONDS="${RESOURCE_MONITOR_PLATFORM_GAP_RCH_TIMEOUT_SECONDS:-900}"

mkdir -p "$RUN_DIR" "$ARTIFACT_ROOT"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
VALIDATION_PASSED=false
STATUS="passed"
MESSAGE="resource monitor platform gap smoke passed"
REPORT_PROJECTION_JSON="null"

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN scenario=%s\n' "$SCENARIO" >"$RUN_LOG_PATH"
    REPORT_PROJECTION_JSON="$(jq -nc '{
        platform_fingerprint: "dry-run",
        probe_count: 4,
        supported_count: 1,
        unavailable_count: 1,
        fallback_count: 1,
        disabled_count: 1,
        sampled_count: 1,
        error_count: 1,
        final_operator_verdict: "degraded_with_unavailable_probes"
    }')"
    VALIDATION_PASSED=true
    STATUS="dry_run"
    MESSAGE="dry run emitted host-template manifest"
else
    set +e
    (
        cd "$PROJECT_ROOT"
        timeout "${RCH_TIMEOUT_SECONDS}s" "${COMMAND_ARGS[@]}"
    ) >"$RUN_LOG_PATH" 2>&1
    COMMAND_EXIT_CODE=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    elif [ "$COMMAND_EXIT_CODE" -ne 0 ] \
        && ! grep -q 'Remote command finished: exit=0' "$RUN_LOG_PATH"; then
        SCRIPT_EXIT_CODE=$COMMAND_EXIT_CODE
        STATUS="failed"
        MESSAGE="rch proof command failed"
    elif ! extract_report_from_log "$RUN_LOG_PATH" "$REPORT_PATH"; then
        SCRIPT_EXIT_CODE=1
        STATUS="failed"
        MESSAGE="resource monitor platform gap report markers missing"
    elif ! validate_report "$REPORT_PATH"; then
        SCRIPT_EXIT_CODE=1
        STATUS="failed"
        MESSAGE="resource monitor platform gap report failed projection validation"
    else
        REPORT_PROJECTION_JSON="$(jq -c '{
            platform_fingerprint: .platform_fingerprint,
            probe_count: (.probe_list | length),
            supported_count,
            unavailable_count,
            fallback_count,
            disabled_count,
            sampled_count: (.sampled_values | length),
            error_count: (.error_messages | length),
            final_operator_verdict
        }' "$REPORT_PATH")"
        VALIDATION_PASSED=true
        if [ "$COMMAND_EXIT_CODE" -ne 0 ]; then
            MESSAGE="remote proof passed; local rch wrapper exited ${COMMAND_EXIT_CODE} after report capture"
        fi
    fi
fi

write_manifest \
    "$MANIFEST_PATH" \
    "$REPORT_PATH" \
    "$RUN_LOG_PATH" \
    "$COMMAND" \
    "$COMMAND_EXIT_CODE" \
    "$SCRIPT_EXIT_CODE" \
    "$VALIDATION_PASSED" \
    "$STATUS" \
    "$MESSAGE"

cp "$MANIFEST_PATH" "$RUN_REPORT_PATH"

printf 'platform_fingerprint=%s\n' "$(jq -r '.report_projection.platform_fingerprint // "not_collected"' "$MANIFEST_PATH")"
printf 'probe_count=%s\n' "$(jq -r '.report_projection.probe_count // 0' "$MANIFEST_PATH")"
printf 'supported_count=%s\n' "$(jq -r '.report_projection.supported_count // 0' "$MANIFEST_PATH")"
printf 'unavailable_count=%s\n' "$(jq -r '.report_projection.unavailable_count // 0' "$MANIFEST_PATH")"
printf 'fallback_count=%s\n' "$(jq -r '.report_projection.fallback_count // 0' "$MANIFEST_PATH")"
printf 'sampled_count=%s\n' "$(jq -r '.report_projection.sampled_count // 0' "$MANIFEST_PATH")"
printf 'error_count=%s\n' "$(jq -r '.report_projection.error_count // 0' "$MANIFEST_PATH")"
printf 'final_operator_verdict=%s\n' "$(jq -r '.report_projection.final_operator_verdict // "unknown"' "$MANIFEST_PATH")"
printf 'run_report=%s\n' "$RUN_REPORT_PATH"

exit "$SCRIPT_EXIT_CODE"
