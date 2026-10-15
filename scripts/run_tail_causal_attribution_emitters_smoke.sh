#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_tail_latency_taxonomy_v1.json"
OUTPUT_ROOT="${TAIL_CAUSAL_ATTRIBUTION_OUTPUT_ROOT:-${PROJECT_ROOT}/target/tail-causal-attribution-smoke}"
RUN_ID="${TAIL_CAUSAL_ATTRIBUTION_RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
MODE="execute"
LIST_ONLY=0
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900s}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_tail_causal_attribution_emitters_smoke.sh [options]

Options:
  --list                  List compact emitter smoke scenarios and exit
  --dry-run               Emit manifests without running cargo
  --execute               Run the rch-backed Rust smoke proof (default)
  --output-root <dir>     Override output root
  --run-id <id>           Stable run directory name
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for tail-causal attribution smoke runner" >&2
        exit 1
    fi
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
        exit 1
    fi
}

require_execute_tools() {
    local missing=0
    for tool in timeout; do
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
        exit 2
    fi
}

artifact_value() {
    jq -r "$1" "$ARTIFACT"
}

list_scenarios() {
    jq -r '.compact_tail_emitter.smoke_scenarios[] | "  \(.scenario_id) / \(.event_id): \(.description)"' "$ARTIFACT"
}

json_string_array() {
    jq -c "$1" "$ARTIFACT"
}

extract_report_from_log() {
    local log_path="$1"
    local report_path="$2"
    awk '
        /TAIL_CAUSAL_ATTRIBUTION_REPORT_JSON_BEGIN/ { capture=1; next }
        /TAIL_CAUSAL_ATTRIBUTION_REPORT_JSON_END/ { capture=0; exit }
        capture { print }
    ' "$log_path" >"$report_path"
    [ -s "$report_path" ]
}

validate_smoke_report() {
    local report_path="$1"
    jq -e '
        .schema_version == "tail-causal-attribution-smoke-report-v1"
        and .bead_id == "asupersync-d87ytw.5"
        and .status == "passed"
        and (.rows | length) == 3
        and all(.rows[]; has("scenario_id") and has("event_id") and has("taxonomy_version") and has("compact_fields") and has("residual_unknown_ns") and has("overhead_estimate_bytes") and has("verdict"))
    ' "$report_path" >/dev/null
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
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
require_execute_tools

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
SMOKE_REPORT_PATH="${RUN_DIR}/tail_causal_attribution_report.json"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
mkdir -p "$RUN_DIR"

STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Contract marker for tests: rch exec -- env CARGO_INCREMENTAL=0
COMMAND_ARGS=(
    timeout
    "$RCH_WRAPPER_TIMEOUT"
    "$RCH_BIN"
    exec
    --
    env
    "CARGO_INCREMENTAL=0"
    "CARGO_PROFILE_TEST_DEBUG=0"
    "RUSTFLAGS=-D warnings -C debuginfo=0"
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tail_causal_attribution_emitters"
    "ASUPERSYNC_TAIL_CAUSAL_ATTRIBUTION_REPORT_PATH=${SMOKE_REPORT_PATH}"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync
    --test
    runtime_tail_latency_taxonomy_contract
    compact_tail_causal_attribution_smoke_emits_report
    --features
    test-internals
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"

STATUS="$(if [ "$MODE" = "execute" ]; then echo passed; else echo dry_run; fi)"
VALIDATION_PASSED=true
COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
MESSAGE="compact tail-causal attribution smoke completed"

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN command=%s\n' "$COMMAND" >"$RUN_LOG_PATH"
else
    set +e
    (
        cd "$PROJECT_ROOT"
        "${COMMAND_ARGS[@]}"
    ) >"$RUN_LOG_PATH" 2>&1
    COMMAND_EXIT_CODE=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH"; then
        STATUS="failed"
        VALIDATION_PASSED=false
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    elif [ "$COMMAND_EXIT_CODE" -ne 0 ]; then
        if extract_report_from_log "$RUN_LOG_PATH" "$SMOKE_REPORT_PATH" && validate_smoke_report "$SMOKE_REPORT_PATH"; then
            STATUS="passed"
            VALIDATION_PASSED=true
            MESSAGE="validated report markers from run log after rch wrapper nonzero exit"
        else
            STATUS="failed"
            VALIDATION_PASSED=false
            SCRIPT_EXIT_CODE="$COMMAND_EXIT_CODE"
            MESSAGE="rch proof command failed before a valid smoke report was emitted"
        fi
    elif [ ! -f "$SMOKE_REPORT_PATH" ] && ! extract_report_from_log "$RUN_LOG_PATH" "$SMOKE_REPORT_PATH"; then
        STATUS="failed"
        VALIDATION_PASSED=false
        COMMAND_EXIT_CODE=1
        SCRIPT_EXIT_CODE=1
        MESSAGE="smoke report markers missing from run log"
    elif ! validate_smoke_report "$SMOKE_REPORT_PATH"; then
        STATUS="failed"
        VALIDATION_PASSED=false
        COMMAND_EXIT_CODE=1
        SCRIPT_EXIT_CODE=1
        MESSAGE="smoke report missing required detailed logging fields"
    fi
fi

if [ "$STATUS" = "failed" ] && [ "$SCRIPT_EXIT_CODE" -eq 0 ]; then
    SCRIPT_EXIT_CODE=1
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg schema_version "tail-causal-attribution-run-report-v1" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg event_schema_version "$(artifact_value '.compact_tail_emitter.event_schema_version')" \
    --arg smoke_report_schema_version "$(artifact_value '.compact_tail_emitter.smoke_report_schema_version')" \
    --arg bead_id "$(artifact_value '.compact_tail_emitter.bead_id')" \
    --arg mode "$MODE" \
    --arg run_id "$RUN_ID" \
    --arg run_dir "$RUN_DIR" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg smoke_report_path "$SMOKE_REPORT_PATH" \
    --arg command "$COMMAND" \
    --arg rch_wrapper_timeout "$RCH_WRAPPER_TIMEOUT" \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --arg started_ts "$STARTED_TS" \
    --arg ended_ts "$ENDED_TS" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --argjson command_exit_code "$COMMAND_EXIT_CODE" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson compact_core_keys "$(json_string_array '.compact_tail_emitter.compact_core_keys')" \
    --argjson smoke_scenarios "$(json_string_array '.compact_tail_emitter.smoke_scenarios')" \
    '{
        schema_version: $schema_version,
        contract_version: $contract_version,
        event_schema_version: $event_schema_version,
        smoke_report_schema_version: $smoke_report_schema_version,
        bead_id: $bead_id,
        mode: $mode,
        run_id: $run_id,
        run_dir: $run_dir,
        run_log_path: $run_log_path,
        smoke_report_path: $smoke_report_path,
        command: $command,
        rch_wrapper_timeout: $rch_wrapper_timeout,
        command_exit_code: $command_exit_code,
        script_exit_code: $script_exit_code,
        validation_passed: $validation_passed,
        compact_core_keys: $compact_core_keys,
        smoke_scenarios: $smoke_scenarios,
        status: $status,
        message: $message,
        started_ts: $started_ts,
        ended_ts: $ended_ts
    }' >"$RUN_REPORT_PATH"

echo "TAIL_CAUSAL_ATTRIBUTION_SMOKE_SUMMARY"
echo "  run_dir=${RUN_DIR}"
echo "  mode=${MODE}"
echo "  status=${STATUS}"
echo "  run_report=${RUN_REPORT_PATH}"
echo "  smoke_report=${SMOKE_REPORT_PATH}"

if [ "$STATUS" != "passed" ]; then
    if [ "$STATUS" != "dry_run" ]; then
        exit "$SCRIPT_EXIT_CODE"
    fi
fi
