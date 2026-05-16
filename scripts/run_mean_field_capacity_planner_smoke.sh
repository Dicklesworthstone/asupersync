#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/mean_field_capacity_planner_smoke_contract_v1.json"
OUTPUT_ROOT="${MEAN_FIELD_CAPACITY_PLANNER_OUTPUT_ROOT:-${PROJECT_ROOT}/target/mean-field-capacity-planner-smoke}"
SCENARIO="AA-MEAN-FIELD-CAPACITY-PLANNER-64C-256G"
RUN_ID="${MEAN_FIELD_CAPACITY_PLANNER_RUN_ID:-manual}"
MODE="dry-run"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_mean_field_capacity_planner_smoke.sh [options]

Options:
  --list                  List smoke scenarios and exit.
  --dry-run               Emit command and run report without executing rch (default).
  --execute               Execute the focused rch-backed smoke proof.
  --scenario <id>         Select scenario id.
  --output-root <path>    Override output root.
  --run-id <id>           Override run id.
USAGE
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for mean-field capacity planner smoke runner" >&2
        exit 2
    fi
}

require_rch() {
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        exit 2
    fi
}

json_escape() {
    jq -Rn --arg value "$1" '$value'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            require_jq
            jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.expected_verdict)"' "$ARTIFACT"
            exit 0
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --scenario)
            SCENARIO="${2:?missing scenario id}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:?missing output root}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:?missing run id}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_jq

if ! jq -e --arg scenario "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $scenario)' "$ARTIFACT" >/dev/null; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 2
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
REPORT_PATH="${RUN_DIR}/mean_field_capacity_planner_report.json"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_JSON_MARKER="ASUPERSYNC_MEAN_FIELD_CAPACITY_PLANNER_REPORT_JSON="
mkdir -p "$RUN_DIR"

PROOF_COMMAND=(
    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_mean_field_capacity_planner" "ASUPERSYNC_MEAN_FIELD_CAPACITY_PLANNER_REPORT_PATH=${REPORT_PATH}"
    "${CARGO_BIN:-cargo}" test -p asupersync --test mean_field_capacity_planner_contract mean_field_capacity_planner_smoke_emits_report --features test-internals -- --nocapture
)
RCH_COMMAND=("${RCH_BIN}" exec -- "${PROOF_COMMAND[@]}")
RUN_COMMAND=(timeout "${RCH_WRAPPER_TIMEOUT}" "${RCH_COMMAND[@]}")
printf -v COMMAND '%q ' "${RUN_COMMAND[@]}"
COMMAND="${COMMAND% }"
COMMAND_STATUS=0
REMOTE_TEST_PASSED=false
REPORT_SOURCE="not_run"
VALIDATION_PASSED=false

{
    printf 'MEAN_FIELD_CAPACITY_PLANNER scenario_id=%s mode=%s report_path=%s\n' "$SCENARIO" "$MODE" "$REPORT_PATH"
    printf 'MEAN_FIELD_CAPACITY_PLANNER command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    require_rch
    set +e
    (
        cd "$PROJECT_ROOT"
        "${RUN_COMMAND[@]}"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

    if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RUN_LOG_PATH"; then
        COMMAND_STATUS=86
        echo "FATAL: rch local fallback detected; refusing local cargo execution" >>"$RUN_LOG_PATH"
        exit "$COMMAND_STATUS"
    fi

    if grep -q 'test result: ok. 1 passed' "$RUN_LOG_PATH"; then
        REMOTE_TEST_PASSED=true
    fi

    if [[ -s "$REPORT_PATH" ]]; then
        REPORT_SOURCE="retrieved"
    else
        REPORT_JSON_LINE="$(grep -a "^${REPORT_JSON_MARKER}" "$RUN_LOG_PATH" | tail -n 1 || true)"
        if [[ -n "$REPORT_JSON_LINE" ]]; then
            printf '%s\n' "${REPORT_JSON_LINE#"$REPORT_JSON_MARKER"}" >"$REPORT_PATH"
            REPORT_SOURCE="reconstructed_from_log"
        else
            REPORT_SOURCE="missing"
        fi
    fi

    if [[ "$COMMAND_STATUS" -ne 0 && "$REMOTE_TEST_PASSED" != "true" ]]; then
        echo "FATAL: mean-field capacity planner command failed with status ${COMMAND_STATUS}" >>"$RUN_LOG_PATH"
        exit "$COMMAND_STATUS"
    fi
    if [[ ! -s "$REPORT_PATH" ]]; then
        echo "FATAL: mean-field capacity planner report missing after ${REPORT_SOURCE}" >>"$RUN_LOG_PATH"
        exit 1
    fi

    jq -e --arg scenario "$SCENARIO" '
        .schema_version == "mean-field-capacity-planner-report-v1"
        and .scenario_id == $scenario
        and .verdict == "recommended"
        and .host_fingerprint_class == "cpu_64_plus_mem_256_plus"
        and (.certificate_refs | length >= 2)
        and (.controller_settings | any(.controller == "arena_capacity"))
        and (.replay_command | contains("rch exec"))
    ' "$REPORT_PATH" >/dev/null
    VALIDATION_PASSED=true
else
    VALIDATION_PASSED=true
fi

jq -n \
    --arg schema_version "mean-field-capacity-planner-run-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg status "$(if [[ "$MODE" == "execute" ]]; then echo passed; else echo dry_run; fi)" \
    --arg command "$COMMAND" \
    --arg command_status "$COMMAND_STATUS" \
    --arg remote_test_passed "$REMOTE_TEST_PASSED" \
    --arg report_source "$REPORT_SOURCE" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg report_path "$REPORT_PATH" \
    --arg validation_passed "$VALIDATION_PASSED" \
    '{
        schema_version: $schema_version,
        scenario_id: $scenario_id,
        mode: $mode,
        status: $status,
        command: $command,
        command_status: ($command_status | tonumber),
        remote_test_passed: ($remote_test_passed == "true"),
        report_source: $report_source,
        validation_passed: ($validation_passed == "true"),
        run_log_path: $run_log_path,
        report_path: $report_path
    }' >"$RUN_REPORT_PATH"

printf 'MEAN_FIELD_CAPACITY_PLANNER_RUN scenario_id=%s status=%s report=%s run_report=%s\n' \
    "$SCENARIO" "$(jq -r '.status' "$RUN_REPORT_PATH")" "$REPORT_PATH" "$RUN_REPORT_PATH"
