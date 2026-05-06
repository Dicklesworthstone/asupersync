#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/controller_provenance_dashboard_contract_v1.json"
OUTPUT_ROOT="${CONTROLLER_PROVENANCE_DASHBOARD_OUTPUT_ROOT:-${PROJECT_ROOT}/target/controller-provenance-dashboard-smoke}"
SCENARIO="AA-CONTROLLER-PROVENANCE-DASHBOARD-64C-256G"
RUN_ID="${CONTROLLER_PROVENANCE_DASHBOARD_RUN_ID:-manual}"
MODE="dry-run"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_controller_provenance_dashboard_smoke.sh [options]

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
        echo "FATAL: jq is required for controller provenance dashboard smoke runner" >&2
        exit 2
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
    if [[ "$missing" -ne 0 ]]; then
        exit 2
    fi
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
if [[ ! -f "$ARTIFACT" ]]; then
    echo "FATAL: contract artifact missing at ${ARTIFACT}" >&2
    exit 2
fi
if [[ "$MODE" == "execute" || "$MODE" == "dry-run" ]]; then
    require_execute_tools
fi

if ! jq -e --arg scenario "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $scenario)' "$ARTIFACT" >/dev/null; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 2
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
REPORT_PATH="${RUN_DIR}/controller_provenance_dashboard.json"
MARKDOWN_PATH="${RUN_DIR}/controller_provenance_dashboard.md"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_JSON_MARKER="ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_JSON="
mkdir -p "$RUN_DIR"

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
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_controller_provenance_dashboard"
    "ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_REPORT_PATH=${REPORT_PATH}"
    "ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_MARKDOWN_PATH=${MARKDOWN_PATH}"
    cargo
    test
    -p
    asupersync
    --test
    controller_provenance_dashboard_contract
    controller_provenance_dashboard_smoke_emits_report
    --features
    test-internals
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"
COMMAND_STATUS=0
SCRIPT_EXIT_CODE=0
REMOTE_TEST_PASSED=false
REPORT_SOURCE="not_run"
STATUS="$(if [[ "$MODE" == "execute" ]]; then echo passed; else echo dry_run; fi)"
MESSAGE="controller provenance dashboard runner completed"

{
    printf 'CONTROLLER_PROVENANCE_DASHBOARD scenario_id=%s mode=%s report_path=%s markdown_path=%s\n' "$SCENARIO" "$MODE" "$REPORT_PATH" "$MARKDOWN_PATH"
    printf 'CONTROLLER_PROVENANCE_DASHBOARD command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    set +e
    (
        cd "$PROJECT_ROOT"
        "${COMMAND_ARGS[@]}"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH"; then
        COMMAND_STATUS=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        MESSAGE="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$RUN_LOG_PATH"
    fi

    if grep -q 'test result: ok. 1 passed' "$RUN_LOG_PATH"; then
        REMOTE_TEST_PASSED=true
    fi

    if [[ "$STATUS" == "failed" ]]; then
        REPORT_SOURCE="not_validated"
    elif [[ -s "$REPORT_PATH" ]]; then
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

    if [[ "$STATUS" != "failed" && "$COMMAND_STATUS" -ne 0 && "$REMOTE_TEST_PASSED" != "true" ]]; then
        STATUS="failed"
        SCRIPT_EXIT_CODE="$COMMAND_STATUS"
        MESSAGE="controller provenance dashboard command failed with status ${COMMAND_STATUS}"
        echo "FATAL: ${MESSAGE}" >>"$RUN_LOG_PATH"
    fi
    if [[ "$STATUS" != "failed" && ! -s "$REPORT_PATH" ]]; then
        STATUS="failed"
        SCRIPT_EXIT_CODE=1
        MESSAGE="controller provenance dashboard report missing after ${REPORT_SOURCE}"
        echo "FATAL: ${MESSAGE}" >>"$RUN_LOG_PATH"
    fi
    if [[ "$STATUS" != "failed" && ! -s "$MARKDOWN_PATH" ]]; then
        jq -r '.markdown' "$REPORT_PATH" >"$MARKDOWN_PATH"
    fi

    if [[ "$STATUS" != "failed" ]] && ! jq -e --arg scenario "$SCENARIO" '
        .schema_version == "controller-provenance-dashboard-v1"
        and .scenario_id == $scenario
        and .verdict == "no_win"
        and .accepted == false
        and .no_win == true
        and .fallback_decision == "hold_for_explicit_no_win_rows"
        and .row_count == 13
        and (.required_owner_beads | length == 13)
        and (.owner_beads | length == 13)
        and (.rows | length == 13)
        and (.unsupported_rows | index("unified_admission_brownout_contract") != null)
        and (.failure_reasons | length == 0)
        and (.dashboard_digest_sha256 | test("^[0-9a-f]{64}$"))
        and (.markdown | contains("| decision_id | owner_bead | controller |"))
        and ([.rows[] | select(.proxy_only == true)] | length) == 0
        and ([.rows[] | select(.expected_artifact_sha256 != .observed_artifact_sha256)] | length) == 0
        and ([.rows[].command_class] | unique | sort) == ["rch_cargo_test", "replay_command", "smoke_runner"]
        and (.replay_command | contains("run_controller_provenance_dashboard_smoke.sh"))
    ' "$REPORT_PATH" >/dev/null; then
        STATUS="failed"
        SCRIPT_EXIT_CODE=1
        MESSAGE="controller provenance dashboard report failed contract validation"
    fi
fi

REPORT_PROJECTION='{}'
if [[ -s "$REPORT_PATH" ]]; then
    REPORT_PROJECTION="$(jq -c '{
        verdict,
        row_count,
        owner_beads,
        unsupported_rows,
        first_failure,
        dashboard_digest_sha256,
        artifact_path: $report_path,
        markdown_path: $markdown_path,
        replay_command
    }' --arg report_path "$REPORT_PATH" --arg markdown_path "$MARKDOWN_PATH" "$REPORT_PATH")"
fi

jq -n \
    --arg schema_version "controller-provenance-dashboard-run-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg status "$STATUS" \
    --arg message "$MESSAGE" \
    --arg command "$COMMAND" \
    --arg command_status "$COMMAND_STATUS" \
    --arg script_exit_code "$SCRIPT_EXIT_CODE" \
    --arg remote_test_passed "$REMOTE_TEST_PASSED" \
    --arg report_source "$REPORT_SOURCE" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg report_path "$REPORT_PATH" \
    --arg markdown_path "$MARKDOWN_PATH" \
    --argjson report_projection "$REPORT_PROJECTION" \
    '{
        schema_version: $schema_version,
        scenario_id: $scenario_id,
        mode: $mode,
        status: $status,
        message: $message,
        command: $command,
        command_status: ($command_status | tonumber),
        script_exit_code: ($script_exit_code | tonumber),
        remote_test_passed: ($remote_test_passed == "true"),
        report_source: $report_source,
        run_log_path: $run_log_path,
        report_path: $report_path,
        markdown_path: $markdown_path
    } + $report_projection' >"$RUN_REPORT_PATH"

printf 'CONTROLLER_PROVENANCE_DASHBOARD_RUN scenario_id=%s status=%s report=%s markdown=%s run_report=%s\n' \
    "$SCENARIO" "$(jq -r '.status' "$RUN_REPORT_PATH")" "$REPORT_PATH" "$MARKDOWN_PATH" "$RUN_REPORT_PATH"

exit "$SCRIPT_EXIT_CODE"
