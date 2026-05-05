#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/controller_provenance_dashboard_contract_v1.json"
OUTPUT_ROOT="${CONTROLLER_PROVENANCE_DASHBOARD_OUTPUT_ROOT:-${PROJECT_ROOT}/target/controller-provenance-dashboard-smoke}"
SCENARIO="AA-CONTROLLER-PROVENANCE-DASHBOARD-64C-256G"
RUN_ID="${CONTROLLER_PROVENANCE_DASHBOARD_RUN_ID:-manual}"
MODE="dry-run"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900}"

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
REPORT_PATH="${RUN_DIR}/controller_provenance_dashboard.json"
MARKDOWN_PATH="${RUN_DIR}/controller_provenance_dashboard.md"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_JSON_MARKER="ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_JSON="
mkdir -p "$RUN_DIR"

COMMAND="timeout ${RCH_WRAPPER_TIMEOUT} rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_controller_provenance_dashboard ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_REPORT_PATH=${REPORT_PATH} ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_MARKDOWN_PATH=${MARKDOWN_PATH} cargo test -p asupersync --test controller_provenance_dashboard_contract controller_provenance_dashboard_smoke_emits_report --features test-internals -- --nocapture"
COMMAND_STATUS=0
REMOTE_TEST_PASSED=false
REPORT_SOURCE="not_run"

{
    printf 'CONTROLLER_PROVENANCE_DASHBOARD scenario_id=%s mode=%s report_path=%s markdown_path=%s\n' "$SCENARIO" "$MODE" "$REPORT_PATH" "$MARKDOWN_PATH"
    printf 'CONTROLLER_PROVENANCE_DASHBOARD command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    set +e
    (
        cd "$PROJECT_ROOT"
        eval "$COMMAND"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

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
        echo "FATAL: controller provenance dashboard command failed with status ${COMMAND_STATUS}" >>"$RUN_LOG_PATH"
        exit "$COMMAND_STATUS"
    fi
    if [[ ! -s "$REPORT_PATH" ]]; then
        echo "FATAL: controller provenance dashboard report missing after ${REPORT_SOURCE}" >>"$RUN_LOG_PATH"
        exit 1
    fi
    if [[ ! -s "$MARKDOWN_PATH" ]]; then
        jq -r '.markdown' "$REPORT_PATH" >"$MARKDOWN_PATH"
    fi

    jq -e --arg scenario "$SCENARIO" '
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
    ' "$REPORT_PATH" >/dev/null
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
    --arg status "$(if [[ "$MODE" == "execute" ]]; then echo passed; else echo dry_run; fi)" \
    --arg command "$COMMAND" \
    --arg command_status "$COMMAND_STATUS" \
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
        command: $command,
        command_status: ($command_status | tonumber),
        remote_test_passed: ($remote_test_passed == "true"),
        report_source: $report_source,
        run_log_path: $run_log_path,
        report_path: $report_path,
        markdown_path: $markdown_path
    } + $report_projection' >"$RUN_REPORT_PATH"

printf 'CONTROLLER_PROVENANCE_DASHBOARD_RUN scenario_id=%s status=%s report=%s markdown=%s run_report=%s\n' \
    "$SCENARIO" "$(jq -r '.status' "$RUN_REPORT_PATH")" "$REPORT_PATH" "$MARKDOWN_PATH" "$RUN_REPORT_PATH"
