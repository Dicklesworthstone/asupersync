#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/final_control_loop_signoff_contract_v1.json"
OUTPUT_ROOT="${FINAL_CONTROL_LOOP_SIGNOFF_OUTPUT_ROOT:-${PROJECT_ROOT}/target/final-control-loop-signoff-smoke}"
SCENARIO="AA-FINAL-CONTROL-LOOP-SIGNOFF-64C-256G"
RUN_ID="${FINAL_CONTROL_LOOP_SIGNOFF_RUN_ID:-manual}"
MODE="dry-run"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_final_control_loop_signoff_smoke.sh [options]

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
        echo "FATAL: jq is required for final control-loop signoff smoke runner" >&2
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
REPORT_PATH="${RUN_DIR}/final_control_loop_signoff.json"
MARKDOWN_PATH="${RUN_DIR}/final_control_loop_signoff.md"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_JSON_MARKER="ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_JSON="
mkdir -p "$RUN_DIR"

DIRTY_PATHS_CSV="$(
    git -C "$PROJECT_ROOT" status --porcelain --untracked-files=no |
        awk '{print $2}' |
        grep -Ev '^\.beads/(issues\.jsonl|beads\.db)$' |
        LC_ALL=C sort -u |
        paste -sd, - || true
)"
DIRTY_PATHS_JSON="$(printf '%s\n' "$DIRTY_PATHS_CSV" | jq -R 'if . == "" then [] else split(",") end')"

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
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_final_control_loop_signoff"
    "ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_DIRTY_PATHS=${DIRTY_PATHS_CSV}"
    "ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_REPORT_PATH=${REPORT_PATH}"
    "ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_MARKDOWN_PATH=${MARKDOWN_PATH}"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync
    --test
    final_control_loop_signoff_audit
    final_control_loop_signoff_smoke_emits_report
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
MESSAGE="final control-loop signoff runner completed"

{
    printf 'FINAL_CONTROL_LOOP_SIGNOFF scenario_id=%s mode=%s report_path=%s markdown_path=%s\n' "$SCENARIO" "$MODE" "$REPORT_PATH" "$MARKDOWN_PATH"
    printf 'FINAL_CONTROL_LOOP_SIGNOFF command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    set +e
    (
        cd "$PROJECT_ROOT"
        "${COMMAND_ARGS[@]}"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

    if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RUN_LOG_PATH"; then
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

    if [[ "$STATUS" != "failed" && ( "$COMMAND_STATUS" -ne 0 || "$REMOTE_TEST_PASSED" != "true" ) ]]; then
        STATUS="failed"
        if [[ "$COMMAND_STATUS" -ne 0 ]]; then
            SCRIPT_EXIT_CODE="$COMMAND_STATUS"
        else
            SCRIPT_EXIT_CODE=1
        fi
        MESSAGE="final control-loop signoff command failed with status ${COMMAND_STATUS}"
        echo "FATAL: ${MESSAGE}" >>"$RUN_LOG_PATH"
    fi
    if [[ "$STATUS" != "failed" && ! -s "$REPORT_PATH" ]]; then
        STATUS="failed"
        SCRIPT_EXIT_CODE=1
        MESSAGE="final control-loop signoff report missing after ${REPORT_SOURCE}"
        echo "FATAL: ${MESSAGE}" >>"$RUN_LOG_PATH"
    fi
    if [[ "$STATUS" != "failed" && ! -s "$MARKDOWN_PATH" ]]; then
        jq -r '.markdown' "$REPORT_PATH" >"$MARKDOWN_PATH"
    fi

    if [[ "$STATUS" != "failed" ]] && ! jq -e --arg scenario "$SCENARIO" --argjson expected_dirty_paths "$DIRTY_PATHS_JSON" '
        .schema_version == "final-control-loop-signoff-v1"
        and .scenario_id == $scenario
        and .verdict == "no_win"
        and .accepted == false
        and .no_win == true
        and .parent_bead == "asupersync-d87ytw"
        and .parent_expected_status == "open"
        and .child_row_count == 14
        and (.required_child_beads | length == 14)
        and (.rows | length == 14)
        and ([.dirty_blockers[].path] | sort) == ($expected_dirty_paths | sort)
        and (.no_win_rows | index("controller_provenance_dashboard") != null)
        and (.failure_reasons | length == 0)
        and (.signoff_digest_sha256 | test("^[0-9a-f]{64}$"))
        and (.markdown | contains("| requirement_id | owner_bead | artifact |"))
        and ([.rows[] | select(.proxy_only == true)] | length) == 0
        and ([.rows[] | select(.expected_artifact_sha256 != .observed_artifact_sha256)] | length) == 0
        and ([.rows[].command_class] | unique | sort) == ["rch_cargo_test", "replay_command", "smoke_runner"]
        and all(.dirty_blockers[]; .retention_policy == "block_parent_epic_close")
    ' "$REPORT_PATH" >/dev/null; then
        STATUS="failed"
        SCRIPT_EXIT_CODE=1
        MESSAGE="final control-loop signoff report failed contract validation"
        echo "FATAL: ${MESSAGE}" >>"$RUN_LOG_PATH"
    fi
fi

REPORT_PROJECTION='{}'
if [[ -s "$REPORT_PATH" ]]; then
    REPORT_PROJECTION="$(jq -c '{
        verdict,
        child_row_count,
        no_win_rows,
        dirty_blockers,
        first_failure,
        signoff_digest_sha256,
        artifact_path: $report_path,
        markdown_path: $markdown_path
    }' --arg report_path "$REPORT_PATH" --arg markdown_path "$MARKDOWN_PATH" "$REPORT_PATH")"
fi

jq -n \
    --arg schema_version "final-control-loop-signoff-run-report-v1" \
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

printf 'FINAL_CONTROL_LOOP_SIGNOFF_RUN scenario_id=%s status=%s report=%s markdown=%s run_report=%s\n' \
    "$SCENARIO" "$(jq -r '.status' "$RUN_REPORT_PATH")" "$REPORT_PATH" "$MARKDOWN_PATH" "$RUN_REPORT_PATH"

exit "$SCRIPT_EXIT_CODE"
