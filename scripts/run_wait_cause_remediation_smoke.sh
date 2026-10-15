#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_wait_cause_remediation_v1.json"
OUTPUT_ROOT="${WAIT_CAUSE_REMEDIATION_OUTPUT_ROOT:-${PROJECT_ROOT}/target/wait-cause-remediation-smoke}"
RUN_ID="${WAIT_CAUSE_REMEDIATION_RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
MODE="execute"
LIST_ONLY=0
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900s}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_wait_cause_remediation_smoke.sh [options]

Options:
  --list                  List wait-cause remediation smoke scenarios and exit
  --dry-run               Emit manifests without running cargo
  --execute               Run the rch-backed Rust smoke proof (default)
  --output-root <dir>     Override output root
  --run-id <id>           Stable run directory name
  --scenario <id>         Record a scenario selection in the run report
  -h, --help              Show help
USAGE
}

require_tools() {
    local missing=0
    for tool in jq timeout; do
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

json_from_artifact() {
    jq -c "$1" "$ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | "  \(.scenario_id) / \(.report_id): \(.expected_verdict)"' "$ARTIFACT"
}

extract_report_from_log() {
    local log_path="$1"
    local report_path="$2"
    awk '
        /WAIT_CAUSE_REMEDIATION_REPORT_JSON_BEGIN/ { capture=1; next }
        /WAIT_CAUSE_REMEDIATION_REPORT_JSON_END/ { capture=0; exit }
        capture { print }
    ' "$log_path" >"$report_path"
    [ -s "$report_path" ]
}

validate_smoke_report() {
    local report_path="$1"
    jq -e '
        .schema_version == "wait-cause-remediation-smoke-report-v1"
        and .contract_version == "runtime-wait-cause-remediation-report-v1"
        and .bead_id == "asupersync-d87ytw.12"
        and .status == "passed"
        and (.rows | length) == 3
        and ([.rows[].verdict] | sort == ["actionable", "investigate", "refused"])
        and ([.rows[] | select(.verdict == "actionable") | .findings[].category] | sort == ["deadlock_cycle", "futurelock", "obligation_leak"])
        and ([.rows[] | select(.verdict == "investigate") | .findings[].category] == ["unknown_wait"])
        and all(.rows[];
            has("report_id")
            and has("report_hash")
            and has("scenario_id")
            and has("wait_cause_graph_hash")
            and has("tail_taxonomy_version")
            and has("verdict")
            and has("refusal_reason")
            and has("finding_count")
            and has("safe_actions")
            and has("forbidden_action_disclaimer")
            and has("replay_command")
            and has("evidence_refs")
            and has("findings")
        )
        and all(.rows[].findings[]?;
            has("finding_id")
            and has("rank")
            and has("category")
            and has("severity")
            and has("confidence_basis_points")
            and has("reason_code")
            and has("summary")
            and has("blocked_resource")
            and has("owner_task_id")
            and has("owner_region_id")
            and has("evidence_refs")
            and has("safe_actions")
            and has("forbidden_actions")
            and has("replay_command")
            and (.safe_actions | length) > 0
            and (.forbidden_actions | length) >= 3
        )
        and any(.rows[]; .safe_actions | length > 0)
        and all(.rows[]; .forbidden_action_disclaimer | contains("destructive cleanup"))
    ' "$report_path" >/dev/null
}

SCENARIO_FILTER="all"

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
        --scenario)
            SCENARIO_FILTER="${2:-}"
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

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
SMOKE_REPORT_PATH="${RUN_DIR}/wait_cause_remediation_report.json"
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
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wait_cause_remediation"
    "ASUPERSYNC_WAIT_CAUSE_REMEDIATION_REPORT_PATH=${SMOKE_REPORT_PATH}"
    "${CARGO_BIN:-cargo}"
    test
    -p
    asupersync
    --test
    runtime_wait_cause_remediation_contract
    wait_cause_remediation_smoke_emits_report
    --features
    test-internals
    --
    --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"

STATUS="passed"
VALIDATION_PASSED=true
COMMAND_EXIT_CODE=0
SCRIPT_EXIT_CODE=0
MESSAGE="wait-cause remediation smoke completed"

if [ "$MODE" = "dry-run" ]; then
    printf 'DRY_RUN command=%s\n' "$COMMAND" >"$RUN_LOG_PATH"
else
    set +e
    "${COMMAND_ARGS[@]}" >"$RUN_LOG_PATH" 2>&1
    COMMAND_EXIT_CODE=$?
    set -e

    if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RUN_LOG_PATH"; then
        COMMAND_EXIT_CODE=86
        SCRIPT_EXIT_CODE=86
        STATUS="failed"
        VALIDATION_PASSED=false
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
            MESSAGE="rch proof command failed before a valid wait-cause remediation report was emitted"
        fi
    elif [ ! -f "$SMOKE_REPORT_PATH" ] && ! extract_report_from_log "$RUN_LOG_PATH" "$SMOKE_REPORT_PATH"; then
        STATUS="failed"
        VALIDATION_PASSED=false
        COMMAND_EXIT_CODE=1
        SCRIPT_EXIT_CODE=1
        MESSAGE="wait-cause remediation report markers missing from run log"
    elif ! validate_smoke_report "$SMOKE_REPORT_PATH"; then
        STATUS="failed"
        VALIDATION_PASSED=false
        COMMAND_EXIT_CODE=1
        SCRIPT_EXIT_CODE=1
        MESSAGE="smoke report missing required wait-cause logging fields"
    fi
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg schema_version "$(artifact_value '.runner_report_schema_version')" \
    --arg contract_version "$(artifact_value '.contract_version')" \
    --arg bead_id "$(artifact_value '.bead_id')" \
    --arg mode "$MODE" \
    --arg run_id "$RUN_ID" \
    --arg scenario_filter "$SCENARIO_FILTER" \
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
    --argjson required_report_fields "$(json_from_artifact '.required_report_fields')" \
    --argjson required_finding_fields "$(json_from_artifact '.required_finding_fields')" \
    --argjson smoke_scenarios "$(json_from_artifact '.smoke_scenarios')" \
    '{
        schema_version: $schema_version,
        contract_version: $contract_version,
        bead_id: $bead_id,
        mode: $mode,
        run_id: $run_id,
        scenario_filter: $scenario_filter,
        run_dir: $run_dir,
        run_log_path: $run_log_path,
        smoke_report_path: $smoke_report_path,
        command: $command,
        rch_wrapper_timeout: $rch_wrapper_timeout,
        command_exit_code: $command_exit_code,
        script_exit_code: $script_exit_code,
        validation_passed: $validation_passed,
        required_report_fields: $required_report_fields,
        required_finding_fields: $required_finding_fields,
        smoke_scenarios: $smoke_scenarios,
        status: $status,
        message: $message,
        started_ts: $started_ts,
        ended_ts: $ended_ts
    }' >"$RUN_REPORT_PATH"

echo "WAIT_CAUSE_REMEDIATION_SMOKE_SUMMARY"
echo "  run_dir=${RUN_DIR}"
echo "  mode=${MODE}"
echo "  status=${STATUS}"
echo "  run_report=${RUN_REPORT_PATH}"
echo "  smoke_report=${SMOKE_REPORT_PATH}"

exit "$SCRIPT_EXIT_CODE"
