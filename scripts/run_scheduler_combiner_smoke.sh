#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DRY_RUN=0
LIST_ONLY=0
SCENARIO_ID="AA-SCHEDULER-COMBINER-CONTENTION"
ARTIFACT_DIR="${ASUPERSYNC_COMBINER_SMOKE_OUT:-$PROJECT_ROOT/.scheduler-combiner-smoke-artifacts/$(date -u +%Y%m%dT%H%M%SZ)}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_scheduler_combiner_smoke.sh [options] [artifact-dir]

Options:
  --list                  List scenario IDs and exit
  --output-root <dir>     Override output/artifact directory
  --dry-run               Emit manifests without executing cargo
  --execute               Execute the rch-backed combiner smoke path (default)
  -h, --help              Show help
USAGE
}

list_scenarios() {
    echo "=== Scheduler Combiner Smoke Scenarios ==="
    echo "  ${SCENARIO_ID} [execute_or_dry_run]: adaptive ready-lane combiner proof for producer counts 1, 8, 32, and 64"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --output-root)
            ARTIFACT_DIR="${2:-}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --execute)
            DRY_RUN=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            ARTIFACT_DIR="$1"
            shift
            ;;
    esac
done

if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_scenarios
    exit 0
fi

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

LOG_FILE="$ARTIFACT_DIR/run.log"
REPORT_FILE="$ARTIFACT_DIR/report.json"
BUNDLE_MANIFEST_FILE="$ARTIFACT_DIR/bundle_manifest.json"
RUN_REPORT_FILE="$ARTIFACT_DIR/run_report.json"
printf -v RCH_INVOCATION '%q' "$RCH_BIN"
COMMAND="${RCH_INVOCATION} exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_scheduler_combiner cargo test -p asupersync --features test-internals --lib ready_combiner_contention_scenario_logs_required_producer_counts -- --nocapture"

mkdir -p "$ARTIFACT_DIR"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
    echo "SCHEDULER_COMBINER_SMOKE schema=scheduler-ready-combiner-smoke-v1"
    echo "SCHEDULER_COMBINER_SMOKE project_root=$PROJECT_ROOT"
    echo "SCHEDULER_COMBINER_SMOKE artifact_dir=$ARTIFACT_DIR"
    echo "SCHEDULER_COMBINER_SMOKE scenario_id=$SCENARIO_ID"
    echo "SCHEDULER_COMBINER_SMOKE bead_id=asupersync-g0kwgh"
    echo "SCHEDULER_COMBINER_SMOKE producer_counts=1,8,32,64"
    echo "SCHEDULER_COMBINER_SMOKE metrics=direct_injections,deferred_injections,combined_injections,fallback_injections,combiner_claim_failures,mode_entries,mode_exits,mode_switches,flushes,max_batch,max_in_flight,max_enqueue_tail_ns"
    echo "SCHEDULER_COMBINER_SMOKE command=$COMMAND"
    echo "SCHEDULER_COMBINER_SMOKE dry_run=$DRY_RUN"
    for producer_count in 1 8 32 64; do
        echo "SCHEDULER_COMBINER_EXPECTED producers=$producer_count items_per_producer=128"
    done
} | tee "$LOG_FILE"

COMMAND_EXIT_CODE=0
if [[ "$DRY_RUN" == "1" ]]; then
    STATUS="dry_run"
    VERDICT="dry run recorded the command and artifact contract without executing cargo"
else
    set +e
    (
        cd "$PROJECT_ROOT"
        bash -lc "$COMMAND"
    ) 2>&1 | tee -a "$LOG_FILE"
    COMMAND_EXIT_CODE=${PIPESTATUS[0]}
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$LOG_FILE" 2>/dev/null; then
        COMMAND_EXIT_CODE=86
        STATUS="failed"
        VERDICT="rch local fallback detected; refusing local cargo execution"
        printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$LOG_FILE"
    elif [[ "$COMMAND_EXIT_CODE" == "0" ]]; then
        STATUS="passed"
        VERDICT="adaptive ready-lane combiner scenario passed for producer counts 1, 8, 32, and 64"
    else
        STATUS="failed"
        VERDICT="adaptive ready-lane combiner scenario failed; inspect run.log for the first failing producer count"
    fi
fi

SCRIPT_EXIT_CODE="$COMMAND_EXIT_CODE"
VALIDATION_PASSED=false
if [[ "$COMMAND_EXIT_CODE" == "0" && "$STATUS" == "passed" ]]; then
    VALIDATION_PASSED=true
elif [[ "$COMMAND_EXIT_CODE" == "0" && "$STATUS" == "dry_run" ]]; then
    VALIDATION_PASSED=true
fi
ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$REPORT_FILE" <<JSON
{
  "schema_version": "scheduler-ready-combiner-smoke-v1",
  "bead_id": "asupersync-g0kwgh",
  "scenario_id": "$SCENARIO_ID",
  "status": "$STATUS",
  "producer_counts": [1, 8, 32, 64],
  "items_per_producer": 128,
  "logged_metrics": [
    "direct_injections",
    "deferred_injections",
    "combined_injections",
    "fallback_injections",
    "combiner_claim_failures",
    "mode_entries",
    "mode_exits",
    "mode_switches",
    "flushes",
    "max_batch",
    "max_in_flight",
    "max_enqueue_tail_ns"
  ],
  "command": "$COMMAND",
  "command_exit_code": $COMMAND_EXIT_CODE,
  "script_exit_code": $SCRIPT_EXIT_CODE,
  "validation_passed": $VALIDATION_PASSED,
  "run_log_path": "$LOG_FILE",
  "artifact_path": "$REPORT_FILE",
  "verdict_summary": "$VERDICT"
}
JSON

cat >"$BUNDLE_MANIFEST_FILE" <<JSON
{
  "schema_version": "scheduler-ready-combiner-smoke-bundle-v1",
  "contract_version": "scheduler-ready-combiner-smoke-v1",
  "scenario_id": "$SCENARIO_ID",
  "bead_id": "asupersync-g0kwgh",
  "artifact_path": "$BUNDLE_MANIFEST_FILE",
  "run_log_path": "$LOG_FILE",
  "report_path": "$REPORT_FILE",
  "run_report_path": "$RUN_REPORT_FILE",
  "mode": "$([[ "$DRY_RUN" == "1" ]] && printf "dry_run" || printf "execute")",
  "producer_counts": [1, 8, 32, 64],
  "command": "$COMMAND",
  "command_exit_code": $COMMAND_EXIT_CODE,
  "script_exit_code": $SCRIPT_EXIT_CODE,
  "validation_passed": $VALIDATION_PASSED,
  "status": "$STATUS",
  "started_ts": "$STARTED_TS",
  "ended_ts": "$ENDED_TS"
}
JSON

cat >"$RUN_REPORT_FILE" <<JSON
{
  "schema_version": "scheduler-ready-combiner-smoke-run-report-v1",
  "contract_version": "scheduler-ready-combiner-smoke-v1",
  "scenario_id": "$SCENARIO_ID",
  "bead_id": "asupersync-g0kwgh",
  "artifact_path": "$RUN_REPORT_FILE",
  "bundle_manifest_path": "$BUNDLE_MANIFEST_FILE",
  "run_log_path": "$LOG_FILE",
  "report_path": "$REPORT_FILE",
  "mode": "$([[ "$DRY_RUN" == "1" ]] && printf "dry_run" || printf "execute")",
  "command": "$COMMAND",
  "command_exit_code": $COMMAND_EXIT_CODE,
  "script_exit_code": $SCRIPT_EXIT_CODE,
  "validation_passed": $VALIDATION_PASSED,
  "status": "$STATUS",
  "message": "$VERDICT"
}
JSON

{
    echo ""
    echo "SCHEDULER_COMBINER_SMOKE report=$REPORT_FILE"
    echo "SCHEDULER_COMBINER_SMOKE bundle_manifest=$BUNDLE_MANIFEST_FILE"
    echo "SCHEDULER_COMBINER_SMOKE run_report=$RUN_REPORT_FILE"
    cat "$REPORT_FILE"
} | tee -a "$LOG_FILE"

exit "$COMMAND_EXIT_CODE"
