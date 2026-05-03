#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

ARTIFACT_DIR="${1:-${ASUPERSYNC_COMBINER_SMOKE_OUT:-$PROJECT_ROOT/.scheduler-combiner-smoke-artifacts/$(date -u +%Y%m%dT%H%M%SZ)}}"
LOG_FILE="$ARTIFACT_DIR/run.log"
REPORT_FILE="$ARTIFACT_DIR/report.json"
COMMAND="rch exec -- cargo test -p asupersync --features test-internals --lib ready_combiner_contention_scenario_logs_required_producer_counts -- --nocapture"

mkdir -p "$ARTIFACT_DIR"

{
    echo "SCHEDULER_COMBINER_SMOKE schema=scheduler-ready-combiner-smoke-v1"
    echo "SCHEDULER_COMBINER_SMOKE project_root=$PROJECT_ROOT"
    echo "SCHEDULER_COMBINER_SMOKE artifact_dir=$ARTIFACT_DIR"
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

    if [[ "$COMMAND_EXIT_CODE" == "0" ]]; then
        STATUS="passed"
        VERDICT="adaptive ready-lane combiner scenario passed for producer counts 1, 8, 32, and 64"
    else
        STATUS="failed"
        VERDICT="adaptive ready-lane combiner scenario failed; inspect run.log for the first failing producer count"
    fi
fi

cat >"$REPORT_FILE" <<JSON
{
  "schema_version": "scheduler-ready-combiner-smoke-v1",
  "bead_id": "asupersync-g0kwgh",
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
  "run_log_path": "$LOG_FILE",
  "verdict_summary": "$VERDICT"
}
JSON

{
    echo ""
    echo "SCHEDULER_COMBINER_SMOKE report=$REPORT_FILE"
    cat "$REPORT_FILE"
} | tee -a "$LOG_FILE"

exit "$COMMAND_EXIT_CODE"
