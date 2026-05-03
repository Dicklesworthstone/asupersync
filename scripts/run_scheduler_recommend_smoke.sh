#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_ROOT="${SCHEDULER_RECOMMEND_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/scheduler-recommend-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
EVIDENCE_FILE="${RUN_DIR}/scheduler_evidence.json"
REPORT_FILE="${RUN_DIR}/scheduler_report.json"

mkdir -p "$RUN_DIR"

cat >"$EVIDENCE_FILE" <<'JSON'
{
  "schema_version": "asupersync.scheduler-evidence.v1",
  "run_label": "mixed-burst-64c",
  "workload_class": "mixed_burst",
  "topology": {
    "worker_threads": 64,
    "cohort_count": 2,
    "memory_budget_gib": 256
  },
  "current_knobs": {
    "worker_threads": 64,
    "steal_batch_size": 8,
    "cancel_streak_limit": 16,
    "global_queue_limit": 0,
    "parking_enabled": true
  },
  "metrics": {
    "wake_to_run_p50_ns": 8000,
    "wake_to_run_p95_ns": 90000,
    "wake_to_run_p99_ns": 220000,
    "queue_residency_p50_ns": 16000,
    "queue_residency_p95_ns": 200000,
    "queue_residency_p99_ns": 520000,
    "ready_backlog_p95": 192,
    "ready_backlog_p99": 320,
    "cancel_debt_p95": 48,
    "cancel_debt_p99": 128,
    "remote_steal_ratio_pct": 42,
    "cross_cohort_wake_p99_ns": 180000
  },
  "notes": [
    "deterministic_lab",
    "smoke_e2e"
  ]
}
JSON

echo "==================================================================="
echo "           SCHEDULER RECOMMEND SMOKE: INPUT EVIDENCE               "
echo "==================================================================="
cat "$EVIDENCE_FILE"
echo ""

pushd "$PROJECT_ROOT" >/dev/null
cargo run -p asupersync --bin offline_tuner --features cli,simd-intrinsics -- \
    scheduler-recommend \
    --evidence-file "$EVIDENCE_FILE" \
    --output-file "$REPORT_FILE"
popd >/dev/null

echo ""
echo "==================================================================="
echo "         SCHEDULER RECOMMEND SMOKE: GENERATED REPORT               "
echo "==================================================================="
cat "$REPORT_FILE"
echo ""

if ! rg -q '"fallback_profile"' "$REPORT_FILE"; then
    echo "FATAL: generated report omitted fallback_profile" >&2
    exit 1
fi

if ! rg -q '"reason_codes"' "$REPORT_FILE"; then
    echo "FATAL: generated report omitted reason_codes" >&2
    exit 1
fi

if ! rg -q '"profile_name": "scale_workers"' "$REPORT_FILE"; then
    echo "FATAL: generated report did not produce the expected scale_workers profile" >&2
    exit 1
fi

echo "Smoke run artifacts:"
echo "  evidence: $EVIDENCE_FILE"
echo "  report:   $REPORT_FILE"
