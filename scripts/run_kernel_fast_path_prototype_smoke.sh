#!/usr/bin/env bash
# Kernel fast path prototype smoke runner (AA-04.2)
#
# Usage:
#   bash ./scripts/run_kernel_fast_path_prototype_smoke.sh --list
#   bash ./scripts/run_kernel_fast_path_prototype_smoke.sh --scenario AA04-SMOKE-FALLBACK-SEAM --dry-run
#   bash ./scripts/run_kernel_fast_path_prototype_smoke.sh --scenario AA04-SMOKE-FALLBACK-SEAM --execute
#
# Bundle schema: kernel-fast-path-prototype-smoke-bundle-v1
# Report schema: kernel-fast-path-prototype-smoke-run-report-v1

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/kernel_fast_path_prototype_v1.json"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
MODE=""
SCENARIO=""

usage() {
  echo "Usage: $0 --list | --scenario <ID> (--dry-run | --execute)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)   MODE="list"; shift ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --dry-run)  MODE="dry-run"; shift ;;
    --execute)  MODE="execute"; shift ;;
    *) usage ;;
  esac
done

[[ -z "$MODE" ]] && usage

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: contract artifact missing at $ARTIFACT" >&2
  exit 1
fi

if [[ "$MODE" == "list" ]]; then
  echo "=== Kernel Fast Path Prototype Smoke Scenarios ==="
  jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.description)"' "$ARTIFACT"
  exit 0
fi

[[ -z "$SCENARIO" ]] && { echo "error: --scenario required with --dry-run/--execute"; exit 1; }

ARTIFACT_COMMAND=$(jq -r --arg sid "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $sid) | .command' "$ARTIFACT")
DESCRIPTION=$(jq -r --arg sid "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $sid) | .description' "$ARTIFACT")

if [[ -z "$ARTIFACT_COMMAND" || "$ARTIFACT_COMMAND" == "null" ]]; then
  echo "error: unknown scenario $SCENARIO"
  exit 1
fi

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "error: rch is required and was not found/executable at: $RCH_BIN" >&2
  exit 1
fi

case "$SCENARIO" in
  AA04-SMOKE-PROTOTYPE-SURFACES)
    TEST_FILTER="prototype_surface"
    ;;
  AA04-SMOKE-FALLBACK-SEAM)
    TEST_FILTER="fallback"
    ;;
  AA04-SMOKE-BENCHMARKS)
    TEST_FILTER="benchmark"
    ;;
  AA04-SMOKE-FUNCTIONAL)
    TEST_FILTER="functional"
    ;;
  *)
    echo "error: scenario ${SCENARIO} is present but has no runner mapping" >&2
    exit 1
    ;;
esac

RUN_ID="run_$(date +%Y%m%d_%H%M%S)"
OUTDIR="target/kernel-fast-path-prototype-smoke/$RUN_ID/$SCENARIO"
mkdir -p "$OUTDIR"
RUN_LOG="$OUTDIR/run.log"
RUN_REPORT="$OUTDIR/run_report.json"

COMMAND_ARGS=(
  "$RCH_BIN"
  exec
  --
  env
  "CARGO_INCREMENTAL=0"
  "CARGO_PROFILE_TEST_DEBUG=0"
  "RUSTFLAGS=-D warnings -C debuginfo=0"
  "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_kernel_fast_path_prototype"
  cargo
  test
  -p
  asupersync
  --test
  kernel_fast_path_prototype_contract
  --features
  test-internals
  "$TEST_FILTER"
  --
  --nocapture
)
printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}"
COMMAND="${COMMAND% }"

cat > "$OUTDIR/bundle_manifest.json" <<BUNDLE
{
  "schema": "kernel-fast-path-prototype-smoke-bundle-v1",
  "scenario_id": "$SCENARIO",
  "description": "$DESCRIPTION",
  "run_id": "$RUN_ID",
  "mode": "$MODE",
  "command": $(jq -n --arg c "$COMMAND" '$c'),
  "artifact_command": $(jq -n --arg c "$ARTIFACT_COMMAND" '$c'),
  "run_report_path": $(jq -n --arg p "$RUN_REPORT" '$p'),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
BUNDLE

if [[ "$MODE" == "dry-run" ]]; then
  printf 'DRY_RUN scenario=%s\n' "$SCENARIO" > "$RUN_LOG"
  cat > "$RUN_REPORT" <<REPORT
{
  "schema": "kernel-fast-path-prototype-smoke-run-report-v1",
  "scenario_id": "$SCENARIO",
  "run_id": "$RUN_ID",
  "mode": "$MODE",
  "status": "dry_run",
  "message": "dry run emitted manifests only",
  "command": $(jq -n --arg c "$COMMAND" '$c'),
  "run_log_path": $(jq -n --arg p "$RUN_LOG" '$p'),
  "command_exit_code": 0,
  "script_exit_code": 0,
  "validation_passed": true,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
REPORT
  echo "[dry-run] $SCENARIO: $DESCRIPTION"
  echo "[dry-run] command: $COMMAND"
  echo "[dry-run] bundle: $OUTDIR/bundle_manifest.json"
  exit 0
fi

echo "=== Executing $SCENARIO ==="
echo "  $DESCRIPTION"
echo "  command: $COMMAND"

EXITCODE=0
set +e
"${COMMAND_ARGS[@]}" > "$RUN_LOG" 2>&1
EXITCODE=$?
set -e

STATUS="passed"
MESSAGE="kernel fast path prototype smoke passed"
if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG"; then
  EXITCODE=86
  STATUS="failed"
  MESSAGE="rch local fallback detected; refusing local cargo execution"
  printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >> "$RUN_LOG"
elif [[ "$EXITCODE" -ne 0 ]]; then
  STATUS="failed"
  MESSAGE="kernel fast path prototype smoke failed"
fi

cat > "$RUN_REPORT" <<REPORT
{
  "schema": "kernel-fast-path-prototype-smoke-run-report-v1",
  "scenario_id": "$SCENARIO",
  "run_id": "$RUN_ID",
  "mode": "$MODE",
  "status": "$STATUS",
  "message": "$MESSAGE",
  "command": $(jq -n --arg c "$COMMAND" '$c'),
  "run_log_path": $(jq -n --arg p "$RUN_LOG" '$p'),
  "command_exit_code": $EXITCODE,
  "script_exit_code": $EXITCODE,
  "validation_passed": $([[ "$EXITCODE" -eq 0 ]] && printf true || printf false),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
REPORT

if [[ $EXITCODE -eq 0 ]]; then
  echo "  PASS (exit 0)"
else
  echo "  FAIL (exit $EXITCODE)"
  tail -20 "$RUN_LOG"
fi

exit $EXITCODE
