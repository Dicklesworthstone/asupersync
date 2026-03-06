#!/usr/bin/env bash
# Kernel fast path substrate comparison smoke runner (AA-04.1)
#
# Usage:
#   bash ./scripts/run_kernel_fast_path_substrate_smoke.sh --list
#   bash ./scripts/run_kernel_fast_path_substrate_smoke.sh --scenario AA04-SMOKE-CANDIDATE-CATALOG --dry-run
#   bash ./scripts/run_kernel_fast_path_substrate_smoke.sh --scenario AA04-SMOKE-CANDIDATE-CATALOG --execute
#
# Bundle schema: kernel-fast-path-substrate-smoke-bundle-v1
# Report schema: kernel-fast-path-substrate-smoke-run-report-v1

set -euo pipefail

ARTIFACT="artifacts/kernel_fast_path_substrate_comparison_v1.json"
RCH_BIN="${RCH_BIN:-rch}"
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

if [[ "$MODE" == "list" ]]; then
  echo "=== Kernel Fast Path Substrate Smoke Scenarios ==="
  jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.description)"' "$ARTIFACT"
  exit 0
fi

[[ -z "$SCENARIO" ]] && { echo "error: --scenario required with --dry-run/--execute"; exit 1; }

COMMAND=$(jq -r --arg sid "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $sid) | .command' "$ARTIFACT")
DESCRIPTION=$(jq -r --arg sid "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $sid) | .description' "$ARTIFACT")

if [[ -z "$COMMAND" || "$COMMAND" == "null" ]]; then
  echo "error: unknown scenario $SCENARIO"
  exit 1
fi

RUN_ID="run_$(date +%Y%m%d_%H%M%S)"
OUTDIR="target/kernel-fast-path-substrate-smoke/$RUN_ID/$SCENARIO"
mkdir -p "$OUTDIR"

cat > "$OUTDIR/bundle_manifest.json" <<BUNDLE
{
  "schema": "kernel-fast-path-substrate-smoke-bundle-v1",
  "scenario_id": "$SCENARIO",
  "description": "$DESCRIPTION",
  "run_id": "$RUN_ID",
  "mode": "$MODE",
  "command": $(jq -n --arg c "$COMMAND" '$c'),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
BUNDLE

if [[ "$MODE" == "dry-run" ]]; then
  echo "[dry-run] $SCENARIO: $DESCRIPTION"
  echo "[dry-run] command: $COMMAND"
  echo "[dry-run] bundle: $OUTDIR/bundle_manifest.json"
  exit 0
fi

echo "=== Executing $SCENARIO ==="
echo "  $DESCRIPTION"
echo "  command: $COMMAND"

EXITCODE=0
eval "$COMMAND" > "$OUTDIR/run.log" 2>&1 || EXITCODE=$?

cat > "$OUTDIR/run_report.json" <<REPORT
{
  "schema": "kernel-fast-path-substrate-smoke-run-report-v1",
  "scenario_id": "$SCENARIO",
  "run_id": "$RUN_ID",
  "exit_code": $EXITCODE,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
REPORT

if [[ $EXITCODE -eq 0 ]]; then
  echo "  PASS (exit 0)"
else
  echo "  FAIL (exit $EXITCODE)"
  tail -20 "$OUTDIR/run.log"
fi

exit $EXITCODE
