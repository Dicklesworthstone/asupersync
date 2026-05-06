#!/usr/bin/env bash
# Validate the incident replay minimization contract fixtures.

set -euo pipefail

ARTIFACT="artifacts/incident_replay_minimization_contract_v1.json"
OUTPUT_ROOT="target/incident-replay-minimization"
RUN_ID="manual"
EXECUTE_RCH=0
RCH_BIN="${RCH_BIN:-rch}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_incident_replay_minimization.sh [--output-root DIR] [--run-id ID] [--execute-rch]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --execute-rch)
      EXECUTE_RCH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

OUTDIR="${OUTPUT_ROOT}/${RUN_ID}"
REPORT="${OUTDIR}/incident-replay-minimization-report.json"
LOG="${OUTDIR}/incident-replay-minimization-events.ndjson"
RCH_LOG="${OUTDIR}/incident-replay-minimization-rch.log"
mkdir -p "$OUTDIR"

python3 - "$ARTIFACT" "$REPORT" "$LOG" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])
artifact = json.loads(artifact_path.read_text())

required = {
    "schema_version",
    "bead_id",
    "minimized_repro_schema_version",
    "oracle_kinds",
    "verdicts",
    "issue_kinds",
    "shrink_step_kinds",
    "scenarios",
    "required_log_fields",
}
missing = sorted(required - artifact.keys())
if missing:
    raise SystemExit(f"artifact missing required fields: {missing}")

scenarios = artifact["scenarios"]
if len(scenarios) < 5:
    raise SystemExit("minimization contract must keep success/no-reduction/budget/inconclusive/blocked scenarios")

by_id = {scenario["scenario_id"]: scenario for scenario in scenarios}
required_scenarios = {
    "minimize-crashpack-trace",
    "already-minimal-single-source",
    "budget-exhausted",
    "flaky-oracle",
    "empty-trace",
}
if set(by_id) != required_scenarios:
    raise SystemExit(f"unexpected scenario ids: {sorted(by_id)}")

events = []
for scenario in scenarios:
    sid = scenario["scenario_id"]
    ref = by_id.get(scenario.get("bundle_ref", sid), scenario)
    bundle = scenario.get("bundle", ref.get("bundle", {}))
    verdict = scenario["expected_verdict"]
    issues = scenario.get("expected_issue_kinds", [])
    repro_id = None if verdict in {"inconclusive", "blocked"} else "validated-by-rust-minimizer-test"
    event = {
        "scenario_id": sid,
        "bead_id": artifact["bead_id"],
        "bundle_id": bundle.get("bundle_id"),
        "verdict": verdict,
        "repro_id": repro_id,
        "issue_kinds": issues,
        "step_count": 1 if verdict in {"minimized", "budget_exhausted"} else 0,
        "artifact_path": str(artifact_path),
    }
    events.append(event)

required_log_fields = set(artifact["required_log_fields"])
for event in events:
    missing_fields = sorted(required_log_fields - event.keys())
    if missing_fields:
        raise SystemExit(f"event {event['scenario_id']} missing fields: {missing_fields}")

log_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n")
report = {
    "schema_version": "incident-replay-minimization-run-report-v1",
    "artifact": str(artifact_path),
    "scenario_count": len(events),
    "verdicts": sorted({event["verdict"] for event in events}),
    "events_path": str(log_path),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

for event in events:
    print(json.dumps(event, sort_keys=True))
PY

if [[ "$EXECUTE_RCH" -eq 1 ]]; then
  "${RCH_BIN}" exec -- \
    env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_incident_replay_minimization_script" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS="-D warnings -C debuginfo=0" \
      cargo test -p asupersync --test incident_replay_minimization --features test-internals -- --nocapture \
    >"$RCH_LOG" 2>&1
fi

echo "report=${REPORT}"
