#!/usr/bin/env bash
# Validate the incident replay promotion contract fixtures.
#
# Default mode is a deterministic catalog smoke that writes structured logs
# without invoking cargo. Pass --execute-rch to run the Rust promotion test
# suite through rch as the heavy end-to-end lane.

set -euo pipefail

ARTIFACT="artifacts/incident_replay_promotion_contract_v1.json"
OUTPUT_ROOT="target/incident-replay-promotion"
RUN_ID="manual"
EXECUTE_RCH=0
RCH_BIN="${RCH_BIN:-rch}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_incident_replay_promotion.sh [--output-root DIR] [--run-id ID] [--execute-rch]
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
REPORT="${OUTDIR}/incident-replay-promotion-report.json"
LOG="${OUTDIR}/incident-replay-promotion-events.ndjson"
RCH_LOG="${OUTDIR}/incident-replay-promotion-rch.log"
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
    "regression_proof_schema_version",
    "minimization_contract",
    "promotion_targets",
    "promotion_verdicts",
    "block_kinds",
    "promotion_policy",
    "scenarios",
    "required_log_fields",
}
missing = sorted(required - artifact.keys())
if missing:
    raise SystemExit(f"artifact missing required fields: {missing}")

expected_targets = {
    "unit_test",
    "integration_test",
    "golden_artifact",
    "fuzz_seed",
    "conformance_fixture",
    "fixture_only",
    "blocker_bead",
}
if set(artifact["promotion_targets"]) != expected_targets:
    raise SystemExit("promotion_targets do not match the Rust target catalog")

scenarios = artifact["scenarios"]
if not any(s["expected_verdict"] in {"promoted", "fixture_only"} for s in scenarios):
    raise SystemExit("promotion contract must include at least one promoted proof scenario")
if not any(s["expected_verdict"] == "blocked" for s in scenarios):
    raise SystemExit("promotion contract must include at least one blocked report scenario")

events = []
for scenario in scenarios:
    verdict = scenario["expected_verdict"]
    block_kinds = scenario.get("expected_block_kinds", [])
    proof_id = None
    proof_command = None
    if verdict != "blocked":
        proof_id = f"validated-by-rust-promotion-test:{scenario['scenario_id']}"
        proof_command = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_incident_replay_promotion_script CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test incident_replay_promotion --features test-internals -- --nocapture"
    events.append(
        {
            "scenario_id": scenario["scenario_id"],
            "bead_id": artifact["bead_id"],
            "verdict": verdict,
            "target": scenario["expected_target"],
            "proof_id": proof_id,
            "block_kinds": block_kinds,
            "source_repro_id": "validated-by-rust-promotion-test",
            "oracle_kind": scenario.get("expected_oracle_kind"),
            "proof_command": proof_command,
            "artifact_path": str(artifact_path),
        }
    )

required_log_fields = set(artifact["required_log_fields"])
for event in events:
    missing_fields = sorted(required_log_fields - event.keys())
    if missing_fields:
        raise SystemExit(f"event {event['scenario_id']} missing fields: {missing_fields}")

log_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n")
report = {
    "schema_version": "incident-replay-promotion-run-report-v1",
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
    env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_incident_replay_promotion_script" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS="-D warnings -C debuginfo=0" \
      cargo test -p asupersync --test incident_replay_promotion --features test-internals -- --nocapture \
    >"$RCH_LOG" 2>&1
fi

echo "report=${REPORT}"
