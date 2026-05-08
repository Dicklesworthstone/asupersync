#!/usr/bin/env bash
# Validate the incident proof report contract fixtures.
#
# Default mode is a deterministic catalog smoke that writes structured report
# rows without invoking cargo. Use --gate-report or --input-jsonl for fail-closed
# CI-style validation of generated report material. Pass --execute-rch to run
# the Rust proof-report test suite through rch as the heavy lane.

set -euo pipefail

ARTIFACT="artifacts/incident_proof_report_contract_v1.json"
OUTPUT_ROOT="target/incident-proof-report"
RUN_ID="manual"
GATE_REPORT=""
INPUT_JSONL=""
EXECUTE_RCH=0
RCH_BIN="${RCH_BIN:-rch}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_incident_proof_report.sh [--artifact PATH] [--output-root DIR] [--run-id ID] [--execute-rch]
  bash scripts/validate_incident_proof_report.sh --gate-report PATH
  bash scripts/validate_incident_proof_report.sh --input-jsonl PATH
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --gate-report)
      GATE_REPORT="$2"
      shift 2
      ;;
    --input-jsonl)
      INPUT_JSONL="$2"
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
REPORT="${OUTDIR}/incident-proof-report-run.json"
LOG="${OUTDIR}/incident-proof-report-events.ndjson"
RCH_LOG="${OUTDIR}/incident-proof-report-rch.log"
mkdir -p "$OUTDIR"

if [[ -n "$GATE_REPORT" ]]; then
  python3 - "$GATE_REPORT" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    report = json.loads(path.read_text())
except Exception as error:
    print(json.dumps({
        "accepted": False,
        "issue_kinds": ["malformed_json"],
        "message": str(error),
        "path": str(path),
    }, sort_keys=True))
    raise SystemExit(1)

issues = []
for field in ["schema_version", "report_id", "incident_id", "redaction_policy_id", "status", "human_summary"]:
    if not report.get(field):
        issues.append("missing_required_field")
if report.get("schema_version") != 1:
    issues.append("unsupported_schema_version")
if not report.get("redaction_passed", False):
    issues.append("redaction_failure")

status = report.get("status")
commands = report.get("proof_commands") or []
if status in {"pass", "fail"} and not commands:
    issues.append("missing_proof_command")
for command in commands:
    line = command.get("command_line", "")
    program = (command.get("command") or {}).get("program")
    if status in {"pass", "fail"} and (
        not command.get("executable_through_rch", False)
        or "rch exec" not in line
        or program != "rch"
    ):
        issues.append("proof_command_not_rch")

retained = report.get("retained_source_hashes") or {}
for source_id, expected_hash in (report.get("expected_fixture_hashes") or {}).items():
    if retained.get(source_id) != expected_hash:
        issues.append("stale_fixture_hash")
if status == "unsupported":
    issues.append("unsupported_source_report")

issues = sorted(set(issues))
accepted = not issues
print(json.dumps({
    "accepted": accepted,
    "issue_kinds": issues,
    "path": str(path),
    "status": status,
}, sort_keys=True))
raise SystemExit(0 if accepted else 1)
PY
  exit $?
fi

if [[ -n "$INPUT_JSONL" ]]; then
  python3 - "$INPUT_JSONL" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
parsed = 0
for line_no, line in enumerate(path.read_text().splitlines(), start=1):
    if not line.strip():
        continue
    try:
        json.loads(line)
    except Exception as error:
        print(json.dumps({
            "accepted": False,
            "issue_kinds": ["malformed_json"],
            "line": line_no,
            "message": str(error),
            "path": str(path),
        }, sort_keys=True))
        raise SystemExit(1)
    parsed += 1
print(json.dumps({"accepted": True, "path": str(path), "rows": parsed}, sort_keys=True))
PY
  exit $?
fi

python3 - "$ARTIFACT" "$REPORT" "$LOG" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])
try:
    artifact = json.loads(artifact_path.read_text())
except Exception as error:
    print(json.dumps({
        "accepted": False,
        "issue_kinds": ["malformed_json"],
        "message": str(error),
        "path": str(artifact_path),
    }, sort_keys=True))
    raise SystemExit(1)

required = {
    "schema_version",
    "bead_id",
    "proof_report_schema_version",
    "upstream_contracts",
    "report_statuses",
    "support_classes",
    "evidence_qualities",
    "validation_issue_kinds",
    "report_required_fields",
    "gate_contract",
    "scenarios",
    "e2e_script",
    "required_log_fields",
}
missing = sorted(required - artifact.keys())
if missing:
    raise SystemExit(f"artifact missing required fields: {missing}")

expected_statuses = {"pass", "fail", "blocked", "fixture_only", "flaky", "unsupported", "no_win"}
if set(artifact["report_statuses"]) != expected_statuses:
    raise SystemExit("report_statuses do not match the Rust status catalog")

required_log_fields = set(artifact["required_log_fields"])
events = []
for scenario in artifact["scenarios"]:
    status = scenario["expected_status"]
    proof_command = None
    if status in {"pass", "fail"}:
        proof_command = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_incident_proof_report_script CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test incident_proof_report --features test-internals -- --nocapture"
    event = {
        "scenario_id": scenario["scenario_id"],
        "bead_id": artifact["bead_id"],
        "status": status,
        "support_class": scenario["expected_support_class"],
        "evidence_quality": scenario["expected_evidence_quality"],
        "gate_success": scenario["expected_gate_success"],
        "validation_issue_kinds": scenario.get("expected_validation_issue_kinds", []),
        "block_kinds": scenario.get("expected_block_kinds", []),
        "proof_command": proof_command,
        "artifact_path": str(artifact_path),
    }
    missing_fields = sorted(required_log_fields - event.keys())
    if missing_fields:
        raise SystemExit(f"event {event['scenario_id']} missing fields: {missing_fields}")
    events.append(event)

observed_statuses = {event["status"] for event in events}
for required_status in ["pass", "blocked", "flaky", "unsupported", "no_win"]:
    if required_status not in observed_statuses:
        raise SystemExit(f"missing fixture status {required_status}")
if not any("malformed_json" in event["validation_issue_kinds"] for event in events):
    raise SystemExit("missing malformed JSON gate scenario")

log_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n")
run_report = {
    "schema_version": "incident-proof-report-run-v1",
    "artifact": str(artifact_path),
    "scenario_count": len(events),
    "statuses": sorted(observed_statuses),
    "failed_gate_scenarios": [
        event["scenario_id"] for event in events if not event["gate_success"]
    ],
    "events_path": str(log_path),
}
report_path.write_text(json.dumps(run_report, indent=2, sort_keys=True) + "\n")
for event in events:
    print(json.dumps(event, sort_keys=True))
PY

if [[ "$EXECUTE_RCH" -eq 1 ]]; then
  "${RCH_BIN}" exec -- \
    env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_incident_proof_report_script" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS="-D warnings -C debuginfo=0" \
      cargo test -p asupersync --test incident_proof_report --features test-internals -- --nocapture \
    >"$RCH_LOG" 2>&1
fi

echo "report=${REPORT}"
