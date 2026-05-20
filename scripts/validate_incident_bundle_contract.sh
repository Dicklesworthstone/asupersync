#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${REPO_ROOT}/artifacts/incident_bundle_contract_v1.json"
OUTPUT_ROOT="${REPO_ROOT}/target/incident-bundle-contract"
RUN_ID="local"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact)
      ARTIFACT_PATH="$2"
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
    -h|--help)
      cat <<'USAGE'
Usage: scripts/validate_incident_bundle_contract.sh [options]

Options:
  --artifact PATH      Incident bundle contract artifact to validate
  --output-root PATH   Directory for incident-bundle-contract-report.json
  --run-id ID          Deterministic run id directory
USAGE
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

REPORT_PATH="${OUTPUT_ROOT}/asupersync-lkygsb.1/${RUN_ID}/incident-bundle-contract-report.json"
mkdir -p "$(dirname "$REPORT_PATH")"

python3 - "$ARTIFACT_PATH" "$REPORT_PATH" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
artifact = json.loads(artifact_path.read_text())
events = []
failures = []

required_source_kinds = {
    "crash_pack",
    "trace_log",
    "support_bundle",
    "readme_claim_failure",
    "conformance_failure",
    "rch_proof_failure",
    "repro_notes",
}
required_issue_kinds = {
    "unsupported_schema_version",
    "missing_required_field",
    "duplicate_source_id",
    "unsupported_source_kind",
    "missing_redaction_policy",
    "redaction_required_but_missing",
    "secret_like_material",
    "oversized_field",
    "external_path",
    "malformed_content_hash",
    "binary_like_payload",
    "duplicate_feature_flag",
}
required_log_fields = [
    "scenario_id",
    "bead_id",
    "bundle_id",
    "verdict",
    "issue_kinds",
    "artifact_path",
]


def record(scenario_id, bundle_id, verdict, issue_kinds):
    row = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("bead_id", ""),
        "bundle_id": bundle_id,
        "verdict": verdict,
        "issue_kinds": issue_kinds,
        "artifact_path": str(report_path),
    }
    events.append(row)
    print(" ".join(f"{field}={json.dumps(row[field], sort_keys=True)}" for field in required_log_fields))


def require(condition, message):
    if not condition:
        failures.append(message)


require(artifact.get("schema_version") == "incident-bundle-contract-v1", "schema_version")
require(artifact.get("bead_id") == "asupersync-lkygsb.1", "bead_id")
require(set(artifact.get("source_kinds", [])) == required_source_kinds, "source_kinds")
require(set(artifact.get("fail_closed_triggers", [])) == required_issue_kinds, "fail_closed_triggers")
require(artifact.get("required_log_fields") == required_log_fields, "required_log_fields")
require(Path(artifact.get("module", "")).as_posix() == "src/trace/incident.rs", "module")

fixtures = artifact.get("fixtures", {})
accepted = fixtures.get("accepted")
require(isinstance(accepted, dict), "accepted_fixture")
if isinstance(accepted, dict):
    require(accepted.get("schema_version") == 1, "accepted_schema_version")
    require(accepted.get("privacy", {}).get("redaction_policy_id"), "accepted_redaction_policy")
    require(accepted.get("sources"), "accepted_sources")
    record("accepted-fixture", accepted.get("bundle_id", ""), "expected_accepted", [])

rejected = fixtures.get("rejected", [])
require(isinstance(rejected, list) and rejected, "rejected_fixtures")
for item in rejected if isinstance(rejected, list) else []:
    scenario_id = item.get("scenario_id", "")
    expected = item.get("expected_issue_kinds", [])
    bundle = item.get("bundle", {})
    require(scenario_id, "rejected_scenario_id")
    require(expected, f"{scenario_id}:expected_issue_kinds")
    require(set(expected).issubset(required_issue_kinds), f"{scenario_id}:unknown_issue_kind")
    require(isinstance(bundle, dict), f"{scenario_id}:bundle")
    record(scenario_id, bundle.get("bundle_id", ""), "expected_blocked", expected)

report = {
    "schema_version": "incident-bundle-contract-report-v1",
    "bead_id": artifact.get("bead_id", ""),
    "artifact_path": str(artifact_path),
    "event_count": len(events),
    "failure_count": len(failures),
    "events": events,
    "failures": failures,
    "verdict": "passed" if not failures else "failed",
    "first_failure": failures[0] if failures else "",
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if failures:
    raise SystemExit(1)
PY
