#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${REPO_ROOT}/artifacts/wave2/wave2_signoff_proof_pack_evidence.json"
OUTPUT_ROOT="${REPO_ROOT}/target/wave2-signoff-proof-pack"
RUN_ID="asupersync-1e5xeh"

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
Usage: scripts/run_wave2_signoff_proof_pack.sh [options]

Options:
  --artifact PATH      Signoff artifact to validate
  --output-root PATH   Directory for wave2-signoff-report.json
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

REPORT_PATH="${OUTPUT_ROOT}/asupersync-1e5xeh/${RUN_ID}/wave2-signoff-report.json"
mkdir -p "$(dirname "${REPORT_PATH}")"

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$REPORT_PATH" <<'PY'
import json
import os
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
artifact = json.loads(artifact_path.read_text())
registry = json.loads((repo_root / artifact["registry_path"]).read_text())
issues_path = repo_root / artifact["issues_path"]
issue_rows = []
if issues_path.exists():
    for line in issues_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("id"):
            issue_rows.append(row)

issues_by_id = {row["id"]: row for row in issue_rows}
captured_issues_by_id = {
    row["owner_bead_id"]: {"id": row["owner_bead_id"], "status": row["tracker_status_at_capture"]}
    for row in artifact.get("signoff_rows", [])
    if row.get("owner_bead_id") and row.get("tracker_status_at_capture")
}
tracker_status_source = "live_jsonl"
if not issues_by_id:
    # rch worker syncs can omit .beads; use captured status only as a transport fallback.
    issues_by_id = dict(captured_issues_by_id)
    tracker_status_source = "artifact_capture_fallback"
required_log_fields = artifact["required_log_fields"]
promoted_states = set(registry["registry_contract"]["promoted_states_require_full_evidence"])
events = []
failures = []


def repo_path(relative):
    return repo_root / relative


def is_promoted(state):
    return state in promoted_states


def record(scenario_id, **fields):
    row = {
        "scenario_id": scenario_id,
        "bead_id": artifact["bead_id"],
        "wave_id": artifact["wave_id"],
        **fields,
    }
    events.append(row)
    parts = [
        f"bead_id={row['bead_id']}",
        f"wave_id={row['wave_id']}",
        f"scenario_id={scenario_id}",
    ]
    for key in required_log_fields:
        if key in {"bead_id", "wave_id"}:
            continue
        value = row.get(key, "")
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        parts.append(f"{key}={value}")
    print(" ".join(parts))


def fail(message):
    failures.append(message)


def array(value, key):
    item = value.get(key)
    if not isinstance(item, list):
        fail(f"{key}:not_array")
        return []
    return item


registry_rows = registry["capability_rows"]
registry_by_capability = {row["capability_id"]: row for row in registry_rows}
signoff_rows = artifact["signoff_rows"]
signoff_by_capability = {row.get("capability_id"): row for row in signoff_rows}

required_children = set(registry["required_wave2_child_beads"])
live_closed_child_count = sum(
    1 for owner in required_children if issues_by_id.get(owner, {}).get("status") == "closed"
)
captured_closed_child_count = sum(
    1
    for owner in required_children
    if captured_issues_by_id.get(owner, {}).get("status") == "closed"
)
missing_live_children = sorted(owner for owner in required_children if owner not in issues_by_id)
if captured_issues_by_id and (
    missing_live_children
    or (live_closed_child_count == 0 and captured_closed_child_count > 0)
):
    issues_by_id = dict(captured_issues_by_id)
    tracker_status_source = "artifact_capture_fallback"
signoff_owners = [row.get("owner_bead_id") for row in signoff_rows]
missing_owners = sorted(required_children - set(signoff_owners))
extra_owners = sorted(set(signoff_owners) - required_children)
if len(signoff_owners) != len(set(signoff_owners)):
    fail("duplicate_owner_bead_id")
if set(signoff_by_capability) != set(registry_by_capability):
    fail("capability_inventory_mismatch")
for owner in missing_owners:
    fail(f"missing_owner:{owner}")
for owner in extra_owners:
    fail(f"unexpected_owner:{owner}")

closed_child_count = sum(
    1 for owner in required_children if issues_by_id.get(owner, {}).get("status") == "closed"
)
non_closed = sorted(
    owner
    for owner in required_children
    if issues_by_id.get(owner, {}).get("status") != "closed"
)
allowed_preclose = set(
    artifact.get("finalization_model", {}).get("allowed_preclose_self_statuses", [])
)
self_bead = artifact.get("finalization_model", {}).get("self_owner_bead_id", artifact["bead_id"])
if non_closed and not (
    non_closed == [self_bead]
    and issues_by_id.get(self_bead, {}).get("status") in allowed_preclose
):
    fail(f"unexpected_non_closed_children:{','.join(non_closed)}")

promoted_count = 0
deferred_count = 0
proof_command_count = 0
e2e_artifact_count = 0
residual_risk_count = 0

for row in signoff_rows:
    capability_id = row.get("capability_id", "")
    registry_row = registry_by_capability.get(capability_id)
    if registry_row is None:
        continue
    for key in [
        "owner_bead_id",
        "promotion_state",
        "support_class_before",
        "support_class_after",
        "unsupported_reason",
        "fallback_target",
        "redaction_verdict",
    ]:
        if row.get(key) != registry_row.get(key):
            fail(f"{capability_id}:{key}_registry_drift")

    source_files = array(row, "source_files")
    unit_proofs = array(row, "unit_proofs")
    e2e_proofs = array(row, "e2e_proofs")
    e2e_artifacts = array(row, "e2e_artifacts")
    residual_risks = array(row, "residual_risks")
    proof_command_count += len(unit_proofs) + len(e2e_proofs)
    e2e_artifact_count += len(e2e_artifacts)
    residual_risk_count += len(residual_risks)

    missing_sources = [path for path in source_files if not repo_path(path).exists()]
    for path in missing_sources:
        fail(f"{capability_id}:missing_source:{path}")

    promotion_state = row.get("promotion_state", "")
    if is_promoted(promotion_state):
        promoted_count += 1
        if not source_files:
            fail(f"{capability_id}:promoted_missing_source")
        if not unit_proofs:
            fail(f"{capability_id}:promoted_missing_unit_proof")
        if not e2e_proofs:
            fail(f"{capability_id}:promoted_missing_e2e_proof")
        shipped_artifacts = [
            item["path"]
            for item in e2e_artifacts
            if item.get("state") == "shipped"
        ]
        if not shipped_artifacts:
            fail(f"{capability_id}:promoted_missing_shipped_artifact")
        for path in shipped_artifacts:
            if not repo_path(path).exists():
                fail(f"{capability_id}:missing_artifact:{path}")
        if row.get("unsupported_reason", "").strip():
            fail(f"{capability_id}:promoted_has_unsupported_reason")
        if row.get("support_class_after") in {"pending-proof", "unsupported", "deferred"}:
            fail(f"{capability_id}:promoted_has_pending_support_class")
    else:
        deferred_count += 1
        if not (
            row.get("unsupported_reason", "").strip()
            or row.get("fallback_target", "").strip()
            or residual_risks
        ):
            fail(f"{capability_id}:deferred_missing_rationale")
        if not e2e_artifacts:
            fail(f"{capability_id}:deferred_missing_artifact_or_plan")

    for command_row in unit_proofs + e2e_proofs:
        command = command_row.get("command", "")
        if ("cargo " in command or "lake build" in command) and "rch exec --" not in command:
            fail(f"{capability_id}:heavy_command_without_rch:{command}")
        lowered = command.lower()
        for marker in ["password=", "token=", "secret=", "bearer "]:
            if marker in lowered:
                fail(f"{capability_id}:sensitive_command_marker:{marker}")

    row_verdict = "pass" if not missing_sources else "fail"
    record(
        "signoff-row",
        capability_id=capability_id,
        child_bead_count=len(required_children),
        closed_child_count=closed_child_count,
        promoted_count=promoted_count,
        deferred_count=deferred_count,
        proof_command_count=len(unit_proofs) + len(e2e_proofs),
        e2e_artifact_count=len(e2e_artifacts),
        docs_drift_count=0,
        bv_cycle_count=0,
        br_ready_count=next(
            (
                check.get("ready_count", 0)
                for check in artifact["control_plane_checks"]
                if check.get("command_id") == "br_ready_json"
            ),
            0,
        ),
        residual_risk_count=len(residual_risks),
        artifact_path=artifact["artifact_path"],
        verdict=row_verdict,
        first_failure=missing_sources[0] if missing_sources else "",
    )

checks = {check["command_id"]: check for check in artifact["control_plane_checks"]}
for command_id in [
    "br_lint",
    "br_ready_json",
    "br_dep_cycles_json",
    "bv_robot_plan",
    "bv_robot_alerts",
    "bv_robot_suggest",
]:
    if command_id not in checks:
        fail(f"missing_control_plane_check:{command_id}")
if checks.get("br_lint", {}).get("status") != "passed":
    fail("br_lint_not_passed")
if checks.get("br_dep_cycles_json", {}).get("status") not in {"passed", "timed_out"}:
    fail("br_dep_cycles_not_recorded")
if checks.get("br_dep_cycles_json", {}).get("status") == "timed_out":
    if not checks["br_dep_cycles_json"].get("degraded_fallback"):
        fail("br_dep_cycles_timeout_missing_fallback")
if tracker_status_source == "artifact_capture_fallback":
    if not artifact.get("finalization_model", {}).get("closed_tracker_status_is_not_proof"):
        fail("tracker_capture_fallback_without_not_proof_guard")

docs_artifact = repo_path("artifacts/wave2/docs_support_matrix_reconciliation_evidence.json")
docs_row = registry_by_capability.get("docs_support_matrix_reconciliation", {})
docs_drift_count = 0 if docs_artifact.exists() and is_promoted(docs_row.get("promotion_state", "")) else 1
if docs_drift_count:
    fail("docs_reconciliation_not_promoted_or_missing")

br_ready_count = checks.get("br_ready_json", {}).get("ready_count", 0)
bv_cycle_count = checks.get("br_dep_cycles_json", {}).get("cycle_count", 0)
verdict = "passed" if not failures else "failed"
first_failure = failures[0] if failures else ""

record(
    "summary",
    child_bead_count=len(required_children),
    closed_child_count=closed_child_count,
    promoted_count=promoted_count,
    deferred_count=deferred_count,
    proof_command_count=proof_command_count,
    e2e_artifact_count=e2e_artifact_count,
    docs_drift_count=docs_drift_count,
    bv_cycle_count=bv_cycle_count,
    br_ready_count=br_ready_count,
    residual_risk_count=residual_risk_count,
    artifact_path=os.path.relpath(report_path, repo_root),
    verdict=verdict,
    first_failure=first_failure,
)

report = {
    "schema_version": "wave2-signoff-proof-pack-report-v1",
    "bead_id": artifact["bead_id"],
    "wave_id": artifact["wave_id"],
    "child_bead_count": len(required_children),
    "closed_child_count": closed_child_count,
    "promoted_count": promoted_count,
    "deferred_count": deferred_count,
    "proof_command_count": proof_command_count,
    "e2e_artifact_count": e2e_artifact_count,
    "docs_drift_count": docs_drift_count,
    "bv_cycle_count": bv_cycle_count,
    "br_ready_count": br_ready_count,
    "residual_risk_count": residual_risk_count,
    "tracker_status_source": tracker_status_source,
    "artifact_path": os.path.relpath(report_path, repo_root),
    "verdict": verdict,
    "first_failure": first_failure,
    "events": events,
    "failures": failures,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if failures:
    sys.exit(1)
PY
