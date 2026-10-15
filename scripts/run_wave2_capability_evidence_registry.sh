#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REGISTRY_PATH="${WAVE2_CAPABILITY_REGISTRY_PATH:-${REPO_ROOT}/artifacts/wave2_capability_evidence_registry_v1.json}"
OUTPUT_ROOT="${WAVE2_CAPABILITY_REGISTRY_OUTPUT_ROOT:-${REPO_ROOT}/target/wave2-capability-evidence-registry}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_wave2_capability_evidence_registry.sh [options]

Options:
  --registry <path>       Registry artifact to validate.
  --output-root <dir>     Directory for registry-report.json.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)
            REGISTRY_PATH="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

python3 - "$REPO_ROOT" "$REGISTRY_PATH" "$OUTPUT_ROOT" <<'PY'
import json
import os
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
registry_path = Path(sys.argv[2])
output_root = Path(sys.argv[3])
report_dir = output_root / "asupersync-6qju7t"
report_path = report_dir / "registry-report.json"

registry = json.loads(registry_path.read_text())
drifts = []
rows = []

RCH_LOCAL_FALLBACK_MARKERS = (
    "[rch] local",
    "falling back to local",
    "local fallback",
    "fallback to local",
    "executing locally",
)


def repo_path(relative):
    return repo_root / relative


def require(condition, failure):
    if not condition:
        drifts.append(failure)


def as_list(value, key):
    items = value.get(key, [])
    if not isinstance(items, list):
        drifts.append(f"{key}:not_array")
        return []
    return items


def log_row(scenario_id, **fields):
    row = {
        "bead_id": "asupersync-6qju7t",
        "wave_id": registry.get("wave_id", ""),
        "scenario_id": scenario_id,
        **fields,
    }
    rows.append(row)
    ordered = [
        f"bead_id={row['bead_id']}",
        f"wave_id={row['wave_id']}",
        f"scenario_id={scenario_id}",
    ]
    for key in sorted(k for k in row if k not in {"bead_id", "wave_id", "scenario_id"}):
        value = row[key]
        if isinstance(value, (list, dict)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        ordered.append(f"{key}={value}")
    print(" ".join(ordered))


support_classes = set(as_list(registry, "support_class_vocabulary"))
required_beads = set(as_list(registry, "required_wave2_child_beads"))
required_log_fields = set(as_list(registry, "required_log_fields"))
capability_rows = as_list(registry, "capability_rows")
contract = registry.get("registry_contract", {})
required_row_fields = set(as_list(contract, "required_row_fields"))
promoted_states = set(as_list(contract, "promoted_states_require_full_evidence"))
closed_owner_beads = set()
issues_path = repo_root / ".beads/issues.jsonl"
if issues_path.exists():
    for line in issues_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            issue = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(issue, dict) and issue.get("status") == "closed" and issue.get("id"):
            closed_owner_beads.add(issue["id"])

require(
    registry.get("schema_version") == "wave2-capability-evidence-registry-v1",
    "schema_version:mismatch",
)
require(registry.get("bead_id") == "asupersync-6qju7t", "bead_id:mismatch")
require(registry.get("wave_id") == "reality-check-wave2", "wave_id:mismatch")
runner_script = registry.get("runner_script", "")
require(bool(runner_script), "runner_script:missing")
require(repo_path(runner_script).is_file(), f"runner_script:not_found:{runner_script}")

capability_ids = []
owner_ids = []

for row in capability_rows:
    capability_id = row.get("capability_id", "")
    owner_bead_id = row.get("owner_bead_id", "")
    capability_ids.append(capability_id)
    owner_ids.append(owner_bead_id)

    missing_fields = sorted(field for field in required_row_fields if field not in row)
    for field in missing_fields:
        drifts.append(f"{capability_id or '<missing>'}:missing_field:{field}")

    support_class_before = row.get("support_class_before", "")
    support_class_after = row.get("support_class_after", "")
    if support_class_before not in support_classes and "-" not in support_class_before:
        drifts.append(f"{capability_id}:unknown_support_class_before:{support_class_before}")
    if support_class_after not in support_classes and "-" not in support_class_after:
        drifts.append(f"{capability_id}:unknown_support_class_after:{support_class_after}")

    source_paths = as_list(row, "source_paths")
    unit_commands = as_list(row, "unit_proof_commands")
    e2e_commands = as_list(row, "e2e_proof_commands")
    artifact_paths = as_list(row, "artifact_paths")
    planned_artifact_paths = as_list(row, "planned_artifact_paths")
    residual_risks = as_list(row, "residual_risks")

    first_failure = ""
    for source_path in source_paths:
        if not repo_path(source_path).exists():
            first_failure = first_failure or f"missing_source:{source_path}"
            drifts.append(f"{capability_id}:missing_source:{source_path}")
    for artifact_path in artifact_paths:
        if not repo_path(artifact_path).exists():
            first_failure = first_failure or f"missing_artifact:{artifact_path}"
            drifts.append(f"{capability_id}:missing_artifact:{artifact_path}")

    for command in unit_commands + e2e_commands:
        lowered = command.lower()
        if any(marker in lowered for marker in RCH_LOCAL_FALLBACK_MARKERS):
            first_failure = first_failure or f"rch_local_fallback_evidence:{command}"
            drifts.append(f"{capability_id}:rch_local_fallback_evidence")
        if ("cargo " in command or "lake build" in command) and "rch exec --" not in command:
            first_failure = first_failure or f"missing_rch:{command}"
            drifts.append(f"{capability_id}:missing_rch:{command}")
        if "cargo " in command and "CARGO_TARGET_DIR=" not in command:
            first_failure = first_failure or f"missing_cargo_target_dir:{command}"
            drifts.append(f"{capability_id}:missing_cargo_target_dir:{command}")
        for marker in ("password=", "token=", "secret=", "bearer "):
            if marker in lowered:
                first_failure = first_failure or f"sensitive_command_marker:{marker}"
                drifts.append(f"{capability_id}:sensitive_command_marker:{marker}")

    promotion_state = row.get("promotion_state", "")
    is_promoted = promotion_state in promoted_states
    unsupported_reason = row.get("unsupported_reason", "")
    fallback_target = row.get("fallback_target", "")
    if owner_bead_id in closed_owner_beads and (
        promotion_state == "pending" or "pending" in support_class_after
    ):
        first_failure = first_failure or "closed_owner_stale_pending_state"
        drifts.append(f"{capability_id}:closed_owner_stale_pending_state:{owner_bead_id}")
    if is_promoted:
        if not source_paths:
            first_failure = first_failure or "promoted_missing_source_paths"
            drifts.append(f"{capability_id}:promoted_missing_source_paths")
        if not unit_commands:
            first_failure = first_failure or "promoted_missing_unit_commands"
            drifts.append(f"{capability_id}:promoted_missing_unit_commands")
        if not e2e_commands:
            first_failure = first_failure or "promoted_missing_e2e_commands"
            drifts.append(f"{capability_id}:promoted_missing_e2e_commands")
        if not artifact_paths:
            first_failure = first_failure or "promoted_missing_artifacts"
            drifts.append(f"{capability_id}:promoted_missing_artifacts")
        if unsupported_reason.strip():
            first_failure = first_failure or "promoted_has_unsupported_reason"
            drifts.append(f"{capability_id}:promoted_has_unsupported_reason")
    elif not unsupported_reason.strip() and not residual_risks:
        first_failure = first_failure or "pending_missing_reason_or_risk"
        drifts.append(f"{capability_id}:pending_missing_reason_or_risk")

    verdict = "pass" if not first_failure else "fail"
    log_row(
        "capability-row",
        capability_id=capability_id,
        support_class_before=support_class_before,
        support_class_after=support_class_after,
        feature_flags=json.dumps(as_list(row, "feature_flags"), sort_keys=True, separators=(",", ":")),
        source_path_count=len(source_paths),
        unit_command_count=len(unit_commands),
        e2e_command_count=len(e2e_commands),
        artifact_count=len(artifact_paths),
        planned_artifact_count=len(planned_artifact_paths),
        unsupported_reason=unsupported_reason,
        fallback_target=fallback_target,
        residual_risk_count=len(residual_risks),
        redaction_verdict=row.get("redaction_verdict", ""),
        owner_bead_id=owner_bead_id,
        verdict=verdict,
        first_failure=first_failure,
    )

if len(capability_ids) != len(set(capability_ids)):
    drifts.append("capability_id:duplicates")
if len(owner_ids) != len(set(owner_ids)):
    drifts.append("owner_bead_id:duplicates")
if set(owner_ids) != required_beads:
    missing = sorted(required_beads - set(owner_ids))
    extra = sorted(set(owner_ids) - required_beads)
    if missing:
        drifts.append("owner_bead_id:missing:" + ",".join(missing))
    if extra:
        drifts.append("owner_bead_id:extra:" + ",".join(extra))

required_runner_fields = {
    "bead_id",
    "wave_id",
    "capability_id",
    "support_class_before",
    "support_class_after",
    "feature_flags",
    "source_path_count",
    "unit_command_count",
    "e2e_command_count",
    "artifact_count",
    "unsupported_reason",
    "fallback_target",
    "residual_risk_count",
    "redaction_verdict",
    "owner_bead_id",
    "verdict",
    "first_failure",
}
missing_log_fields = sorted(required_runner_fields - required_log_fields)
if missing_log_fields:
    drifts.append("required_log_fields:missing:" + ",".join(missing_log_fields))

verdict = "passed" if not drifts else "failed"
summary = {
    "bead_id": "asupersync-6qju7t",
    "wave_id": registry.get("wave_id", ""),
    "scenario_id": "summary",
    "capability_id": "wave2_capability_evidence_registry",
    "support_class_before": "missing-registry",
    "support_class_after": "artifact-contract-backed",
    "feature_flags": "[]",
    "source_path_count": len({source for row in capability_rows for source in as_list(row, "source_paths")}),
    "unit_command_count": sum(len(as_list(row, "unit_proof_commands")) for row in capability_rows),
    "e2e_command_count": sum(len(as_list(row, "e2e_proof_commands")) for row in capability_rows),
    "artifact_count": sum(len(as_list(row, "artifact_paths")) for row in capability_rows),
    "unsupported_reason": "",
    "fallback_target": "fail closed on missing field or stale evidence",
    "residual_risk_count": sum(len(as_list(row, "residual_risks")) for row in capability_rows),
    "redaction_verdict": "not_applicable",
    "owner_bead_id": "asupersync-6qju7t",
    "verdict": "pass" if verdict == "passed" else "fail",
    "first_failure": drifts[0] if drifts else "",
}
rows.append(summary)
ordered = [
    f"bead_id={summary['bead_id']}",
    f"wave_id={summary['wave_id']}",
    "scenario_id=summary",
]
for key in sorted(k for k in summary if k not in {"bead_id", "wave_id", "scenario_id"}):
    ordered.append(f"{key}={summary[key]}")
print(" ".join(ordered))

report = {
    "schema_version": "wave2-capability-evidence-registry-report-v1",
    "registry_schema_version": registry.get("schema_version", ""),
    "registry_path": os.path.relpath(registry_path, repo_root),
    "bead_id": "asupersync-6qju7t",
    "wave_id": registry.get("wave_id", ""),
    "capability_row_count": len(capability_rows),
    "required_child_bead_count": len(required_beads),
    "support_class_count": len(support_classes),
    "required_log_field_count": len(required_log_fields),
    "artifact_path": os.path.relpath(report_path, repo_root),
    "verdict": verdict,
    "first_failure": drifts[0] if drifts else "",
    "drift_count": len(drifts),
    "drifts": drifts,
    "rows": rows,
}

report_dir.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if drifts:
    sys.exit(1)
PY
