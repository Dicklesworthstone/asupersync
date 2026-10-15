#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${OPERATOR_SWARM_PROFILE_DIAGNOSTICS_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/operator_swarm_profile_diagnostics_evidence.json}"
OUTPUT_ROOT="${OPERATOR_SWARM_PROFILE_DIAGNOSTICS_OUTPUT_ROOT:-${REPO_ROOT}/target/operator-swarm-profile-diagnostics}"
PROFILE="all"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"

usage() {
    cat <<'USAGE'
Usage: scripts/run_operator_swarm_profile_diagnostics.sh [options]

Options:
  --artifact <path>       Operator diagnostics contract artifact.
  --output-root <dir>     Directory for run_report.json and run.log.
  --profile <profile>     host profile filter or all.
  --run-id <id>           Deterministic run id for tests.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact)
            ARTIFACT_PATH="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
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

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$OUTPUT_ROOT" "$PROFILE" "$RUN_ID" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
artifact_path = Path(sys.argv[2]).resolve()
output_root = Path(sys.argv[3]).resolve()
profile_filter = sys.argv[4]
run_id = sys.argv[5]

contract = json.loads(artifact_path.read_text())
required_fields = contract["required_log_fields"]
rows = contract["diagnostic_rows"]

selected_rows = [
    row
    for row in rows
    if profile_filter == "all" or row["host_profile"] == profile_filter
]
if not selected_rows:
    valid = ", ".join(sorted({row["host_profile"] for row in rows}))
    raise SystemExit(f"unknown profile {profile_filter}; expected one of {valid}, all")


def repo_relative(path):
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


def log_value(value):
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"\s+", "_", text.strip())
    return text


def contains_sensitive(value):
    lowered = json.dumps(value, sort_keys=True).lower()
    for marker in ["api_token=super-secret", "bearer raw", "password=", "secret=", "token=super-secret"]:
        if marker in lowered:
            return marker
    return ""


report_dir = output_root / f"run_{run_id}"
report_dir.mkdir(parents=True, exist_ok=True)
run_log_path = report_dir / "run.log"
run_report_path = report_dir / "run_report.json"

first_failure = ""
line_rows = []
log_lines = []

for source_path in contract["source_evidence_paths"]:
    path = repo_root / source_path
    if not path.exists():
        first_failure = first_failure or f"missing_source:{source_path}"

for row in selected_rows:
    output_row = {
        "bead_id": contract["bead_id"],
        "scenario_id": row["scenario_id"],
        "host_profile": row["host_profile"],
        "selected_profile": row["selected_profile"],
        "confidence_score": row["confidence_score"],
        "saturation_class": row["saturation_class"],
        "primary_bottleneck": row["primary_bottleneck"],
        "recommended_action": row["recommended_action"],
        "rollback_trigger": row["rollback_trigger"],
        "no_win_reason": row["no_win_reason"],
        "redaction_verdict": row["redaction_verdict"],
        "artifact_path": repo_relative(run_report_path),
        "verdict": row["verdict"],
        "first_failure": row["first_failure"],
        "case_tags": row["case_tags"],
        "source_refs": row["source_refs"],
    }

    missing = [field for field in required_fields if field not in output_row]
    if missing:
        output_row["first_failure"] = output_row["first_failure"] or "missing_required_log_fields"
        first_failure = first_failure or f"{row['scenario_id']}:missing:{','.join(missing)}"

    if row["selected_profile"] != "conservative_baseline":
        if row["confidence_score"] < 90:
            output_row["first_failure"] = output_row["first_failure"] or "aggressive_profile_low_confidence"
        if not row["rollback_trigger"]:
            output_row["first_failure"] = output_row["first_failure"] or "aggressive_profile_missing_rollback"

    marker = contains_sensitive(row)
    if marker:
        output_row["first_failure"] = output_row["first_failure"] or f"sensitive_marker:{marker}"

    if output_row["first_failure"]:
        first_failure = first_failure or f"{row['scenario_id']}:{output_row['first_failure']}"

    line_rows.append(output_row)
    log_lines.append(" ".join(f"{field}={log_value(output_row[field])}" for field in required_fields))
    print(log_lines[-1])

validation_passed = first_failure == "" and all(
    row["verdict"] in {"pass", "no_win"} and row["first_failure"] == ""
    for row in line_rows
)

run_log_path.write_text("\n".join(log_lines) + "\n")
report = {
    "schema_version": "operator-swarm-profile-diagnostics-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "run_id": run_id,
    "profile_filter": profile_filter,
    "artifact_path": repo_relative(artifact_path),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "required_log_fields": required_fields,
    "source_evidence_paths": contract["source_evidence_paths"],
    "required_saturation_classes": contract["required_saturation_classes"],
    "recommendation_case_requirements": contract["recommendation_case_requirements"],
    "diagnostic_rows": line_rows,
    "validation_passed": validation_passed,
    "first_failure": first_failure,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if not validation_passed:
    raise SystemExit(1)
PY
