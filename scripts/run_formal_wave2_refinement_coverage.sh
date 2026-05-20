#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_PATH="${FORMAL_WAVE2_REFINEMENT_COVERAGE_PATH:-${REPO_ROOT}/artifacts/formal_wave2_refinement_coverage_v1.json}"
OUTPUT_ROOT="${FORMAL_WAVE2_REFINEMENT_COVERAGE_OUTPUT_ROOT:-${REPO_ROOT}/target/formal-wave2-refinement-coverage}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_formal_wave2_refinement_coverage.sh [options]

Options:
  --manifest <path>      Coverage manifest to validate.
  --output-root <dir>    Directory for coverage-report.json.
  -h, --help             Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest)
            MANIFEST_PATH="${2:-}"
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

python3 - "$REPO_ROOT" "$MANIFEST_PATH" "$OUTPUT_ROOT" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
output_root = Path(sys.argv[3])
if not output_root.is_absolute():
    output_root = repo_root / output_root
report_dir = output_root / "asupersync-i6uzso"
report_path = report_dir / "coverage-report.json"

manifest = json.loads(manifest_path.read_text())
failures = []
rows = []


def repo_path(relative):
    return repo_root / relative


def cargo_command_has_target_dir(command):
    return "rch exec -- env " in command and "CARGO_TARGET_DIR=" in command


def as_list(value, key, ctx):
    item = value.get(key, [])
    if not isinstance(item, list):
        failures.append(f"{ctx}:{key}:not_array")
        return []
    return item


def nonempty(value, key, ctx):
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        failures.append(f"{ctx}:{key}:missing")
        return ""
    return item


def first_or_empty(values):
    return values[0] if values else ""


def log_row(scenario_id, **fields):
    row = {
        "bead_id": "asupersync-i6uzso",
        "scenario_id": scenario_id,
        **fields,
    }
    rows.append(row)
    ordered = [f"bead_id={row['bead_id']}", f"scenario_id={scenario_id}"]
    for key in sorted(k for k in row if k not in {"bead_id", "scenario_id"}):
        value = row[key]
        if isinstance(value, (list, dict)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        ordered.append(f"{key}={value}")
    print(" ".join(ordered))


proof_tiers = set(as_list(manifest, "proof_tier_vocabulary", "manifest"))
required_log_fields = set(as_list(manifest, "required_log_fields", "manifest"))
core_invariants = set(as_list(manifest, "canonical_core_invariants", "manifest"))

if manifest.get("schema_version") != "formal-wave2-refinement-coverage-v1":
    failures.append("manifest:schema_version:mismatch")
if manifest.get("bead_id") != "asupersync-i6uzso":
    failures.append("manifest:bead_id:mismatch")
runner_script = manifest.get("runner_script", "")
if not runner_script or not repo_path(runner_script).is_file():
    failures.append(f"manifest:runner_script:not_found:{runner_script}")

lane_ids = []
for lane in as_list(manifest, "lane_rows", "manifest"):
    lane_id = nonempty(lane, "lane_id", "lane")
    lane_ids.append(lane_id)
    proof_tier = nonempty(lane, "proof_tier", lane_id)
    owner_bead_id = nonempty(lane, "owner_bead_id", lane_id)
    invariant_ids = as_list(lane, "invariant_ids", lane_id)
    theorem_names = as_list(lane, "theorem_names", lane_id)
    model_artifacts = as_list(lane, "model_artifacts", lane_id)
    source_paths = as_list(lane, "source_paths", lane_id)
    runtime_tests = as_list(lane, "runtime_tests", lane_id)
    e2e_artifacts = as_list(lane, "e2e_artifacts", lane_id)
    assumptions = as_list(lane, "assumptions", lane_id)
    missing_evidence = as_list(lane, "missing_evidence", lane_id)
    commands = as_list(lane, "proof_commands", lane_id)

    first_failure = ""
    if proof_tier not in proof_tiers:
        first_failure = first_failure or f"unknown_proof_tier:{proof_tier}"
        failures.append(f"{lane_id}:unknown_proof_tier:{proof_tier}")
    if not owner_bead_id.startswith("asupersync-"):
        first_failure = first_failure or f"bad_owner_bead:{owner_bead_id}"
        failures.append(f"{lane_id}:bad_owner_bead:{owner_bead_id}")
    if not invariant_ids:
        first_failure = first_failure or "missing_invariant_ids"
        failures.append(f"{lane_id}:missing_invariant_ids")
    for invariant_id in invariant_ids:
        if invariant_id not in core_invariants:
            first_failure = first_failure or f"unknown_invariant:{invariant_id}"
            failures.append(f"{lane_id}:unknown_invariant:{invariant_id}")
    if not theorem_names:
        first_failure = first_failure or "missing_theorem_names"
        failures.append(f"{lane_id}:missing_theorem_names")

    for field_name, values in [
        ("model_artifacts", model_artifacts),
        ("source_paths", source_paths),
        ("runtime_tests", runtime_tests),
        ("e2e_artifacts", e2e_artifacts),
    ]:
        for relative in values:
            if not isinstance(relative, str) or not relative.strip():
                first_failure = first_failure or f"{field_name}:blank"
                failures.append(f"{lane_id}:{field_name}:blank")
                continue
            if not repo_path(relative).exists():
                first_failure = first_failure or f"{field_name}:missing:{relative}"
                failures.append(f"{lane_id}:{field_name}:missing:{relative}")

    for command in commands:
        if not isinstance(command, str) or not command.strip():
            first_failure = first_failure or "command:blank"
            failures.append(f"{lane_id}:command:blank")
            continue
        lower = command.lower()
        if "cargo " in command:
            if "rch exec --" not in command:
                first_failure = first_failure or f"missing_rch:{command}"
                failures.append(f"{lane_id}:missing_rch:{command}")
            elif not cargo_command_has_target_dir(command):
                first_failure = first_failure or f"missing_cargo_target_dir:{command}"
                failures.append(f"{lane_id}:missing_cargo_target_dir:{command}")
        elif "lake build" in command and "rch exec --" not in command:
            first_failure = first_failure or f"missing_rch:{command}"
            failures.append(f"{lane_id}:missing_rch:{command}")
        for marker in ("password=", "token=", "secret=", "bearer "):
            if marker in lower:
                first_failure = first_failure or f"sensitive_command_marker:{marker}"
                failures.append(f"{lane_id}:sensitive_command_marker:{marker}")

    if proof_tier in {"lean-checked", "tla-checked", "lab-oracle-backed", "artifact-contract-backed"}:
        if missing_evidence:
            first_failure = first_failure or "strong_tier_has_missing_evidence"
            failures.append(f"{lane_id}:strong_tier_has_missing_evidence")
        if not e2e_artifacts:
            first_failure = first_failure or "strong_tier_missing_e2e_artifact"
            failures.append(f"{lane_id}:strong_tier_missing_e2e_artifact")
    if proof_tier in {"assumption-bound", "unproved"}:
        if not missing_evidence:
            first_failure = first_failure or "weak_tier_missing_evidence_inventory"
            failures.append(f"{lane_id}:weak_tier_missing_evidence_inventory")
        for item in missing_evidence:
            if not isinstance(item, dict) or not str(item.get("owner_bead_id", "")).startswith("asupersync-"):
                first_failure = first_failure or "missing_evidence_without_owner"
                failures.append(f"{lane_id}:missing_evidence_without_owner")

    if not assumptions:
        first_failure = first_failure or "missing_assumptions"
        failures.append(f"{lane_id}:missing_assumptions")

    log_row(
        "lane-coverage",
        lane_id=lane_id,
        invariant_id=",".join(invariant_ids),
        proof_tier=proof_tier,
        theorem_name=",".join(theorem_names),
        model_artifact=first_or_empty(model_artifacts),
        source_path=first_or_empty(source_paths),
        runtime_test=first_or_empty(runtime_tests),
        e2e_artifact=first_or_empty(e2e_artifacts),
        assumption_count=len(assumptions),
        missing_evidence_count=len(missing_evidence),
        verdict="pass" if not first_failure else "fail",
        first_failure=first_failure,
    )

if len(lane_ids) != len(set(lane_ids)):
    failures.append("lane_id:duplicates")

missing_log_fields = required_log_fields - set(rows[0].keys() if rows else [])
if missing_log_fields:
    failures.append("required_log_fields:missing:" + ",".join(sorted(missing_log_fields)))

summary_first_failure = failures[0] if failures else ""
log_row(
    "summary",
    lane_id="formal_wave2_refinement_coverage",
    invariant_id=",".join(sorted(core_invariants)),
    proof_tier="mixed",
    theorem_name="mixed",
    model_artifact="artifacts/formal_wave2_refinement_coverage_v1.json",
    source_path="formal/lean/coverage",
    runtime_test="tests/formal_wave2_refinement_coverage_contract.rs",
    e2e_artifact=str(report_path.relative_to(repo_root)),
    assumption_count=sum(len(as_list(lane, "assumptions", "summary")) for lane in as_list(manifest, "lane_rows", "summary")),
    missing_evidence_count=sum(len(as_list(lane, "missing_evidence", "summary")) for lane in as_list(manifest, "lane_rows", "summary")),
    verdict="pass" if not failures else "fail",
    first_failure=summary_first_failure,
)

report = {
    "schema_version": "formal-wave2-refinement-coverage-report-v1",
    "bead_id": "asupersync-i6uzso",
    "wave_id": manifest.get("wave_id", ""),
    "manifest_path": str(manifest_path),
    "verdict": "passed" if not failures else "failed",
    "failures": failures,
    "rows": rows,
}
report_dir.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if failures:
    sys.exit(1)
PY
