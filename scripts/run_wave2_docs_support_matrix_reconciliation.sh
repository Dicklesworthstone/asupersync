#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${WAVE2_DOCS_SUPPORT_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/docs_support_matrix_reconciliation_evidence.json}"
OUTPUT_ROOT="${WAVE2_DOCS_SUPPORT_OUTPUT_ROOT:-${REPO_ROOT}/target/wave2-docs-support-matrix}"
RUN_ID="${WAVE2_DOCS_SUPPORT_RUN_ID:-default}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_wave2_docs_support_matrix_reconciliation.sh [options]

Options:
  --artifact <path>       Wave2 docs support evidence artifact to validate.
  --output-root <dir>     Directory for the reconciliation report.
  --run-id <id>           Stable run identifier used in the output path.
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

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$OUTPUT_ROOT" "$RUN_ID" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
output_root = Path(sys.argv[3])
run_id = sys.argv[4]
report_dir = output_root / "asupersync-xl06qj" / run_id
report_path = report_dir / "docs-support-matrix-report.json"

artifact = json.loads(artifact_path.read_text())
drifts = []
log_rows = []


def repo_path(relative):
    return repo_root / relative


def rel_path(path):
    try:
        return str(Path(path).resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)


def as_list(value, key):
    items = value.get(key, [])
    if not isinstance(items, list):
        drifts.append(f"{key}:not_array")
        return []
    return items


def require(condition, failure):
    if not condition:
        drifts.append(failure)


def read_text(relative):
    path = repo_path(relative)
    try:
        return path.read_text()
    except Exception as exc:
        drifts.append(f"read_failed:{relative}:{exc}")
        return ""


def compact(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


required_log_fields = as_list(artifact, "required_log_fields")
docs_checked = as_list(artifact, "docs_checked")
source_artifacts_checked = as_list(artifact, "source_artifacts_checked")
support_classes_seen = as_list(artifact, "public_support_classes")
command_examples = as_list(artifact, "command_examples_checked")
artifact_log_path = artifact.get("artifact_path", rel_path(artifact_path))


def record(scenario_id, *, verdict="pass", first_failure="", **fields):
    row = {
        "bead_id": "asupersync-xl06qj",
        "scenario_id": scenario_id,
        "docs_checked": docs_checked,
        "source_artifacts_checked": source_artifacts_checked,
        "support_classes_seen": support_classes_seen,
        "promoted_capabilities": promoted_capabilities,
        "deferred_capabilities": deferred_capabilities,
        "deferred_links_checked": len(deferred_capabilities),
        "command_examples_checked": len(command_examples),
        "drift_count": len(drifts),
        "artifact_path": artifact_log_path,
        "verdict": verdict,
        "first_failure": first_failure,
    }
    row.update(fields)
    missing = [field for field in required_log_fields if field not in row]
    if missing:
        drifts.append(f"{scenario_id}:log_fields_missing:{','.join(missing)}")
        row["drift_count"] = len(drifts)
        row["verdict"] = "fail"
        row["first_failure"] = row.get("first_failure") or drifts[-1]
    log_rows.append(row)
    print(" ".join(f"{field}={compact(row.get(field, ''))}" for field in required_log_fields))


require(
    artifact.get("schema_version") == "wave2-docs-support-matrix-reconciliation-evidence-v1",
    "schema_version:mismatch",
)
require(artifact.get("bead_id") == "asupersync-xl06qj", "bead_id:mismatch")
require(
    artifact.get("capability_id") == "docs_support_matrix_reconciliation",
    "capability_id:mismatch",
)

for path_key in ("runner_script", "contract_test"):
    path = artifact.get(path_key, "")
    require(bool(path), f"{path_key}:missing")
    require(repo_path(path).is_file(), f"{path_key}:not_found:{path}")

registry_path = artifact.get("deferred_registry_policy", {}).get(
    "registry_path",
    "artifacts/wave2_capability_evidence_registry_v1.json",
)
registry = json.loads(repo_path(registry_path).read_text())
promoted_states = set(
    registry.get("registry_contract", {}).get("promoted_states_require_full_evidence", [])
)
registry_rows = registry.get("capability_rows", [])
registry_by_capability = {row.get("capability_id", ""): row for row in registry_rows}
promoted_capabilities = sorted(
    row.get("capability_id", "")
    for row in registry_rows
    if row.get("promotion_state") in promoted_states
)
deferred_capabilities = sorted(
    row.get("capability_id", "")
    for row in registry_rows
    if row.get("promotion_state") not in promoted_states
)

for doc in docs_checked:
    exists = repo_path(doc).is_file()
    require(exists, f"doc_missing:{doc}")
record("docs-exist", verdict="pass" if not drifts else "fail", first_failure=drifts[0] if drifts else "")

for source in source_artifacts_checked:
    path = repo_path(source)
    exists = path.exists()
    parse_ok = True
    if exists and source.endswith(".json"):
        try:
            json.loads(path.read_text())
        except Exception as exc:
            parse_ok = False
            drifts.append(f"source_json_parse_failed:{source}:{exc}")
    require(exists, f"source_artifact_missing:{source}")
    require(parse_ok, f"source_artifact_unparseable:{source}")
record("source-artifacts", verdict="pass" if not drifts else "fail", first_failure=drifts[0] if drifts else "")

for doc_contract in as_list(artifact, "doc_marker_contract"):
    path = doc_contract.get("path", "")
    text = read_text(path)
    missing = [marker for marker in doc_contract.get("required", []) if marker not in text]
    stale = [marker for marker in doc_contract.get("forbidden", []) if marker in text]
    for marker in missing:
        drifts.append(f"doc_marker_missing:{path}:{marker}")
    for marker in stale:
        drifts.append(f"doc_forbidden_marker_present:{path}:{marker}")
    record(
        "doc-marker-contract",
        verdict="pass" if not missing and not stale else "fail",
        first_failure=(missing + stale + [""])[0],
        doc=path,
    )

for support_row in as_list(artifact, "support_class_doc_markers"):
    support_class = support_row.get("support_class", "")
    failures = []
    for requirement in support_row.get("docs_required", []):
        path = requirement.get("path", "")
        text = read_text(path)
        for marker in requirement.get("markers", []):
            if marker not in text:
                failures.append(f"{path}:{marker}")
    for failure in failures:
        drifts.append(f"support_class_marker_missing:{support_class}:{failure}")
    record(
        "support-class-contract",
        verdict="pass" if not failures else "fail",
        first_failure=(failures + [""])[0],
        support_class=support_class,
    )

declared_promoted = {
    row.get("capability_id", "")
    for row in as_list(artifact, "promoted_capability_markers")
}
missing_promoted = sorted(set(promoted_capabilities) - declared_promoted)
for capability_id in missing_promoted:
    drifts.append(f"promoted_capability_missing:{capability_id}")

for promoted_row in as_list(artifact, "promoted_capability_markers"):
    capability_id = promoted_row.get("capability_id", "")
    registry_row = registry_by_capability.get(capability_id)
    failures = []
    if registry_row is None:
        failures.append(f"registry_row_missing:{capability_id}")
    else:
        expected = promoted_row.get("expected_support_class_after", "")
        actual = registry_row.get("support_class_after", "")
        if expected and actual != expected:
            failures.append(f"support_class_after_mismatch:{capability_id}:{actual}:{expected}")
        if registry_row.get("promotion_state") in promoted_states:
            if registry_row.get("unsupported_reason", "").strip():
                failures.append(f"promoted_unsupported_reason_present:{capability_id}")
            if not registry_row.get("artifact_paths", []):
                failures.append(f"promoted_artifact_paths_empty:{capability_id}")
    for source in promoted_row.get("source_artifacts", []):
        if not repo_path(source).exists():
            failures.append(f"promoted_source_missing:{capability_id}:{source}")
    for marker in promoted_row.get("doc_markers", []):
        path = marker.get("path", "")
        text = read_text(path)
        marker_text = marker.get("marker", "")
        if marker_text not in text:
            failures.append(f"promoted_doc_marker_missing:{capability_id}:{path}:{marker_text}")
    for failure in failures:
        drifts.append(failure)
    record(
        "promoted-capability",
        verdict="pass" if not failures else "fail",
        first_failure=(failures + [""])[0],
        promoted_capability=capability_id,
    )

for row in registry_rows:
    capability_id = row.get("capability_id", "")
    if row.get("promotion_state") in promoted_states:
        continue
    has_reason = bool(row.get("unsupported_reason", "").strip())
    has_residual = bool(row.get("residual_risks", []))
    has_fallback_or_artifact = bool(
        row.get("fallback_target", "").strip()
        or row.get("planned_artifact_paths", [])
        or row.get("artifact_paths", [])
    )
    if not ((has_reason or has_residual) and has_fallback_or_artifact):
        drifts.append(f"deferred_rationale_missing:{capability_id}")
record(
    "deferred-registry-policy",
    verdict="pass" if not any(drift.startswith("deferred_rationale_missing:") for drift in drifts) else "fail",
    first_failure=next((drift for drift in drifts if drift.startswith("deferred_rationale_missing:")), ""),
)

all_commands = [entry.get("command", "") for entry in command_examples]
for row in registry_rows:
    all_commands.extend(row.get("unit_proof_commands", []))
    all_commands.extend(row.get("e2e_proof_commands", []))
for command in all_commands:
    if ("cargo " in command or "lake build" in command) and "rch exec --" not in command:
        drifts.append(f"command_missing_rch:{command}")
    for forbidden in ("password=", "token=", "secret=", "bearer "):
        if forbidden in command.lower():
            drifts.append(f"command_sensitive_marker:{forbidden}:{command}")
record(
    "proof-command-policy",
    verdict="pass" if not any(drift.startswith("command_") for drift in drifts) else "fail",
    first_failure=next((drift for drift in drifts if drift.startswith("command_")), ""),
)

verdict = "passed" if not drifts else "failed"
report = {
    "schema_version": "wave2-docs-support-matrix-reconciliation-report-v1",
    "bead_id": "asupersync-xl06qj",
    "capability_id": "docs_support_matrix_reconciliation",
    "run_id": run_id,
    "artifact_path": rel_path(artifact_path),
    "report_path": rel_path(report_path),
    "docs_checked": docs_checked,
    "source_artifacts_checked": source_artifacts_checked,
    "support_classes_seen": support_classes_seen,
    "promoted_capabilities": promoted_capabilities,
    "deferred_capabilities": deferred_capabilities,
    "deferred_links_checked": len(deferred_capabilities),
    "command_examples_checked": len(command_examples),
    "drift_count": len(drifts),
    "verdict": verdict,
    "first_failure": drifts[0] if drifts else "",
    "rows": log_rows,
    "drifts": drifts,
}

report_dir.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
record(
    "summary",
    docs_checked=docs_checked,
    source_artifacts_checked=source_artifacts_checked,
    support_classes_seen=support_classes_seen,
    promoted_capabilities=promoted_capabilities,
    deferred_capabilities=deferred_capabilities,
    deferred_links_checked=len(deferred_capabilities),
    command_examples_checked=len(command_examples),
    drift_count=len(drifts),
    artifact_path=artifact_log_path,
    verdict=verdict,
    first_failure=drifts[0] if drifts else "",
)

if drifts:
    print("validation_failed=" + ",".join(drifts), file=sys.stderr)
    sys.exit(1)
PY
