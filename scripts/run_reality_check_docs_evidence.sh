#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${REPO_ROOT}/artifacts/reality_check_docs_contract_v1.json"
ARTIFACT_PATH="${REALITY_CHECK_DOCS_ARTIFACT_PATH:-${REPO_ROOT}/target/reality-check-docs/asupersync-rckdoc/docs-evidence-report.json}"

mkdir -p "$(dirname "${ARTIFACT_PATH}")"

python3 - "$REPO_ROOT" "$CONTRACT_PATH" "$ARTIFACT_PATH" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
artifact_path = Path(sys.argv[3])

contract = json.loads(contract_path.read_text())
drifts = []
checks = []


def repo_path(relative):
    return repo_root / relative


def read_text(relative):
    path = repo_path(relative)
    try:
        return path.read_text()
    except Exception as exc:
        drifts.append(f"read_failed:{relative}:{exc}")
        return ""


def record(scenario_id, **fields):
    row = {
        "bead_id": "asupersync-rckdoc",
        "scenario_id": scenario_id,
        **fields,
    }
    checks.append(row)
    ordered = [
        f"bead_id={row['bead_id']}",
        f"scenario_id={scenario_id}",
    ]
    for key in sorted(k for k in row if k not in {"bead_id", "scenario_id"}):
        value = row[key]
        if isinstance(value, (list, dict)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        ordered.append(f"{key}={value}")
    print(" ".join(ordered))


def require(condition, failure):
    if not condition:
        drifts.append(failure)


docs_checked = contract.get("docs_checked", [])
source_artifacts_checked = contract.get("source_artifacts_checked", [])
support_classes_seen = contract.get("support_classes_seen", [])
deferred_links_checked = contract.get("deferred_links_checked", [])
closed_bead_evidence_checked = contract.get("closed_bead_evidence_checked", [])

for doc in docs_checked:
    exists = repo_path(doc).is_file()
    require(exists, f"missing_doc:{doc}")
    record("doc-exists", doc=doc, exists=exists, verdict="pass" if exists else "fail")

for artifact in source_artifacts_checked:
    exists = repo_path(artifact).is_file()
    parse_ok = False
    if exists and artifact.endswith(".json"):
        try:
            json.loads(repo_path(artifact).read_text())
            parse_ok = True
        except Exception as exc:
            drifts.append(f"json_parse_failed:{artifact}:{exc}")
    else:
        parse_ok = exists
    require(exists, f"missing_source_artifact:{artifact}")
    require(parse_ok, f"unparseable_source_artifact:{artifact}")
    record(
        "source-artifact",
        artifact=artifact,
        exists=exists,
        parse_ok=parse_ok,
        verdict="pass" if exists and parse_ok else "fail",
    )

for doc_contract in contract.get("doc_marker_contract", []):
    path = doc_contract["path"]
    text = read_text(path)
    missing = [marker for marker in doc_contract.get("required", []) if marker not in text]
    stale = [marker for marker in doc_contract.get("forbidden", []) if marker in text]
    for marker in missing:
        drifts.append(f"missing_required_marker:{path}:{marker}")
    for marker in stale:
        drifts.append(f"forbidden_marker_present:{path}:{marker}")
    record(
        "doc-marker-contract",
        doc=path,
        required_count=len(doc_contract.get("required", [])),
        missing_required_count=len(missing),
        forbidden_count=len(doc_contract.get("forbidden", [])),
        stale_forbidden_count=len(stale),
        verdict="pass" if not missing and not stale else "fail",
        first_failure=(missing + stale + [""])[0],
    )

for support_row in contract.get("support_class_contract", []):
    support_class = support_row["support_class"]
    failures = []
    for requirement in support_row.get("docs_required", []):
        path = requirement["path"]
        text = read_text(path)
        for marker in requirement.get("markers", []):
            if marker not in text:
                failures.append(f"{path}:{marker}")
    for failure in failures:
        drifts.append(f"support_class_marker_missing:{support_class}:{failure}")
    record(
        "support-class-contract",
        support_class=support_class,
        docs_required=len(support_row.get("docs_required", [])),
        missing_count=len(failures),
        verdict="pass" if not failures else "fail",
        first_failure=(failures + [""])[0],
    )

for row in deferred_links_checked:
    surface_id = row["surface_id"]
    artifact = row["artifact"]
    artifact_exists = repo_path(artifact).exists()
    owner_bead = row.get("owner_bead", "")
    has_owner_or_reason = owner_bead.startswith("asupersync-") or bool(
        row.get("intentional_explanation", "").strip()
    )
    marker_failures = []
    for marker in row.get("doc_markers", []):
        text = read_text(marker["path"])
        if marker["marker"] not in text:
            marker_failures.append(f"{marker['path']}:{marker['marker']}")
    require(artifact_exists, f"deferred_artifact_missing:{surface_id}:{artifact}")
    require(has_owner_or_reason, f"deferred_owner_or_reason_missing:{surface_id}")
    for failure in marker_failures:
        drifts.append(f"deferred_marker_missing:{surface_id}:{failure}")
    record(
        "deferred-link",
        surface_id=surface_id,
        support_class=row.get("support_class", ""),
        owner_bead=owner_bead,
        artifact=artifact,
        artifact_exists=artifact_exists,
        marker_count=len(row.get("doc_markers", [])),
        missing_marker_count=len(marker_failures),
        verdict="pass"
        if artifact_exists and has_owner_or_reason and not marker_failures
        else "fail",
        first_failure=(marker_failures + [""])[0],
    )

git_available = (repo_root / ".git").exists()
for row in closed_bead_evidence_checked:
    bead_id = row["bead_id"]
    commit = row["commit"]
    commit_exists = True
    if git_available:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        commit_exists = result.returncode == 0
    evidence_missing = [
        path for path in row.get("evidence_files", []) if not repo_path(path).exists()
    ]
    has_commands = bool(row.get("validation_commands"))
    require(commit_exists, f"closed_bead_commit_missing:{bead_id}:{commit}")
    for path in evidence_missing:
        drifts.append(f"closed_bead_evidence_missing:{bead_id}:{path}")
    require(has_commands, f"closed_bead_validation_missing:{bead_id}")
    record(
        "closed-bead-evidence",
        closed_bead=bead_id,
        commit=commit,
        commit_exists=commit_exists,
        evidence_files=len(row.get("evidence_files", [])),
        evidence_missing_count=len(evidence_missing),
        validation_commands=len(row.get("validation_commands", [])),
        verdict="pass" if commit_exists and not evidence_missing and has_commands else "fail",
        first_failure=(evidence_missing + ([] if commit_exists else [commit]) + [""])[0],
    )

verdict = "passed" if not drifts else "failed"
report = {
    "bead_id": "asupersync-rckdoc",
    "contract_path": os.path.relpath(contract_path, repo_root),
    "docs_checked": docs_checked,
    "source_artifacts_checked": source_artifacts_checked,
    "support_classes_seen": support_classes_seen,
    "deferred_links_checked": len(deferred_links_checked),
    "closed_bead_evidence_checked": len(closed_bead_evidence_checked),
    "drift_count": len(drifts),
    "artifact_path": os.path.relpath(artifact_path, repo_root),
    "verdict": verdict,
    "first_failure": drifts[0] if drifts else "",
    "checks": checks,
    "drifts": drifts,
}

artifact_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
record(
    "summary",
    docs_checked=json.dumps(docs_checked, sort_keys=True),
    source_artifacts_checked=json.dumps(source_artifacts_checked, sort_keys=True),
    support_classes_seen=json.dumps(support_classes_seen, sort_keys=True),
    deferred_links_checked=len(deferred_links_checked),
    closed_bead_evidence_checked=len(closed_bead_evidence_checked),
    drift_count=len(drifts),
    artifact_path=os.path.relpath(artifact_path, repo_root),
    verdict=verdict,
    first_failure=drifts[0] if drifts else "",
)

if drifts:
    sys.exit(1)
PY
