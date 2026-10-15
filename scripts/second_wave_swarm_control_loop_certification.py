#!/usr/bin/env python3
"""Emit a deterministic second-wave swarm control-loop certification report.

The helper is intentionally read-only. It consumes an explicit fixture or
contract artifact and writes JSON or Markdown to stdout. It does not inspect
live trackers, launch proof commands, mutate Git, send mail, or rewrite files.
"""

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "second-wave-swarm-control-loop-certification-v1"
FIXTURE_SCHEMA_VERSION = "second-wave-swarm-control-loop-certification-fixture-v1"
CONTRACT_SCHEMA_VERSION = "second-wave-swarm-control-loop-certification-contract-v1"
REQUIRED_RCH_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- "


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def load_fixture(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: fixture must be a JSON object")
    if value.get("schema_version") == CONTRACT_SCHEMA_VERSION:
        fixture = value.get("fixture")
        if not isinstance(fixture, dict):
            raise SystemExit(f"{path}: contract artifact must contain fixture object")
    else:
        fixture = value
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: fixture schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    return fixture


def path_exists(repo_root: Path, path_text: str) -> bool:
    return bool(path_text) and (repo_root / path_text).exists()


def command_has_remote_envelope(command: str, envelope: dict[str, Any]) -> bool:
    timeout = int_value(envelope.get("timeout_seconds"))
    memory = int_value(envelope.get("memory_mb"))
    return (
        command.startswith(REQUIRED_RCH_PREFIX)
        and "CARGO_TARGET_DIR=" in command
        and bool_value(envelope.get("remote_required"))
        and bool_value(envelope.get("local_fallback_allowed"), True) is False
        and bool_value(envelope.get("target_dir_isolated"))
        and timeout > 0
        and memory > 0
    )


def row_source_paths(row: dict[str, Any]) -> list[str]:
    paths = [
        string(row.get("artifact_path")),
        string(row.get("script_path")),
        string(row.get("contract_test")),
        string(row.get("doc_path")),
    ]
    paths.extend(string_list(row.get("additional_receipts")))
    return [path for path in paths if path]


def row_digest(row: dict[str, Any]) -> str:
    material = {
        "child_bead_id": row.get("child_bead_id"),
        "artifact_path": row.get("artifact_path"),
        "contract_test": row.get("contract_test"),
        "receipt_schema_version": row.get("receipt_schema_version"),
        "rerun_command": row.get("rerun_command"),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def classify_row(
    fixture: dict[str, Any],
    row: dict[str, Any],
    required_children: set[str],
    repo_root: Path,
) -> dict[str, Any]:
    repo = fixture.get("repo") if isinstance(fixture.get("repo"), dict) else {}
    source_head = string(repo.get("source_head"))
    command = string(row.get("rerun_command"))
    envelope = row.get("command_envelope")
    if not isinstance(envelope, dict):
        envelope = {}

    reason_codes: list[str] = []
    child_bead_id = string(row.get("child_bead_id"))
    if child_bead_id not in required_children:
        reason_codes.append("unknown-child")
    if string(row.get("child_status")) != "closed":
        reason_codes.append("open-child")
    if not bool_value(row.get("current_receipt")):
        reason_codes.append("non-current-receipt")
    if string(row.get("artifact_head")) != source_head:
        reason_codes.append("stale-head")
    if not command_has_remote_envelope(command, envelope):
        reason_codes.append("missing-rch-envelope")
    if bool_value(row.get("local_fallback_observed")):
        reason_codes.append("local-fallback")
    if int_value(row.get("executed_tests")) <= 0:
        reason_codes.append("zero-test")
    if bool_value(row.get("advisory_only")):
        reason_codes.append("advisory-only")

    missing_paths = [
        path for path in row_source_paths(row) if not path_exists(repo_root, path)
    ]
    if missing_paths:
        reason_codes.append("missing-artifact")

    return {
        "evidence_id": string(row.get("evidence_id")),
        "child_bead_id": child_bead_id,
        "child_title": string(row.get("child_title")),
        "classification": "green" if not reason_codes else "red",
        "accepted": not reason_codes,
        "reason_codes": sorted(dict.fromkeys(reason_codes)),
        "artifact_path": string(row.get("artifact_path")),
        "script_path": string(row.get("script_path")),
        "contract_test": string(row.get("contract_test")),
        "doc_path": string(row.get("doc_path")),
        "additional_receipts": string_list(row.get("additional_receipts")),
        "receipt_schema_version": string(row.get("receipt_schema_version")),
        "executed_tests": int_value(row.get("executed_tests")),
        "advisory_only": bool_value(row.get("advisory_only")),
        "local_fallback_observed": bool_value(row.get("local_fallback_observed")),
        "artifact_head": string(row.get("artifact_head")),
        "source_head": source_head,
        "missing_paths": missing_paths,
        "command_envelope": envelope,
        "rerun_command": command,
        "refresh_command": string(row.get("refresh_command")),
        "evidence_digest": row_digest(row),
    }


def classify_fixture(
    fixture: dict[str, Any], generated_at: str, repo_root: Path
) -> dict[str, Any]:
    required_children = set(string_list(fixture.get("required_child_beads")))
    rows = [
        classify_row(fixture, row, required_children, repo_root)
        for row in dict_list(fixture.get("child_evidence"))
    ]
    rejected_rows = [
        classify_row(fixture, row, required_children, repo_root)
        for row in dict_list(fixture.get("rejection_fixtures"))
    ]
    accepted_children = {
        string(row.get("child_bead_id")) for row in rows if row.get("accepted")
    }
    missing_required = sorted(required_children - accepted_children)
    open_blockers = dict_list(fixture.get("open_blockers"))
    non_claims = string_list(fixture.get("non_claims"))
    operator_workflow_certified = (
        len(missing_required) == 0
        and all(bool_value(row.get("accepted")) for row in rows)
        and len(rows) == len(required_children)
    )
    parent_close_allowed = (
        operator_workflow_certified
        and not open_blockers
        and bool_value(fixture.get("parent_epic_close_allowed"))
    )
    summary = {
        "required_children": len(required_children),
        "accepted_rows": sum(1 for row in rows if row["accepted"]),
        "rejected_rows": len(rejected_rows),
        "missing_required_children": len(missing_required),
        "operator_workflow_certified": operator_workflow_certified,
        "certification_verdict": "pass" if operator_workflow_certified else "no_win",
        "parent_epic_close_allowed": parent_close_allowed,
        "release_ready": False,
        "broad_workspace_health": False,
        "performance_benchmark": False,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "bundle_id": string(fixture.get("bundle_id")),
        "parent_bead_id": string(fixture.get("parent_bead_id")),
        "generated_at": generated_at,
        "summary": summary,
        "missing_required_children": missing_required,
        "rows": rows,
        "rejected_rows": rejected_rows,
        "open_blockers": open_blockers,
        "non_claims": non_claims,
        "operator_refresh": fixture.get("operator_refresh", {}),
    }


def format_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Second-Wave Swarm Control-Loop Certification",
        "",
        f"bundle_id: `{report['bundle_id']}`",
        f"parent_bead_id: `{report['parent_bead_id']}`",
        f"generated_at: `{report['generated_at']}`",
        f"certification_verdict: `{summary['certification_verdict']}`",
        f"operator_workflow_certified: `{str(summary['operator_workflow_certified']).lower()}`",
        f"parent_epic_close_allowed: `{str(summary['parent_epic_close_allowed']).lower()}`",
        "",
        "## Green",
        "",
    ]
    for row in report["rows"]:
        status = "accepted" if row["accepted"] else "rejected"
        lines.extend(
            [
                f"- `{row['child_bead_id']}` {status}: {row['child_title']}",
                f"  - artifact: `{row['artifact_path']}`",
                f"  - contract: `{row['contract_test']}`",
                f"  - rerun: `{row['rerun_command']}`",
            ]
        )
    lines.extend(["", "## Yellow", ""])
    for blocker in report["open_blockers"]:
        lines.append(
            f"- `{string(blocker.get('id'))}` {string(blocker.get('status'))}: {string(blocker.get('reason'))}"
        )
    for non_claim in report["non_claims"]:
        lines.append(f"- {non_claim}")
    lines.extend(["", "## Red", ""])
    for row in report["rejected_rows"]:
        lines.append(
            f"- `{row['evidence_id']}` rejected for `{', '.join(row['reason_codes'])}`"
        )
    lines.extend(["", "## Exact Rerun Commands", ""])
    for row in report["rows"]:
        lines.append(f"- `{row['child_bead_id']}`: `{row['rerun_command']}`")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit a second-wave swarm control-loop certification report."
    )
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument(
        "--output",
        choices=["json", "markdown"],
        default="json",
        help="Report format to write to stdout.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="Repository root used for source-reference existence checks.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fixture = load_fixture(args.fixture)
    report = classify_fixture(fixture, args.generated_at, args.repo_root)
    if args.output == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(format_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
