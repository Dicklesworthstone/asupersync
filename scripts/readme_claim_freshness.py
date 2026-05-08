#!/usr/bin/env python3
"""Check proof-status doc claim markers against live README/AGENTS text."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "readme-claim-freshness-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def claim_entries(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    entries = snapshot.get("claim_categories")
    if not isinstance(entries, list):
        raise ValueError("snapshot claim_categories must be an array")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"claim_categories[{index}] must be an object")
    return entries


def marker_map(entry: dict[str, Any]) -> dict[str, list[str]]:
    markers = entry.get("doc_claim_markers")
    if not isinstance(markers, dict):
        raise ValueError(f"{entry.get('claim_id', '<unknown>')} doc_claim_markers must be an object")

    result: dict[str, list[str]] = {}
    for doc_name, values in markers.items():
        if not isinstance(doc_name, str) or not doc_name:
            raise ValueError("doc_claim_markers document names must be nonempty strings")
        if not isinstance(values, list):
            raise ValueError(f"{doc_name} markers must be an array")
        normalized: list[str] = []
        for marker in values:
            if not isinstance(marker, str) or not marker.strip():
                raise ValueError(f"{doc_name} markers must be nonempty strings")
            normalized.append(marker)
        result[doc_name] = normalized
    return result


def build_receipt(
    *,
    snapshot_path: Path,
    readme_path: Path,
    agents_path: Path,
    generated_at: str,
) -> dict[str, Any]:
    snapshot = load_json(snapshot_path)
    docs = {
        "README.md": {
            "path": str(readme_path),
            "text": read_text(readme_path),
        },
        "AGENTS.md": {
            "path": str(agents_path),
            "text": read_text(agents_path),
        },
    }

    document_rows = {
        name: {
            "path": data["path"],
            "required_marker_count": 0,
            "present_marker_count": 0,
            "missing_marker_count": 0,
        }
        for name, data in docs.items()
    }

    claim_rows: list[dict[str, Any]] = []
    missing_total = 0
    required_total = 0
    present_total = 0

    for entry in claim_entries(snapshot):
        claim_id = entry.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id:
            raise ValueError("each claim category must have a nonempty claim_id")
        category = entry.get("category")
        if not isinstance(category, str) or not category:
            raise ValueError(f"{claim_id} must have a nonempty category")
        status = entry.get("status")
        if not isinstance(status, str) or not status:
            raise ValueError(f"{claim_id} must have a nonempty status")

        missing_markers: list[dict[str, str]] = []
        present_markers: list[dict[str, str]] = []
        for doc_name, markers in marker_map(entry).items():
            if doc_name not in docs:
                raise ValueError(f"{claim_id} references unsupported document {doc_name}")
            for marker in markers:
                document_rows[doc_name]["required_marker_count"] += 1
                required_total += 1
                marker_row = {"document": doc_name, "marker": marker}
                if marker in docs[doc_name]["text"]:
                    document_rows[doc_name]["present_marker_count"] += 1
                    present_total += 1
                    present_markers.append(marker_row)
                else:
                    document_rows[doc_name]["missing_marker_count"] += 1
                    missing_total += 1
                    missing_markers.append(marker_row)

        claim_rows.append(
            {
                "claim_id": claim_id,
                "category": category,
                "status": status,
                "fresh": not missing_markers,
                "required_marker_count": len(missing_markers) + len(present_markers),
                "present_marker_count": len(present_markers),
                "missing_marker_count": len(missing_markers),
                "missing_doc_markers": missing_markers,
            }
        )

    verdict = "fresh" if missing_total == 0 else "stale"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": generated_at[:10],
        "snapshot": str(snapshot_path),
        "documents": document_rows,
        "claim_count": len(claim_rows),
        "required_marker_count": required_total,
        "present_marker_count": present_total,
        "missing_marker_count": missing_total,
        "claims": claim_rows,
        "verdict": verdict,
        "decision": "passed" if verdict == "fresh" else "blocked-doc-stale",
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare proof status snapshot doc_claim_markers against README.md and AGENTS.md."
    )
    parser.add_argument("--snapshot", default="artifacts/proof_status_snapshot_v1.json")
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--agents", default="AGENTS.md")
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = build_receipt(
        snapshot_path=Path(args.snapshot),
        readme_path=Path(args.readme),
        agents_path=Path(args.agents),
        generated_at=args.generated_at,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
