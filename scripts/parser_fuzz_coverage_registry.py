#!/usr/bin/env python3
"""Build a deterministic public-parser fuzz coverage registry.

The helper is intentionally fixture/input driven. It does not scan, mutate, or
register fuzz targets; it turns an explicit parser-surface inventory into a
machine-readable coverage receipt that can gate later fuzz-governance work.
"""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "parser-fuzz-coverage-registry-v1"
INPUT_SCHEMA_VERSION = "parser-fuzz-coverage-input-v1"
RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def current_date(generated_at: str) -> dt.date:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date()
    return parsed.date()


def parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def surface_id(surface: dict[str, Any]) -> str:
    return str(surface.get("id") or f"{surface.get('path', '')}::{surface.get('symbol', '')}")


def target_id(target: dict[str, Any]) -> str:
    return str(target.get("id") or target.get("path") or "unknown-target")


def normalize_surfaces(raw: list[Any]) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        sid = surface_id(item)
        surfaces.append(
            {
                "id": sid,
                "path": str(item.get("path", "")),
                "symbol": str(item.get("symbol", "")),
                "visibility": str(item.get("visibility", "pub")),
                "input_kind": str(item.get("input_kind", "")),
                "risk": str(item.get("risk", "medium")).lower(),
                "category": str(item.get("category", "uncategorized")),
            }
        )
    return sorted(surfaces, key=lambda surface: surface["id"])


def normalize_targets(raw: list[Any]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        tid = target_id(item)
        existing = by_id.get(tid)
        normalized = {
            "id": tid,
            "path": str(item.get("path", "")),
            "exists": bool(item.get("exists", True)),
            "covers": sorted(set(string_list(item.get("covers")))),
            "references": sorted(set(string_list(item.get("references")))),
        }
        if existing is None:
            by_id[tid] = normalized
            continue
        existing["exists"] = bool(existing["exists"] or normalized["exists"])
        existing["covers"] = sorted(set(existing["covers"]) | set(normalized["covers"]))
        existing["references"] = sorted(set(existing["references"]) | set(normalized["references"]))
        if not existing["path"] and normalized["path"]:
            existing["path"] = normalized["path"]
    normalized_targets = [
        {
            "id": str(target["id"]),
            "path": str(target["path"]),
            "exists": bool(target["exists"]),
            "covers": sorted(set(string_list(target["covers"]))),
            "references": sorted(set(string_list(target["references"]))),
        }
        for target in by_id.values()
    ]
    return sorted(normalized_targets, key=lambda target: target["id"])


def normalize_exemptions(raw: list[Any]) -> dict[str, dict[str, Any]]:
    exemptions: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("surface_id", ""))
        if not sid:
            continue
        exemptions[sid] = {
            "surface_id": sid,
            "reason": str(item.get("reason", "")),
            "expires": str(item.get("expires", "")),
        }
    return exemptions


def valid_exemption(exemption: dict[str, Any] | None, today: dt.date) -> tuple[bool, str]:
    if exemption is None:
        return False, "missing"
    reason = str(exemption.get("reason", "")).strip()
    expires_raw = str(exemption.get("expires", ""))
    expires = parse_date(expires_raw)
    if not reason:
        return False, "missing-reason"
    if expires is None:
        return False, "invalid-expiry"
    if expires < today:
        return False, "expired"
    return True, "valid"


def target_partially_references(surface: dict[str, Any], target: dict[str, Any]) -> bool:
    references = set(target["references"])
    if surface["id"] in references:
        return True
    if surface["symbol"] and surface["symbol"] in references:
        return True
    return bool(surface["path"] and surface["path"] in references)


def classify_surface(
    surface: dict[str, Any],
    targets: list[dict[str, Any]],
    exemption: dict[str, Any] | None,
    today: dt.date,
) -> dict[str, Any]:
    sid = surface["id"]
    covering = [target for target in targets if sid in target["covers"] and target["exists"]]
    stale_covering = [target for target in targets if sid in target["covers"] and not target["exists"]]
    partial = [
        target
        for target in targets
        if sid not in target["covers"] and target["exists"] and target_partially_references(surface, target)
    ]
    exemption_ok, exemption_status = valid_exemption(exemption, today)

    if covering:
        status = "covered"
    elif exemption_ok:
        status = "exempt"
    elif partial:
        status = "partial"
    else:
        status = "missing"

    evidence = {
        "covering_targets": [target["id"] for target in covering],
        "partial_targets": [target["id"] for target in partial],
        "stale_covering_targets": [target["id"] for target in stale_covering],
        "exemption_status": exemption_status,
    }
    if exemption is not None:
        evidence["exemption"] = exemption

    return {
        "surface": surface,
        "status": status,
        "risk_rank": RISK_RANK.get(surface["risk"], RISK_RANK["medium"]),
        "evidence": evidence,
    }


def build_action_items(records: list[dict[str, Any]]) -> list[str]:
    action_items: list[str] = []
    for record in records:
        sid = record["surface"]["id"]
        status = record["status"]
        if status == "missing":
            action_items.append(f"add a fuzz target covering {sid}")
        elif status == "partial":
            action_items.append(f"make coverage for {sid} explicit with a target covers entry")
        stale_targets = record["evidence"]["stale_covering_targets"]
        if stale_targets:
            action_items.append(f"refresh stale fuzz target evidence for {sid}: {', '.join(stale_targets)}")
        if record["evidence"]["exemption_status"] in {"missing-reason", "invalid-expiry", "expired"}:
            action_items.append(f"repair exemption metadata for {sid}")
    return action_items


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    generated_at = args.generated_at or utc_now()
    today = current_date(generated_at)

    surfaces = normalize_surfaces(as_list(data.get("parser_surfaces")))
    targets = normalize_targets(as_list(data.get("fuzz_targets")))
    exemptions = normalize_exemptions(as_list(data.get("exemptions")))
    records = [classify_surface(surface, targets, exemptions.get(surface["id"]), today) for surface in surfaces]

    counts = {
        "covered": sum(1 for record in records if record["status"] == "covered"),
        "exempt": sum(1 for record in records if record["status"] == "exempt"),
        "partial": sum(1 for record in records if record["status"] == "partial"),
        "missing": sum(1 for record in records if record["status"] == "missing"),
        "stale_covering_targets": sum(
            len(record["evidence"]["stale_covering_targets"]) for record in records
        ),
        "invalid_exemptions": sum(
            1
            for record in records
            if record["evidence"]["exemption_status"] in {"missing-reason", "invalid-expiry", "expired"}
        ),
    }
    input_schema_recognized = data.get("schema_version") == INPUT_SCHEMA_VERSION
    every_public_surface_accounted_for = counts["missing"] == 0
    partial_references_absent = counts["partial"] == 0
    exemptions_valid = counts["invalid_exemptions"] == 0
    active_target_coverage_only = counts["stale_covering_targets"] == 0
    passes = (
        input_schema_recognized
        and every_public_surface_accounted_for
        and partial_references_absent
        and exemptions_valid
        and active_target_coverage_only
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": data.get("schema_version", ""),
        "generated_at": generated_at,
        "current_date": today.isoformat(),
        "source": str(input_path),
        "source_counts": {
            "parser_surfaces": len(surfaces),
            "fuzz_targets": len(targets),
            "exemptions": len(exemptions),
        },
        "summary": counts | {"passes": passes},
        "requirements": {
            "input_schema_recognized": input_schema_recognized,
            "every_public_byte_or_string_parser_has_coverage_or_exemption": every_public_surface_accounted_for,
            "partial_references_are_not_counted_as_coverage": partial_references_absent,
            "exemptions_have_reason_and_future_expiry": exemptions_valid,
            "coverage_uses_active_fuzz_target": active_target_coverage_only,
        },
        "coverage": records,
        "missing_coverage": [record["surface"]["id"] for record in records if record["status"] == "missing"],
        "partial_coverage": [record["surface"]["id"] for record in records if record["status"] == "partial"],
        "action_items": build_action_items(records),
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
            "edits_fuzz_manifest": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a parser fuzz coverage registry")
    parser.add_argument("--input", required=True, help="JSON parser/fuzz inventory")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
