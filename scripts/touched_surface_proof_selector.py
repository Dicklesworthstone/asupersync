#!/usr/bin/env python3
"""Select proof lanes for touched paths without running proofs.

The selector consumes a manifest-shaped fixture with explicit path rules and
proof lanes. It produces a deterministic receipt that separates directly
selected proof lanes from supplemental broad-frontier lanes and blocked lanes.
"""

import argparse
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "touched-surface-proof-selector-v1"
INPUT_SCHEMA_VERSION = "touched-surface-proof-selector-input-v1"


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


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def normalize_path(path: str) -> str:
    return path.strip().lstrip("./")


def matches_pattern(path: str, pattern: str) -> bool:
    normalized = normalize_path(path)
    pattern = normalize_path(pattern)
    if pattern.endswith("/**"):
        return normalized.startswith(pattern[:-3].rstrip("/") + "/")
    if pattern.endswith("/"):
        return normalized.startswith(pattern)
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(normalized, pattern)
    return normalized == pattern or normalized.startswith(pattern.rstrip("/") + "/")


def lane_id(lane: dict[str, Any]) -> str:
    return str(lane.get("lane_id", ""))


def normalize_lanes(raw_lanes: list[Any]) -> dict[str, dict[str, Any]]:
    lanes: dict[str, dict[str, Any]] = {}
    for item in raw_lanes:
        if not isinstance(item, dict):
            continue
        lid = lane_id(item)
        if not lid:
            continue
        lanes[lid] = {
            "lane_id": lid,
            "kind": str(item.get("kind", "")),
            "command": str(item.get("command", "")),
            "guarantee_ids": sorted(set(string_list(item.get("guarantee_ids")))),
            "source_paths": sorted(set(string_list(item.get("source_paths")))),
            "covers": str(item.get("covers", "")),
            "explicit_not_covered": str(item.get("explicit_not_covered", "")),
            "broad_frontier": bool(item.get("broad_frontier", False)),
        }
    return lanes


def normalize_rules(raw_rules: list[Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        patterns = sorted(set(string_list(item.get("patterns"))))
        lane_ids = sorted(set(string_list(item.get("lane_ids"))))
        supplemental_lane_ids = sorted(set(string_list(item.get("supplemental_lane_ids"))))
        if not patterns or (not lane_ids and not supplemental_lane_ids):
            continue
        rules.append(
            {
                "rule_id": str(item.get("rule_id", "")),
                "patterns": patterns,
                "lane_ids": lane_ids,
                "supplemental_lane_ids": supplemental_lane_ids,
                "reason": str(item.get("reason", "")),
            }
        )
    return sorted(rules, key=lambda rule: rule["rule_id"])


def normalize_blocked(raw_blocked: list[Any]) -> dict[str, dict[str, Any]]:
    blocked: dict[str, dict[str, Any]] = {}
    for item in raw_blocked:
        if not isinstance(item, dict):
            continue
        lid = str(item.get("lane_id", ""))
        if not lid:
            continue
        blocked[lid] = {
            "lane_id": lid,
            "reason": str(item.get("reason", "")),
            "blocked_by_paths": sorted(set(string_list(item.get("blocked_by_paths")))),
        }
    return blocked


def add_selection(
    selections: dict[str, dict[str, Any]],
    lanes: dict[str, dict[str, Any]],
    lane: str,
    touched_path: str,
    rule_id: str,
    reason: str,
) -> None:
    if lane not in lanes:
        return
    entry = selections.setdefault(
        lane,
        {
            "lane": lanes[lane],
            "matched_paths": [],
            "rule_ids": [],
            "reasons": [],
        },
    )
    entry["matched_paths"] = sorted(set(entry["matched_paths"] + [touched_path]))
    if rule_id:
        entry["rule_ids"] = sorted(set(entry["rule_ids"] + [rule_id]))
    if reason:
        entry["reasons"] = sorted(set(entry["reasons"] + [reason]))


def select_by_rules(
    touched_files: list[str],
    lanes: dict[str, dict[str, Any]],
    rules: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], set[str]]:
    direct: dict[str, dict[str, Any]] = {}
    supplemental: dict[str, dict[str, Any]] = {}
    matched_paths: set[str] = set()

    for path in touched_files:
        for rule in rules:
            if not any(matches_pattern(path, pattern) for pattern in rule["patterns"]):
                continue
            matched_paths.add(path)
            for lane in rule["lane_ids"]:
                add_selection(direct, lanes, lane, path, rule["rule_id"], rule["reason"])
            for lane in rule["supplemental_lane_ids"]:
                add_selection(supplemental, lanes, lane, path, rule["rule_id"], rule["reason"])

    return direct, supplemental, matched_paths


def select_by_lane_sources(
    touched_files: list[str],
    lanes: dict[str, dict[str, Any]],
    already_matched_paths: set[str],
) -> dict[str, dict[str, Any]]:
    direct: dict[str, dict[str, Any]] = {}
    for path in touched_files:
        if path in already_matched_paths:
            continue
        for lane in lanes.values():
            if any(matches_pattern(path, source) for source in lane["source_paths"]):
                add_selection(
                    direct,
                    lanes,
                    lane["lane_id"],
                    path,
                    "source-path-fallback",
                    "touched path overlaps lane source_paths",
                )
    return direct


def split_blocked(
    selections: dict[str, dict[str, Any]],
    blocked: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    available: list[dict[str, Any]] = []
    blocked_rows: list[dict[str, Any]] = []
    for lane, selection in sorted(selections.items()):
        row = {
            "lane_id": lane,
            "kind": selection["lane"]["kind"],
            "command": selection["lane"]["command"],
            "guarantee_ids": selection["lane"]["guarantee_ids"],
            "matched_paths": selection["matched_paths"],
            "rule_ids": selection["rule_ids"],
            "reasons": selection["reasons"],
            "broad_frontier": selection["lane"]["broad_frontier"],
        }
        if lane in blocked:
            row["blocked"] = blocked[lane]
            blocked_rows.append(row)
        else:
            available.append(row)
    return available, blocked_rows


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    generated_at = args.generated_at or utc_now()

    touched_files = sorted({normalize_path(path) for path in string_list(data.get("touched_files"))})
    lanes = normalize_lanes(as_list(data.get("lanes")))
    rules = normalize_rules(as_list(data.get("selection_rules")))
    blocked = normalize_blocked(as_list(data.get("blocked_lanes")))

    direct, supplemental, matched = select_by_rules(touched_files, lanes, rules)
    fallback = select_by_lane_sources(touched_files, lanes, matched)
    for lane, selection in fallback.items():
        if lane not in direct:
            direct[lane] = selection

    all_matched_paths = set()
    for selections in [direct, supplemental]:
        for selection in selections.values():
            all_matched_paths.update(selection["matched_paths"])

    selected, blocked_selected = split_blocked(direct, blocked)
    supplemental_selected, blocked_supplemental = split_blocked(supplemental, blocked)
    unmatched = [path for path in touched_files if path not in all_matched_paths]
    no_touched_files = len(touched_files) == 0
    passes = not no_touched_files and len(unmatched) == 0 and len(blocked_selected) == 0

    action_items: list[str] = []
    for row in blocked_selected + blocked_supplemental:
        action_items.append(
            f"resolve blocked proof lane {row['lane_id']}: {row['blocked'].get('reason', '')}"
        )
    for path in unmatched:
        action_items.append(f"add a selection rule or lane source path for {path}")
    if no_touched_files:
        action_items.append("provide at least one touched file before selecting proof lanes")

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": data.get("schema_version", ""),
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "source": str(input_path),
        "source_counts": {
            "touched_files": len(touched_files),
            "lanes": len(lanes),
            "selection_rules": len(rules),
            "blocked_lanes": len(blocked),
        },
        "summary": {
            "passes": passes,
            "selected_count": len(selected),
            "supplemental_count": len(supplemental_selected),
            "blocked_selected_count": len(blocked_selected),
            "unmatched_touched_count": len(unmatched),
        },
        "touched_files": touched_files,
        "selected_lanes": selected,
        "supplemental_lanes": supplemental_selected,
        "blocked_selected_lanes": blocked_selected,
        "blocked_supplemental_lanes": blocked_supplemental,
        "unmatched_touched_files": unmatched,
        "action_items": action_items,
        "operator_notes": [
            "Selected lanes are proof suggestions only; this helper does not execute rch or cargo.",
            "Supplemental lanes are broad frontier evidence and should not be cited as the only touched-surface proof.",
            "Blocked lanes must be surfaced separately instead of replaced by unrelated green checks.",
        ],
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_rch": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_agent_mail_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Select proof lanes for touched paths")
    parser.add_argument("--input", required=True, help="JSON touched-surface selector input")
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
