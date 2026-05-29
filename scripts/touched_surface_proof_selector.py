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
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db", ".beads/beads.db-wal"}


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
    normalized = path.strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


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


def dirty_receipt_from_data(data: dict[str, Any], dirty_receipt_path: str) -> dict[str, Any] | None:
    if dirty_receipt_path:
        return json.loads(Path(dirty_receipt_path).read_text(encoding="utf-8"))
    receipt = data.get("dirty_tree_receipt")
    return receipt if isinstance(receipt, dict) else None


def is_tracker_path(path: str) -> bool:
    normalized = normalize_path(path)
    return normalized in TRACKER_PATHS or normalized.startswith(".beads/")


def is_source_like_dirty_path(path: str) -> bool:
    normalized = normalize_path(path)
    if is_tracker_path(normalized):
        return False
    return normalized.startswith(
        (
            "src/",
            "tests/",
            "benches/",
            "examples/",
            "conformance/",
            "asupersync-",
            "franken",
            "drop_unwrap_finder/",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain",
        )
    )


def dirty_row_path(row: dict[str, Any]) -> str:
    return normalize_path(str(row.get("path", "")))


def dirty_row_owner(row: dict[str, Any]) -> str:
    owner = row.get("owner")
    if isinstance(owner, str) and owner:
        return owner
    evidence = row.get("evidence")
    if isinstance(evidence, dict):
        holder = evidence.get("reservation_holder") or evidence.get("message_from")
        if isinstance(holder, str):
            return holder
    return ""


def dirty_row_status(row: dict[str, Any]) -> str:
    return str(row.get("status", ""))


def dirty_row_staging_decision(row: dict[str, Any]) -> str:
    staging = row.get("staging_guidance")
    if isinstance(staging, dict):
        return str(staging.get("decision", ""))
    return ""


def dirty_row_relation(path: str, touched_files: list[str]) -> str:
    if any(matches_pattern(path, touched) or matches_pattern(touched, path) for touched in touched_files):
        return "overlaps-touched"
    return "outside-touched"


def normalize_dirty_rows(receipt: dict[str, Any], touched_files: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    raw_rows = receipt.get("rows")
    if not isinstance(raw_rows, list):
        return rows
    for item in raw_rows:
        if not isinstance(item, dict):
            continue
        path = dirty_row_path(item)
        if not path:
            continue
        classification = str(item.get("classification", "unattributed")) or "unattributed"
        rows.append(
            {
                "path": path,
                "status": dirty_row_status(item),
                "classification": classification,
                "owner": dirty_row_owner(item),
                "staging_decision": dirty_row_staging_decision(item),
                "scope": "tracker-only" if is_tracker_path(path) else "source-or-proof-surface",
                "relation_to_touched": dirty_row_relation(path, touched_files),
                "source_like": is_source_like_dirty_path(path),
            }
        )
    return sorted(rows, key=lambda row: row["path"])


def build_dirty_tree_preflight(
    receipt: dict[str, Any] | None,
    touched_files: list[str],
) -> dict[str, Any] | None:
    if receipt is None:
        return None

    rows = normalize_dirty_rows(receipt, touched_files)
    tracker_rows = [row for row in rows if row["scope"] == "tracker-only"]
    source_rows = [row for row in rows if row["scope"] != "tracker-only"]
    peer_rows = [
        row
        for row in source_rows
        if row["classification"] in {"peer-owned", "owner-conflict"}
    ]
    unattributed_rows = [row for row in source_rows if row["classification"] == "unattributed"]
    self_rows = [row for row in source_rows if row["classification"] == "self-owned"]
    self_outside_rows = [
        row for row in self_rows if row["relation_to_touched"] == "outside-touched"
    ]

    action_items: list[str] = []
    for row in peer_rows:
        action_items.append(
            "wait for peer-owned dirty path "
            f"{row['path']} held by {row['owner'] or 'unknown-owner'} before running cargo/rch proof"
        )
    for row in unattributed_rows:
        action_items.append(
            f"ask for handoff or reserve dirty path {row['path']} before running cargo/rch proof"
        )

    if peer_rows:
        decision = "wait"
        reason = "peer-owned dirty source/proof paths would be synced into the remote proof tree"
    elif unattributed_rows:
        decision = "ask-for-handoff"
        reason = "unattributed dirty source/proof paths need ownership before proof execution"
    elif self_outside_rows or tracker_rows:
        decision = "run-with-caveat"
        caveats = []
        if self_outside_rows:
            caveats.append("self-owned dirty paths outside touched surface are included in the proof tree")
        if tracker_rows:
            caveats.append("tracker-only dirt does not affect compiled code but must stay out of source commits")
        reason = "; ".join(caveats)
    else:
        decision = "run"
        reason = "dirty tree is clean or limited to self-owned touched paths"

    return {
        "decision": decision,
        "reason": reason,
        "dirty_path_count": len(rows),
        "tracker_only_count": len(tracker_rows),
        "source_or_proof_dirty_count": len(source_rows),
        "peer_owned_count": len(peer_rows),
        "unattributed_count": len(unattributed_rows),
        "self_owned_count": len(self_rows),
        "rows": rows,
        "blockers": peer_rows + unattributed_rows,
        "caveats": tracker_rows + self_outside_rows,
        "action_items": action_items,
    }


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
    dirty_preflight = build_dirty_tree_preflight(
        dirty_receipt_from_data(data, args.dirty_receipt),
        touched_files,
    )
    dirty_blocks = dirty_preflight is not None and dirty_preflight["decision"] in {
        "wait",
        "ask-for-handoff",
    }
    passes = (
        not no_touched_files
        and len(unmatched) == 0
        and len(blocked_selected) == 0
        and not dirty_blocks
    )

    action_items: list[str] = []
    for row in blocked_selected + blocked_supplemental:
        action_items.append(
            f"resolve blocked proof lane {row['lane_id']}: {row['blocked'].get('reason', '')}"
        )
    for path in unmatched:
        action_items.append(f"add a selection rule or lane source path for {path}")
    if no_touched_files:
        action_items.append("provide at least one touched file before selecting proof lanes")
    if dirty_preflight is not None:
        action_items.extend(dirty_preflight["action_items"])

    receipt = {
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
    if dirty_preflight is not None:
        receipt["summary"]["dirty_tree_decision"] = dirty_preflight["decision"]
        receipt["dirty_tree_preflight"] = dirty_preflight
        receipt["operator_notes"].append(
            "Dirty-tree preflight is advisory for proof execution; wait/ask decisions mean cargo/rch proof evidence would be contaminated."
        )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Select proof lanes for touched paths")
    parser.add_argument("--input", required=True, help="JSON touched-surface selector input")
    parser.add_argument(
        "--dirty-receipt",
        default="",
        help="Optional dirty_tree_ownership_receipt.py JSON output to gate proof execution",
    )
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
