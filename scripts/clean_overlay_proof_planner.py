#!/usr/bin/env python3
"""Build a deterministic clean-overlay proof input manifest.

The planner is a non-mutating preflight helper. It models which selected paths
may enter a focused RCH proof overlay and which dirty shared-main paths must be
excluded or treated as blockers before proof execution.
"""

import argparse
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "clean-overlay-proof-planner-v1"
INPUT_SCHEMA_VERSION = "clean-overlay-proof-planner-input-v1"
FORBIDDEN_ACTIONS = {
    "runs_cargo": False,
    "runs_rch": False,
    "runs_git_mutation": False,
    "runs_git_branch": False,
    "runs_git_worktree": False,
    "runs_destructive_command": False,
    "runs_agent_mail_mutation": False,
    "runs_beads_mutation": False,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def has_glob_magic(path: str) -> bool:
    return any(char in path for char in "*?[")


def path_matches(pattern: str, path: str) -> bool:
    pattern = normalize_path(pattern)
    path = normalize_path(path)
    if not pattern or not path:
        return False
    if pattern == path:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path):
        return True
    pattern_is_glob = has_glob_magic(pattern)
    path_is_glob = has_glob_magic(path)
    return (not pattern_is_glob and path.startswith(pattern + "/")) or (
        not path_is_glob and pattern.startswith(path + "/")
    )


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [normalize_path(item) for item in as_list(value) if isinstance(item, str) and normalize_path(item)]


def holder_name(row: dict[str, Any]) -> str:
    for key in ("agent_name", "agent", "holder", "owner", "from", "name"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def row_pattern(row: dict[str, Any]) -> str:
    for key in ("path_pattern", "path", "pattern", "glob"):
        value = row.get(key)
        if isinstance(value, str) and normalize_path(value):
            return normalize_path(value)
    return ""


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def active_reservation(row: dict[str, Any], generated_at: str) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires = parse_timestamp(row.get("expires_ts") or row.get("expires_at"))
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    return expires is None or expires > now


def normalized_reservations(data: dict[str, Any], generated_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in as_list(data.get("reservations")):
        if not isinstance(item, dict):
            continue
        pattern = row_pattern(item)
        holder = holder_name(item)
        if not pattern or not holder:
            continue
        rows.append(
            {
                "holder": holder,
                "path_pattern": pattern,
                "exclusive": bool(item.get("exclusive", True)),
                "active": active_reservation(item, generated_at),
                "reservation_id": str(item.get("id", "")),
                "expires_ts": str(item.get("expires_ts") or item.get("expires_at") or ""),
            }
        )
    return sorted(rows, key=lambda row: (row["path_pattern"], row["holder"], row["reservation_id"]))


def dirty_status(raw_status: str) -> str:
    status = raw_status.strip()
    if not status:
        return "modified"
    if status == "??":
        return "untracked"
    if "D" in status:
        return "deleted"
    if "R" in status:
        return "renamed"
    return "modified"


def normalized_dirty_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in as_list(data.get("dirty_entries")):
        if not isinstance(item, dict):
            continue
        path = normalize_path(str(item.get("path", "")))
        if not path:
            continue
        status = dirty_status(str(item.get("status", item.get("kind", ""))))
        rows.append(
            {
                "path": path,
                "status": status,
                "raw_status": str(item.get("status", "")),
            }
        )
    return sorted(rows, key=lambda row: row["path"])


def matching_reservations(
    path: str,
    reservations: list[dict[str, Any]],
    agent_name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matches = [
        row
        for row in reservations
        if row["active"] and row["exclusive"] and path_matches(row["path_pattern"], path)
    ]
    self_rows = [row for row in matches if row["holder"] == agent_name]
    peer_rows = [row for row in matches if row["holder"] != agent_name]
    return self_rows, peer_rows


def selected_match(path: str, selected_patterns: list[str]) -> str:
    for pattern in selected_patterns:
        if path_matches(pattern, path):
            return pattern
    return ""


def clean_selected_rows(
    selected_patterns: list[str],
    dirty_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    dirty_paths = {row["path"] for row in dirty_rows}
    rows = []
    for pattern in selected_patterns:
        if has_glob_magic(pattern):
            continue
        if pattern not in dirty_paths:
            rows.append(
                {
                    "path": pattern,
                    "status": "clean-at-head",
                    "matched_selected_pattern": pattern,
                    "overlay_source": "head",
                    "reservation_evidence": [],
                }
            )
    return rows


def blocker(kind: str, path: str, detail: str, matched_pattern: str = "") -> dict[str, str]:
    row = {"kind": kind, "path": path, "detail": detail}
    if matched_pattern:
        row["matched_selected_pattern"] = matched_pattern
    return row


def build_manifest(data: dict[str, Any], generated_at: str) -> dict[str, Any]:
    agent_name = str(data.get("agent_name", ""))
    selected_patterns = sorted(set(string_list(data.get("selected_paths"))))
    dirty_rows = normalized_dirty_entries(data)
    reservations = normalized_reservations(data, generated_at)
    report_only = bool(data.get("report_only", False))

    included = clean_selected_rows(selected_patterns, dirty_rows)
    excluded: list[dict[str, Any]] = []
    blockers: list[dict[str, str]] = []

    for row in dirty_rows:
        path = row["path"]
        matched = selected_match(path, selected_patterns)
        self_reservations, peer_reservations = matching_reservations(path, reservations, agent_name)
        reservation_evidence = self_reservations or peer_reservations

        if row["status"] == "deleted":
            blockers.append(blocker("deleted-path-refused", path, "deleted paths are never admitted to a clean proof overlay", matched))
            excluded.append(
                {
                    "path": path,
                    "status": row["status"],
                    "reason": "deleted-path-refused",
                    "reservation_evidence": reservation_evidence,
                }
            )
            continue

        if not matched:
            blockers.append(blocker("unselected-dirty-path", path, "dirty path is outside selected overlay inputs"))
            excluded.append(
                {
                    "path": path,
                    "status": row["status"],
                    "reason": "outside-selected-paths",
                    "reservation_evidence": reservation_evidence,
                }
            )
            continue

        if not self_reservations:
            kind = "selected-path-reserved-by-peer" if peer_reservations else "selected-path-unreserved"
            detail = (
                "selected path is reserved by another agent"
                if peer_reservations
                else "selected dirty path lacks an active self reservation"
            )
            blockers.append(blocker(kind, path, detail, matched))
            excluded.append(
                {
                    "path": path,
                    "status": row["status"],
                    "matched_selected_pattern": matched,
                    "reason": kind,
                    "reservation_evidence": reservation_evidence,
                }
            )
            continue

        included.append(
            {
                "path": path,
                "status": row["status"],
                "matched_selected_pattern": matched,
                "overlay_source": "worktree-untracked" if row["status"] == "untracked" else "worktree-dirty",
                "reservation_evidence": self_reservations,
            }
        )

    included = sorted(included, key=lambda row: (row["path"], row["status"]))
    excluded = sorted(excluded, key=lambda row: (row["path"], row["reason"]))
    blockers = sorted(blockers, key=lambda row: (row["path"], row["kind"]))

    proof_allowed = len(blockers) == 0 and len(selected_patterns) > 0 and not report_only
    decision = "admit-clean-overlay-proof" if proof_allowed else "fail-closed"
    if report_only:
        decision = "report-only-dry-run"

    command_intent = data.get("command_intent") if isinstance(data.get("command_intent"), dict) else {}
    no_claim_boundaries = string_list(data.get("no_claim_boundaries"))
    if not no_claim_boundaries:
        no_claim_boundaries = [
            "does not prove broad workspace health",
            "does not run cargo or rch",
            "does not authorize local cargo fallback",
            "does not permit branches, worktrees, scratch clones, or destructive cleanup",
        ]

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": str(data.get("schema_version", "")),
        "generated_at": generated_at,
        "agent_name": agent_name,
        "head": str(data.get("head", "")),
        "decision": decision,
        "proof_allowed": proof_allowed,
        "report_only": report_only,
        "summary": {
            "selected_pattern_count": len(selected_patterns),
            "included_count": len(included),
            "excluded_dirty_count": len(excluded),
            "blocker_count": len(blockers),
        },
        "selected_paths": selected_patterns,
        "included_paths": included,
        "excluded_dirty_paths": excluded,
        "blockers": blockers,
        "command_intent": {
            "description": str(command_intent.get("description", "")),
            "command": str(command_intent.get("command", "")),
            "remote_required": bool(command_intent.get("remote_required", True)),
        },
        "no_claim_boundaries": no_claim_boundaries,
        "operator_notes": [
            "This helper only plans proof inputs; it never constructs a branch, worktree, scratch clone, or overlay directory.",
            "Default mode fails closed on any unselected dirty path, deleted path, or selected dirty path without an active self reservation.",
            "Set report_only=true only for dry-run reporting; report-only output is not proof admission.",
        ],
        "non_mutating": True,
        "forbidden_actions": FORBIDDEN_ACTIONS,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a clean-overlay proof input manifest")
    parser.add_argument("--input", required=True, help="JSON planner input fixture")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        manifest = build_manifest(data, args.generated_at or utc_now())
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
