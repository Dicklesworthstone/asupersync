#!/usr/bin/env python3
"""Render a non-mutating claim/reservation/start-message receipt.

The receipt models the safe shared-main sequence for claiming a bead:
inspect, reserve tracker files, reserve implementation files, update Beads,
and send an Agent Mail start message. This script never performs those
actions; it emits the exact next commands and fails closed when a fixture says
the sequence would conflict.
"""

import argparse
import fnmatch
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SCHEMA_VERSION = "claim-reservation-start-receipt-v1"
TRACKER_PATHS = [".beads/issues.jsonl", ".beads/beads.db"]
MUTATING_FORBIDDEN = [
    "git branch",
    "git checkout -b",
    "git switch -c",
    "git worktree",
    "git reset",
    "git clean",
    "cargo ",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic claim/reservation/start-message receipt."
    )
    parser.add_argument("--bead-id", required=True)
    parser.add_argument("--agent-name", required=True)
    parser.add_argument("--project-key", default="/data/projects/asupersync")
    parser.add_argument("--planned-path", action="append", default=[])
    parser.add_argument("--reservation-snapshot", required=True)
    parser.add_argument("--git-status-snapshot", required=True)
    parser.add_argument("--generated-at", default="2026-05-08T00:00:00Z")
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text())
    except Exception as error:
        return {"unavailable": True, "error": str(error), "path": path}


def parse_time(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def path_matches(pattern: str, path: str) -> bool:
    pattern = pattern.strip().replace("\\", "/")
    path = path.strip().replace("\\", "/")
    if not pattern or not path:
        return False
    pattern_dir = pattern.rstrip("/")
    path_dir = path.rstrip("/")
    return (
        pattern == path
        or fnmatch.fnmatchcase(path, pattern)
        or fnmatch.fnmatchcase(pattern, path)
        or path_dir.startswith(pattern_dir + "/")
        or pattern_dir.startswith(path_dir + "/")
    )


def first_match(pattern: str, paths: Iterable[str]) -> Optional[str]:
    for path in paths:
        if path_matches(pattern, path):
            return path
    return None


def snapshot_rows(snapshot: Any) -> List[Dict[str, Any]]:
    if isinstance(snapshot, list):
        return [item for item in snapshot if isinstance(item, dict)]
    if not isinstance(snapshot, dict):
        return []
    rows: List[Dict[str, Any]] = []
    for key in ("reservations", "active_reservations", "granted"):
        value = snapshot.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    return rows


def snapshot_conflicts(snapshot: Any) -> List[Dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return []
    conflicts = snapshot.get("conflicts")
    if not isinstance(conflicts, list):
        return []
    return [item for item in conflicts if isinstance(item, dict)]


def holder_name(row: Dict[str, Any]) -> str:
    for key in ("agent", "agent_name", "holder", "owner"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def row_pattern(row: Dict[str, Any]) -> str:
    for key in ("path_pattern", "path", "pattern", "glob"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def is_active(row: Dict[str, Any], now: datetime) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires = parse_time(str(row.get("expires_ts") or row.get("expires_at") or ""))
    if expires is None:
        return True
    return expires > now


def normalized_conflict(
    path: str,
    pattern: str,
    holder: str,
    kind: str,
    source: str,
    expires_ts: str = "",
) -> Dict[str, Any]:
    return {
        "kind": kind,
        "path": path,
        "path_pattern": pattern,
        "holder": holder or "unknown",
        "expires_ts": expires_ts,
        "source": source,
    }


def analyze_reservations(
    snapshot: Any,
    agent_name: str,
    planned_paths: List[str],
    generated_at: str,
) -> Dict[str, Any]:
    now = parse_time(generated_at) or datetime.now(timezone.utc)
    tracker_conflicts: List[Dict[str, Any]] = []
    implementation_conflicts: List[Dict[str, Any]] = []

    if isinstance(snapshot, dict) and snapshot.get("unavailable"):
        conflict = normalized_conflict(
            str(snapshot.get("path", "")),
            str(snapshot.get("path", "")),
            "",
            "reservation-snapshot-unavailable",
            "snapshot",
        )
        return {
            "tracker": {"status": "blocked", "conflicts": [conflict]},
            "implementation": {"status": "blocked", "conflicts": [conflict]},
        }

    for conflict in snapshot_conflicts(snapshot):
        path = str(conflict.get("path") or "")
        holders = conflict.get("holders")
        if not isinstance(holders, list) or not holders:
            holders = [conflict]
        for holder in holders:
            if not isinstance(holder, dict):
                continue
            pattern = row_pattern(holder) or path
            owner = holder_name(holder)
            expires_ts = str(holder.get("expires_ts") or holder.get("expires_at") or "")
            row = normalized_conflict(path, pattern, owner, "", "snapshot.conflicts", expires_ts)
            if first_match(pattern, TRACKER_PATHS) or first_match(path, TRACKER_PATHS):
                row["kind"] = "tracker-reservation-conflict"
                tracker_conflicts.append(row)
            if first_match(pattern, planned_paths) or first_match(path, planned_paths):
                row["kind"] = "implementation-reservation-conflict"
                implementation_conflicts.append(row)

    for row in snapshot_rows(snapshot):
        if not row.get("exclusive", True) or not is_active(row, now):
            continue
        holder = holder_name(row)
        if holder == agent_name:
            continue
        pattern = row_pattern(row)
        if not pattern:
            continue
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        tracker_path = first_match(pattern, TRACKER_PATHS)
        implementation_path = first_match(pattern, planned_paths)
        if tracker_path:
            tracker_conflicts.append(
                normalized_conflict(
                    tracker_path,
                    pattern,
                    holder,
                    "tracker-reservation-conflict",
                    "snapshot.reservations",
                    expires_ts,
                )
            )
        if implementation_path:
            implementation_conflicts.append(
                normalized_conflict(
                    implementation_path,
                    pattern,
                    holder,
                    "implementation-reservation-conflict",
                    "snapshot.reservations",
                    expires_ts,
                )
            )

    return {
        "tracker": {
            "status": "blocked" if tracker_conflicts else "clear",
            "conflicts": tracker_conflicts,
        },
        "implementation": {
            "status": "blocked" if implementation_conflicts else "clear",
            "conflicts": implementation_conflicts,
        },
    }


def status_lines(snapshot: Any) -> List[str]:
    if isinstance(snapshot, list):
        return [str(line) for line in snapshot]
    if isinstance(snapshot, dict):
        value = snapshot.get("status_lines")
        if isinstance(value, list):
            return [str(line) for line in value]
    return []


def staged_paths(snapshot: Any) -> List[str]:
    paths: List[str] = []
    for line in status_lines(snapshot):
        if len(line) < 4:
            continue
        index_status = line[0]
        if index_status not in (" ", "?"):
            paths.append(line[3:])
    return paths


def analyze_dirty_index(snapshot: Any) -> Dict[str, Any]:
    staged = staged_paths(snapshot)
    return {
        "status": "blocked" if staged else "clear",
        "staged_paths": staged,
    }


def command_sequence(
    bead_id: str,
    agent_name: str,
    project_key: str,
    planned_paths: List[str],
    allowed: bool,
) -> List[Dict[str, Any]]:
    tracker = json.dumps(TRACKER_PATHS)
    planned = json.dumps(planned_paths)
    return [
        {
            "step": 1,
            "tool": "br",
            "command": f"br show {bead_id} --json",
            "mutates": False,
            "allowed_now": True,
        },
        {
            "step": 2,
            "tool": "Agent Mail",
            "command": (
                "file_reservation_paths("
                f"project_key={project_key!r}, agent_name={agent_name!r}, "
                f"paths={tracker}, ttl_seconds=3600, exclusive=true)"
            ),
            "mutates": True,
            "allowed_now": True,
        },
        {
            "step": 3,
            "tool": "Agent Mail",
            "command": (
                "file_reservation_paths("
                f"project_key={project_key!r}, agent_name={agent_name!r}, "
                f"paths={planned}, ttl_seconds=3600, exclusive=true)"
            ),
            "mutates": True,
            "allowed_now": True,
        },
        {
            "step": 4,
            "tool": "br",
            "command": f"br update {bead_id} --status in_progress --assignee {agent_name} --json",
            "mutates": True,
            "allowed_now": allowed,
        },
        {
            "step": 5,
            "tool": "Agent Mail",
            "command": (
                "send_message("
                f"project_key={project_key!r}, sender_name={agent_name!r}, "
                f"thread_id={bead_id!r}, subject='[{bead_id}] start', "
                f"body_md='Reserved paths: {', '.join(planned_paths)}')"
            ),
            "mutates": True,
            "allowed_now": allowed,
        },
    ]


def recommended_action(
    reservation: Dict[str, Any],
    dirty_index: Dict[str, Any],
) -> str:
    if dirty_index["status"] == "blocked":
        return "clear-dirty-index-before-claim"
    if reservation["tracker"]["status"] == "blocked":
        return "wait-for-tracker-reservation"
    if reservation["implementation"]["status"] == "blocked":
        return "wait-for-implementation-reservation"
    return "run-claim-sequence"


def build_receipt(args: argparse.Namespace) -> Dict[str, Any]:
    planned_paths = sorted(set(args.planned_path))
    reservation_snapshot = load_json(args.reservation_snapshot)
    git_status_snapshot = load_json(args.git_status_snapshot)
    reservation = analyze_reservations(
        reservation_snapshot,
        args.agent_name,
        planned_paths,
        args.generated_at,
    )
    dirty_index = analyze_dirty_index(git_status_snapshot)
    action = recommended_action(reservation, dirty_index)
    allowed = action == "run-claim-sequence"
    commands = command_sequence(
        args.bead_id,
        args.agent_name,
        args.project_key,
        planned_paths,
        allowed,
    )
    command_text = "\n".join(item["command"] for item in commands)
    forbidden_hits = [token for token in MUTATING_FORBIDDEN if token in command_text]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": args.generated_at,
        "bead_id": args.bead_id,
        "agent": args.agent_name,
        "project_key": args.project_key,
        "planned_paths": planned_paths,
        "tracker_paths": TRACKER_PATHS,
        "preflight": {
            "reservation": reservation,
            "dirty_index": dirty_index,
            "forbidden_command_tokens": forbidden_hits,
        },
        "tracker_mutation_status": "ready" if allowed else "not-attempted",
        "implementation_reservation_status": reservation["implementation"]["status"],
        "message_status": "ready" if allowed else "not-attempted",
        "recommended_next_action": action,
        "planned_commands": commands,
    }


def main() -> int:
    args = parse_args()
    receipt = build_receipt(args)
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
