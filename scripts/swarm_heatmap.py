#!/usr/bin/env python3
"""Emit a non-mutating swarm heatmap for shared-main coordination.

The helper correlates agent activity, file reservations, dirty git paths, and
announced CARGO_TARGET_DIR values. It reads fixtures or optional snapshots and
never edits files, mutates Beads, sends Agent Mail, runs Cargo, branches, or
stages changes.
"""

import argparse
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-heatmap-v1"
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db", ".beads/beads.db-wal"}
TARGET_DIR_RE = re.compile(r"CARGO_TARGET_DIR(?:=|:)\s*`?([^`\s,;)]+)")
FORBIDDEN_COMMAND_TOKENS = [
    "git branch",
    "git checkout -b",
    "git switch -c",
    "git worktree",
    "git reset",
    "git clean",
    "cargo ",
    "rm -rf",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


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


def timestamp_key(value: str) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return ""
    return parsed.isoformat()


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def load_json(path: Path | None) -> Any:
    if path is None:
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rows_from(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in keys:
        maybe_rows = value.get(key)
        if isinstance(maybe_rows, list):
            rows.extend(item for item in maybe_rows if isinstance(item, dict))
    return rows


def holder_name(row: dict[str, Any]) -> str:
    for key in ("agent_name", "agent", "holder", "owner", "from", "name"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def row_pattern(row: dict[str, Any]) -> str:
    for key in ("path_pattern", "path", "pattern", "glob"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").rstrip("/")


def has_glob_magic(path: str) -> bool:
    return any(char in path for char in "*?[")


def path_matches(pattern: str, path: str) -> bool:
    pattern = normalize_path(pattern)
    path = normalize_path(path)
    if not pattern or not path:
        return False
    if pattern == path or fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path):
        return True
    pattern_is_glob = has_glob_magic(pattern)
    path_is_glob = has_glob_magic(path)
    return (not pattern_is_glob and path.startswith(f"{pattern}/")) or (
        not path_is_glob and pattern.startswith(f"{path}/")
    )


def path_overlaps(left: str, right: str) -> bool:
    return path_matches(left, right) or path_matches(right, left)


def is_active_reservation(row: dict[str, Any], now: str) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires_at = parse_timestamp(str(row.get("expires_ts") or row.get("expires_at") or ""))
    now_ts = parse_timestamp(now) or dt.datetime.now(dt.timezone.utc)
    return expires_at is None or expires_at > now_ts


def reservation_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(
        agent_mail,
        ("reservations", "active_reservations", "file_reservations", "granted"),
    )
    rows.extend(rows_from(source, ("reservations", "active_reservations")))
    return rows


def message_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(agent_mail, ("messages", "inbox", "threads"))
    rows.extend(rows_from(source, ("messages", "inbox", "threads")))
    return rows


def agent_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(agent_mail, ("agents",))
    rows.extend(rows_from(source, ("agents",)))
    return rows


def dirty_entries(source: dict[str, Any]) -> list[dict[str, str]]:
    dirty = source.get("dirty_tree", {}) if isinstance(source, dict) else {}
    rows = dirty.get("entries") if isinstance(dirty, dict) else []
    entries: list[dict[str, str]] = []
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        if path:
            entries.append({"status": str(item.get("status") or ""), "path": path})
    return sorted(entries, key=lambda row: row["path"])


def normalize_reservation(row: dict[str, Any], generated_at: str) -> dict[str, Any]:
    pattern = row_pattern(row)
    holder = holder_name(row)
    active = is_active_reservation(row, generated_at)
    released = bool(row.get("released_ts") or row.get("released_at"))
    if released:
        classification = "released"
    elif active:
        classification = "active"
    else:
        classification = "expired"
    return {
        "id": str(row.get("id") or ""),
        "path_pattern": pattern,
        "holder": holder or "unknown",
        "exclusive": bool(row.get("exclusive", True)),
        "expires_ts": str(row.get("expires_ts") or row.get("expires_at") or ""),
        "released": released,
        "classification": classification,
    }


def active_reservations(reservations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in reservations
        if row["classification"] == "active" and row["exclusive"] and row["path_pattern"]
    ]


def message_text(row: dict[str, Any]) -> str:
    return "\n".join(
        str(row.get(key, ""))
        for key in ("subject", "body_md", "body", "message", "thread_id", "paths", "target_dir")
    )


def target_dirs_for_agent(agent: str, messages: list[dict[str, Any]], agents: list[dict[str, Any]]) -> list[str]:
    dirs: set[str] = set()
    for row in agents:
        if holder_name(row) != agent:
            continue
        for key in ("target_dir", "cargo_target_dir"):
            value = row.get(key)
            if isinstance(value, str) and value:
                dirs.add(value)
        values = row.get("target_dirs")
        if isinstance(values, list):
            dirs.update(str(value) for value in values if isinstance(value, str) and value)
    for row in messages:
        if holder_name(row) != agent:
            continue
        text = message_text(row)
        dirs.update(match.group(1).strip("`'\"").rstrip(".") for match in TARGET_DIR_RE.finditer(text))
    return sorted(dirs)


def latest_activity(agent: str, messages: list[dict[str, Any]], agents: list[dict[str, Any]]) -> str:
    candidates: list[str] = []
    for row in agents:
        if holder_name(row) == agent:
            for key in ("last_active_ts", "last_seen_ts", "updated_at", "created_ts"):
                value = row.get(key)
                if isinstance(value, str) and value:
                    candidates.append(value)
    for row in messages:
        if holder_name(row) == agent:
            value = row.get("created_ts") or row.get("created_at")
            if isinstance(value, str) and value:
                candidates.append(value)
    return max(candidates, key=timestamp_key) if candidates else ""


def reservation_owner_for_path(path: str, reservations: list[dict[str, Any]]) -> dict[str, Any] | None:
    for row in reservations:
        if path_matches(row["path_pattern"], path):
            return row
    return None


def message_owner_for_path(path: str, messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [row for row in messages if path in message_text(row)]
    if not matches:
        return None
    return max(matches, key=lambda row: timestamp_key(str(row.get("created_ts") or row.get("created_at") or "")))


def dirty_rows(
    entries: list[dict[str, str]],
    agent: str,
    reservations: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in entries:
        path = entry["path"]
        reservation = reservation_owner_for_path(path, reservations)
        message = message_owner_for_path(path, messages)
        owner = reservation["holder"] if reservation else holder_name(message or {})
        source = "reservation" if reservation else "message" if message else "none"
        if path in TRACKER_PATHS:
            classification = "tracker-state"
            stay_off = True
        elif owner == agent:
            classification = "self-owned"
            stay_off = False
        elif owner:
            classification = "peer-owned"
            stay_off = True
        else:
            classification = "unattributed"
            stay_off = True
        rows.append(
            {
                "path": path,
                "status": entry["status"],
                "owner": owner,
                "owner_source": source,
                "classification": classification,
                "stay_off": stay_off,
            }
        )
    return rows


def reservation_overlaps(reservations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overlaps: list[dict[str, Any]] = []
    for left_index, left in enumerate(reservations):
        for right in reservations[left_index + 1 :]:
            if left["holder"] == right["holder"]:
                continue
            if not path_overlaps(left["path_pattern"], right["path_pattern"]):
                continue
            overlaps.append(
                {
                    "left_holder": left["holder"],
                    "left_path_pattern": left["path_pattern"],
                    "right_holder": right["holder"],
                    "right_path_pattern": right["path_pattern"],
                    "severity": "warning",
                }
            )
    return sorted(
        overlaps,
        key=lambda row: (
            row["left_path_pattern"],
            row["right_path_pattern"],
            row["left_holder"],
            row["right_holder"],
        ),
    )


def stay_off_surfaces(
    active: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    surfaces: list[dict[str, str]] = []
    for row in active:
        if row["holder"] == agent:
            continue
        surfaces.append(
            {
                "path": row["path_pattern"],
                "holder": row["holder"],
                "reason": "active peer reservation",
            }
        )
    for row in dirty:
        if not row["stay_off"]:
            continue
        holder = str(row.get("owner") or "unknown")
        surfaces.append(
            {
                "path": row["path"],
                "holder": holder,
                "reason": f"dirty {row['classification']}",
            }
        )
    unique = {(row["path"], row["holder"]): row for row in surfaces}
    return [unique[key] for key in sorted(unique)]


def open_surfaces(source: dict[str, Any], stay_off: list[dict[str, str]]) -> list[str]:
    blocked = [row["path"] for row in stay_off]
    candidates = source.get("candidate_surfaces", []) if isinstance(source, dict) else []
    open_paths = []
    for value in candidates if isinstance(candidates, list) else []:
        path = str(value)
        if path and not any(path_overlaps(path, blocked_path) for blocked_path in blocked):
            open_paths.append(path)
    return sorted(set(open_paths))


def active_agent_rows(
    reservations: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    agents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    names: set[str] = set()
    names.update(row["holder"] for row in reservations if row["holder"] != "unknown")
    names.update(row["owner"] for row in dirty if row["owner"])
    names.update(holder_name(row) for row in messages if holder_name(row))
    names.update(holder_name(row) for row in agents if holder_name(row))

    rows = []
    for name in sorted(names):
        agent_reservations = [row["path_pattern"] for row in reservations if row["holder"] == name]
        agent_dirty = [row["path"] for row in dirty if row["owner"] == name]
        agent_target_dirs = target_dirs_for_agent(name, messages, agents)
        if not agent_reservations and not agent_dirty and not agent_target_dirs:
            continue
        rows.append(
            {
                "name": name,
                "last_activity_ts": latest_activity(name, messages, agents),
                "active_reservations": agent_reservations,
                "dirty_paths": agent_dirty,
                "target_dirs": agent_target_dirs,
            }
        )
    return rows


def run_text(repo_path: Path, command: list[str], timeout: float) -> tuple[str, str]:
    try:
        output = subprocess.run(
            command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except FileNotFoundError:
        return "unavailable", ""
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except subprocess.CalledProcessError as error:
        return f"error:{error.returncode}", ""
    return "ok", output.stdout.rstrip("\n")


def parse_status_lines(raw: str) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        if len(line) >= 4:
            entries.append({"status": line[:2], "path": line[3:]})
    return entries


def live_probe(
    repo_path: Path,
    timeout: float,
    agents: Any,
    reservations: Any,
    messages: Any,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    return {
        "agents": rows_from(agents, ("agents",)),
        "agent_mail": {
            "available": bool(agents or reservations or messages),
            "status": "snapshot" if agents or reservations or messages else "snapshot-unavailable",
            "reservations": rows_from(reservations, ("reservations", "active_reservations", "granted")),
            "messages": rows_from(messages, ("messages", "inbox", "threads")),
        },
        "dirty_tree": {
            "status": status,
            "entries": parse_status_lines(raw_status if status == "ok" else ""),
        },
    }


def build_heatmap(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
) -> dict[str, Any]:
    reservations = [normalize_reservation(row, generated_at) for row in reservation_rows(source)]
    active = active_reservations(reservations)
    messages = message_rows(source)
    agents = agent_rows(source)
    dirty = dirty_rows(dirty_entries(source), agent, active, messages)
    stay_off = stay_off_surfaces(active, dirty, agent)
    active_agents = active_agent_rows(active, dirty, messages, agents)
    overlaps = reservation_overlaps(active)
    target_dirs = sorted(
        {
            target_dir
            for row in active_agents
            for target_dir in row["target_dirs"]
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": agent,
        "repo_path": repo_path,
        "summary": {
            "active_agents": len(active_agents),
            "active_reservations": len(active),
            "expired_or_released_reservations": sum(
                1 for row in reservations if row["classification"] != "active"
            ),
            "dirty_paths": len(dirty),
            "stay_off_surfaces": len(stay_off),
            "target_dirs": len(target_dirs),
        },
        "active_agents": active_agents,
        "reservations": {
            "active": active,
            "expired_or_released": [
                row for row in reservations if row["classification"] != "active"
            ],
            "overlaps": overlaps,
        },
        "dirty_paths": dirty,
        "target_dirs": target_dirs,
        "suggested_stay_off_surfaces": stay_off,
        "suggested_open_surfaces": open_surfaces(source, stay_off),
        "subsystems": {
            "git": str(source.get("dirty_tree", {}).get("status", "ok")),
            "agent_mail": str(source.get("agent_mail", {}).get("status", "fixture")),
        },
        "safety": {
            "mutating_commands_executed": False,
            "beads_mutated": False,
            "cargo_executed": False,
            "agent_mail_mutated": False,
            "branch_or_worktree_operations": False,
            "forbidden_command_tokens": [],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a read-only shared-main swarm heatmap.")
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Current agent name")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument("--agents-snapshot", type=Path, help="Optional Agent Mail agents JSON snapshot")
    parser.add_argument("--reservation-snapshot", type=Path, help="Optional reservation JSON snapshot")
    parser.add_argument("--message-snapshot", type=Path, help="Optional Agent Mail messages JSON snapshot")
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()
    generated_at = args.generated_at or utc_now()
    if args.fixture:
        source = load_json(args.fixture)
    else:
        source = live_probe(
            repo_path=repo_path,
            timeout=args.timeout,
            agents=load_json(args.agents_snapshot),
            reservations=load_json(args.reservation_snapshot),
            messages=load_json(args.message_snapshot),
        )
    receipt = build_heatmap(
        source=source if isinstance(source, dict) else {},
        repo_path=str(repo_path),
        agent=args.agent,
        generated_at=generated_at,
    )
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
