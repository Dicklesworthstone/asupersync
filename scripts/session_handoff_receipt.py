#!/usr/bin/env python3
"""
Build a non-mutating JSON handoff receipt for shared-main agent sessions.

The live mode only runs read-only probes. Fixture mode is the contract surface:
it keeps tests deterministic and lets coordination failures be represented
without requiring a live Agent Mail server or rch daemon.
"""

import argparse
import datetime as dt
import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "session-handoff-receipt-v1"
NEXT_ACTIONS = {
    "claim-ready-bead",
    "avoid-peer-owned-surface",
    "wait-for-reservation",
    "proof-only",
    "reopen-stale-bead",
    "blocked",
}
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db"}
TRACKER_DIRS = {".beads"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_repo_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def paths_overlap(left: str, right: str) -> bool:
    left = normalize_repo_path(left)
    right = normalize_repo_path(right)
    if not left or not right:
        return False
    if left == right or fnmatch.fnmatchcase(left, right) or fnmatch.fnmatchcase(right, left):
        return True
    left_is_glob = any(char in left for char in "*?[")
    right_is_glob = any(char in right for char in "*?[")
    return (not left_is_glob and right.startswith(f"{left}/")) or (
        not right_is_glob and left.startswith(f"{right}/")
    )


def tracker_reservation_path(pattern: str) -> bool:
    return any(paths_overlap(pattern, path) for path in TRACKER_PATHS | TRACKER_DIRS)


def run_json(repo_path: Path, command: list[str], timeout: float) -> tuple[str, Any]:
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
        return "unavailable", None
    except subprocess.TimeoutExpired:
        return "timeout", None
    except subprocess.CalledProcessError as error:
        return f"error:{error.returncode}", None

    try:
        return "ok", json.loads(output.stdout)
    except json.JSONDecodeError:
        return "malformed-json", None


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
        if not line:
            continue
        status = line[:2]
        path = line[3:] if len(line) > 3 else ""
        if path:
            entries.append(
                {
                    "status": status,
                    "path": path,
                    "cluster": "unknown",
                    "action": "inspect diff and assign owner before validation",
                }
            )
    return entries


def live_probe(repo_path: Path, timeout: float) -> dict[str, Any]:
    branch_status, branch = run_text(repo_path, ["git", "branch", "--show-current"], timeout)
    upstream_status, upstream = run_text(
        repo_path,
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        timeout,
    )
    ahead = 0
    behind = 0
    if upstream_status == "ok" and upstream:
        counts_status, counts = run_text(
            repo_path,
            ["git", "rev-list", "--left-right", "--count", f"{upstream}...HEAD"],
            timeout,
        )
        if counts_status == "ok":
            parts = counts.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                behind = int(parts[0])
                ahead = int(parts[1])

    dirty_status, dirty_tree = run_json(
        repo_path,
        ["bash", "scripts/classify_dirty_tree.sh", "--json"],
        timeout,
    )
    if dirty_status != "ok":
        status_status, raw_status = run_text(
            repo_path,
            ["git", "status", "--porcelain=v1"],
            timeout,
        )
        dirty_tree = {
            "entries": parse_status_lines(raw_status if status_status == "ok" else ""),
            "staged_count": 0,
            "unstaged_tracked_count": 0,
            "untracked_count": 0,
        }
    dirty_entries = normalize_dirty_entries(dirty_tree if isinstance(dirty_tree, dict) else {})
    proof_runner_status, proof_suggestions = live_proof_suggestions(
        repo_path,
        [entry["path"] for entry in dirty_entries],
        timeout,
    )

    ready_status, ready = run_json(repo_path, ["br", "ready", "--json"], timeout)
    progress_status, progress = run_json(
        repo_path,
        ["br", "list", "--status", "in_progress", "--json"],
        timeout,
    )
    rch_status, rch_queue = run_text(repo_path, ["rch", "queue"], timeout)

    return {
        "git": {
            "branch": branch if branch_status == "ok" else "",
            "upstream": upstream if upstream_status == "ok" else "",
            "ahead": ahead,
            "behind": behind,
        },
        "dirty_tree": dirty_tree,
        "beads": {
            "ready": ready if ready_status == "ok" and isinstance(ready, list) else [],
            "in_progress": extract_issues(progress),
            "status": {
                "ready": ready_status,
                "in_progress": progress_status,
            },
        },
        "agent_mail": {
            "available": False,
            "reservations": [],
            "status": "not_configured",
        },
        "proof_runner": {
            "status": proof_runner_status,
            "suggested_lanes": proof_suggestions,
        },
        "rch": {
            "available": rch_status == "ok",
            "queue_summary": compact_summary(rch_queue) if rch_status == "ok" else rch_status,
        },
    }


def live_proof_suggestions(
    repo_path: Path,
    touched_files: list[str],
    timeout: float,
) -> tuple[str, list[str]]:
    if not touched_files:
        return "not_required", []

    command = [
        "python3",
        "scripts/proof_runner.py",
        "--suggest-lanes",
        "--touched-files",
        *touched_files[:25],
        "--output",
        "json",
    ]
    status, payload = run_json(repo_path, command, timeout)
    if status != "ok" or not isinstance(payload, dict):
        return status, []

    suggestions = payload.get("suggested_lanes", [])
    if not isinstance(suggestions, list):
        return "malformed-json", []
    return "ok", [str(lane) for lane in suggestions if isinstance(lane, str) and lane]


def extract_issues(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        issues = value.get("issues")
        if isinstance(issues, list):
            return [item for item in issues if isinstance(item, dict)]
    return []


def compact_summary(raw: str) -> str:
    return " ".join(raw.split())[:500]


def normalize_dirty_entries(source: dict[str, Any]) -> list[dict[str, str]]:
    raw_entries = source.get("entries", [])
    entries = []
    for item in raw_entries if isinstance(raw_entries, list) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", ""))
        if not path:
            continue
        entries.append(
            {
                "status": str(item.get("status", "")),
                "path": path,
                "cluster": str(item.get("cluster", "unknown")),
                "action": str(item.get("action", "")),
            }
        )
    return entries


def dirty_clusters(entries: list[dict[str, str]]) -> list[dict[str, Any]]:
    by_cluster: dict[str, dict[str, Any]] = {}
    for entry in entries:
        cluster = entry["cluster"] or "unknown"
        bucket = by_cluster.setdefault(
            cluster,
            {
                "cluster": cluster,
                "paths": [],
                "actions": [],
            },
        )
        bucket["paths"].append(entry["path"])
        action = entry.get("action", "")
        if action and action not in bucket["actions"]:
            bucket["actions"].append(action)
    return [by_cluster[key] for key in sorted(by_cluster)]


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def classify_reservations(agent: str, snapshot: dict[str, Any], now: str) -> list[dict[str, Any]]:
    now_ts = parse_timestamp(now) or dt.datetime.now(dt.timezone.utc)
    reservations = snapshot.get("reservations", [])
    rows = []
    for item in reservations if isinstance(reservations, list) else []:
        if not isinstance(item, dict):
            continue
        pattern = str(
            item.get("path_pattern")
            or item.get("path")
            or item.get("pattern")
            or item.get("glob")
            or ""
        )
        if not pattern:
            continue
        holder = str(
            item.get("agent_name")
            or item.get("agent")
            or item.get("holder")
            or item.get("owner")
            or ""
        )
        expires_ts = str(item.get("expires_ts") or item.get("expires_at") or "")
        released_ts = item.get("released_ts") or item.get("released_at")
        expires_at = parse_timestamp(expires_ts)
        expired = bool(released_ts) or bool(expires_at and expires_at <= now_ts)

        if expired:
            classification = "expired"
        elif not holder:
            classification = "unknown-owner"
        elif holder == agent:
            classification = "owned-active"
        elif tracker_reservation_path(pattern):
            classification = "tracker-conflict"
        else:
            classification = "peer-active"

        rows.append(
            {
                "path_pattern": pattern,
                "holder": holder or "unknown",
                "expires_ts": expires_ts,
                "exclusive": bool(item.get("exclusive", True)),
                "classification": classification,
            }
        )
    return rows


def stale_in_progress(
    issues: list[dict[str, Any]],
    now: str,
    stale_after_hours: int,
) -> list[dict[str, Any]]:
    now_ts = parse_timestamp(now) or dt.datetime.now(dt.timezone.utc)
    stale = []
    for issue in issues:
        updated = parse_timestamp(issue.get("updated_at"))
        if not updated:
            continue
        age_hours = (now_ts - updated).total_seconds() / 3600
        if age_hours >= stale_after_hours:
            issue_id = issue.get("id")
            if not isinstance(issue_id, str) or not issue_id:
                continue
            stale.append(
                {
                    "id": issue_id,
                    "assignee": str(issue.get("assignee", "")),
                    "updated_at": issue.get("updated_at", ""),
                    "age_hours": round(age_hours, 2),
                }
            )
    return stale


def bead_ids(issues: list[dict[str, Any]]) -> list[str]:
    ids = []
    for issue in issues:
        issue_id = issue.get("id")
        if isinstance(issue_id, str) and issue_id:
            ids.append(issue_id)
    return ids


def claimable_ready_ids(issues: list[dict[str, Any]]) -> list[str]:
    ids = []
    for issue in issues:
        if str(issue.get("issue_type") or "") == "epic":
            continue
        issue_id = issue.get("id")
        if isinstance(issue_id, str) and issue_id:
            ids.append(issue_id)
    return ids


def choose_next_action(
    ready_ids: list[str],
    dirty: list[dict[str, str]],
    reservations: list[dict[str, Any]],
    proof_suggestions: list[str],
    stale: list[dict[str, Any]],
    agent_mail_available: bool,
    branch: str,
) -> dict[str, Any]:
    conflicts = [
        row
        for row in reservations
        if row["classification"] in {"peer-active", "tracker-conflict", "unknown-owner"}
    ]
    if branch and branch != "main":
        return {
            "category": "blocked",
            "reason": "current branch is not main",
        }
    if conflicts:
        return {
            "category": "wait-for-reservation",
            "reason": "active peer or tracker reservation conflict",
            "path_pattern": conflicts[0]["path_pattern"],
            "holder": conflicts[0]["holder"],
        }
    if dirty:
        peer_dirty = [
            entry
            for entry in dirty
            if entry["cluster"] not in {"beads-tracker-state"}
            and "local" not in entry.get("cluster", "")
        ]
        if peer_dirty:
            return {
                "category": "avoid-peer-owned-surface",
                "reason": "dirty paths need owner attribution before staging or validation",
                "path": peer_dirty[0]["path"],
            }
    if ready_ids:
        return {
            "category": "claim-ready-bead",
            "reason": "ready bead exists and no blocking reservation was found",
            "bead_id": ready_ids[0],
        }
    if proof_suggestions:
        return {
            "category": "proof-only",
            "reason": "no ready bead is available, but proof suggestions exist",
            "lane": proof_suggestions[0],
        }
    if stale:
        return {
            "category": "reopen-stale-bead",
            "reason": "stale in-progress bead needs owner or reclaim review",
            "bead_id": stale[0].get("id", ""),
            "assignee": stale[0].get("assignee", ""),
            "updated_at": stale[0].get("updated_at", ""),
            "age_hours": stale[0].get("age_hours", 0),
        }
    if not agent_mail_available:
        return {
            "category": "blocked",
            "reason": "Agent Mail snapshot unavailable and no local ready work was found",
        }
    return {
        "category": "blocked",
        "reason": "no actionable ready bead or proof lane was found",
    }


def build_receipt(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
    stale_after_hours: int,
) -> dict[str, Any]:
    git = source.get("git", {})
    dirty_source = source.get("dirty_tree") or source.get("dirty_classifier") or {}
    dirty_entries = normalize_dirty_entries(dirty_source if isinstance(dirty_source, dict) else {})
    ready = extract_issues(source.get("beads", {}).get("ready", []))
    in_progress = extract_issues(source.get("beads", {}).get("in_progress", []))
    ready_ids = bead_ids(ready)
    claimable_ready = claimable_ready_ids(ready)
    in_progress_ids = bead_ids(in_progress)
    stale_ids = stale_in_progress(in_progress, generated_at, stale_after_hours)
    agent_mail = source.get("agent_mail", {})
    agent_mail_available = bool(agent_mail.get("available", False))
    reservations = classify_reservations(agent, agent_mail if isinstance(agent_mail, dict) else {}, generated_at)
    proof_runner = source.get("proof_runner", {})
    suggested_lanes = proof_runner.get("suggested_lanes", [])
    proof_suggestions = [
        str(lane) for lane in suggested_lanes if isinstance(lane, str) and lane
    ]
    rch = source.get("rch", {})
    branch = str(git.get("branch", ""))
    next_action = choose_next_action(
        claimable_ready,
        dirty_entries,
        reservations,
        proof_suggestions,
        stale_ids,
        agent_mail_available,
        branch,
    )
    if next_action["category"] not in NEXT_ACTIONS:
        raise ValueError(f"invalid next action: {next_action['category']}")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "agent": agent,
        "repo_path": repo_path,
        "branch": {
            "current": branch,
            "upstream": str(git.get("upstream", "")),
            "ahead": int(git.get("ahead", 0) or 0),
            "behind": int(git.get("behind", 0) or 0),
            "is_main": branch == "main",
        },
        "dirty_clusters": dirty_clusters(dirty_entries),
        "active_bead_ids": {
            "ready": ready_ids,
            "in_progress": in_progress_ids,
            "stale_in_progress": stale_ids,
        },
        "reservation_conflicts": [
            row
            for row in reservations
            if row["classification"] in {"peer-active", "tracker-conflict", "unknown-owner"}
        ],
        "reservation_snapshot": {
            "available": agent_mail_available,
            "classifications": reservations,
        },
        "proof_suggestions": proof_suggestions,
        "rch": {
            "available": bool(rch.get("available", False)),
            "queue_summary": compact_summary(str(rch.get("queue_summary", ""))),
        },
        "subsystems": {
            "git": "ok" if branch else "unavailable",
            "dirty_tree": "ok",
            "beads": str(source.get("beads", {}).get("status", "ok")),
            "agent_mail": "ok" if agent_mail_available else str(agent_mail.get("status", "unavailable")),
            "proof_runner": str(proof_runner.get("status", "ok")),
            "rch": "ok" if rch.get("available", False) else "unavailable",
        },
        "next_action": next_action,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit a redaction-safe, non-mutating shared-main handoff receipt."
    )
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Agent name for ownership classification")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic receipts")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument(
        "--stale-after-hours",
        type=int,
        default=12,
        help="Age threshold for stale in-progress candidates",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    generated_at = args.generated_at or utc_now()
    if args.fixture:
        source = load_json(args.fixture)
    else:
        source = live_probe(repo_path, args.timeout)

    receipt = build_receipt(
        source=source,
        repo_path=str(repo_path),
        agent=args.agent,
        generated_at=generated_at,
        stale_after_hours=args.stale_after_hours,
    )
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
