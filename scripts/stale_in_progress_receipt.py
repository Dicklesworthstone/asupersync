#!/usr/bin/env python3
"""Emit a non-mutating stale in-progress bead analysis receipt.

The helper correlates fixture or read-only live inputs across Beads, Agent Mail,
recent commits, and dirty tracker state. It never reopens, closes, comments on,
or claims a bead. Instead it emits the exact proposed follow-up command or
message for an operator/agent to run after obtaining the right reservation.
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "stale-in-progress-receipt-v1"
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db"}
CLASSIFICATIONS = {
    "fresh-active-peer",
    "probably-stale",
    "blocked-by-active-reservation",
    "closed-by-recent-commit",
    "needs-human-escalation",
}
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


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


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


def age_hours(now: dt.datetime, timestamp: Any) -> float | None:
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return None
    return round((now - parsed).total_seconds() / 3600, 2)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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
    return "ok", output.stdout.strip()


def extract_issues(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        issues = value.get("issues")
        if isinstance(issues, list):
            return [item for item in issues if isinstance(item, dict)]
    return []


def extract_rows(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
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


def row_holder(row: dict[str, Any]) -> str:
    for key in ("agent_name", "agent", "holder", "owner", "from"):
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


def contains_bead(row: dict[str, Any], bead_id: str) -> bool:
    haystack = " ".join(
        str(row.get(key, ""))
        for key in ("id", "thread_id", "subject", "body_md", "message", "reason", "summary", "hash")
    )
    return bead_id in haystack


def dirty_tracker_status(source: dict[str, Any]) -> dict[str, Any]:
    dirty = source.get("dirty_tree") or {}
    entries = dirty.get("entries") if isinstance(dirty, dict) else []
    rows = [item for item in entries if isinstance(item, dict)]
    dirty_paths = [str(row.get("path", "")) for row in rows if row.get("path")]
    tracker_dirty = [path for path in dirty_paths if path in TRACKER_PATHS]
    non_tracker_dirty = [path for path in dirty_paths if path and path not in TRACKER_PATHS]
    if tracker_dirty and not non_tracker_dirty:
        status = "dirty-tracker-only"
    elif tracker_dirty:
        status = "dirty-tracker-and-code"
    elif dirty_paths:
        status = "dirty-non-tracker"
    else:
        status = "clean"
    return {
        "status": status,
        "tracker_paths": tracker_dirty,
        "non_tracker_paths": non_tracker_dirty,
    }


def reservation_rows(agent_mail: dict[str, Any]) -> list[dict[str, Any]]:
    rows = extract_rows(
        agent_mail,
        ("reservations", "active_reservations", "file_reservations", "granted"),
    )
    conflicts = extract_rows(agent_mail, ("conflicts",))
    for conflict in conflicts:
        holders = conflict.get("holders")
        if isinstance(holders, list):
            path = str(conflict.get("path", ""))
            for holder in holders:
                if isinstance(holder, dict):
                    merged = dict(holder)
                    if path and not row_pattern(merged):
                        merged["path_pattern"] = path
                    rows.append(merged)
        else:
            rows.append(conflict)
    return rows


def active_reservation_for(
    rows: list[dict[str, Any]],
    bead_id: str,
    generated_at: str,
) -> dict[str, Any] | None:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    best: dict[str, Any] | None = None
    for row in rows:
        if not row.get("exclusive", True):
            continue
        if row.get("released_ts") or row.get("released_at"):
            continue
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        expires_at = parse_timestamp(expires_ts)
        active = expires_at is None or expires_at > now
        if not active:
            continue
        if not contains_bead(row, bead_id):
            pattern = row_pattern(row)
            reason = str(row.get("reason", ""))
            if bead_id not in reason and bead_id not in pattern:
                continue
        best = row
        break
    return best


def expired_reservation_for(
    rows: list[dict[str, Any]],
    bead_id: str,
    generated_at: str,
) -> dict[str, Any] | None:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    for row in rows:
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        expires_at = parse_timestamp(expires_ts)
        if expires_at is None or expires_at > now:
            continue
        if contains_bead(row, bead_id):
            return row
    return None


def agent_profiles(agent_mail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for row in extract_rows(agent_mail, ("agents", "profiles")):
        name = row_holder(row) or str(row.get("name", ""))
        if name:
            profiles[name] = row
    return profiles


def recent_message_for(agent_mail: dict[str, Any], bead_id: str) -> dict[str, Any] | None:
    messages = extract_rows(agent_mail, ("messages", "inbox", "threads"))
    matches = [row for row in messages if contains_bead(row, bead_id)]
    matches.sort(key=lambda row: str(row.get("created_ts") or row.get("created_at") or ""), reverse=True)
    return matches[0] if matches else None


def recent_commit_for(source: dict[str, Any], bead_id: str) -> dict[str, Any] | None:
    git = source.get("git", {})
    commits = extract_rows(git, ("recent_commits", "commits"))
    for commit in commits:
        if contains_bead(commit, bead_id):
            return commit
    return None


def live_probe(repo_path: Path, timeout: float) -> dict[str, Any]:
    progress_status, progress = run_json(
        repo_path,
        ["br", "list", "--status", "in_progress", "--json"],
        timeout,
    )
    log_status, log_text = run_text(
        repo_path,
        ["git", "log", "--date=iso-strict", "--pretty=format:%H%x09%cI%x09%s", "-50"],
        timeout,
    )
    commits = []
    if log_status == "ok":
        for line in log_text.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3:
                commits.append(
                    {
                        "hash": parts[0],
                        "created_ts": parts[1],
                        "subject": parts[2],
                    }
                )
    status_status, raw_status = run_text(
        repo_path,
        ["git", "status", "--porcelain=v1"],
        timeout,
    )
    dirty_entries = []
    if status_status == "ok":
        for line in raw_status.splitlines():
            if len(line) >= 4:
                dirty_entries.append({"status": line[:2], "path": line[3:]})

    return {
        "beads": {
            "status": progress_status,
            "in_progress": extract_issues(progress),
        },
        "agent_mail": {
            "available": False,
            "status": "live-agent-mail-not-configured",
            "agents": [],
            "reservations": [],
            "messages": [],
        },
        "git": {
            "status": log_status,
            "recent_commits": commits,
        },
        "dirty_tree": {
            "status": status_status,
            "entries": dirty_entries,
        },
    }


def proposed_action(
    classification: str,
    bead_id: str,
    assignee: str,
    holder: str,
    commit: dict[str, Any] | None,
) -> dict[str, Any]:
    if classification == "fresh-active-peer":
        recipient = assignee or holder or "peer-agent"
        return {
            "kind": "agent-mail-reply",
            "mutates": True,
            "allowed_now": True,
            "target": recipient,
            "command": (
                "send_message("
                f"thread_id={bead_id!r}, to={[recipient]!r}, "
                f"subject='[{bead_id}] freshness check', "
                "body_md='I see active work/reservations and will stand off.')"
            ),
        }
    if classification == "blocked-by-active-reservation":
        return {
            "kind": "agent-mail-reply",
            "mutates": True,
            "allowed_now": True,
            "target": holder or "reservation-holder",
            "command": (
                "send_message("
                f"thread_id={bead_id!r}, to={[holder or 'reservation-holder']!r}, "
                "subject='Reservation freshness check', "
                "body_md='Please confirm whether this reservation is still active.')"
            ),
        }
    if classification == "closed-by-recent-commit":
        commit_hash = str((commit or {}).get("hash", ""))[:12]
        return {
            "kind": "br-update-command",
            "mutates": True,
            "allowed_now": False,
            "requires": "tracker reservation plus clean staged index",
            "command": f"br close {bead_id} --reason 'Shipped in {commit_hash}' --json",
        }
    if classification == "probably-stale":
        return {
            "kind": "br-update-command",
            "mutates": True,
            "allowed_now": False,
            "requires": "tracker reservation plus human/agent confirmation",
            "command": f"br update {bead_id} --status open --json",
        }
    return {
        "kind": "blocker-bead-suggestion",
        "mutates": True,
        "allowed_now": False,
        "requires": "tracker reservation or human escalation",
        "command": (
            "br create "
            f"'Investigate stale-state ambiguity for {bead_id}' "
            "--priority 2 --type task --json"
        ),
    }


def classify_issue(
    issue: dict[str, Any],
    source: dict[str, Any],
    generated_at: str,
    stale_after_hours: int,
    active_after_hours: int,
    dirty_tracker: dict[str, Any],
) -> dict[str, Any]:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    bead_id = str(issue.get("id", ""))
    assignee = str(issue.get("assignee") or issue.get("created_by") or "")
    updated_at = str(issue.get("updated_at") or issue.get("created_at") or "")
    issue_age = age_hours(now, updated_at)
    agent_mail = source.get("agent_mail") if isinstance(source.get("agent_mail"), dict) else {}
    agent_mail_available = bool(agent_mail.get("available", False))
    profiles = agent_profiles(agent_mail)
    assignee_profile = profiles.get(assignee, {})
    assignee_last_active = str(assignee_profile.get("last_active_ts") or "")
    assignee_age = age_hours(now, assignee_last_active)
    reservations = reservation_rows(agent_mail)
    active_reservation = active_reservation_for(reservations, bead_id, generated_at)
    expired_reservation = expired_reservation_for(reservations, bead_id, generated_at)
    message = recent_message_for(agent_mail, bead_id)
    message_created_at = str((message or {}).get("created_ts") or (message or {}).get("created_at") or "")
    message_age = age_hours(now, message_created_at)
    commit = recent_commit_for(source, bead_id)

    holder = row_holder(active_reservation or {}) or row_holder(expired_reservation or {})
    reservation_expires = str(
        (active_reservation or expired_reservation or {}).get("expires_ts")
        or (active_reservation or expired_reservation or {}).get("expires_at")
        or ""
    )

    if dirty_tracker["status"] in {"dirty-tracker-only", "dirty-tracker-and-code"}:
        classification = "needs-human-escalation"
        rationale = "tracker files are already dirty, so automated stale-state updates would mix ownership"
    elif commit is not None:
        classification = "closed-by-recent-commit"
        rationale = "recent commit references the in-progress bead"
    elif not agent_mail_available:
        classification = "needs-human-escalation"
        rationale = "Agent Mail data is unavailable, so freshness cannot be verified"
    elif active_reservation is not None:
        if holder == assignee or assignee_age is None or assignee_age <= active_after_hours:
            classification = "fresh-active-peer"
            rationale = "active reservation and peer freshness evidence indicate live work"
        else:
            classification = "blocked-by-active-reservation"
            rationale = "active reservation exists, but owner freshness is weak or mismatched"
    elif (
        (issue_age is not None and issue_age < stale_after_hours)
        or (assignee_age is not None and assignee_age <= active_after_hours)
        or (message_age is not None and message_age <= active_after_hours)
    ):
        classification = "fresh-active-peer"
        rationale = "recent issue, agent, or thread activity indicates live work"
    elif issue_age is not None and issue_age >= stale_after_hours:
        classification = "probably-stale"
        if expired_reservation is not None:
            rationale = "old in-progress bead has only expired reservation evidence"
        else:
            rationale = "old in-progress bead lacks fresh Agent Mail or commit evidence"
    else:
        classification = "needs-human-escalation"
        rationale = "missing timestamps prevent a defensible stale/fresh decision"

    if classification not in CLASSIFICATIONS:
        raise ValueError(f"invalid classification: {classification}")

    return {
        "id": bead_id,
        "title": str(issue.get("title", "")),
        "assignee": assignee,
        "classification": classification,
        "rationale": rationale,
        "evidence": {
            "generated_at": generated_at,
            "current_date": current_date(generated_at),
            "issue_updated_at": updated_at,
            "issue_age_hours": issue_age,
            "assignee_last_active_ts": assignee_last_active,
            "assignee_inactive_hours": assignee_age,
            "message_created_ts": message_created_at,
            "message_age_hours": message_age,
            "reservation_holder": holder,
            "reservation_path_pattern": row_pattern(active_reservation or expired_reservation or {}),
            "reservation_expires_ts": reservation_expires,
            "reservation_expired": bool(expired_reservation is not None and active_reservation is None),
            "commit_hash": str((commit or {}).get("hash", "")),
            "commit_created_ts": str((commit or {}).get("created_ts") or ""),
            "commit_subject": str((commit or {}).get("subject", "")),
        },
        "proposed_action": proposed_action(classification, bead_id, assignee, holder, commit),
    }


def forbidden_hits(actions: list[dict[str, Any]]) -> list[str]:
    text = "\n".join(str(action.get("command", "")) for action in actions)
    return [token for token in FORBIDDEN_COMMAND_TOKENS if token in text]


def build_receipt(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
    stale_after_hours: int,
    active_after_hours: int,
) -> dict[str, Any]:
    dirty_tracker = dirty_tracker_status(source)
    issues = extract_issues(source.get("beads", {}).get("in_progress", []))
    classifications = [
        classify_issue(
            issue,
            source,
            generated_at,
            stale_after_hours,
            active_after_hours,
            dirty_tracker,
        )
        for issue in issues
    ]
    actions = [row["proposed_action"] for row in classifications]
    hits = forbidden_hits(actions)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": agent,
        "repo_path": repo_path,
        "thresholds": {
            "stale_after_hours": stale_after_hours,
            "active_after_hours": active_after_hours,
        },
        "subsystems": {
            "beads": str(source.get("beads", {}).get("status", "ok")),
            "agent_mail": str(source.get("agent_mail", {}).get("status", "unavailable")),
            "git": str(source.get("git", {}).get("status", "ok")),
            "dirty_tree": str(source.get("dirty_tree", {}).get("status", "ok")),
        },
        "tracker_state": dirty_tracker,
        "classifications": classifications,
        "summary": {
            "total_in_progress": len(classifications),
            "fresh_active_peer": sum(
                1 for row in classifications if row["classification"] == "fresh-active-peer"
            ),
            "probably_stale": sum(
                1 for row in classifications if row["classification"] == "probably-stale"
            ),
            "blocked_by_active_reservation": sum(
                1
                for row in classifications
                if row["classification"] == "blocked-by-active-reservation"
            ),
            "closed_by_recent_commit": sum(
                1
                for row in classifications
                if row["classification"] == "closed-by-recent-commit"
            ),
            "needs_human_escalation": sum(
                1
                for row in classifications
                if row["classification"] == "needs-human-escalation"
            ),
        },
        "safety": {
            "mutating_commands_executed": False,
            "beads_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "forbidden_command_tokens": hits,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a non-mutating stale in-progress bead analysis receipt."
    )
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Agent generating the receipt")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic receipts")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument(
        "--stale-after-hours",
        type=int,
        default=12,
        help="Age threshold before an in-progress bead is stale",
    )
    parser.add_argument(
        "--active-after-hours",
        type=int,
        default=4,
        help="Age threshold for fresh Agent Mail or assignee activity",
    )
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
        active_after_hours=args.active_after_hours,
    )
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
