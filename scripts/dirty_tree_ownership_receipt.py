#!/usr/bin/env python3
"""Emit a non-mutating dirty-tree ownership receipt.

The receipt correlates dirty git paths with Agent Mail reservations, recent
messages, and bead ids. It never stages, commits, resets, cleans, branches, or
mutates Beads. The output is meant to make the safe staging boundary explicit
before agents accidentally mix peer-owned shared-main work into a commit.
"""

import argparse
import datetime as dt
import fnmatch
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "dirty-tree-ownership-receipt-v1"
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db", ".beads/beads.db-wal"}
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


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def project_slug(repo_path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", str(repo_path.resolve()).strip("/")).strip("-").lower()


def default_reservation_artifact_dir(repo_path: Path) -> Path:
    return (
        Path.home()
        / ".mcp_agent_mail_git_mailbox_repo"
        / "projects"
        / project_slug(repo_path)
        / "file_reservations"
    )


def load_reservation_artifacts(reservation_dir: Path) -> tuple[str, list[dict[str, Any]], list[str]]:
    if not reservation_dir.exists():
        return "offline-reservation-artifacts-missing", [], []
    if not reservation_dir.is_dir():
        return "offline-reservation-artifacts-not-directory", [], [str(reservation_dir)]

    rows = []
    errors = []
    for path in sorted(reservation_dir.glob("*.json")):
        try:
            loaded = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: {error}")
            continue
        if not isinstance(loaded, dict):
            errors.append(f"{path}: expected object")
            continue
        row = dict(loaded)
        row["artifact_path"] = str(path)
        rows.append(row)

    status = "offline-reservation-artifacts-ok" if not errors else "offline-reservation-artifacts-partial"
    return status, rows, errors


def attach_reservation_artifacts(
    source: dict[str, Any],
    repo_path: Path,
    reservation_artifact_dir: Path | None,
) -> dict[str, Any]:
    artifact_dir = reservation_artifact_dir or default_reservation_artifact_dir(repo_path)
    status, reservations, errors = load_reservation_artifacts(artifact_dir)
    merged = dict(source)
    existing_mail = source.get("agent_mail") if isinstance(source.get("agent_mail"), dict) else {}
    agent_mail = dict(existing_mail)
    agent_mail.update(
        {
            "available": status in {"offline-reservation-artifacts-ok", "offline-reservation-artifacts-partial"},
            "status": status,
            "reservation_artifact_dir": str(artifact_dir),
            "reservation_artifact_errors": errors[:20],
            "reservations": reservations,
        }
    )
    merged["agent_mail"] = agent_mail
    return merged


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


def run_json(repo_path: Path, command: list[str], timeout: float) -> tuple[str, Any]:
    status, text = run_text(repo_path, command, timeout)
    if status != "ok":
        return status, None
    try:
        return "ok", json.loads(text)
    except json.JSONDecodeError:
        return "malformed-json", None


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").rstrip("/")


def status_paths(status: str, path: str) -> list[str]:
    if ("R" in status or "C" in status) and " -> " in path:
        paths = []
        for part in path.split(" -> ", 1):
            normalized = normalize_path(part.strip())
            if normalized and normalized not in paths:
                paths.append(normalized)
        return paths
    return [path] if path else []


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


def git_entries(source: dict[str, Any]) -> list[dict[str, str]]:
    git = source.get("git", {})
    raw_entries = git.get("entries") if isinstance(git, dict) else []
    entries = []
    for item in raw_entries if isinstance(raw_entries, list) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", ""))
        status = str(item.get("status", ""))
        for expanded_path in status_paths(status, path):
            entries.append(
                {
                    "status": status,
                    "path": expanded_path,
                }
            )
    return entries


def parse_status_lines(raw: str) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        if len(line) < 4:
            continue
        status = line[:2]
        path = line[3:]
        for expanded_path in status_paths(status, path):
            entries.append({"status": status, "path": expanded_path})
    return entries


def live_probe(
    repo_path: Path,
    timeout: float,
    reservation_artifact_dir: Path | None,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    branch_status, branch = run_text(repo_path, ["git", "branch", "--show-current"], timeout)
    upstream_status, upstream_counts = run_text(
        repo_path,
        ["git", "rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
        timeout,
    )
    upstream_ref_status, upstream_ref = run_text(
        repo_path,
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        timeout,
    )
    beads_status, beads = run_json(repo_path, ["br", "list", "--json"], timeout)
    ahead = 0
    behind = 0
    if upstream_status == "ok":
        parts = upstream_counts.split()
        if len(parts) == 2:
            ahead = parse_int(parts[0])
            behind = parse_int(parts[1])
        else:
            upstream_status = "malformed-counts"
    source = {
        "git": {
            "status": status,
            "branch": branch if branch_status == "ok" else "",
            "upstream": {
                "status": upstream_status,
                "branch": upstream_ref if upstream_ref_status == "ok" else "",
                "ahead": ahead,
                "behind": behind,
            },
            "entries": parse_status_lines(raw_status if status == "ok" else ""),
        },
        "agent_mail": {
            "available": False,
            "status": "live-agent-mail-not-configured",
            "reservations": [],
            "messages": [],
        },
        "beads": {
            "status": beads_status,
            "issues": extract_rows(beads, ("issues",)) if isinstance(beads, dict) else [],
        },
    }
    return attach_reservation_artifacts(source, repo_path, reservation_artifact_dir)


def reservation_rows(agent_mail: dict[str, Any]) -> list[dict[str, Any]]:
    rows = extract_rows(
        agent_mail,
        ("reservations", "active_reservations", "file_reservations", "granted"),
    )
    for conflict in extract_rows(agent_mail, ("conflicts",)):
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


def active_reservations_for_path(
    rows: list[dict[str, Any]],
    path: str,
    generated_at: str,
) -> list[dict[str, Any]]:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    matches = []
    for row in rows:
        if not row.get("exclusive", True):
            continue
        if row.get("released_ts") or row.get("released_at"):
            continue
        pattern = row_pattern(row)
        if not pattern or not path_matches(pattern, path):
            continue
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        expires_at = parse_timestamp(expires_ts)
        if expires_at is not None and expires_at <= now:
            continue
        matches.append(row)
    return matches


def messages_for_path(agent_mail: dict[str, Any], path: str) -> list[dict[str, Any]]:
    messages = extract_rows(agent_mail, ("messages", "inbox", "threads"))
    matches = []
    for row in messages:
        haystack = " ".join(
            str(row.get(key, ""))
            for key in ("subject", "body_md", "message", "thread_id", "path", "paths")
        )
        if path in haystack:
            matches.append(row)
    matches.sort(key=lambda row: str(row.get("created_ts") or row.get("created_at") or ""), reverse=True)
    return matches


def bead_for_path(source: dict[str, Any], path: str) -> dict[str, Any] | None:
    beads = source.get("beads", {})
    issues = extract_rows(beads, ("issues", "ready", "in_progress")) if isinstance(beads, dict) else []
    for issue in issues:
        haystack = " ".join(
            str(issue.get(key, ""))
            for key in ("id", "title", "description", "notes", "close_reason")
        )
        if path in haystack:
            return issue
    return None


def staging_command(path: str, allowed: bool) -> dict[str, Any]:
    return {
        "kind": "git-add-pathspec",
        "command": f"git add -- {path}",
        "mutates": True,
        "allowed_now": allowed,
    }


def contact_command(path: str, owner: str, thread_id: str) -> dict[str, Any]:
    recipient = owner or "suspected-owner"
    return {
        "kind": "agent-mail-contact",
        "command": (
            "send_message("
            f"thread_id={thread_id!r}, to={[recipient]!r}, "
            "subject='Dirty tree ownership check', "
            f"body_md='Please confirm ownership for {path}.')"
        ),
        "mutates": True,
        "allowed_now": True,
    }


def ownership_for_entry(
    source: dict[str, Any],
    agent: str,
    generated_at: str,
    entry: dict[str, str],
) -> dict[str, Any]:
    path = entry["path"]
    status = entry["status"]
    agent_mail = source.get("agent_mail") if isinstance(source.get("agent_mail"), dict) else {}
    reservations = active_reservations_for_path(reservation_rows(agent_mail), path, generated_at)
    messages = messages_for_path(agent_mail, path)
    bead = bead_for_path(source, path)

    owners = []
    for reservation in reservations:
        owner = holder_name(reservation)
        if owner and owner not in owners:
            owners.append(owner)
    for message in messages[:1]:
        owner = holder_name(message)
        if owner and owner not in owners:
            owners.append(owner)

    first_reservation = reservations[0] if reservations else {}
    first_message = messages[0] if messages else {}
    bead_id = str((bead or {}).get("id", ""))

    if path in TRACKER_PATHS:
        classification = "tracker-state"
        owner = owners[0] if owners else "tracker-owner-required"
        decision = "do-not-stage"
        reason = "tracker files must not be mixed with unrelated implementation commits"
        action = contact_command(path, owner, bead_id or "tracker-state")
    elif len(owners) > 1:
        classification = "owner-conflict"
        owner = ",".join(owners)
        decision = "do-not-stage"
        reason = "multiple ownership signals match the dirty path"
        action = contact_command(path, owners[0], bead_id or "dirty-tree-ownership")
    elif owners and owners[0] == agent:
        classification = "self-owned"
        owner = agent
        decision = "safe-to-stage-with-pathspec"
        reason = "active reservation or message indicates current agent ownership"
        action = staging_command(path, True)
    elif owners:
        classification = "peer-owned"
        owner = owners[0]
        decision = "do-not-stage"
        reason = "active peer reservation or recent peer message owns this path"
        action = contact_command(path, owner, bead_id or "dirty-tree-ownership")
    else:
        classification = "unattributed"
        owner = ""
        decision = "needs-owner"
        reason = "no reservation, message, or bead evidence matched this dirty path"
        action = contact_command(path, owner, bead_id or "dirty-tree-ownership")

    index_status = status[:1] if status else ""
    worktree_status = status[1:2] if len(status) > 1 else ""
    if index_status not in {"", " ", "?"} and classification != "self-owned":
        decision = "unstage-before-commit"
        reason = "path is already staged without current-agent ownership evidence"

    return {
        "path": path,
        "status": status,
        "classification": classification,
        "owner": owner,
        "bead_id": bead_id,
        "staging_guidance": {
            "decision": decision,
            "reason": reason,
        },
        "evidence": {
            "generated_at": generated_at,
            "current_date": current_date(generated_at),
            "reservation_holder": holder_name(first_reservation),
            "reservation_path_pattern": row_pattern(first_reservation),
            "reservation_expires_ts": str(
                first_reservation.get("expires_ts") or first_reservation.get("expires_at") or ""
            ),
            "message_from": holder_name(first_message),
            "message_created_ts": str(first_message.get("created_ts") or first_message.get("created_at") or ""),
            "message_subject": str(first_message.get("subject", "")),
            "index_status": index_status,
            "worktree_status": worktree_status,
        },
        "proposed_action": action,
    }


def forbidden_hits(rows: list[dict[str, Any]]) -> list[str]:
    text = "\n".join(str(row["proposed_action"].get("command", "")) for row in rows)
    return [token for token in FORBIDDEN_COMMAND_TOKENS if token in text]


def is_index_staged(row: dict[str, Any]) -> bool:
    index_status = str(row["evidence"].get("index_status", ""))
    return index_status not in {"", " ", "?"}


def pathspec(paths: list[str]) -> str:
    return " ".join(shlex.quote(path) for path in paths)


def reservation_context_for_path(
    source: dict[str, Any] | None,
    path: str,
    generated_at: str,
) -> dict[str, str]:
    if source is None:
        return {}
    agent_mail = source.get("agent_mail") if isinstance(source.get("agent_mail"), dict) else {}
    reservations = active_reservations_for_path(reservation_rows(agent_mail), path, generated_at)
    if not reservations:
        return {}
    reservation = reservations[0]
    return {
        "reservation_id": str(reservation.get("id", "")),
        "reservation_holder": holder_name(reservation),
        "reservation_path_pattern": row_pattern(reservation),
        "reservation_expires_ts": str(reservation.get("expires_ts") or reservation.get("expires_at") or ""),
        "reservation_artifact_path": str(reservation.get("artifact_path", "")),
    }


def outside_staged_scope(row: dict[str, Any], source: dict[str, Any] | None) -> str:
    classification = str(row["classification"])
    if classification == "self-owned":
        return "own-reserved"
    if classification == "peer-owned":
        return "peer-reserved"
    if classification == "owner-conflict":
        return "conflicting-reservation"
    if classification == "tracker-state":
        return "tracker-state"
    if classification == "unattributed":
        agent_mail = source.get("agent_mail") if isinstance(source, dict) and isinstance(source.get("agent_mail"), dict) else {}
        if agent_mail.get("status") in {"ok", "offline-reservation-artifacts-ok", "offline-reservation-artifacts-partial"}:
            return "unreserved"
        return "unknown"
    return "unknown"


def staged_outside_blocker(
    row: dict[str, Any],
    source: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    path = str(row["path"])
    reservation = reservation_context_for_path(source, path, generated_at)
    return {
        "path": path,
        "scope": outside_staged_scope(row, source),
        "classification": row["classification"],
        "owner": row["owner"],
        "status": row["status"],
        "reason": "staged path is outside the declared commit path set",
        **reservation,
    }


def normalize_declared_commit_paths(
    raw_paths: list[str],
    repo_path: Path,
) -> tuple[list[str], list[dict[str, str]]]:
    repo_path = repo_path.resolve()
    normalized_paths: list[str] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()

    for raw_path in raw_paths:
        if raw_path == "":
            errors.append(
                {
                    "path": raw_path,
                    "reason": "declared commit path must not be empty",
                }
            )
            continue

        candidate = Path(raw_path)
        resolved = candidate.resolve() if candidate.is_absolute() else (repo_path / candidate).resolve()
        try:
            relative = resolved.relative_to(repo_path)
        except ValueError:
            errors.append(
                {
                    "path": raw_path,
                    "reason": "declared commit path resolves outside repository",
                }
            )
            continue

        normalized = normalize_path(relative.as_posix())
        if not normalized or normalized == ".":
            errors.append(
                {
                    "path": raw_path,
                    "reason": "declared commit path must name a repository file",
                }
            )
            continue
        if normalized not in seen:
            seen.add(normalized)
            normalized_paths.append(normalized)

    return normalized_paths, errors


def build_declared_commit_preflight(
    rows: list[dict[str, Any]],
    raw_paths: list[str],
    repo_path: Path,
    source: dict[str, Any] | None = None,
    generated_at: str = "",
) -> dict[str, Any]:
    declared_paths, path_errors = normalize_declared_commit_paths(raw_paths, repo_path)
    declared = set(declared_paths)
    rows_by_path = {str(row["path"]): row for row in rows}
    declared_rows = [rows_by_path[path] for path in declared_paths if path in rows_by_path]
    declared_dirty_paths = [str(row["path"]) for row in declared_rows]
    declared_missing = [path for path in declared_paths if path not in rows_by_path]
    staged_paths = [str(row["path"]) for row in rows if is_index_staged(row)]
    outside_rows = [row for row in rows if str(row["path"]) not in declared]
    staged_outside = [row for row in outside_rows if is_index_staged(row)]
    own_reserved_staged_outside = [
        staged_outside_blocker(row, source, generated_at)
        for row in staged_outside
        if outside_staged_scope(row, source) == "own-reserved"
    ]
    commit_race_blockers = [
        staged_outside_blocker(row, source, generated_at)
        for row in staged_outside
        if outside_staged_scope(row, source) != "own-reserved"
    ]
    tracker_rows = [row for row in declared_rows if row["classification"] == "tracker-state"]
    non_tracker_declared = [
        str(row["path"])
        for row in declared_rows
        if row["classification"] != "tracker-state"
    ]
    unsafe_declared = [
        str(row["path"])
        for row in declared_rows
        if row["classification"] in {"peer-owned", "owner-conflict"}
    ]
    unattributed_declared = [
        str(row["path"])
        for row in declared_rows
        if row["classification"] == "unattributed"
    ]
    untracked_declared = [
        str(row["path"])
        for row in declared_rows
        if str(row.get("status", "")).startswith("??")
    ]
    final_commit_paths = [
        str(row["path"])
        for row in declared_rows
        if row["classification"] in {"self-owned", "tracker-state", "unattributed"}
        and str(row.get("status", "")) != "??"
    ]

    if path_errors:
        decision = "refuse-invalid-declared-paths"
        reason = "one or more declared paths are empty or outside the repository"
    elif not declared_paths:
        decision = "refuse-empty-declared-paths"
        reason = "declare at least one project-relative path before committing"
    elif unsafe_declared:
        decision = "refuse-unowned-declared-paths"
        reason = "declared commit paths include peer-owned or conflicted paths"
    elif untracked_declared:
        decision = "refuse-untracked-declared-paths"
        reason = "untracked declared paths must be staged before git commit --only can include them"
    elif commit_race_blockers:
        decision = "refuse-staged-paths-outside-declared-scope"
        reason = "staged paths outside the declared commit set require coordination or explicit declaration"
    elif tracker_rows and non_tracker_declared:
        decision = "refuse-mixed-tracker-commit"
        reason = "tracker files require a tracker-only commit surface"
    elif not final_commit_paths:
        decision = "refuse-no-dirty-declared-paths"
        reason = "no dirty declared paths are available for the path-limited commit"
    elif tracker_rows:
        decision = "ready-tracker-only-path-limited-commit"
        reason = "declared tracker paths are the entire commit surface"
    else:
        decision = "ready-path-limited-commit"
        reason = "path-limited commit excludes unrelated staged and unstaged paths"

    allowed = decision in {
        "ready-path-limited-commit",
        "ready-tracker-only-path-limited-commit",
    }
    command = f"git commit --only -- {pathspec(final_commit_paths)}" if allowed else ""

    return {
        "allowed": allowed,
        "decision": decision,
        "reason": reason,
        "declared_paths": declared_paths,
        "declared_path_errors": path_errors,
        "declared_dirty_paths": declared_dirty_paths,
        "declared_clean_or_missing_paths": declared_missing,
        "currently_staged_paths": staged_paths,
        "staged_paths_outside_scope": [str(row["path"]) for row in staged_outside],
        "own_reserved_staged_paths_outside_scope": own_reserved_staged_outside,
        "commit_race_blockers": commit_race_blockers,
        "dirty_paths_outside_scope": [str(row["path"]) for row in outside_rows],
        "dirty_peer_paths_outside_scope": [
            str(row["path"])
            for row in outside_rows
            if row["classification"] in {"peer-owned", "owner-conflict"}
        ],
        "dirty_unattributed_paths_outside_scope": [
            str(row["path"])
            for row in outside_rows
            if row["classification"] == "unattributed"
        ],
        "dirty_unstaged_paths_outside_scope": [
            str(row["path"])
            for row in outside_rows
            if not is_index_staged(row)
        ],
        "unsafe_declared_paths": unsafe_declared,
        "unattributed_declared_paths": unattributed_declared,
        "untracked_declared_paths": untracked_declared,
        "final_commit_path_set": final_commit_paths if allowed else [],
        "path_limited_commit_command": command,
        "ordinary_index_commit_allowed": False,
        "peer_index_preservation_required": bool(
            final_commit_paths and any(path not in final_commit_paths for path in staged_paths)
        ),
    }


def commit_boundary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    self_owned = [
        str(row["path"])
        for row in rows
        if row["classification"] == "self-owned" and is_index_staged(row)
    ]
    non_self = [
        str(row["path"])
        for row in rows
        if row["classification"] != "self-owned" and is_index_staged(row)
    ]

    if self_owned and non_self:
        decision = "path-limited-commit-required"
        reason = "self-owned staged paths share the index with peer or unattributed staged paths"
    elif non_self:
        decision = "do-not-commit-index"
        reason = "staged paths do not have current-agent ownership evidence"
    elif self_owned:
        decision = "ordinary-index-commit-safe"
        reason = "all staged paths have current-agent ownership evidence"
    else:
        decision = "no-staged-self-owned-paths"
        reason = "no current-agent staged paths are ready to commit"

    command = ""
    if self_owned:
        command = f"git commit --only -- {pathspec(self_owned)}"

    return {
        "decision": decision,
        "reason": reason,
        "ordinary_index_commit_allowed": decision == "ordinary-index-commit-safe",
        "peer_index_preservation_required": bool(self_owned and non_self),
        "self_owned_staged_paths": self_owned,
        "non_self_staged_paths": non_self,
        "path_limited_commit_command": command,
    }


def normalized_upstream(source: dict[str, Any]) -> dict[str, Any] | None:
    git = source.get("git", {})
    if not isinstance(git, dict):
        return None
    upstream = git.get("upstream")
    if not isinstance(upstream, dict):
        return None
    status = str(upstream.get("status", "unknown"))
    ahead = parse_int(upstream.get("ahead"))
    behind = parse_int(upstream.get("behind"))
    return {
        "status": status,
        "branch": str(upstream.get("branch", "")),
        "ahead": ahead,
        "behind": behind,
        "requires_refresh": status == "ok" and behind > 0,
    }


def shared_main_boundary(
    rows: list[dict[str, Any]],
    upstream: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if upstream is None:
        return None

    safe_to_stage = [
        str(row["path"])
        for row in rows
        if row["staging_guidance"]["decision"] == "safe-to-stage-with-pathspec"
    ]
    unsafe_to_stage = [
        str(row["path"])
        for row in rows
        if row["staging_guidance"]["decision"] != "safe-to-stage-with-pathspec"
    ]
    staged_without_ownership = [
        str(row["path"])
        for row in rows
        if row["classification"] != "self-owned" and is_index_staged(row)
    ]

    if upstream["requires_refresh"]:
        decision = "refresh-before-commit"
        reason = "local main is behind upstream; refresh before relying on this staging set"
    elif staged_without_ownership:
        decision = "pathspec-only"
        reason = "the index contains staged paths without current-agent ownership evidence"
    elif safe_to_stage:
        decision = "safe-pathspecs-available"
        reason = "current-agent owned paths can be staged explicitly with pathspecs"
    else:
        decision = "blocked-no-owned-paths"
        reason = "no dirty paths have current-agent ownership evidence"

    return {
        "decision": decision,
        "reason": reason,
        "upstream_drift": upstream,
        "safe_to_stage_paths": safe_to_stage,
        "unsafe_to_stage_paths": unsafe_to_stage,
        "staged_without_ownership_paths": staged_without_ownership,
        "recommended_git_add_command": f"git add -- {pathspec(safe_to_stage)}" if safe_to_stage else "",
    }


def build_receipt(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
    declared_commit_paths: list[str] | None = None,
) -> dict[str, Any]:
    rows = [
        ownership_for_entry(source, agent, generated_at, entry)
        for entry in git_entries(source)
    ]
    hits = forbidden_hits(rows)
    boundary = commit_boundary(rows)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": agent,
        "repo_path": repo_path,
        "subsystems": {
            "git": str(source.get("git", {}).get("status", "ok")),
            "agent_mail": str(source.get("agent_mail", {}).get("status", "unavailable")),
            "beads": str(source.get("beads", {}).get("status", "ok")),
        },
        "commit_boundary": boundary,
        "rows": rows,
        "summary": {
            "total_paths": len(rows),
            "self_owned": sum(1 for row in rows if row["classification"] == "self-owned"),
            "peer_owned": sum(1 for row in rows if row["classification"] == "peer-owned"),
            "tracker_state": sum(1 for row in rows if row["classification"] == "tracker-state"),
            "owner_conflict": sum(1 for row in rows if row["classification"] == "owner-conflict"),
            "unattributed": sum(1 for row in rows if row["classification"] == "unattributed"),
            "safe_to_stage": sum(
                1
                for row in rows
                if row["staging_guidance"]["decision"] == "safe-to-stage-with-pathspec"
            ),
            "do_not_stage": sum(
                1
                for row in rows
                if row["staging_guidance"]["decision"] in {"do-not-stage", "unstage-before-commit"}
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
    shared_boundary = shared_main_boundary(rows, normalized_upstream(source))
    if shared_boundary is not None:
        receipt["shared_main_boundary"] = shared_boundary
    if declared_commit_paths is not None:
        receipt["declared_commit"] = build_declared_commit_preflight(
            rows=rows,
            raw_paths=declared_commit_paths,
            repo_path=Path(repo_path),
            source=source,
            generated_at=generated_at,
        )
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a non-mutating dirty-tree ownership receipt."
    )
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Agent generating the receipt")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic receipts")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument(
        "--declared-commit-preflight",
        action="store_true",
        help="Evaluate declared commit paths and exit nonzero unless a path-limited commit is safe",
    )
    parser.add_argument(
        "--commit-path",
        action="append",
        default=[],
        help="Project-relative path intended for git commit --only; repeat for multi-path commits",
    )
    parser.add_argument(
        "--reservation-artifact-dir",
        type=Path,
        help="Read offline Agent Mail file reservation artifacts from this directory",
    )
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()
    generated_at = args.generated_at or utc_now()
    if args.fixture:
        source = load_json(args.fixture)
        if args.reservation_artifact_dir is not None:
            source = attach_reservation_artifacts(source, repo_path, args.reservation_artifact_dir)
    else:
        source = live_probe(repo_path, args.timeout, args.reservation_artifact_dir)
    receipt = build_receipt(
        source=source,
        repo_path=str(repo_path),
        agent=args.agent,
        generated_at=generated_at,
        declared_commit_paths=args.commit_path if args.declared_commit_preflight or args.commit_path else None,
    )
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    if "declared_commit" in receipt and not receipt["declared_commit"]["allowed"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
