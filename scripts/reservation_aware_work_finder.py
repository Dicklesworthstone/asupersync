#!/usr/bin/env python3
"""Emit a non-mutating reservation-aware work finder receipt.

The helper ranks ready beads and approved fallback-lane candidates while
respecting active file reservations and dirty shared-main paths. It never
claims beads, reserves files, edits code, sends Agent Mail, runs Cargo, or
mutates git state. Output is available as stable JSON or compact Markdown.
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


SCHEMA_VERSION = "reservation-aware-work-finder-v1"
APPROVED_FALLBACK_LANES = {
    "testing-fuzzing",
    "mock-code-finder",
    "deadlock-finder-and-fixer",
    "testing-golden-artifacts",
    "testing-conformance-harnesses",
}
DEFAULT_FALLBACK_CANDIDATES = [
    {
        "candidate_id": "testing-conformance-harnesses:session-handoff-receipt",
        "lane": "testing-conformance-harnesses",
        "title": "Harden session handoff receipt contracts",
        "priority": 1,
        "paths": [
            "scripts/session_handoff_receipt.py",
            "tests/session_handoff_receipt_contract.rs",
            "tests/fixtures/session_handoff_receipt",
        ],
        "proof_commands": [
            "python3 -m py_compile scripts/session_handoff_receipt.py",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_session_handoff cargo test -p asupersync --test session_handoff_receipt_contract",
        ],
        "completion_aliases": [
            "asupersync-c8thc8.11",
            "harden session handoff receipt contracts",
            "session handoff receipt contracts",
        ],
    },
    {
        "candidate_id": "testing-golden-artifacts:proof-receipt-inventory",
        "lane": "testing-golden-artifacts",
        "title": "Refresh proof receipt inventory goldens",
        "priority": 2,
        "paths": [
            "scripts/proof_receipt_inventory.py",
            "tests/proof_receipt_inventory_contract.rs",
            "tests/fixtures/proof_receipt_inventory",
        ],
        "proof_commands": [
            "python3 -m py_compile scripts/proof_receipt_inventory.py",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_proof_receipt_inventory cargo test -p asupersync --test proof_receipt_inventory_contract",
        ],
        "completion_aliases": [
            "harden proof receipt safety cues",
            "proof receipt inventory",
            "proof_receipt_inventory",
        ],
    },
    {
        "candidate_id": "mock-code-finder:proof-runner-contracts",
        "lane": "mock-code-finder",
        "title": "Audit proof runner contracts for placeholder behavior",
        "priority": 3,
        "paths": [
            "scripts/proof_runner.py",
            "tests/proof_runner_contract.rs",
            "tests/fixtures/proof_runner",
        ],
        "proof_commands": [
            "python3 -m py_compile scripts/proof_runner.py",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_proof_runner cargo test -p asupersync --test proof_runner_contract",
        ],
        "completion_aliases": [
            "block unsafe proof runner fallback commands",
            "block unsafe proof-runner fallback commands",
            "proof runner contracts",
            "proof_runner_contract",
        ],
    },
]
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
SAFE_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CARGO_COMMAND_RE = re.compile(r"(?<![A-Za-z0-9_-])cargo(?![A-Za-z0-9_-])")
REMOTE_REQUIRED_VALUES = {"1", "true", "yes", "on"}
RCH_LOCAL_FALLBACK_RE = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
DISK_CRITICAL_BYTES = 1 * 1024 * 1024 * 1024
DISK_LOW_BYTES = 5 * 1024 * 1024 * 1024
DEFAULT_STALE_IN_PROGRESS_MINUTES = 120
DEFAULT_ACTIVE_AGENT_WINDOW_MINUTES = 30
TRACKER_PATHS = (".beads/issues.jsonl", ".beads/beads.db")


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


def normalize_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def path_matches(pattern: str, path: str) -> bool:
    pattern = normalize_path(pattern)
    path = normalize_path(path)
    if not pattern or not path:
        return False
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3].rstrip("/") + "/")
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path)
    return path == pattern or path.startswith(pattern.rstrip("/") + "/")


def any_path_matches(patterns: list[str], path: str) -> bool:
    return any(path_matches(pattern, path) or path_matches(path, pattern) for pattern in patterns)


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
            return normalize_path(value)
    return ""


def active_reservation(row: dict[str, Any], generated_at: str) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires_at = parse_timestamp(str(row.get("expires_ts") or row.get("expires_at") or ""))
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    return expires_at is None or expires_at > now


def reservation_rows(source: dict[str, Any], generated_at: str) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    raw_rows = rows_from(
        agent_mail,
        ("reservations", "active_reservations", "file_reservations", "granted"),
    )
    raw_rows.extend(rows_from(source, ("reservations", "active_reservations")))
    rows = []
    for item in raw_rows:
        pattern = row_pattern(item)
        if not pattern:
            continue
        rows.append(
            {
                "path_pattern": pattern,
                "holder": holder_name(item) or "unknown",
                "exclusive": bool(item.get("exclusive", True)),
                "expires_ts": str(item.get("expires_ts") or item.get("expires_at") or ""),
                "active": active_reservation(item, generated_at),
            }
        )
    return sorted(rows, key=lambda row: (row["path_pattern"], row["holder"], row["expires_ts"]))


def dirty_entries(source: dict[str, Any]) -> list[dict[str, Any]]:
    dirty = source.get("dirty_tree", {}) if isinstance(source, dict) else {}
    rows = dirty.get("entries") if isinstance(dirty, dict) else []
    entries = []
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        for path in status_paths(status, str(item.get("path") or "")):
            entries.append(
                {
                    "path": path,
                    "status": status,
                    "owner": str(item.get("owner") or ""),
                }
            )
    return sorted(entries, key=lambda row: row["path"])


def owner_for_dirty_path(
    dirty: dict[str, Any],
    reservations: list[dict[str, Any]],
) -> tuple[str, str]:
    explicit_owner = str(dirty.get("owner") or "")
    if explicit_owner:
        return explicit_owner, "dirty-entry"
    for row in reservations:
        if row["active"] and row["exclusive"] and path_matches(row["path_pattern"], dirty["path"]):
            return row["holder"], "reservation"
    return "", "none"


def issue_rows(value: Any) -> list[dict[str, Any]]:
    return rows_from(value, ("issues", "ready"))


def ready_issues(source: dict[str, Any]) -> list[dict[str, Any]]:
    beads = source.get("beads", {}) if isinstance(source, dict) else {}
    rows = issue_rows(beads.get("ready", []))
    rows.extend(issue_rows(beads))
    if isinstance(beads.get("ready"), list):
        rows.extend(item for item in beads["ready"] if isinstance(item, dict))
    seen: set[str] = set()
    unique = []
    for row in rows:
        issue_id = str(row.get("id") or "")
        if issue_id and issue_id not in seen:
            seen.add(issue_id)
            unique.append(row)
    return unique


def in_progress_issues(source: dict[str, Any]) -> list[dict[str, Any]]:
    beads = source.get("beads", {}) if isinstance(source, dict) else {}
    rows = rows_from(beads, ("in_progress", "in_progress_issues"))
    for row in rows_from(beads, ("issues", "ready")):
        if str(row.get("status") or "") == "in_progress":
            rows.append(row)

    seen: set[str] = set()
    unique = []
    for row in rows:
        issue_id = str(row.get("id") or "")
        if issue_id and issue_id not in seen:
            seen.add(issue_id)
            unique.append(row)
    return unique


def candidate_paths(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    value = row.get("paths")
    if isinstance(value, list):
        paths.extend(normalize_path(str(path)) for path in value if str(path).strip())
    for key in ("path", "target_path", "file", "glob"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(normalize_path(value))
    return sorted(set(path for path in paths if path))


def fallback_candidates(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows = rows_from(source, ("fallback_lanes", "candidates", "fallback_candidates"))
    if not rows:
        rows = DEFAULT_FALLBACK_CANDIDATES
    candidates = []
    for index, row in enumerate(rows):
        lane = str(row.get("lane") or row.get("skill") or "")
        if not lane:
            continue
        candidate_id = str(row.get("candidate_id") or row.get("id") or f"{lane}:{index + 1}")
        raw_aliases = row.get("completion_aliases", [])
        if not isinstance(raw_aliases, list):
            raw_aliases = []
        candidates.append(
            {
                "kind": "fallback-lane",
                "candidate_id": candidate_id,
                "lane": lane,
                "title": str(row.get("title") or candidate_id),
                "priority": int(row.get("priority", 2) or 2),
                "paths": candidate_paths(row),
                "no_build_validation": bool(
                    row.get("no_build_validation") or row.get("source_only_validation")
                ),
                "requires_tracker_update": bool(row.get("requires_tracker_update")),
                "create_bead": bool(row.get("create_bead")),
                "proof_commands": [
                    str(command)
                    for command in row.get("proof_commands", [])
                    if isinstance(command, str) and command
                ],
                "completion_aliases": [
                    str(alias)
                    for alias in raw_aliases
                    if isinstance(alias, str) and alias.strip()
                ],
            }
        )
    return candidates


def ready_candidates(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for issue in ready_issues(source):
        issue_id = str(issue.get("id") or "")
        if not issue_id:
            continue
        rows.append(
            {
                "kind": "ready-bead",
                "candidate_id": issue_id,
                "bead_id": issue_id,
                "lane": "br-ready",
                "title": str(issue.get("title") or issue_id),
                "issue_type": str(issue.get("issue_type") or ""),
                "priority": int(issue.get("priority", 2) or 2),
                "paths": candidate_paths(issue),
                "no_build_validation": bool(
                    issue.get("no_build_validation") or issue.get("source_only_validation")
                ),
                "requires_tracker_update": True,
                "create_bead": False,
                "proof_commands": [
                    str(command)
                    for command in issue.get("proof_commands", [])
                    if isinstance(command, str) and command
                ],
            }
        )
    return rows


def reservation_blockers(
    paths: list[str],
    reservations: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    blockers = []
    for reservation in reservations:
        if not reservation["active"] or not reservation["exclusive"]:
            continue
        if reservation["holder"] == agent:
            continue
        if not any_path_matches(paths, reservation["path_pattern"]):
            continue
        blockers.append(
            {
                "kind": "active-reservation",
                "holder": reservation["holder"],
                "path_pattern": reservation["path_pattern"],
                "expires_ts": reservation["expires_ts"],
            }
        )
    return blockers


def tracker_lock_from(
    reservations: list[dict[str, Any]],
    agent: str,
) -> dict[str, Any]:
    for reservation in reservations:
        if not reservation["active"] or not reservation["exclusive"]:
            continue
        if reservation["holder"] == agent:
            continue
        if not any(path_matches(reservation["path_pattern"], tracker) for tracker in TRACKER_PATHS):
            continue
        return {
            "active": True,
            "holder": reservation["holder"],
            "path_pattern": reservation["path_pattern"],
            "expires_ts": reservation["expires_ts"],
        }
    return {
        "active": False,
        "holder": "",
        "path_pattern": "",
        "expires_ts": "",
    }


def candidate_requires_tracker(candidate: dict[str, Any]) -> bool:
    if candidate["kind"] == "ready-bead":
        return True
    return bool(candidate.get("requires_tracker_update") or candidate.get("create_bead"))


def tracker_blockers(
    candidate: dict[str, Any],
    tracker_lock: dict[str, Any],
) -> list[dict[str, str]]:
    if not tracker_lock["active"] or not candidate_requires_tracker(candidate):
        return []
    return [
        {
            "kind": "tracker-active-reservation",
            "holder": str(tracker_lock["holder"]),
            "path_pattern": str(tracker_lock["path_pattern"]),
            "expires_ts": str(tracker_lock["expires_ts"]),
            "reason": "candidate requires a Beads tracker mutation while the tracker ledger is reserved",
        }
    ]


def tracker_dirty_blockers(
    candidate: dict[str, Any],
    dirty: list[dict[str, Any]],
    reservations: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    if not candidate_requires_tracker(candidate):
        return []

    blockers = []
    for row in dirty:
        if not any_path_matches(list(TRACKER_PATHS), row["path"]):
            continue
        owner, source = owner_for_dirty_path(row, reservations)
        if owner == agent:
            continue
        blockers.append(
            {
                "kind": "tracker-dirty-peer-path" if owner else "tracker-dirty-unattributed-path",
                "path": row["path"],
                "holder": owner or "unknown",
                "source": source,
                "reason": "candidate requires a Beads tracker mutation while a tracker path is already dirty",
            }
        )
    return blockers


def dirty_blockers(
    paths: list[str],
    dirty: list[dict[str, Any]],
    reservations: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    blockers = []
    for row in dirty:
        if not any_path_matches(paths, row["path"]):
            continue
        owner, source = owner_for_dirty_path(row, reservations)
        if owner == agent:
            continue
        blockers.append(
            {
                "kind": "dirty-peer-path" if owner else "dirty-unattributed-path",
                "path": row["path"],
                "holder": owner or "unknown",
                "source": source,
            }
        )
    return blockers


def lane_blockers(candidate: dict[str, Any]) -> list[dict[str, str]]:
    if candidate["kind"] != "fallback-lane":
        return []
    if candidate["lane"] in APPROVED_FALLBACK_LANES:
        return []
    return [
        {
            "kind": "unapproved-fallback-lane",
            "lane": candidate["lane"],
        }
    ]


def _first_non_assignment(argv: list[str], start: int = 0) -> int:
    index = start
    while index < len(argv) and "=" in argv[index]:
        name, _value = argv[index].split("=", 1)
        if not SAFE_ENV_NAME.fullmatch(name):
            break
        index += 1
    return index


def command_mentions_cargo(command: str) -> bool:
    return CARGO_COMMAND_RE.search(command.lower()) is not None


def command_routes_cargo_through_rch(command: str) -> bool:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return not command_mentions_cargo(command)

    lowered = [arg.lower() for arg in argv]
    if "cargo" not in lowered:
        return not command_mentions_cargo(command)

    program_index = _first_non_assignment(argv)
    if program_index >= len(argv):
        return False
    if lowered[program_index:program_index + 3] != ["rch", "exec", "--"]:
        return False
    command_requires_remote = any(
        assignment.startswith("RCH_REQUIRE_REMOTE=")
        and assignment.split("=", 1)[1].lower() in REMOTE_REQUIRED_VALUES
        for assignment in argv[:program_index]
    )

    remote_index = program_index + 3
    command_uses_target_dir = False
    if remote_index < len(argv) and lowered[remote_index] == "env":
        env_start = remote_index + 1
        remote_index = _first_non_assignment(argv, env_start)
        command_uses_target_dir = any(
            arg.startswith("CARGO_TARGET_DIR=")
            for arg in argv[env_start:remote_index]
        )
    return (
        remote_index < len(argv)
        and lowered[remote_index] == "cargo"
        and command_uses_target_dir
        and command_requires_remote
    )


def proof_command_blockers(candidate: dict[str, Any]) -> list[dict[str, str]]:
    blockers = []
    for command in candidate.get("proof_commands", []):
        command_text = str(command)
        collapsed = " ".join(command_text.lower().split())
        if RCH_LOCAL_FALLBACK_RE.search(command_text):
            blockers.append(
                {
                    "kind": "rch-local-fallback-proof-command",
                    "token": "rch-local-fallback",
                    "command": command_text,
                    "reason": "proof command evidence reports rch local fallback",
                }
            )
        for token in FORBIDDEN_COMMAND_TOKENS:
            if token == "cargo ":
                if command_mentions_cargo(command_text) and not command_routes_cargo_through_rch(command_text):
                    blockers.append(
                        {
                            "kind": "unsafe-proof-command",
                            "token": "bare-cargo",
                            "command": command_text,
                            "reason": (
                                "Cargo proof commands must route through "
                                "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo"
                            ),
                        }
                    )
                continue
            if token in collapsed:
                blockers.append(
                    {
                        "kind": "unsafe-proof-command",
                        "token": token,
                        "command": command_text,
                        "reason": "proof command proposes a forbidden operation",
                    }
                )
    return blockers


def proof_commands_require_rch_heavy_work(candidate: dict[str, Any]) -> bool:
    return any(command_mentions_cargo(str(command)) for command in candidate.get("proof_commands", []))


def completed_issues(source: dict[str, Any]) -> list[dict[str, Any]]:
    beads = source.get("beads", {}) if isinstance(source, dict) else {}
    rows = []
    rows.extend(issue_rows(beads.get("closed", [])))
    rows.extend(issue_rows(beads.get("completed", [])))
    rows.extend(rows_from(beads, ("closed_issues", "completed_issues")))
    rows.extend(completed_git_commits(source))
    for row in rows_from(beads, ("issues",)):
        if str(row.get("status") or "") == "closed":
            rows.append(row)

    seen: set[str] = set()
    unique = []
    for row in rows:
        issue_id = str(row.get("id") or "")
        if issue_id and issue_id not in seen:
            seen.add(issue_id)
            unique.append(row)
    return unique


def completed_git_commits(source: dict[str, Any]) -> list[dict[str, Any]]:
    git = source.get("git", {}) if isinstance(source, dict) else {}
    rows = rows_from(git, ("recent_commits", "commits"))
    completed = []
    for row in rows:
        commit_id = str(row.get("id") or row.get("commit") or row.get("sha") or row.get("hash") or "")
        subject = str(row.get("subject") or row.get("title") or row.get("message") or "")
        body = str(row.get("body") or row.get("description") or "")
        if not commit_id and not subject:
            continue
        completed.append(
            {
                "id": commit_id,
                "title": subject or commit_id,
                "description": body,
                "close_reason": "recent git commit",
                "labels": ["git-log"],
                "status": "closed",
            }
        )
    return completed


def normalized_search_text(*values: Any) -> str:
    text = " ".join(str(value or "") for value in values)
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


def issue_search_text(issue: dict[str, Any]) -> str:
    return normalized_search_text(
        issue.get("id"),
        issue.get("title"),
        issue.get("description"),
        issue.get("close_reason"),
        " ".join(str(label) for label in issue.get("labels", []) if isinstance(label, str)),
    )


def completed_work_blockers(
    candidate: dict[str, Any],
    completed: list[dict[str, Any]],
) -> list[dict[str, str]]:
    if candidate["kind"] != "fallback-lane":
        return []
    aliases = [
        normalized_search_text(alias)
        for alias in candidate.get("completion_aliases", [])
        if normalized_search_text(alias)
    ]
    if not aliases:
        return []

    blockers = []
    for issue in completed:
        issue_id = str(issue.get("id") or "")
        haystack = issue_search_text(issue)
        matched_alias = next((alias for alias in aliases if alias and alias in haystack), "")
        if not matched_alias:
            continue
        blockers.append(
            {
                "kind": "fallback-already-completed",
                "closed_issue_id": issue_id,
                "closed_issue_title": str(issue.get("title") or issue_id),
                "matched_alias": matched_alias,
                "reason": "fallback candidate overlaps previously closed Beads work",
            }
        )
        break
    return blockers


def candidate_has_no_build_validation(candidate: dict[str, Any]) -> bool:
    if not candidate.get("no_build_validation"):
        return False
    return not proof_commands_require_rch_heavy_work(candidate)


def disk_pressure_blockers(
    candidate: dict[str, Any],
    disk_pressure: dict[str, Any],
) -> list[dict[str, str]]:
    if disk_pressure["level"] != "critical":
        return []
    if not proof_commands_require_rch_heavy_work(candidate):
        return []
    if candidate_has_no_build_validation(candidate):
        return []
    return [
        {
            "kind": "critical-disk-pressure-rch-heavy",
            "level": disk_pressure["level"],
            "available_bytes": str(disk_pressure["available_bytes"]),
            "reason": "critical disk pressure blocks rch/Cargo-heavy recommendations",
        }
    ]


def bead_blockers(candidate: dict[str, Any]) -> list[dict[str, str]]:
    if candidate["kind"] != "ready-bead":
        return []
    if candidate.get("issue_type") != "epic":
        return []
    if candidate["paths"] or candidate["proof_commands"]:
        return []
    return [
        {
            "kind": "non-shippable-epic",
            "reason": "ready epic has no paths or proof commands; use child beads or fallback lanes",
        }
    ]


def files_to_reserve(candidate: dict[str, Any]) -> list[str]:
    paths = list(candidate["paths"])
    if candidate_requires_tracker(candidate):
        paths.append(".beads/issues.jsonl")
    return sorted(set(normalize_path(path) for path in paths if path))


def validation_class(candidate: dict[str, Any]) -> str:
    if candidate_has_no_build_validation(candidate):
        return "source-only"
    if proof_commands_require_rch_heavy_work(candidate):
        return "rch-cargo"
    if candidate.get("proof_commands"):
        return "non-cargo"
    return "inspection-only"


def safety_reason(candidate: dict[str, Any], blockers: list[dict[str, str]]) -> str:
    if blockers:
        kinds = ", ".join(sorted({blocker["kind"] for blocker in blockers}))
        return f"blocked by {kinds}"
    tracker_text = "tracker mutation required" if candidate_requires_tracker(candidate) else "no tracker mutation required"
    return f"no active peer reservation or dirty path blocks the candidate; {tracker_text}"


def classify_candidate(
    candidate: dict[str, Any],
    reservations: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    completed: list[dict[str, Any]],
    agent: str,
    disk_pressure: dict[str, Any],
    tracker_lock: dict[str, Any],
) -> dict[str, Any]:
    paths = candidate["paths"]
    blockers = []
    blockers.extend(lane_blockers(candidate))
    blockers.extend(completed_work_blockers(candidate, completed))
    blockers.extend(proof_command_blockers(candidate))
    blockers.extend(disk_pressure_blockers(candidate, disk_pressure))
    blockers.extend(bead_blockers(candidate))
    blockers.extend(tracker_blockers(candidate, tracker_lock))
    blockers.extend(tracker_dirty_blockers(candidate, dirty, reservations, agent))
    blockers.extend(reservation_blockers(paths, reservations, agent))
    blockers.extend(dirty_blockers(paths, dirty, reservations, agent))

    if blockers:
        status = "blocked"
        action = "wait-or-pick-next-candidate"
    elif candidate["kind"] == "ready-bead":
        status = "ready-to-claim"
        action = "claim-bead-and-reserve-paths"
    else:
        status = "ready-fallback"
        action = "inspect-then-create-or-claim-bead"

    row = dict(candidate)
    row["status"] = status
    row["blockers"] = blockers
    row["recommended_action"] = action
    row["files_to_reserve"] = files_to_reserve(candidate)
    row["validation_class"] = validation_class(candidate)
    row["tracker_mutation_required"] = candidate_requires_tracker(candidate)
    row["safety_reason"] = safety_reason(candidate, blockers)
    return row


def candidate_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    kind_rank = 0 if row["kind"] == "ready-bead" else 1
    return (kind_rank, int(row["priority"]), row["candidate_id"])


def recommendation(candidates: list[dict[str, Any]], disk_pressure: dict[str, Any]) -> dict[str, Any]:
    ready = [row for row in candidates if row["status"] in {"ready-to-claim", "ready-fallback"}]
    if ready:
        chosen = sorted(ready, key=candidate_sort_key)[0]
        if chosen["kind"] == "ready-bead":
            category = "claim-ready-bead"
        else:
            category = "run-fallback-lane"
        return {
            "category": category,
            "candidate_id": chosen["candidate_id"],
            "lane": chosen["lane"],
            "title": chosen["title"],
            "paths": chosen["paths"],
            "files_to_reserve": chosen["files_to_reserve"],
            "validation_class": chosen["validation_class"],
            "reason": "first unblocked candidate by kind and priority",
            "safety_reason": chosen["safety_reason"],
        }
    cleanup_candidates = disk_pressure.get("cleanup_candidates", [])
    if disk_pressure["level"] == "critical" and cleanup_candidates:
        chosen = cleanup_candidates[0]
        return {
            "category": "request-cleanup-authorization",
            "candidate_id": str(chosen.get("candidate_id") or chosen.get("path") or "disk-cleanup"),
            "lane": "disk-pressure-cleanup-authorization",
            "title": str(chosen.get("title") or "Request authorization for stale artifact cleanup"),
            "paths": [str(chosen["path"])] if chosen.get("path") else [],
            "files_to_reserve": [],
            "validation_class": "human-authorization",
            "reason": "critical disk pressure leaves no safe work candidate; ask for explicit cleanup authorization",
            "safety_reason": "cleanup is report-only and requires explicit user authorization",
        }
    if candidates:
        first = sorted(candidates, key=candidate_sort_key)[0]
        return {
            "category": "blocked-no-safe-work",
            "candidate_id": first["candidate_id"],
            "lane": first["lane"],
            "title": first["title"],
            "paths": first["paths"],
            "files_to_reserve": first["files_to_reserve"],
            "validation_class": first["validation_class"],
            "reason": "all candidates are blocked by reservations, dirty paths, or policy",
            "safety_reason": first["safety_reason"],
        }
    return {
        "category": "blocked-no-candidates",
        "candidate_id": "",
        "lane": "",
        "title": "",
        "paths": [],
        "files_to_reserve": [],
        "validation_class": "none",
        "reason": "no ready beads or fallback candidates were provided",
        "safety_reason": "no candidates were supplied",
    }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_int(*values: Any) -> int | None:
    for value in values:
        parsed = _int_or_none(value)
        if parsed is not None:
            return parsed
    return None


def infer_disk_level(available_bytes: int | None, explicit_level: str = "") -> str:
    if explicit_level in {"green", "healthy", "normal"}:
        return "green"
    if explicit_level in {"yellow", "low", "warning"}:
        return "low"
    if explicit_level in {"red", "critical", "fatal"}:
        return "critical"
    if available_bytes is None:
        return "unknown"
    if available_bytes < DISK_CRITICAL_BYTES:
        return "critical"
    if available_bytes < DISK_LOW_BYTES:
        return "low"
    return "green"


def normalize_cleanup_candidate(row: dict[str, Any], index: int) -> dict[str, Any]:
    reclaimable = _first_int(
        row.get("reclaimable_bytes"),
        row.get("size_bytes"),
        row.get("bytes"),
        row.get("estimated_reclaimable_bytes"),
    )
    return {
        "candidate_id": str(row.get("candidate_id") or row.get("id") or f"cleanup:{index + 1}"),
        "path": normalize_path(str(row.get("path") or "")),
        "title": str(row.get("title") or row.get("category") or "stale artifact candidate"),
        "reclaimable_bytes": reclaimable,
        "source": str(row.get("source") or row.get("pattern_name") or "fixture"),
        "requires_authorization": True,
        "delete_command": None,
    }


def cleanup_candidates_from(source: dict[str, Any]) -> list[dict[str, Any]]:
    disk = source.get("disk_pressure", {}) if isinstance(source, dict) else {}
    rows = rows_from(disk, ("cleanup_candidates", "candidates", "stale_target_candidates"))
    inventory = source.get("target_inventory", {}) if isinstance(source, dict) else {}
    inventory_rows = []
    for row in rows_from(inventory, ("candidates",)):
        if not row.get("authorization_candidate"):
            continue
        inventory_row = dict(row)
        inventory_row.setdefault("candidate_id", inventory_row.get("target_name") or inventory_row.get("path"))
        inventory_row.setdefault("source", "target_inventory")
        inventory_row.setdefault("reclaimable_bytes", inventory_row.get("size_bytes"))
        inventory_row.setdefault("title", "stale rch target candidate")
        inventory_rows.append(inventory_row)
    rows.extend(inventory_rows)
    candidates = [
        normalize_cleanup_candidate(row, index)
        for index, row in enumerate(rows)
        if isinstance(row, dict)
    ]
    return sorted(
        candidates,
        key=lambda row: (-(row["reclaimable_bytes"] or 0), row["candidate_id"]),
    )


def disk_pressure_from_source(source: dict[str, Any]) -> dict[str, Any]:
    disk = source.get("disk_pressure", {}) if isinstance(source, dict) else {}
    available_bytes = _first_int(
        disk.get("available_bytes"),
        disk.get("free_bytes"),
        disk.get("free"),
        disk.get("volume_available"),
    )
    level = infer_disk_level(available_bytes, str(disk.get("level") or disk.get("pressure") or ""))
    ballast_releasable = _first_int(
        disk.get("ballast_releasable_bytes"),
        disk.get("releasable_bytes"),
    )
    cleanup_candidates = cleanup_candidates_from(source)
    return {
        "level": level,
        "available_bytes": available_bytes,
        "rch_heavy_work_allowed": level != "critical",
        "ballast_releasable_bytes": ballast_releasable,
        "cleanup_candidates": cleanup_candidates,
        "source": str(disk.get("status") or disk.get("source") or "fixture"),
    }


def parse_df_bytes(raw: str) -> dict[str, Any]:
    available: list[int] = []
    for line in raw.splitlines()[1:]:
        columns = line.split()
        if len(columns) < 4:
            continue
        value = _int_or_none(columns[3])
        if value is not None:
            available.append(value)
    available_bytes = min(available) if available else None
    return {
        "status": "df",
        "available_bytes": available_bytes,
        "level": infer_disk_level(available_bytes),
        "cleanup_candidates": [],
    }


def disk_pressure_non_build_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        {
            "candidate_id": row["candidate_id"],
            "lane": row["lane"],
            "title": row["title"],
            "paths": row["paths"],
            "status": row["status"],
        }
        for row in candidates
        if row["kind"] == "fallback-lane"
        and row["status"] == "ready-fallback"
        and not proof_commands_require_rch_heavy_work(row)
    ]
    return sorted(rows, key=lambda row: (row["lane"], row["candidate_id"]))


def source_proof_receipt(source: dict[str, Any]) -> dict[str, Any]:
    for key in ("proof_receipt", "rch_receipt", "artifact_free_proof_receipt"):
        value = source.get(key)
        if isinstance(value, dict):
            receipt = value.get("artifact_free_proof_receipt")
            if isinstance(receipt, dict):
                return receipt
            return value
    return {}


def proof_result_from(source: dict[str, Any]) -> dict[str, Any]:
    receipt = source_proof_receipt(source)
    remote = receipt.get("remote_command_result") if isinstance(receipt, dict) else {}
    if not isinstance(remote, dict):
        remote = {}
    return {
        "status": str(remote.get("status") or "unknown"),
        "exit_code": remote.get("exit_code"),
        "line": int(remote.get("line") or 0),
        "reason": str(remote.get("reason") or ""),
        "classification": str(receipt.get("classification") or "unknown"),
        "decision": str(receipt.get("decision") or "unknown"),
        "target_dir": str(receipt.get("target_dir") or ""),
        "selected_worker": str(receipt.get("selected_worker") or ""),
    }


def retrieval_blocker_from(source: dict[str, Any]) -> dict[str, Any]:
    receipt = source_proof_receipt(source)
    retrieval = receipt.get("artifact_retrieval_result") if isinstance(receipt, dict) else {}
    if not isinstance(retrieval, dict):
        retrieval = {}
    return {
        "status": str(retrieval.get("status") or "unknown"),
        "kind": str(retrieval.get("blocker_kind") or ""),
        "line": int(retrieval.get("blocker_line") or 0),
        "text": str(retrieval.get("blocker_text") or ""),
    }


def handoff_cleanup_candidates(disk_pressure: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": row["candidate_id"],
            "path": row["path"],
            "title": row["title"],
            "reclaimable_bytes": row["reclaimable_bytes"],
            "source": row["source"],
            "requires_authorization": row["requires_authorization"],
            "delete_command": row["delete_command"],
        }
        for row in disk_pressure.get("cleanup_candidates", [])
    ]


def build_closeout_handoff(
    source: dict[str, Any],
    agent: str,
    generated_at: str,
    recommendation_row: dict[str, Any],
    disk_pressure: dict[str, Any],
    dirty: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "disk-pressure-autopilot-handoff-v1",
        "generated_at": generated_at,
        "agent": agent,
        "active_dirty_paths": dirty,
        "chosen_next_lane": {
            "category": recommendation_row["category"],
            "candidate_id": recommendation_row["candidate_id"],
            "lane": recommendation_row["lane"],
            "title": recommendation_row["title"],
            "paths": recommendation_row["paths"],
            "files_to_reserve": recommendation_row["files_to_reserve"],
            "validation_class": recommendation_row["validation_class"],
            "reason": recommendation_row["reason"],
            "safety_reason": recommendation_row["safety_reason"],
        },
        "remote_proof_result": proof_result_from(source),
        "artifact_retrieval_blocker": retrieval_blocker_from(source),
        "disk_pressure_status": {
            "level": disk_pressure["level"],
            "available_bytes": disk_pressure["available_bytes"],
            "rch_heavy_work_allowed": disk_pressure["rch_heavy_work_allowed"],
            "ballast_releasable_bytes": disk_pressure["ballast_releasable_bytes"],
            "source": disk_pressure["source"],
        },
        "cleanup_candidates": handoff_cleanup_candidates(disk_pressure),
        "authorization": {
            "cleanup_requires_explicit_user_authorization": True,
            "automatic_cleanup_performed": False,
            "delete_command_available": False,
            "instruction": (
                "Do not delete cleanup candidates unless the user explicitly authorizes "
                "the exact cleanup command or paths."
            ),
        },
        "non_mutating": True,
        "preserves_peer_dirty_paths": True,
    }


def stale_after_minutes_from(source: dict[str, Any]) -> int:
    beads = source.get("beads", {}) if isinstance(source, dict) else {}
    parsed = _first_int(
        beads.get("stale_after_minutes"),
        source.get("stale_in_progress_after_minutes"),
    )
    return parsed if parsed is not None and parsed > 0 else DEFAULT_STALE_IN_PROGRESS_MINUTES


def issue_owner(issue: dict[str, Any]) -> str:
    for key in ("assignee", "owner", "agent", "claimed_by", "updated_by", "created_by"):
        value = issue.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def stale_in_progress_reports(
    source: dict[str, Any],
    generated_at: str,
    active_agent_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    threshold = stale_after_minutes_from(source)
    active_agent_names = active_agent_names or set()
    reports = []
    for issue in in_progress_issues(source):
        updated_at = parse_timestamp(
            str(issue.get("updated_at") or issue.get("claimed_at") or issue.get("created_at") or "")
        )
        if updated_at is None:
            continue
        age_minutes = int((now - updated_at).total_seconds() // 60)
        if age_minutes < threshold:
            continue
        issue_id = str(issue.get("id") or "")
        owner = issue_owner(issue)
        owner_active = owner in active_agent_names
        reports.append(
            {
                "id": issue_id,
                "title": str(issue.get("title") or issue_id),
                "owner": owner,
                "owner_active": owner_active,
                "updated_at": updated_at.isoformat().replace("+00:00", "Z"),
                "age_minutes": age_minutes,
                "threshold_minutes": threshold,
                "status": "stale-report-only",
                "recommended_action": (
                    "message-active-owner-before-reopen"
                    if owner_active
                    else "coordinate-before-reopen-or-force-release"
                ),
                "requires_explicit_action": True,
                "force_release_performed": False,
                "reopen_performed": False,
            }
        )
    return sorted(reports, key=lambda row: (-row["age_minutes"], row["id"]))


def active_agent_window_minutes_from(source: dict[str, Any]) -> int:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    parsed = _first_int(
        agent_mail.get("active_agent_window_minutes") if isinstance(agent_mail, dict) else None,
        source.get("active_agent_window_minutes") if isinstance(source, dict) else None,
    )
    return parsed if parsed is not None and parsed > 0 else DEFAULT_ACTIVE_AGENT_WINDOW_MINUTES


def agent_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    return rows_from(agent_mail, ("agents", "active_agents", "registered_agents"))


def active_agent_reports(source: dict[str, Any], generated_at: str) -> list[dict[str, Any]]:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    window = active_agent_window_minutes_from(source)
    rows = []
    for row in agent_rows(source):
        name = holder_name(row)
        if not name:
            continue
        last_active = parse_timestamp(
            str(row.get("last_active_ts") or row.get("last_seen_ts") or row.get("updated_at") or "")
        )
        if last_active is None:
            continue
        age_minutes = int((now - last_active).total_seconds() // 60)
        if age_minutes > window:
            continue
        rows.append(
            {
                "name": name,
                "program": str(row.get("program") or ""),
                "task_description": str(row.get("task_description") or ""),
                "last_active_ts": last_active.isoformat().replace("+00:00", "Z"),
                "age_minutes": age_minutes,
            }
        )
    return sorted(rows, key=lambda row: (row["age_minutes"], row["name"]))


def ack_required_backlog(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = []
    for row in rows_from(
        agent_mail,
        ("ack_required", "ack_required_messages", "unacknowledged", "inbox"),
    ):
        ack_required = bool(row.get("ack_required", True))
        acknowledged = bool(row.get("acknowledged") or row.get("acknowledged_at") or row.get("ack_ts"))
        if not ack_required or acknowledged:
            continue
        message_id = str(row.get("id") or row.get("message_id") or "")
        rows.append(
            {
                "id": message_id,
                "from": str(row.get("from") or row.get("sender") or row.get("sender_name") or ""),
                "subject": str(row.get("subject") or message_id),
                "created_ts": str(row.get("created_ts") or row.get("created_at") or ""),
                "importance": str(row.get("importance") or "normal"),
            }
        )
    return sorted(rows, key=lambda row: (row["created_ts"], row["id"]))


def peer_dirty_path_reports(
    dirty: list[dict[str, Any]],
    reservations: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    rows = []
    for row in dirty:
        owner, source = owner_for_dirty_path(row, reservations)
        if owner == agent:
            continue
        rows.append(
            {
                "path": row["path"],
                "status": row["status"],
                "holder": owner or "unknown",
                "source": source,
            }
        )
    return sorted(rows, key=lambda row: row["path"])


def coordination_next_action(
    ack_backlog: list[dict[str, Any]],
    tracker_lock: dict[str, Any],
    stale_in_progress: list[dict[str, Any]],
    peer_dirty_paths: list[dict[str, str]],
    recommendation_row: dict[str, Any],
) -> str:
    if ack_backlog:
        return "ack-required-mail-before-new-work"
    if tracker_lock.get("active") and ".beads/issues.jsonl" in recommendation_row.get("files_to_reserve", []):
        return "wait-for-tracker-or-run-source-only-fallback"
    if stale_in_progress:
        return "coordinate-before-reopen-or-force-release"
    if peer_dirty_paths:
        return "avoid-peer-dirty-paths-and-use-safe-recommendation"
    category = str(recommendation_row.get("category") or "")
    if category == "claim-ready-bead":
        return "claim-ready-bead-and-reserve-paths"
    if category == "run-fallback-lane":
        return "run-fallback-lane"
    return category or "blocked-no-safe-work"


def coordination_churn_from(
    source: dict[str, Any],
    agent: str,
    generated_at: str,
    reservations: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    tracker_lock: dict[str, Any],
    stale_in_progress: list[dict[str, Any]],
    recommendation_row: dict[str, Any],
) -> dict[str, Any]:
    active_agents = active_agent_reports(source, generated_at)
    ack_backlog = ack_required_backlog(source)
    peer_dirty_paths = peer_dirty_path_reports(dirty, reservations, agent)
    max_stale_age = max((row["age_minutes"] for row in stale_in_progress), default=0)
    source_only_safe = (
        recommendation_row.get("category") == "run-fallback-lane"
        and ".beads/issues.jsonl" not in recommendation_row.get("files_to_reserve", [])
    )
    return {
        "schema_version": "coordination-churn-governor-v1",
        "active_agent_window_minutes": active_agent_window_minutes_from(source),
        "active_agent_count": len(active_agents),
        "active_agents": active_agents,
        "ack_required_backlog_count": len(ack_backlog),
        "ack_required_backlog": ack_backlog,
        "tracker_lock_state": {
            "active": bool(tracker_lock.get("active")),
            "holder": str(tracker_lock.get("holder") or ""),
            "path_pattern": str(tracker_lock.get("path_pattern") or ""),
            "expires_ts": str(tracker_lock.get("expires_ts") or ""),
        },
        "stale_in_progress_count": len(stale_in_progress),
        "max_stale_issue_age_minutes": max_stale_age,
        "stale_work_action": (
            "coordinate-before-reopen-or-force-release" if stale_in_progress else "none"
        ),
        "peer_dirty_path_count": len(peer_dirty_paths),
        "peer_dirty_paths": peer_dirty_paths,
        "source_only_safe_to_proceed": source_only_safe,
        "recommended_next_action": coordination_next_action(
            ack_backlog,
            tracker_lock,
            stale_in_progress,
            peer_dirty_paths,
            recommendation_row,
        ),
        "required_reservations": recommendation_row.get("files_to_reserve", []),
        "mutations_performed": {
            "beads": False,
            "agent_mail": False,
            "force_release": False,
            "reopen": False,
        },
    }


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


def parse_status_lines(raw: str) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        if len(line) >= 4:
            status = line[:2]
            for path in status_paths(status, line[3:]):
                entries.append({"status": status, "path": path})
    return entries


def status_paths(status: str, path: str) -> list[str]:
    path = path.strip()
    if not path:
        return []
    if ("R" in status or "C" in status) and " -> " in path:
        return [normalize_path(part) for part in path.split(" -> ", 1) if part.strip()]
    return [normalize_path(path)]


def parse_git_oneline(raw: str) -> list[dict[str, str]]:
    rows = []
    for line in raw.splitlines():
        commit_id, separator, subject = line.strip().partition(" ")
        if not commit_id or not separator:
            continue
        rows.append(
            {
                "id": commit_id,
                "subject": subject,
            }
        )
    return rows


def closed_issues_from_jsonl(repo_path: Path) -> list[dict[str, Any]]:
    path = repo_path / ".beads" / "issues.jsonl"
    if not path.exists():
        return []
    rows = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and str(row.get("status") or "") == "closed":
                    rows.append(row)
    except OSError:
        return []
    return rows


def live_probe(
    repo_path: Path,
    timeout: float,
    reservations: Any,
    candidates: Any,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    ready_status, ready = run_json(repo_path, ["br", "ready", "--json"], timeout)
    df_status, raw_df = run_text(repo_path, ["df", "-B1", "/", "/tmp"], timeout)
    log_status, raw_log = run_text(repo_path, ["git", "log", "--oneline", "-50"], timeout)
    return {
        "beads": {
            "ready": ready if ready_status == "ok" and isinstance(ready, list) else [],
            "closed": closed_issues_from_jsonl(repo_path),
            "status": ready_status,
        },
        "git": {
            "status": log_status,
            "recent_commits": parse_git_oneline(raw_log if log_status == "ok" else ""),
        },
        "agent_mail": {
            "status": "snapshot" if reservations else "snapshot-unavailable",
            "reservations": rows_from(
                reservations,
                ("reservations", "active_reservations", "file_reservations", "granted"),
            ),
        },
        "dirty_tree": {
            "status": status,
            "entries": parse_status_lines(raw_status if status == "ok" else ""),
        },
        "disk_pressure": parse_df_bytes(raw_df) if df_status == "ok" else {"status": df_status},
        "fallback_lanes": rows_from(candidates, ("fallback_lanes", "candidates", "fallback_candidates")),
    }


def build_receipt(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
) -> dict[str, Any]:
    reservations = reservation_rows(source, generated_at)
    dirty = dirty_entries(source)
    completed = completed_issues(source)
    disk_pressure = disk_pressure_from_source(source)
    tracker_lock = tracker_lock_from(reservations, agent)
    active_agent_names = {row["name"] for row in active_agent_reports(source, generated_at)}
    stale_in_progress = stale_in_progress_reports(source, generated_at, active_agent_names)
    candidates = ready_candidates(source) + fallback_candidates(source)
    classified = [
        classify_candidate(candidate, reservations, dirty, completed, agent, disk_pressure, tracker_lock)
        for candidate in sorted(candidates, key=candidate_sort_key)
    ]
    disk_pressure["non_build_fallback_candidates"] = disk_pressure_non_build_candidates(classified)
    rec = recommendation(classified, disk_pressure)
    blocked = [row for row in classified if row["status"] == "blocked"]
    ready = [row for row in classified if row["status"] != "blocked"]
    coordination_churn = coordination_churn_from(
        source=source,
        agent=agent,
        generated_at=generated_at,
        reservations=reservations,
        dirty=dirty,
        tracker_lock=tracker_lock,
        stale_in_progress=stale_in_progress,
        recommendation_row=rec,
    )
    closeout_handoff = build_closeout_handoff(
        source=source,
        agent=agent,
        generated_at=generated_at,
        recommendation_row=rec,
        disk_pressure=disk_pressure,
        dirty=dirty,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": agent,
        "repo_path": repo_path,
        "summary": {
            "candidate_count": len(classified),
            "ready_count": len(ready),
            "blocked_count": len(blocked),
            "ready_bead_count": sum(1 for row in classified if row["kind"] == "ready-bead"),
            "fallback_count": sum(1 for row in classified if row["kind"] == "fallback-lane"),
            "stale_in_progress_count": len(stale_in_progress),
        },
        "recommendation": rec,
        "coordination_churn": coordination_churn,
        "closeout_handoff": closeout_handoff,
        "disk_pressure": disk_pressure,
        "candidates": classified,
        "stale_in_progress": stale_in_progress,
        "tracker_lock": tracker_lock,
        "active_reservations": [row for row in reservations if row["active"]],
        "dirty_paths": dirty,
        "approved_fallback_lanes": sorted(APPROVED_FALLBACK_LANES),
        "subsystems": {
            "beads": str(source.get("beads", {}).get("status", "fixture")),
            "agent_mail": str(source.get("agent_mail", {}).get("status", "fixture")),
            "git": str(source.get("dirty_tree", {}).get("status", "fixture")),
        },
        "safety": {
            "mutating_commands_executed": False,
            "beads_mutated": False,
            "agent_mail_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "forbidden_command_tokens": [],
        },
    }


def markdown_value(value: Any) -> str:
    text = str(value) if value is not None else ""
    text = " ".join(text.split())
    return text.replace("|", "\\|") or "-"


def markdown_code(value: Any) -> str:
    text = markdown_value(value)
    return f"`{text}`" if text != "-" else "-"


def markdown_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def markdown_bytes(value: Any) -> str:
    parsed = _int_or_none(value)
    if parsed is None:
        return "unknown"
    if parsed < 0:
        return f"{parsed} B"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(parsed)
    unit = units[0]
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return f"{parsed} B"
    return f"{amount:.2f} {unit}"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(markdown_value(value) for value in row) + " |")
    return lines


def append_markdown_table(
    lines: list[str],
    title: str,
    headers: list[str],
    rows: list[list[Any]],
    empty_text: str,
) -> None:
    lines.extend(["", f"## {title}"])
    if rows:
        lines.extend(markdown_table(headers, rows))
    else:
        lines.append(empty_text)


def limited_rows(rows: list[Any], limit: int = 6) -> tuple[list[Any], int]:
    visible = rows[:limit]
    return visible, max(0, len(rows) - len(visible))


def render_candidate_rows(candidates: list[dict[str, Any]], status: str) -> list[list[Any]]:
    rows = []
    for row in candidates:
        if row.get("status") != status:
            continue
        rows.append(
            [
                markdown_code(row.get("candidate_id")),
                markdown_code(row.get("lane")),
                markdown_code(row.get("validation_class")),
                row.get("safety_reason") or "",
            ]
        )
    return rows


def render_blocker_rows(candidates: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for candidate in candidates:
        for blocker in candidate.get("blockers", []):
            rows.append(
                [
                    markdown_code(candidate.get("candidate_id")),
                    markdown_code(blocker.get("kind")),
                    blocker.get("holder") or blocker.get("lane") or "-",
                    blocker.get("path") or blocker.get("path_pattern") or "-",
                    blocker.get("reason") or blocker.get("source") or "-",
                ]
            )
    return rows


def render_markdown_dashboard(receipt: dict[str, Any]) -> str:
    summary = receipt.get("summary", {})
    recommendation_row = receipt.get("recommendation", {})
    coordination = receipt.get("coordination_churn", {})
    disk_pressure = receipt.get("disk_pressure", {})
    handoff = receipt.get("closeout_handoff", {})
    proof_result = handoff.get("remote_proof_result", {}) if isinstance(handoff, dict) else {}
    retrieval_blocker = handoff.get("artifact_retrieval_blocker", {}) if isinstance(handoff, dict) else {}
    safety = receipt.get("safety", {})
    candidates = [row for row in receipt.get("candidates", []) if isinstance(row, dict)]

    lines = [
        "# Swarm Evidence Dashboard",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Schema | {markdown_code(receipt.get('schema_version'))} |",
        f"| Generated | {markdown_code(receipt.get('generated_at'))} |",
        f"| Current date | {markdown_code(receipt.get('current_date'))} |",
        f"| Agent | {markdown_code(receipt.get('agent'))} |",
        f"| Repo | {markdown_code(receipt.get('repo_path'))} |",
        "",
        "## Summary",
    ]
    lines.extend(
        markdown_table(
            ["Metric", "Value"],
            [
                ["candidates", summary.get("candidate_count", 0)],
                ["ready", summary.get("ready_count", 0)],
                ["blocked", summary.get("blocked_count", 0)],
                ["ready beads", summary.get("ready_bead_count", 0)],
                ["fallback lanes", summary.get("fallback_count", 0)],
                ["stale in-progress", summary.get("stale_in_progress_count", 0)],
            ],
        )
    )

    lines.extend(["", "## Recommendation"])
    lines.extend(
        markdown_table(
            ["Field", "Value"],
            [
                ["category", markdown_code(recommendation_row.get("category"))],
                ["candidate", markdown_code(recommendation_row.get("candidate_id"))],
                ["lane", markdown_code(recommendation_row.get("lane"))],
                ["validation", markdown_code(recommendation_row.get("validation_class"))],
                ["reason", recommendation_row.get("reason") or ""],
                ["safety", recommendation_row.get("safety_reason") or ""],
            ],
        )
    )
    files_to_reserve = recommendation_row.get("files_to_reserve", [])
    lines.append("")
    lines.append("Files to reserve:")
    if files_to_reserve:
        lines.extend(f"- {markdown_code(path)}" for path in files_to_reserve)
    else:
        lines.append("- none")

    lines.extend(["", "## Coordination Churn"])
    tracker_state = coordination.get("tracker_lock_state", {}) if isinstance(coordination, dict) else {}
    lines.extend(
        markdown_table(
            ["Field", "Value"],
            [
                ["active agents", coordination.get("active_agent_count", 0)],
                ["ack-required backlog", coordination.get("ack_required_backlog_count", 0)],
                ["tracker lock active", markdown_bool(tracker_state.get("active"))],
                ["tracker holder", tracker_state.get("holder") or "-"],
                ["stale in-progress", coordination.get("stale_in_progress_count", 0)],
                ["max stale age minutes", coordination.get("max_stale_issue_age_minutes", 0)],
                ["peer dirty paths", coordination.get("peer_dirty_path_count", 0)],
                ["source-only safe", markdown_bool(coordination.get("source_only_safe_to_proceed"))],
                ["next action", markdown_code(coordination.get("recommended_next_action"))],
                ["stale action", markdown_code(coordination.get("stale_work_action"))],
            ],
        )
    )

    ready_rows = render_candidate_rows(candidates, "ready-to-claim")
    ready_rows.extend(render_candidate_rows(candidates, "ready-fallback"))
    append_markdown_table(
        lines,
        "Safe Work",
        ["Candidate", "Lane", "Validation", "Safety"],
        ready_rows,
        "No unblocked work candidates.",
    )

    blocker_rows, extra_blockers = limited_rows(render_blocker_rows(candidates))
    if extra_blockers:
        blocker_rows.append(["+", "+", "+", f"{extra_blockers} more blockers", "+"])
    append_markdown_table(
        lines,
        "Blockers",
        ["Candidate", "Kind", "Owner", "Path", "Reason"],
        blocker_rows,
        "No candidate blockers.",
    )

    reservation_rows = [
        [
            markdown_code(row.get("path_pattern")),
            row.get("holder") or "unknown",
            markdown_bool(row.get("exclusive", True)),
            markdown_code(row.get("expires_ts")),
        ]
        for row in receipt.get("active_reservations", [])
        if isinstance(row, dict)
    ]
    append_markdown_table(
        lines,
        "Active Reservations",
        ["Path", "Holder", "Exclusive", "Expires"],
        reservation_rows,
        "No active reservations in snapshot.",
    )

    dirty_rows = [
        [
            markdown_code(row.get("path")),
            markdown_code(row.get("status")),
            row.get("owner") or "unknown",
        ]
        for row in receipt.get("dirty_paths", [])
        if isinstance(row, dict)
    ]
    append_markdown_table(
        lines,
        "Dirty Paths",
        ["Path", "Status", "Owner"],
        dirty_rows,
        "No dirty paths in snapshot.",
    )

    lines.extend(["", "## Disk And Proof"])
    lines.extend(
        markdown_table(
            ["Field", "Value"],
            [
                ["disk level", markdown_code(disk_pressure.get("level"))],
                ["available", markdown_bytes(disk_pressure.get("available_bytes"))],
                ["rch heavy work allowed", markdown_bool(disk_pressure.get("rch_heavy_work_allowed"))],
                ["ballast releasable", markdown_bytes(disk_pressure.get("ballast_releasable_bytes"))],
                ["proof status", markdown_code(proof_result.get("status"))],
                ["proof decision", markdown_code(proof_result.get("decision"))],
                ["proof target", markdown_code(proof_result.get("target_dir"))],
                ["retrieval status", markdown_code(retrieval_blocker.get("status"))],
                ["retrieval blocker", retrieval_blocker.get("text") or retrieval_blocker.get("kind") or "-"],
            ],
        )
    )

    cleanup_rows = [
        [
            markdown_code(row.get("candidate_id")),
            markdown_code(row.get("path")),
            markdown_bytes(row.get("reclaimable_bytes")),
            markdown_bool(row.get("requires_authorization")),
            "none" if row.get("delete_command") is None else "present",
        ]
        for row in disk_pressure.get("cleanup_candidates", [])
        if isinstance(row, dict)
    ]
    append_markdown_table(
        lines,
        "Cleanup Authorization",
        ["Candidate", "Path", "Reclaimable", "Requires Auth", "Delete Command"],
        cleanup_rows,
        "No cleanup candidates in snapshot.",
    )

    stale_rows = [
        [
            markdown_code(row.get("id")),
            row.get("owner") or "unknown",
            row.get("age_minutes", 0),
            row.get("recommended_action") or "",
            markdown_bool(row.get("force_release_performed")),
            markdown_bool(row.get("reopen_performed")),
        ]
        for row in receipt.get("stale_in_progress", [])
        if isinstance(row, dict)
    ]
    append_markdown_table(
        lines,
        "Stale In-Progress",
        ["Issue", "Owner", "Age Minutes", "Action", "Force Released", "Reopened"],
        stale_rows,
        "No stale in-progress issues in snapshot.",
    )

    lines.extend(["", "## Safety"])
    lines.extend(
        markdown_table(
            ["Invariant", "Value"],
            [
                ["mutating commands executed", markdown_bool(safety.get("mutating_commands_executed"))],
                ["beads mutated", markdown_bool(safety.get("beads_mutated"))],
                ["agent mail mutated", markdown_bool(safety.get("agent_mail_mutated"))],
                ["cargo executed", markdown_bool(safety.get("cargo_executed"))],
                ["branch/worktree operations", markdown_bool(safety.get("branch_or_worktree_operations"))],
                [
                    "forbidden command tokens",
                    len(safety.get("forbidden_command_tokens", []))
                    if isinstance(safety.get("forbidden_command_tokens", []), list)
                    else "unknown",
                ],
            ],
        )
    )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find safe ready or fallback work without mutation.")
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Current agent name")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument("--reservation-snapshot", type=Path, help="Optional Agent Mail reservation snapshot")
    parser.add_argument("--candidate-snapshot", type=Path, help="Optional fallback candidate snapshot")
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
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
            reservations=load_json(args.reservation_snapshot),
            candidates=load_json(args.candidate_snapshot),
        )
    receipt = build_receipt(
        source=source if isinstance(source, dict) else {},
        repo_path=str(repo_path),
        agent=args.agent,
        generated_at=generated_at,
    )
    if args.output == "json":
        json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown_dashboard(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
