#!/usr/bin/env python3
"""Emit a non-mutating receipt for landed-but-open bead closeout.

The helper correlates in-progress bead rows with commit references, proof
messages, and tracker reservations. It does not close, reopen, claim, sync,
stage, or commit anything; it only emits a proposed closeout command with the
evidence needed to decide whether an operator should run it later.
"""

import argparse
import datetime as dt
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "landed-but-open-receipt-v1"
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db"}
TRACKER_DIRS = {".beads"}
BEAD_RE = re.compile(r"\basupersync-[a-z0-9]+(?:\.\d+)?\b")
PROOF_MARKERS = (
    "validation",
    "proof",
    "passed",
    "remote exit 0",
    "remote success",
    "tests passed",
    "cargo test",
    "rustfmt",
    "git diff --check",
)


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


def extract_rows(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in keys:
        maybe = value.get(key)
        if isinstance(maybe, list):
            rows.extend(item for item in maybe if isinstance(item, dict))
    return rows


def extract_issues(source: dict[str, Any]) -> list[dict[str, Any]]:
    beads = source.get("beads", {}) if isinstance(source, dict) else {}
    return extract_rows(beads, ("issues", "in_progress"))


def row_text(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    return " ".join(str(row.get(key, "")) for key in keys)


def contains_bead(row: dict[str, Any], bead_id: str) -> bool:
    return bead_id in row_text(
        row,
        (
            "id",
            "thread_id",
            "subject",
            "body_md",
            "body",
            "message",
            "summary",
            "hash",
            "commit",
            "close_reason",
        ),
    )


def short_hash(row: dict[str, Any]) -> str:
    value = str(row.get("hash") or row.get("commit") or "")
    return value[:12]


def matching_commits(source: dict[str, Any], bead_id: str) -> list[dict[str, Any]]:
    git = source.get("git", {}) if isinstance(source, dict) else {}
    commits = extract_rows(git, ("commits", "log"))
    rows = [row for row in commits if contains_bead(row, bead_id)]
    rows.sort(key=lambda row: str(row.get("created_ts") or row.get("authored_ts") or ""))
    return rows


def matching_messages(source: dict[str, Any], bead_id: str) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    messages = extract_rows(agent_mail, ("messages", "inbox", "threads"))
    rows = [row for row in messages if contains_bead(row, bead_id)]
    rows.sort(key=lambda row: str(row.get("created_ts") or row.get("created_at") or ""))
    return rows


def proof_lines(messages: list[dict[str, Any]], commits: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for row in [*messages, *commits]:
        text = row_text(row, ("subject", "body_md", "body", "message", "summary"))
        for raw_line in text.splitlines() or [text]:
            lowered = raw_line.lower()
            if any(marker in lowered for marker in PROOF_MARKERS):
                line = " ".join(raw_line.split())
                if line and line not in lines:
                    lines.append(line[:280])
            if len(lines) >= 6:
                return lines
    return lines


def row_holder(row: dict[str, Any]) -> str:
    for key in ("agent", "agent_name", "holder", "owner", "from"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def row_pattern(row: dict[str, Any]) -> str:
    for key in ("path_pattern", "path", "pattern", "glob"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def has_glob_magic(path: str) -> bool:
    return any(char in path for char in "*?[")


def paths_overlap(left: str, right: str) -> bool:
    left = normalize_path(left)
    right = normalize_path(right)
    if not left or not right:
        return False
    if left == right or fnmatch.fnmatchcase(right, left) or fnmatch.fnmatchcase(left, right):
        return True
    left_is_glob = has_glob_magic(left)
    right_is_glob = has_glob_magic(right)
    return (not left_is_glob and right.startswith(f"{left}/")) or (
        not right_is_glob and left.startswith(f"{right}/")
    )


def overlaps_tracker_path(pattern: str) -> bool:
    if not pattern:
        return False
    return any(paths_overlap(pattern, tracker_path) for tracker_path in TRACKER_PATHS | TRACKER_DIRS)


def reservation_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
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


def active_tracker_conflicts(source: dict[str, Any], generated_at: str, agent: str) -> list[dict[str, Any]]:
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    conflicts: list[dict[str, Any]] = []
    for row in reservation_rows(source):
        if row.get("released_ts") or row.get("released_at"):
            continue
        if not row.get("exclusive", True):
            continue
        holder = row_holder(row)
        if holder == agent:
            continue
        pattern = row_pattern(row)
        if not overlaps_tracker_path(pattern) and not overlaps_tracker_path(str(row.get("path", ""))):
            continue
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        expires_at = parse_timestamp(expires_ts)
        if expires_at is not None and expires_at <= now:
            continue
        conflicts.append(
            {
                "path": pattern or str(row.get("path", "")),
                "holder": holder,
                "expires_ts": expires_ts,
            }
        )
    return conflicts


def proposed_close_command(bead_id: str, commit_hash: str) -> str:
    reason = f"Shipped in {commit_hash}" if commit_hash else "Shipped; evidence in receipt"
    return f"br close {bead_id} --reason {reason!r} --json"


def classify_issue(
    source: dict[str, Any],
    issue: dict[str, Any],
    generated_at: str,
    agent: str,
) -> dict[str, Any]:
    bead_id = str(issue.get("id") or "")
    commits = matching_commits(source, bead_id)
    messages = matching_messages(source, bead_id)
    proofs = proof_lines(messages, commits)
    tracker_conflicts = active_tracker_conflicts(source, generated_at, agent)
    commit_hash = short_hash(commits[-1]) if commits else ""

    if not commits:
        classification = "not-landed"
        decision = "keep-open"
        rationale = "no commit row references this bead"
    elif not proofs:
        classification = "landed-missing-proof"
        decision = "verify-before-close"
        rationale = "a commit references the bead but no proof lines were found"
    elif tracker_conflicts:
        classification = "landed-awaiting-tracker"
        decision = "wait-for-tracker"
        rationale = "code and proof evidence exist, but tracker files are actively reserved"
    else:
        classification = "ready-to-close"
        decision = "close-with-reservation"
        rationale = "code and proof evidence exist and no active tracker conflict was observed"

    return {
        "id": bead_id,
        "title": str(issue.get("title") or ""),
        "status": str(issue.get("status") or ""),
        "classification": classification,
        "decision": decision,
        "rationale": rationale,
        "evidence": {
            "commit_hash": commit_hash,
            "commit_count": len(commits),
            "message_count": len(messages),
            "proof_line_count": len(proofs),
            "proof_lines": proofs,
            "tracker_conflicts": tracker_conflicts,
        },
        "proposed_action": {
            "kind": "br-close" if classification in {"ready-to-close", "landed-awaiting-tracker"} else "collect-proof",
            "command": proposed_close_command(bead_id, commit_hash),
            "allowed_now": classification == "ready-to-close",
            "requires_tracker_reservation": True,
        },
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    source = load_json(Path(args.fixture))
    generated_at = args.generated_at or utc_now()
    issues = [issue for issue in extract_issues(source) if str(issue.get("status") or "") == "in_progress"]
    if args.bead_id:
        issues = [issue for issue in issues if issue.get("id") == args.bead_id]
    rows = [classify_issue(source, issue, generated_at, args.agent) for issue in issues]
    summary: dict[str, int] = {}
    for row in rows:
        key = str(row["classification"])
        summary[key] = summary.get(key, 0) + 1
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    git = source.get("git", {}) if isinstance(source, dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": args.agent,
        "repo_path": str(Path(args.repo_path)),
        "source_counts": {
            "in_progress_issues": len(issues),
            "agent_mail_messages": len(extract_rows(agent_mail, ("messages", "inbox", "threads"))),
            "git_commits": len(extract_rows(git, ("commits", "log"))),
            "reservation_rows": len(reservation_rows(source)),
        },
        "rows": rows,
        "summary": summary,
        "safety": {
            "non_mutating": True,
            "beads_mutated": False,
            "agent_mail_mutated": False,
            "git_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "files_deleted": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a landed-but-open bead closeout receipt")
    parser.add_argument("--fixture", required=True, help="Fixture JSON with beads, git, and Agent Mail rows")
    parser.add_argument("--repo-path", default=".", help="Repository path recorded in the receipt")
    parser.add_argument("--agent", default="", help="Agent producing the receipt")
    parser.add_argument("--bead-id", default="", help="Restrict output to one bead id")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
