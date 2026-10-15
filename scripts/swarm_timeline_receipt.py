#!/usr/bin/env python3
"""Emit a redacted cross-agent timeline receipt without mutating state.

The helper consumes fixture rows shaped like Agent Mail messages and git
commits, then produces a compact chronological artifact suitable for handoff
messages. It preserves bead ids, agents, timestamps, subjects, commit ids, and
validation summaries while redacting secrets and oversized body text.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-timeline-receipt-v1"
MAX_SUMMARY_CHARS = 320
MAX_VALIDATION_LINES = 5
BEAD_RE = re.compile(r"\basupersync-[a-z0-9]+(?:\.\d+)?\b")
TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|password|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)
URL_QUERY_RE = re.compile(r"(https?://[^\s?#)>\]]+)\?[^ \n)>\]]+")
LONG_WORD_RE = re.compile(r"\b[A-Za-z0-9._~/+=-]{96,}\b")
SPACE_RE = re.compile(r"\s+")


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


def rows_from(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
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


def redact_text(text: str, counts: dict[str, int]) -> str:
    def count_sub(pattern: re.Pattern[str], replacement: str, label: str, value: str) -> str:
        redacted, changed = pattern.subn(replacement, value)
        counts[label] = counts.get(label, 0) + changed
        counts["total"] = counts.get("total", 0) + changed
        return redacted

    text = count_sub(TOKEN_RE, r"\1[REDACTED_TOKEN]", "token", text)
    text = count_sub(KEY_VALUE_SECRET_RE, r"\1\2[REDACTED_SECRET]", "secret", text)
    text = count_sub(URL_QUERY_RE, r"\1?[REDACTED_QUERY]", "url_query", text)
    text = count_sub(LONG_WORD_RE, "[REDACTED_LONG_TOKEN]", "long_token", text)
    return text


def compact_text(text: str, counts: dict[str, int]) -> str:
    redacted = redact_text(text, counts)
    compact = SPACE_RE.sub(" ", redacted).strip()
    if len(compact) <= MAX_SUMMARY_CHARS:
        return compact
    counts["truncated"] = counts.get("truncated", 0) + 1
    counts["total"] = counts.get("total", 0) + 1
    return compact[: MAX_SUMMARY_CHARS - 19].rstrip() + " [TRUNCATED]"


def bead_ids_from(*values: str) -> list[str]:
    found: set[str] = set()
    for value in values:
        found.update(BEAD_RE.findall(value or ""))
    return sorted(found)


def classify_event(subject: str, body: str, source: str) -> str:
    haystack = f"{subject}\n{body}".lower()
    if any(word in haystack for word in ("blocked", "blocker", "conflict", "failed before")):
        return "block"
    if source == "git" and BEAD_RE.search(subject):
        return "ship"
    if any(word in haystack for word in ("ship ", "shipped", "landed", "completed", "pushed", "closed ")):
        return "ship"
    if any(word in haystack for word in ("starting", "claiming", "claimed", "taking ")):
        return "claim"
    if "reserved" in haystack or "reservation" in haystack:
        return "reservation"
    if any(word in haystack for word in ("validation", "proof", "passed", "cargo test", "rch exec")):
        return "validation"
    if any(word in haystack for word in ("tracker", "br close", "br show", ".beads")):
        return "tracker"
    if source == "git" and BEAD_RE.search(subject):
        return "ship"
    return "note"


def validation_lines(text: str, counts: dict[str, int]) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        lowered = raw_line.lower()
        if any(
            marker in lowered
            for marker in (
                "validation",
                "proof",
                "passed",
                "failed",
                "cargo test",
                "rch exec",
                "rustfmt",
                "git diff --check",
                "remote exit",
            )
        ):
            line = compact_text(raw_line, counts)
            if line and line not in lines:
                lines.append(line)
        if len(lines) >= MAX_VALIDATION_LINES:
            break
    return lines


def stable_event_id(parts: list[str]) -> str:
    digest = hashlib.sha1("\0".join(parts).encode("utf-8")).hexdigest()
    return digest[:12]


def message_events(source: dict[str, Any], counts: dict[str, int]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    messages = rows_from(agent_mail, ("messages", "inbox", "threads"))
    events = []
    for row in messages:
        subject = str(row.get("subject") or "")
        body = str(row.get("body_md") or row.get("body") or row.get("message") or "")
        thread_id = str(row.get("thread_id") or "")
        created_ts = str(row.get("created_ts") or row.get("created_at") or "")
        agent = str(row.get("from") or row.get("sender") or row.get("agent") or "unknown")
        kind = classify_event(subject, body, "mail")
        bead_ids = bead_ids_from(subject, body, thread_id)
        summary_basis = body or subject
        event_id = stable_event_id(["mail", created_ts, agent, thread_id, subject, kind])
        events.append(
            {
                "event_id": event_id,
                "source": "agent-mail",
                "source_refs": [str(row.get("id") or event_id)],
                "kind": kind,
                "created_ts": created_ts,
                "agent": agent,
                "thread_id": thread_id,
                "subject": compact_text(subject, counts),
                "bead_ids": bead_ids,
                "summary": compact_text(summary_basis, counts),
                "validation": validation_lines(body, counts),
            }
        )
    return events


def commit_events(source: dict[str, Any], counts: dict[str, int]) -> list[dict[str, Any]]:
    git = source.get("git", {}) if isinstance(source, dict) else {}
    commits = rows_from(git, ("commits", "log"))
    events = []
    for row in commits:
        commit_hash = str(row.get("hash") or row.get("commit") or "")[:12]
        subject = str(row.get("subject") or row.get("message") or "")
        body = str(row.get("body") or "")
        created_ts = str(row.get("created_ts") or row.get("authored_ts") or row.get("date") or "")
        agent = str(row.get("author") or row.get("agent") or "git")
        kind = classify_event(subject, body, "git")
        bead_ids = bead_ids_from(subject, body)
        event_id = stable_event_id(["git", commit_hash, created_ts, agent, subject, kind])
        events.append(
            {
                "event_id": event_id,
                "source": "git",
                "source_refs": [commit_hash or event_id],
                "kind": kind,
                "created_ts": created_ts,
                "agent": agent,
                "thread_id": "",
                "subject": compact_text(subject, counts),
                "bead_ids": bead_ids,
                "summary": compact_text(body or subject, counts),
                "commit": commit_hash,
                "validation": validation_lines(body, counts),
            }
        )
    return events


def coalesce_events(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    duplicate_count = 0
    for event in events:
        key = (
            event.get("kind"),
            event.get("created_ts"),
            event.get("agent"),
            event.get("thread_id"),
            event.get("subject"),
            tuple(event.get("bead_ids") or []),
            event.get("commit", ""),
        )
        if key not in grouped:
            grouped[key] = event
            continue
        duplicate_count += 1
        existing = grouped[key]
        refs = set(existing.get("source_refs") or [])
        refs.update(event.get("source_refs") or [])
        existing["source_refs"] = sorted(refs)
        existing["duplicates"] = int(existing.get("duplicates") or 0) + 1
        validation = list(existing.get("validation") or [])
        for line in event.get("validation") or []:
            if line not in validation:
                validation.append(line)
        existing["validation"] = validation[:MAX_VALIDATION_LINES]
    result = list(grouped.values())
    result.sort(key=lambda row: (str(row.get("created_ts") or ""), str(row.get("event_id") or "")))
    return result, duplicate_count


def unresolved_cues(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ship_indexes: dict[str, list[int]] = {}
    claims: list[tuple[str, str, dict[str, Any], int]] = []
    blockers: list[tuple[str, dict[str, Any], int]] = []
    cues: list[dict[str, Any]] = []

    for event_index, event in enumerate(events):
        bead_ids = event.get("bead_ids") or []
        if event.get("kind") == "ship":
            for bead_id in bead_ids:
                ship_indexes.setdefault(str(bead_id), []).append(event_index)
            if not event.get("validation"):
                cues.append(
                    {
                        "kind": "validation-evidence-gap",
                        "bead_id": bead_ids[0] if bead_ids else "",
                        "agent": event.get("agent", ""),
                        "event_id": event.get("event_id", ""),
                        "reason": "ship event has no validation summary lines",
                    }
                )
        elif event.get("kind") == "claim":
            for bead_id in bead_ids:
                claims.append((str(bead_id), str(event.get("agent") or ""), event, event_index))
        elif event.get("kind") == "block":
            for bead_id in bead_ids:
                blockers.append((str(bead_id), event, event_index))

    def has_later_ship(bead_id: str, event_index: int) -> bool:
        return any(ship_index > event_index for ship_index in ship_indexes.get(bead_id, []))

    for bead_id, agent, event, event_index in sorted(
        claims, key=lambda item: (item[0], item[1], str(item[2].get("event_id") or ""))
    ):
        if not has_later_ship(bead_id, event_index):
            cues.append(
                {
                    "kind": "active-claim-without-ship",
                    "bead_id": bead_id,
                    "agent": agent,
                    "event_id": event.get("event_id", ""),
                    "reason": "claim has no later ship event in this receipt",
                }
            )

    for bead_id, event, event_index in sorted(
        blockers, key=lambda item: (item[0], str(item[1].get("event_id") or ""))
    ):
        if not has_later_ship(bead_id, event_index):
            cues.append(
                {
                    "kind": "unresolved-blocker",
                    "bead_id": bead_id,
                    "agent": event.get("agent", ""),
                    "event_id": event.get("event_id", ""),
                    "reason": "blocker has no later ship event in this receipt",
                }
            )
    return cues


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    source = load_json(Path(args.fixture))
    generated_at = args.generated_at or utc_now()
    redaction_counts: dict[str, int] = {"total": 0}
    raw_events = message_events(source, redaction_counts) + commit_events(source, redaction_counts)
    events, duplicates = coalesce_events(raw_events)
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    git = source.get("git", {}) if isinstance(source, dict) else {}
    source_counts = {
        "agent_mail_messages": len(rows_from(agent_mail, ("messages", "inbox", "threads"))),
        "git_commits": len(rows_from(git, ("commits", "log"))),
        "events_before_coalescing": len(raw_events),
        "duplicates_coalesced": duplicates,
        "timeline_events": len(events),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": args.agent,
        "repo_path": str(Path(args.repo_path)),
        "source_counts": source_counts,
        "timeline": events,
        "redaction_counts": redaction_counts,
        "unresolved_cues": unresolved_cues(events),
        "safety": {
            "non_mutating": True,
            "agent_mail_mutated": False,
            "beads_mutated": False,
            "git_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "files_deleted": False,
        },
        "safety_notes": [
            "fixture mode reads JSON only",
            "no Agent Mail acknowledgements, sends, reservations, or Beads updates are performed",
            "cargo/rch commands are not executed by this helper",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a redacted cross-agent timeline receipt")
    parser.add_argument("--fixture", required=True, help="Fixture JSON with agent_mail and git rows")
    parser.add_argument("--repo-path", default=".", help="Repository path recorded in the receipt")
    parser.add_argument("--agent", default="", help="Agent producing the receipt")
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
