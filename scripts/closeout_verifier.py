#!/usr/bin/env python3
"""Verify shared-main closeout evidence without mutating repo state.

The verifier consumes either a JSON fixture/source bundle or a small live git
probe and emits pass/fail rows for the closeout obligations agents routinely
forget: pushed main, synced master, closed bead when applicable, closeout mail,
released reservations, and reported validation. It never pushes, closes beads,
sends mail, stages files, or edits tracker state.
"""

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "closeout-verifier-v1"
FORBIDDEN_ACTIONS = {
    "runs_git_mutation": False,
    "runs_beads_mutation": False,
    "runs_agent_mail_mutation": False,
    "runs_destructive_command": False,
    "runs_cargo": False,
}
CARGO_PROOF_COMMAND = re.compile(
    r"\bcargo(?:\s+fuzz)?\s+"
    r"(?:build|check|clippy|doc|fmt|fuzz|run|test|tree)\b",
    re.IGNORECASE,
)
RCH_LOCAL_FALLBACK = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
COMMAND_SPLIT = re.compile(r"(?:\n|;|&&|\band\b)")


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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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
        return f"error:{error.returncode}", error.stdout.strip()
    return "ok", output.stdout.strip()


def live_source(repo_path: Path, timeout: float) -> dict[str, Any]:
    head_status, head = run_text(repo_path, ["git", "rev-parse", "HEAD"], timeout)
    main_status, origin_main = run_text(repo_path, ["git", "rev-parse", "origin/main"], timeout)
    master_status, origin_master = run_text(
        repo_path, ["git", "rev-parse", "origin/master"], timeout
    )
    branch_status, branch = run_text(repo_path, ["git", "branch", "--show-current"], timeout)
    commit = head if head_status == "ok" else ""
    return {
        "closeout": {
            "mode": "code-only",
            "slice_id": commit[:12] if commit else "unknown",
            "commit": commit,
            "agent": "",
        },
        "git": {
            "branch": branch if branch_status == "ok" else "",
            "main_head": commit,
            "origin_main": origin_main if main_status == "ok" else "",
            "origin_master": origin_master if master_status == "ok" else "",
        },
        "beads": {"issues": []},
        "agent_mail": {"messages": [], "reservations": []},
    }


def rows_from(value: Any, *keys: str) -> list[dict[str, Any]]:
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


def text_field(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def command_segments(text: str) -> list[str]:
    return [segment.strip(" `\t\r") for segment in COMMAND_SPLIT.split(text) if segment.strip()]


def bare_cargo_validation_segments(text: str) -> list[str]:
    bare_segments: list[str] = []
    for segment in command_segments(text):
        lowered = segment.lower()
        for match in CARGO_PROOF_COMMAND.finditer(segment):
            if "rch exec" not in lowered[: match.start()]:
                validation_start = lowered.rfind("validation", 0, match.start())
                reported = segment[validation_start:] if validation_start >= 0 else segment
                bare_segments.append(reported.strip(" `\t\r"))
                break
    return bare_segments


def rch_local_fallback_segments(text: str) -> list[str]:
    fallback_segments: list[str] = []
    for segment in command_segments(text):
        if RCH_LOCAL_FALLBACK.search(segment):
            fallback_segments.append(segment.strip(" `\t\r"))
    return fallback_segments


def missing_remote_required_cargo_segments(text: str) -> list[str]:
    missing_segments: list[str] = []
    for segment in command_segments(text):
        lowered = segment.lower()
        for match in CARGO_PROOF_COMMAND.finditer(segment):
            if "rch exec" in lowered[: match.start()] and "rch_require_remote=1" not in lowered:
                validation_start = lowered.rfind("validation", 0, match.start())
                reported = segment[validation_start:] if validation_start >= 0 else segment
                missing_segments.append(reported.strip(" `\t\r"))
                break
    return missing_segments


def closeout_mode(closeout: dict[str, Any]) -> str:
    mode = text_field(closeout, "mode", "slice_mode")
    return mode or "bead-backed"


def closeout_thread(closeout: dict[str, Any]) -> str:
    return text_field(closeout, "thread_id", "bead_id", "slice_id")


def row(
    row_id: str,
    status: str,
    summary: str,
    *,
    evidence: dict[str, Any],
    remediation: str = "",
) -> dict[str, Any]:
    item = {
        "row_id": row_id,
        "status": status,
        "summary": summary,
        "evidence": evidence,
    }
    if remediation:
        item["remediation"] = remediation
    return item


def verify_main_pushed(closeout: dict[str, Any], git: dict[str, Any]) -> dict[str, Any]:
    commit = text_field(closeout, "commit")
    origin_main = text_field(git, "origin_main")
    status = "pass" if commit and origin_main == commit else "fail"
    return row(
        "main_pushed",
        status,
        "origin/main points at the closeout commit"
        if status == "pass"
        else "origin/main does not point at the closeout commit",
        evidence={
            "command": "git rev-parse origin/main",
            "expected_commit": commit,
            "observed_commit": origin_main,
        },
        remediation="push the closeout commit to origin/main" if status == "fail" else "",
    )


def verify_master_synced(closeout: dict[str, Any], git: dict[str, Any]) -> dict[str, Any]:
    commit = text_field(closeout, "commit")
    origin_main = text_field(git, "origin_main")
    origin_master = text_field(git, "origin_master")
    status = "pass" if commit and origin_main == commit and origin_master == commit else "fail"
    return row(
        "master_synced",
        status,
        "origin/master is synced to origin/main at the closeout commit"
        if status == "pass"
        else "origin/master is not synced to the closeout commit",
        evidence={
            "command": "git rev-parse origin/main origin/master",
            "expected_commit": commit,
            "origin_main": origin_main,
            "origin_master": origin_master,
        },
        remediation="run git push origin main:master after pushing main" if status == "fail" else "",
    )


def issue_status(beads: dict[str, Any], bead_id: str) -> str:
    for issue in rows_from(beads, "issues"):
        if text_field(issue, "id") == bead_id:
            return text_field(issue, "status")
    return ""


def verify_bead_state(closeout: dict[str, Any], beads: dict[str, Any]) -> list[dict[str, Any]]:
    mode = closeout_mode(closeout)
    bead_id = text_field(closeout, "bead_id")
    if mode == "code-only" or not bead_id:
        return [
            row(
                "tracker_reconciliation_note",
                "warn",
                "code-only slice has no bead to close; record a tracker reconciliation note if one is later created",
                evidence={
                    "slice_mode": mode,
                    "bead_id": bead_id or None,
                    "source": "closeout.mode",
                },
            )
        ]
    status = issue_status(beads, bead_id)
    outcome = "pass" if status == "closed" else "fail"
    return [
        row(
            "bead_closed",
            outcome,
            f"bead {bead_id} is closed"
            if outcome == "pass"
            else f"bead {bead_id} is not closed",
            evidence={
                "command": f"br show {bead_id} --json",
                "bead_id": bead_id,
                "observed_status": status or "missing",
            },
            remediation=f"close {bead_id} after code, validation, push, mail, and reservation release"
            if outcome == "fail"
            else "",
        )
    ]


def message_matches(message: dict[str, Any], closeout: dict[str, Any]) -> bool:
    commit = text_field(closeout, "commit")
    thread_id = closeout_thread(closeout)
    agent = text_field(closeout, "agent")
    body = text_field(message, "body_md", "body", "text")
    subject = text_field(message, "subject")
    if agent and text_field(message, "from", "sender", "sender_name") != agent:
        return False
    thread_match = not thread_id or text_field(message, "thread_id") == thread_id
    commit_match = not commit or commit in body or commit[:9] in body or commit in subject
    closeout_match = "closed" in subject.lower() or "closeout" in body.lower()
    return thread_match and commit_match and closeout_match


def verify_closeout_mail(closeout: dict[str, Any], agent_mail: dict[str, Any]) -> dict[str, Any]:
    messages = rows_from(agent_mail, "messages", "outbox")
    matched = [message for message in messages if message_matches(message, closeout)]
    status = "pass" if matched else "fail"
    return row(
        "closeout_mail",
        status,
        "closeout mail found for the slice" if status == "pass" else "no closeout mail found",
        evidence={
            "thread_id": closeout_thread(closeout),
            "expected_commit": text_field(closeout, "commit"),
            "matched_message_ids": [
                message.get("id") for message in matched if message.get("id") is not None
            ],
        },
        remediation="send a closeout message on the slice thread" if status == "fail" else "",
    )


def reservation_owner(row_value: dict[str, Any]) -> str:
    return text_field(row_value, "agent", "agent_name", "holder", "owner", "from")


def reservation_path(row_value: dict[str, Any]) -> str:
    return text_field(row_value, "path", "path_pattern", "pattern", "glob")


def reservation_released(row_value: dict[str, Any]) -> bool:
    return bool(text_field(row_value, "released_ts", "released_at"))


def reservation_active(row_value: dict[str, Any], generated_at: str) -> bool:
    if reservation_released(row_value):
        return False
    expires_ts = text_field(row_value, "expires_ts", "expires_at")
    if not expires_ts:
        return True
    expires_at = parse_timestamp(expires_ts)
    generated = parse_timestamp(generated_at)
    return expires_at is None or generated is None or expires_at > generated


def verify_reservations(
    closeout: dict[str, Any],
    agent_mail: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    agent = text_field(closeout, "agent")
    reservations = rows_from(agent_mail, "reservations", "file_reservations")
    owned = [
        item
        for item in reservations
        if not agent or reservation_owner(item) == agent
    ]
    active = [item for item in owned if reservation_active(item, generated_at)]
    status = "pass" if not active else "fail"
    return row(
        "reservations_released",
        status,
        "no active closeout-owner reservations remain"
        if status == "pass"
        else "closeout-owner reservations are still active",
        evidence={
            "agent": agent,
            "active_reservations": [
                {
                    "id": item.get("id"),
                    "path": reservation_path(item),
                    "expires_ts": text_field(item, "expires_ts", "expires_at"),
                }
                for item in active
            ],
        },
        remediation="release file reservations before finalizing closeout" if status == "fail" else "",
    )


def verify_validation_reported(closeout: dict[str, Any], agent_mail: dict[str, Any]) -> dict[str, Any]:
    explicit = closeout.get("validation_reported")
    messages = rows_from(agent_mail, "messages", "outbox")
    matched = [message for message in messages if message_matches(message, closeout)]
    matched_bodies = [text_field(message, "body_md", "body", "text") for message in matched]
    mail_mentions_validation = any(
        "validation" in body.lower()
        for body in matched_bodies
    )
    bare_cargo_segments = [
        segment
        for body in matched_bodies
        for segment in bare_cargo_validation_segments(body)
    ]
    rch_local_segments = [
        segment
        for body in matched_bodies
        for segment in rch_local_fallback_segments(body)
    ]
    missing_remote_required_segments = [
        segment
        for body in matched_bodies
        for segment in missing_remote_required_cargo_segments(body)
    ]
    validation_present = explicit is True or mail_mentions_validation
    status = (
        "pass"
        if validation_present
        and not bare_cargo_segments
        and not rch_local_segments
        and not missing_remote_required_segments
        else "fail"
    )
    evidence = {
        "closeout_validation_reported": explicit,
        "mail_mentions_validation": mail_mentions_validation,
    }
    if bare_cargo_segments:
        evidence["bare_cargo_validation_segments"] = bare_cargo_segments
    if rch_local_segments:
        evidence["rch_local_fallback_segments"] = rch_local_segments
    if missing_remote_required_segments:
        evidence["missing_remote_required_cargo_segments"] = missing_remote_required_segments
    if rch_local_segments:
        summary = "validation evidence reports rch local fallback"
        remediation = "rerun and report remote rch validation; local fallback is not acceptable proof"
    elif missing_remote_required_segments:
        summary = "validation evidence omits RCH_REQUIRE_REMOTE=1 for rch Cargo proof"
        remediation = (
            "rerun and report Cargo validation as RCH_REQUIRE_REMOTE=1 rch exec -- "
            "env CARGO_TARGET_DIR=... cargo ..."
        )
    elif bare_cargo_segments:
        summary = "validation evidence reports bare Cargo instead of rch exec"
        remediation = "rerun and report Cargo validation through rch exec -- env CARGO_TARGET_DIR=... cargo ..."
    else:
        summary = (
            "validation evidence is reported"
            if status == "pass"
            else "validation evidence is missing from closeout evidence"
        )
        remediation = (
            "include exact validation commands and outcomes in closeout mail"
            if status == "fail"
            else ""
        )
    return row(
        "validation_reported",
        status,
        summary,
        evidence=evidence,
        remediation=remediation,
    )


def summarize_status(rows: list[dict[str, Any]]) -> str:
    if any(item["status"] == "fail" for item in rows):
        return "fail"
    if any(item["status"] == "warn" for item in rows):
        return "warn"
    return "pass"


def build_report(source: dict[str, Any], *, generated_at: str, fixture_path: str) -> dict[str, Any]:
    closeout = source.get("closeout", {}) if isinstance(source.get("closeout"), dict) else {}
    git = source.get("git", {}) if isinstance(source.get("git"), dict) else {}
    beads = source.get("beads", {}) if isinstance(source.get("beads"), dict) else {}
    agent_mail = (
        source.get("agent_mail", {}) if isinstance(source.get("agent_mail"), dict) else {}
    )

    rows = [
        verify_main_pushed(closeout, git),
        verify_master_synced(closeout, git),
        *verify_bead_state(closeout, beads),
        verify_closeout_mail(closeout, agent_mail),
        verify_reservations(closeout, agent_mail, generated_at),
        verify_validation_reported(closeout, agent_mail),
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "fixture_path": fixture_path,
        "slice_id": text_field(closeout, "slice_id", "bead_id"),
        "slice_mode": closeout_mode(closeout),
        "commit": text_field(closeout, "commit"),
        "overall_status": summarize_status(rows),
        "summary": {
            "pass": sum(1 for item in rows if item["status"] == "pass"),
            "fail": sum(1 for item in rows if item["status"] == "fail"),
            "warn": sum(1 for item in rows if item["status"] == "warn"),
        },
        "rows": rows,
        "non_mutating": True,
        "forbidden_actions": FORBIDDEN_ACTIONS,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify shared-main closeout evidence")
    parser.add_argument("--fixture", default="", help="JSON source fixture")
    parser.add_argument("--repo-path", default=".", help="Repository root for live git probes")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=5.0, help="Live command timeout")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    generated_at = args.generated_at or utc_now()
    try:
        if args.fixture:
            source = load_json(Path(args.fixture))
        else:
            source = live_source(Path(args.repo_path), args.timeout)
    except OSError as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    report = build_report(source, generated_at=generated_at, fixture_path=args.fixture)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
