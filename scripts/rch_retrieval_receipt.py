#!/usr/bin/env python3
"""Classify rch remote-execution logs without mutating the repo.

The receipt separates the proof command outcome from post-command artifact
retrieval. This matters when a remote cargo test has already printed a remote
success marker, but the local rch wrapper later stalls while retrieving
`.rch-target` artifacts.
"""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-retrieval-receipt-v1"
LOCAL_FALLBACK_RE = re.compile(r"(?m)(^\[RCH\] local \(|falling back to local)")
REMOTE_FINISHED_RE = re.compile(r"Remote command finished: exit=(?P<exit>-?\d+)")
REMOTE_FAILED_RE = re.compile(r"(?m)^\[RCH\] remote .* failed \(exit (?P<exit>-?\d+)\)")
ARTIFACTS_RETRIEVED_RE = re.compile(r"Artifacts retrieved in (?P<elapsed_ms>\d+)ms")
TIMEOUT_RE = re.compile(r"(?i)(timed out|timeout|terminated|signal TERM|exit code -1)")


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


def line_number(text: str, needle: str) -> int:
    index = text.find(needle)
    if index < 0:
        return 0
    return text.count("\n", 0, index) + 1


def last_remote_exit(text: str) -> int | None:
    matches = list(REMOTE_FINISHED_RE.finditer(text))
    if matches:
        return int(matches[-1].group("exit"))
    failure = REMOTE_FAILED_RE.search(text)
    if failure:
        return int(failure.group("exit"))
    return None


def classify(text: str, wrapper_exit_code: int | None) -> dict[str, Any]:
    local_fallback = LOCAL_FALLBACK_RE.search(text) is not None
    remote_exit = last_remote_exit(text)
    remote_success = remote_exit == 0
    remote_failed = (remote_exit is not None and remote_exit != 0) or REMOTE_FAILED_RE.search(text) is not None
    retrieval_started = "Retrieving build artifacts" in text
    retrieval_match = ARTIFACTS_RETRIEVED_RE.search(text)
    retrieval_completed = retrieval_match is not None
    timeout_observed = TIMEOUT_RE.search(text) is not None or wrapper_exit_code in {124, 143, -1}

    if local_fallback:
        classification = "local_fallback"
        decision = "invalid"
    elif remote_failed:
        classification = "remote_failure"
        decision = "failed"
    elif remote_success and retrieval_started and not retrieval_completed and timeout_observed:
        classification = "passed_after_retrieval_timeout"
        decision = "pass-with-retrieval-blocker"
    elif remote_success and retrieval_completed:
        classification = "remote_success"
        decision = "passed"
    elif remote_success:
        classification = "remote_success_retrieval_unknown"
        decision = "pass-with-retrieval-unknown"
    else:
        classification = "needs-human-escalation"
        decision = "unknown"

    retrieval_elapsed_ms = None
    if retrieval_match:
        retrieval_elapsed_ms = int(retrieval_match.group("elapsed_ms"))

    return {
        "classification": classification,
        "decision": decision,
        "markers": {
            "local_fallback": local_fallback,
            "remote_exit_code": remote_exit,
            "remote_success": remote_success,
            "remote_failure": remote_failed,
            "retrieval_started": retrieval_started,
            "retrieval_completed": retrieval_completed,
            "retrieval_elapsed_ms": retrieval_elapsed_ms,
            "timeout_observed": timeout_observed,
            "remote_success_line": line_number(text, "Remote command finished: exit=0"),
            "retrieval_started_line": line_number(text, "Retrieving build artifacts"),
        },
    }


def remediation_for(classification: str) -> dict[str, Any]:
    if classification == "passed_after_retrieval_timeout":
        return {
            "summary": "remote proof passed, but artifact retrieval did not finish",
            "operator_note": (
                "Record the remote command as passed only when the remote success marker "
                "is present; record artifact retrieval as a separate blocker."
            ),
            "next_steps": [
                "capture the remote success line and test summary in the closeout",
                "inspect retrieval excludes and CARGO_TARGET_DIR sizing before rerunning",
                "terminate stale local wrapper/rsync only after the remote success marker is captured",
            ],
        }
    if classification == "remote_success":
        return {
            "summary": "remote proof and artifact retrieval completed",
            "operator_note": "The log covers both remote execution and artifact retrieval.",
            "next_steps": ["use the receipt as supporting proof"],
        }
    if classification == "remote_failure":
        return {
            "summary": "remote proof failed before a usable pass marker",
            "operator_note": "Do not treat this as a green proof.",
            "next_steps": ["fix the first remote diagnostic or surface the external blocker"],
        }
    if classification == "local_fallback":
        return {
            "summary": "rch attempted or used local fallback",
            "operator_note": "Reject local cargo/test output for this repo's proof lanes.",
            "next_steps": ["rerun through rch remote execution after worker health is restored"],
        }
    return {
        "summary": "rch log did not contain enough markers for an automated verdict",
        "operator_note": "Do not infer success from incomplete proof output.",
        "next_steps": ["capture a complete rch log or rerun the focused proof lane"],
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    log_path = Path(args.log)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    generated_at = args.generated_at or utc_now()
    analysis = classify(text, args.wrapper_exit_code)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "log_path": str(log_path),
        "command": args.command,
        "wrapper_exit_code": args.wrapper_exit_code,
        "classification": analysis["classification"],
        "decision": analysis["decision"],
        "markers": analysis["markers"],
        "remediation": remediation_for(analysis["classification"]),
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify rch artifact retrieval logs")
    parser.add_argument("--log", required=True, help="Path to an rch stdout/stderr log")
    parser.add_argument("--command", default="", help="Proof command represented by the log")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--wrapper-exit-code", type=int, help="Local wrapper exit code, if known")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except OSError as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
