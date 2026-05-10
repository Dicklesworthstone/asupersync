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
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-retrieval-receipt-v1"
LOCAL_FALLBACK_RE = re.compile(r"(?m)(^\[RCH\] local \(|falling back to local)")
REMOTE_FINISHED_RE = re.compile(r"Remote command finished: exit=(?P<exit>-?\d+)")
REMOTE_FAILED_RE = re.compile(r"(?m)^\[RCH\] remote .* failed \(exit (?P<exit>-?\d+)\)")
ARTIFACTS_RETRIEVED_RE = re.compile(
    r"Artifacts retrieved in (?P<elapsed_ms>\d+)ms"
    r"(?: \((?P<file_count>\d+) files, (?P<byte_count>\d+) bytes\))?"
)
RETRIEVAL_STAGE_RE = re.compile(r"(?m)^\s*.*Retrieving artifacts from .*$")
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


def extract_target_dir(command: str) -> str | None:
    if not command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        if token.startswith("CARGO_TARGET_DIR="):
            return token.split("=", 1)[1]
    return None


def classify(text: str, wrapper_exit_code: int | None) -> dict[str, Any]:
    local_fallback = LOCAL_FALLBACK_RE.search(text) is not None
    remote_exit = last_remote_exit(text)
    remote_success = remote_exit == 0
    remote_failed = (remote_exit is not None and remote_exit != 0) or REMOTE_FAILED_RE.search(text) is not None
    explicit_retrieval_stage_count = len(RETRIEVAL_STAGE_RE.findall(text))
    retrieval_matches = list(ARTIFACTS_RETRIEVED_RE.finditer(text))
    retrieval_completed_count = len(retrieval_matches)
    retrieval_started = "Retrieving build artifacts" in text or explicit_retrieval_stage_count > 0
    retrieval_stage_count = explicit_retrieval_stage_count
    if retrieval_stage_count == 0 and (retrieval_started or retrieval_completed_count > 0):
        retrieval_stage_count = 1
    retrieval_completed = retrieval_completed_count > 0 and retrieval_completed_count >= retrieval_stage_count
    retrieval_partial = retrieval_started and retrieval_completed_count < retrieval_stage_count
    timeout_observed = TIMEOUT_RE.search(text) is not None or wrapper_exit_code in {124, 143, -1}

    if local_fallback:
        classification = "local_fallback"
        decision = "invalid"
    elif remote_failed:
        classification = "remote_failure"
        decision = "failed"
    elif remote_success and retrieval_partial and timeout_observed:
        classification = "passed_after_retrieval_timeout"
        decision = "pass-with-retrieval-blocker"
    elif remote_success and retrieval_completed:
        classification = "remote_success"
        decision = "passed"
    elif remote_success:
        classification = "remote_success_retrieval_unknown"
        decision = "pass-with-retrieval-unknown"
    elif timeout_observed:
        classification = "wrapper_interrupted"
        decision = "unknown-interrupted"
    else:
        classification = "needs-human-escalation"
        decision = "unknown"

    retrieval_elapsed_ms = None
    artifact_file_count = None
    artifact_bytes = None
    if retrieval_matches:
        retrieval_elapsed_ms = sum(int(match.group("elapsed_ms")) for match in retrieval_matches)
        file_counts = [
            int(match.group("file_count"))
            for match in retrieval_matches
            if match.group("file_count") is not None
        ]
        byte_counts = [
            int(match.group("byte_count"))
            for match in retrieval_matches
            if match.group("byte_count") is not None
        ]
        if file_counts:
            artifact_file_count = sum(file_counts)
        if byte_counts:
            artifact_bytes = sum(byte_counts)

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
            "retrieval_partial": retrieval_partial,
            "retrieval_stage_count": retrieval_stage_count,
            "retrieval_completed_count": retrieval_completed_count,
            "retrieval_elapsed_ms": retrieval_elapsed_ms,
            "artifact_file_count": artifact_file_count,
            "artifact_bytes": artifact_bytes,
            "timeout_observed": timeout_observed,
            "remote_success_line": line_number(text, "Remote command finished: exit=0"),
            "retrieval_started_line": line_number(text, "Retrieving build artifacts"),
        },
    }


def _budget_violation(
    metric: str, observed: int | None, limit: int | None
) -> dict[str, Any] | None:
    if limit is None:
        return None
    if observed is None:
        return {
            "metric": metric,
            "observed": None,
            "limit": limit,
            "reason": "missing-observation",
        }
    if observed > limit:
        return {
            "metric": metric,
            "observed": observed,
            "limit": limit,
            "reason": "over-budget",
        }
    return None


def artifact_budget(args: argparse.Namespace, markers: dict[str, Any]) -> dict[str, Any]:
    limits = {
        "max_retrieval_ms": args.max_retrieval_ms,
        "max_artifact_files": args.max_artifact_files,
        "max_artifact_bytes": args.max_artifact_bytes,
    }
    observed = {
        "retrieval_elapsed_ms": markers["retrieval_elapsed_ms"],
        "artifact_file_count": markers["artifact_file_count"],
        "artifact_bytes": markers["artifact_bytes"],
    }
    configured = any(value is not None for value in limits.values())
    violations = [
        violation
        for violation in [
            _budget_violation(
                "retrieval_elapsed_ms",
                observed["retrieval_elapsed_ms"],
                limits["max_retrieval_ms"],
            ),
            _budget_violation(
                "artifact_file_count",
                observed["artifact_file_count"],
                limits["max_artifact_files"],
            ),
            _budget_violation(
                "artifact_bytes",
                observed["artifact_bytes"],
                limits["max_artifact_bytes"],
            ),
        ]
        if violation is not None
    ]

    if not configured:
        status = "not-configured"
        within_budget = None
    elif markers["retrieval_started"] and not markers["retrieval_completed"]:
        status = "retrieval-incomplete"
        within_budget = False
        violations.append(
            {
                "metric": "retrieval_completed",
                "observed": False,
                "limit": True,
                "reason": "retrieval-timeout-or-incomplete",
            }
        )
    elif violations:
        status = "over-budget"
        within_budget = False
    else:
        status = "within-budget"
        within_budget = True

    return {
        "proof_lane": args.proof_lane or "unspecified",
        "configured": configured,
        "status": status,
        "within_budget": within_budget,
        "limits": limits,
        "observed": observed,
        "violations": violations,
        "rchignore_remediation": {
            "recommended_patterns": [".rch-*/", ".rch_target*/"],
            "operator_note": (
                "Keep per-lane CARGO_TARGET_DIR values under transient rch scratch paths "
                "or add equivalent bulky artifact directories to .rchignore before rerunning."
            ),
            "next_steps": [
                "use a lane-specific CARGO_TARGET_DIR under ${TMPDIR:-/tmp}/rch_target_<lane>",
                "exclude transient rch scratch directories from artifact retrieval",
                "rerun the same focused proof lane after trimming artifact fanout",
            ],
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
    if classification == "wrapper_interrupted":
        return {
            "summary": "local wrapper stopped before a remote proof verdict was captured",
            "operator_note": (
                "Do not infer pass or fail without a Remote command finished marker "
                "or a remote failure marker."
            ),
            "next_steps": [
                "capture a complete rch log with the remote exit marker",
                "check whether an old wrapper or rsync process is still running",
                "rerun the exact focused proof lane with the same CARGO_TARGET_DIR discipline",
            ],
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
    budget = artifact_budget(args, analysis["markers"])
    decision = analysis["decision"]
    if analysis["classification"] == "remote_success" and budget["status"] == "over-budget":
        decision = "passed-with-artifact-budget-warning"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "log_path": str(log_path),
        "command": args.command,
        "proof_lane": args.proof_lane or "unspecified",
        "target_dir": extract_target_dir(args.command),
        "guarantee": args.guarantee or "unspecified",
        "wrapper_exit_code": args.wrapper_exit_code,
        "classification": analysis["classification"],
        "decision": decision,
        "markers": analysis["markers"],
        "artifact_budget": budget,
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
    parser.add_argument("--proof-lane", default="", help="Stable proof-lane id for budget reporting")
    parser.add_argument(
        "--guarantee",
        default="",
        help="Exact guarantee this proof lane establishes when the receipt is green",
    )
    parser.add_argument(
        "--max-retrieval-ms",
        type=int,
        help="Warn when artifact retrieval exceeds this duration",
    )
    parser.add_argument(
        "--max-artifact-files",
        type=int,
        help="Warn when retrieved artifact file count exceeds this",
    )
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        help="Warn when retrieved artifact bytes exceed this",
    )
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
