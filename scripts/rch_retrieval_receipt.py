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
REMOTE_COMMAND_RE = re.compile(r"(?m)^\s*.*Executing command remotely:\s*(?P<command>.+)$")
SELECTED_WORKER_RE = re.compile(r"Selected worker:\s*(?P<worker>\S+)")
REMOTE_FINISHED_RE = re.compile(
    r"Remote command finished: exit=(?P<exit>-?\d+)(?: in (?P<elapsed_ms>\d+)ms)?"
)
REMOTE_FAILED_RE = re.compile(
    r"(?m)^\[RCH\] remote (?P<worker>\S+) failed \(exit (?P<exit>-?\d+)\)"
)
ARTIFACTS_RETRIEVED_RE = re.compile(
    r"Artifacts retrieved in (?P<elapsed_ms>\d+)ms"
    r"(?: \((?P<file_count>\d+) files, (?P<byte_count>\d+) bytes\))?"
)
RETRIEVAL_STAGE_RE = re.compile(r"(?m)^\s*.*Retrieving artifacts from .*$")
TIMEOUT_RE = re.compile(r"(?i)(timed out|timeout|terminated|signal TERM|exit code -1)")
DISK_FULL_RE = re.compile(
    r"(?i)(ENOSPC|No space left on device|os error 28|error 28)"
)
CRITICAL_PRESSURE_RE = re.compile(r"critical_pressure=(?P<level>\d+)")
REMOTE_REQUIRED_TRUE_VALUES = {"1", "true", "yes", "on"}


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


def first_matching_line(text: str, pattern: re.Pattern[str]) -> dict[str, Any] | None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return {"line": line_no, "text": line.strip()}
    return None


def retrieval_blocker_from_log(text: str) -> dict[str, Any] | None:
    disk_full = first_matching_line(text, DISK_FULL_RE)
    if disk_full is not None:
        return {
            "kind": "local-disk-full",
            "line": disk_full["line"],
            "text": disk_full["text"],
            "local_disk_pressure": "critical",
        }

    timeout = first_matching_line(text, TIMEOUT_RE)
    if timeout is not None:
        return {
            "kind": "wrapper-timeout",
            "line": timeout["line"],
            "text": timeout["text"],
            "local_disk_pressure": "unknown",
        }

    return None


def last_remote_exit(text: str) -> int | None:
    matches = list(REMOTE_FINISHED_RE.finditer(text))
    if matches:
        return int(matches[-1].group("exit"))
    failure = REMOTE_FAILED_RE.search(text)
    if failure:
        return int(failure.group("exit"))
    return None


def remote_command_from_log(text: str) -> str | None:
    match = REMOTE_COMMAND_RE.search(text)
    if match:
        return match.group("command").strip()
    return None


def selected_worker_from_log(text: str) -> str | None:
    match = SELECTED_WORKER_RE.search(text)
    if match:
        return match.group("worker")
    failure = REMOTE_FAILED_RE.search(text)
    if failure:
        return failure.group("worker")
    return None


def remote_elapsed_ms(text: str) -> int | None:
    matches = list(REMOTE_FINISHED_RE.finditer(text))
    if not matches:
        return None
    elapsed = matches[-1].group("elapsed_ms")
    if elapsed is None:
        return None
    return int(elapsed)


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


def command_tokens(command: str) -> list[str]:
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def first_non_env_assignment(tokens: list[str], start: int = 0) -> int:
    index = start
    while index < len(tokens) and "=" in tokens[index]:
        name, _value = tokens[index].split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            break
        index += 1
    return index


def env_assignment_value(tokens: list[str], name: str) -> str | None:
    prefix = f"{name}="
    for token in tokens:
        if token.startswith(prefix):
            return token.split("=", 1)[1]
    return None


def command_classification(command: str, target_dir: str | None) -> dict[str, Any]:
    tokens = command_tokens(command)
    lowered = [token.lower() for token in tokens]
    program_index = first_non_env_assignment(tokens)
    program = lowered[program_index] if program_index < len(tokens) else ""
    runs_rch_exec = (
        program_index + 2 < len(tokens)
        and lowered[program_index : program_index + 3] == ["rch", "exec", "--"]
    )
    cargo_index = lowered.index("cargo") if "cargo" in lowered else -1
    runs_cargo = cargo_index >= 0
    cargo_subcommand = (
        lowered[cargo_index + 1] if cargo_index >= 0 and cargo_index + 1 < len(lowered) else ""
    )
    remote_required_value = env_assignment_value(tokens, "RCH_REQUIRE_REMOTE")
    remote_required = (
        remote_required_value is not None
        and remote_required_value.lower() in REMOTE_REQUIRED_TRUE_VALUES
    )

    if runs_rch_exec and runs_cargo:
        command_class = "rch-cargo-proof"
    elif runs_rch_exec:
        command_class = "rch-non-cargo-proof"
    elif runs_cargo:
        command_class = "bare-cargo-proof"
    elif command:
        command_class = "non-cargo-command"
    else:
        command_class = "unknown"

    return {
        "class": command_class,
        "program": program,
        "runs_rch_exec": runs_rch_exec,
        "runs_cargo": runs_cargo,
        "cargo_subcommand": cargo_subcommand,
        "remote_required": remote_required,
        "remote_required_env": remote_required_value or "",
        "target_dir": target_dir,
        "target_dir_present": target_dir is not None,
    }


def audit_target_dir(
    args: argparse.Namespace, analysis: dict[str, Any], target_dir: str | None
) -> dict[str, Any]:
    tokens = command_tokens(args.command)
    runs_cargo = "cargo" in tokens
    runs_rch = "rch" in tokens and "exec" in tokens
    active_target_dirs = args.active_target_dir or []
    findings: list[dict[str, Any]] = []

    if analysis["markers"]["local_fallback"]:
        findings.append(
            {
                "severity": "blocker",
                "code": "local-fallback-marker",
                "message": "rch log contains a local fallback marker",
                "closeout_note": "Do not use this receipt as remote proof; rerun through rch remote execution.",
            }
        )
    if runs_cargo and not runs_rch:
        findings.append(
            {
                "severity": "blocker",
                "code": "cargo-without-rch",
                "message": "cargo command is not routed through rch exec",
                "closeout_note": "Cargo proof lanes in this repo must use rch exec.",
            }
        )
    if runs_cargo and target_dir is None:
        findings.append(
            {
                "severity": "blocker",
                "code": "missing-cargo-target-dir",
                "message": "cargo proof command is missing CARGO_TARGET_DIR",
                "closeout_note": "Rerun with a per-agent CARGO_TARGET_DIR before citing this proof lane.",
            }
        )
    if target_dir is not None and target_dir in active_target_dirs:
        findings.append(
            {
                "severity": "warning",
                "code": "reused-target-dir",
                "message": "target dir matches a concurrently active target dir",
                "target_dir": target_dir,
                "closeout_note": "Use a fresh CARGO_TARGET_DIR for concurrent proof lanes.",
            }
        )

    blocker_count = sum(1 for finding in findings if finding["severity"] == "blocker")
    warning_count = sum(1 for finding in findings if finding["severity"] == "warning")
    if blocker_count > 0:
        status = "blocker"
    elif warning_count > 0:
        status = "warning"
    else:
        status = "pass"

    return {
        "schema_version": "rch-target-dir-audit-v1",
        "status": status,
        "findings": findings,
        "summary": {
            "blockers": blocker_count,
            "warnings": warning_count,
        },
        "command_classification": {
            "runs_cargo": runs_cargo,
            "runs_rch": runs_rch,
            "target_dir": target_dir,
            "active_target_dirs": active_target_dirs,
            "local_fallback": analysis["markers"]["local_fallback"],
        },
        "non_mutating": True,
    }


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
    retrieval_blocker = retrieval_blocker_from_log(text)
    disk_full_observed = (
        retrieval_blocker is not None and retrieval_blocker["kind"] == "local-disk-full"
    )
    timeout_observed = TIMEOUT_RE.search(text) is not None or wrapper_exit_code in {124, 143, -1}

    if local_fallback:
        classification = "local_fallback"
        decision = "invalid"
    elif remote_failed:
        classification = "remote_failure"
        decision = "failed"
    elif remote_success and retrieval_partial and disk_full_observed:
        classification = "passed_after_retrieval_enospc"
        decision = "pass-with-retrieval-blocker"
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
        "retrieval_blocker": retrieval_blocker,
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
    if classification == "passed_after_retrieval_enospc":
        return {
            "summary": "remote proof passed, but local artifact retrieval hit disk pressure",
            "operator_note": (
                "Record the remote command as passed only when the remote success marker "
                "is present; record local ENOSPC during artifact retrieval as a separate "
                "disk-pressure blocker."
            ),
            "next_steps": [
                "capture the remote success line and test summary in the closeout",
                "record the exact ENOSPC retrieval blocker line",
                "recover local disk space before rerunning or retrieving artifacts",
            ],
        }
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


def artifact_status(markers: dict[str, Any]) -> tuple[str, str]:
    if markers["retrieval_completed"]:
        return ("retrieved", "artifact retrieval completed")
    if markers["retrieval_started"] and not markers["retrieval_completed"]:
        if markers["timeout_observed"]:
            return (
                "retrieval_failed",
                "artifact retrieval started but the local wrapper timed out or was interrupted",
            )
        return (
            "retrieval_incomplete",
            "artifact retrieval started but no completion marker was observed",
        )
    if markers["remote_failure"]:
        return ("not_requested", "remote command failed before artifact retrieval")
    if markers["remote_success"]:
        return ("not_available", "remote proof passed but no artifact retrieval marker was observed")
    return ("not_available", "no remote proof verdict was available")


def remote_command_result(markers: dict[str, Any]) -> dict[str, Any]:
    if markers["local_fallback"]:
        status = "invalid"
        reason = "rch used local fallback"
    elif markers["remote_success"]:
        status = "pass"
        reason = "remote command finished with exit 0"
    elif markers["remote_failure"]:
        status = "fail"
        reason = "remote command finished with nonzero exit"
    else:
        status = "unknown"
        reason = "no remote command verdict marker was captured"

    return {
        "status": status,
        "exit_code": markers["remote_exit_code"],
        "line": markers["remote_success_line"],
        "reason": reason,
    }


def artifact_retrieval_result(
    markers: dict[str, Any], retrieval_blocker: dict[str, Any] | None
) -> dict[str, Any]:
    status, reason = artifact_status(markers)
    if markers["retrieval_completed"]:
        result_status = "pass"
    elif retrieval_blocker is not None:
        result_status = "blocked"
    elif markers["retrieval_started"]:
        result_status = "unknown"
    elif markers["remote_failure"]:
        result_status = "not_requested"
    else:
        result_status = "not_available"

    return {
        "status": result_status,
        "detail": status,
        "reason": reason,
        "started": markers["retrieval_started"],
        "completed": markers["retrieval_completed"],
        "partial": markers["retrieval_partial"],
        "started_line": markers["retrieval_started_line"],
        "blocker_kind": retrieval_blocker["kind"] if retrieval_blocker else None,
        "blocker_line": retrieval_blocker["line"] if retrieval_blocker else 0,
        "blocker_text": retrieval_blocker["text"] if retrieval_blocker else "",
    }


def local_disk_pressure_result(
    retrieval_blocker: dict[str, Any] | None, text: str = ""
) -> dict[str, Any]:
    if retrieval_blocker is not None and retrieval_blocker["kind"] == "local-disk-full":
        return {
            "status": "critical",
            "signal": "enospc",
            "evidence_line": retrieval_blocker["line"],
            "evidence_text": retrieval_blocker["text"],
        }
    critical_pressure = first_matching_line(text, CRITICAL_PRESSURE_RE)
    if critical_pressure is not None:
        return {
            "status": "critical",
            "signal": "critical_pressure",
            "evidence_line": critical_pressure["line"],
            "evidence_text": critical_pressure["text"],
        }
    return {
        "status": "unknown",
        "signal": "",
        "evidence_line": 0,
        "evidence_text": "",
    }


def first_blocker_from_log(
    text: str, analysis: dict[str, Any], retrieval_blocker: dict[str, Any] | None
) -> dict[str, Any]:
    if analysis["markers"]["local_fallback"]:
        fallback = first_matching_line(text, LOCAL_FALLBACK_RE)
        return {
            "kind": "local-fallback",
            "source": "rch-wrapper",
            "line": fallback["line"] if fallback else 0,
            "text": fallback["text"] if fallback else "rch local fallback observed",
            "file": "rch-local-fallback",
        }
    if retrieval_blocker is not None:
        return {
            "kind": retrieval_blocker["kind"],
            "source": "artifact-retrieval",
            "line": retrieval_blocker["line"],
            "text": retrieval_blocker["text"],
            "file": "artifact-retrieval",
        }
    if analysis["markers"]["remote_failure"]:
        error_line = first_matching_line(text, re.compile(r"^\s*error(?:\[[^\]]+\])?:\s*"))
        if error_line is not None:
            return {
                "kind": "remote-error",
                "source": "remote-command",
                "line": error_line["line"],
                "text": error_line["text"],
                "file": "remote-stderr",
            }
        return {
            "kind": "remote-failure",
            "source": "remote-command",
            "line": 0,
            "text": "remote command finished with nonzero exit",
            "file": "remote-command",
        }
    if analysis["classification"] == "wrapper_interrupted":
        interrupted = first_matching_line(text, TIMEOUT_RE)
        return {
            "kind": "wrapper-interrupted",
            "source": "rch-wrapper",
            "line": interrupted["line"] if interrupted else 0,
            "text": interrupted["text"] if interrupted else "wrapper interrupted before remote verdict",
            "file": "rch-wrapper",
        }
    return {
        "kind": "none",
        "source": "",
        "line": 0,
        "text": "",
        "file": "",
    }


def remote_required_status(
    command_class: dict[str, Any], markers: dict[str, Any]
) -> dict[str, Any]:
    required = command_class["remote_required"]
    if not required:
        status = "not-declared"
    elif markers["local_fallback"]:
        status = "failed-local-fallback"
    elif markers["remote_success"] or markers["remote_failure"]:
        status = "satisfied"
    else:
        status = "unproven"
    return {
        "required": required,
        "status": status,
        "local_fallback_refused": markers["local_fallback"],
        "remote_verdict_observed": markers["remote_success"] or markers["remote_failure"],
    }


def operator_decision_for(classification: str) -> str:
    if classification == "remote_success":
        return "cite-remote-proof"
    if classification in {
        "passed_after_retrieval_enospc",
        "passed_after_retrieval_timeout",
        "remote_success_retrieval_unknown",
    }:
        return "cite-remote-result-and-surface-retrieval-blocker"
    if classification == "remote_failure":
        return "surface-remote-failure"
    if classification == "local_fallback":
        return "reject-local-fallback-rerun-remote"
    if classification == "wrapper_interrupted":
        return "rerun-incomplete-proof"
    return "escalate-incomplete-proof"


def cleanup_authorization_result(
    args: argparse.Namespace, local_pressure: dict[str, Any]
) -> dict[str, Any]:
    stale_target_candidates = args.stale_target_candidate or []
    local_cleanup_blocker = local_pressure["status"] == "critical"
    requires_authorization = local_cleanup_blocker or bool(stale_target_candidates)

    if requires_authorization:
        status = "required"
        reason = (
            "local disk pressure or stale target candidates require explicit cleanup authorization"
        )
        next_steps = [
            "record remote proof and artifact retrieval as separate closeout fields",
            "ask the user for explicit written authorization before deleting any candidate",
            "rerun the same focused proof lane after authorized cleanup or pressure relief",
        ]
    else:
        status = "not_required"
        reason = "no cleanup candidate or disk-pressure blocker was detected"
        next_steps = ["no cleanup action is needed for this receipt"]

    return {
        "status": status,
        "authorized": False,
        "report_only": True,
        "reason": reason,
        "required_authorization": (
            "explicit written user authorization is required before deleting files or directories"
        ),
        "stale_target_candidates": stale_target_candidates,
        "executable_cleanup_commands": [],
        "forbidden_without_authorization": [
            "delete target directories",
            "remove rch scratch artifacts",
            "clean build caches",
            "truncate logs or session history",
        ],
        "next_steps": next_steps,
    }


def proof_lifecycle_contract(
    args: argparse.Namespace, text: str, analysis: dict[str, Any], target_dir: str | None
) -> dict[str, Any]:
    markers = analysis["markers"]
    retrieval_blocker = analysis.get("retrieval_blocker")
    remote_result = remote_command_result(markers)
    retrieval_result = artifact_retrieval_result(markers, retrieval_blocker)
    local_pressure = local_disk_pressure_result(retrieval_blocker, text)
    cleanup_authorization = cleanup_authorization_result(args, local_pressure)

    return {
        "schema_version": "proof-artifact-lifecycle-contract-v1",
        "command": args.command,
        "log_remote_command": remote_command_from_log(text),
        "proof_lane": args.proof_lane or "unspecified",
        "guarantee": args.guarantee or "unspecified",
        "target_dir": target_dir,
        "selected_worker": selected_worker_from_log(text),
        "wrapper_exit_code": args.wrapper_exit_code,
        "classification": analysis["classification"],
        "decision": analysis["decision"],
        "remote_result": remote_result,
        "retrieval_result": retrieval_result,
        "local_pressure": local_pressure,
        "cleanup_authorization": cleanup_authorization,
        "closeout_template": (
            "remote_result.status={remote_status}; "
            "retrieval_result.status={retrieval_status}; "
            "local_pressure.status={pressure_status}; "
            "cleanup_authorization.status={cleanup_status}; "
            "cleanup_authorization.authorized=false"
        ).format(
            remote_status=remote_result["status"],
            retrieval_status=retrieval_result["status"],
            pressure_status=local_pressure["status"],
            cleanup_status=cleanup_authorization["status"],
        ),
        "non_mutating": True,
    }


def artifact_free_proof_receipt(
    args: argparse.Namespace, text: str, analysis: dict[str, Any], target_dir: str | None
) -> dict[str, Any]:
    markers = analysis["markers"]
    retrieval_blocker = analysis.get("retrieval_blocker")
    status, status_reason = artifact_status(markers)
    command_class = command_classification(args.command, target_dir)
    first_blocker = first_blocker_from_log(text, analysis, retrieval_blocker)
    local_fallback_refusal = {
        "observed": markers["local_fallback"],
        "refused_as_remote_proof": markers["local_fallback"],
        "reason": (
            "local fallback markers invalidate this receipt as remote proof"
            if markers["local_fallback"]
            else ""
        ),
    }
    retrieval_result = artifact_retrieval_result(markers, retrieval_blocker)
    return {
        "schema_version": "artifact-free-rch-proof-receipt-v1",
        "command": args.command,
        "log_remote_command": remote_command_from_log(text),
        "proof_lane": args.proof_lane or "unspecified",
        "guarantee": args.guarantee or "unspecified",
        "target_dir": target_dir,
        "selected_worker": selected_worker_from_log(text),
        "remote_exit_status": markers["remote_exit_code"],
        "remote_elapsed_ms": remote_elapsed_ms(text),
        "wrapper_exit_code": args.wrapper_exit_code,
        "classification": analysis["classification"],
        "decision": analysis["decision"],
        "operator_decision": operator_decision_for(analysis["classification"]),
        "remote_required_status": remote_required_status(command_class, markers),
        "command_class": command_class,
        "first_blocker": first_blocker,
        "retrieval_blocker": retrieval_blocker,
        "local_fallback_refusal": local_fallback_refusal,
        "remote_command_result": remote_command_result(markers),
        "artifact_retrieval_result": retrieval_result,
        "local_disk_pressure": local_disk_pressure_result(retrieval_blocker),
        "artifact_status": status,
        "artifact_status_reason": status_reason,
        "artifact_retrieval": {
            "started": markers["retrieval_started"],
            "completed": markers["retrieval_completed"],
            "partial": markers["retrieval_partial"],
            "elapsed_ms": markers["retrieval_elapsed_ms"],
            "file_count": markers["artifact_file_count"],
            "byte_count": markers["artifact_bytes"],
        },
        "closeout_fields": [
            "command",
            "log_remote_command",
            "selected_worker",
            "remote_exit_status",
            "remote_elapsed_ms",
            "remote_required_status",
            "command_class",
            "first_blocker",
            "retrieval_blocker",
            "local_fallback_refusal",
            "operator_decision",
            "artifact_status",
            "wrapper_exit_code",
            "classification",
            "decision",
        ],
        "non_mutating": True,
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    log_path = Path(args.log)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    generated_at = args.generated_at or utc_now()
    analysis = classify(text, args.wrapper_exit_code)
    target_dir = extract_target_dir(args.command)
    budget = artifact_budget(args, analysis["markers"])
    decision = analysis["decision"]
    if analysis["classification"] == "remote_success" and budget["status"] == "over-budget":
        decision = "passed-with-artifact-budget-warning"
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "log_path": str(log_path),
        "command": args.command,
        "proof_lane": args.proof_lane or "unspecified",
        "target_dir": target_dir,
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
    if args.audit_target_dir:
        receipt["target_dir_audit"] = audit_target_dir(args, analysis, target_dir)
    if args.artifact_free_proof_receipt:
        receipt["artifact_free_proof_receipt"] = artifact_free_proof_receipt(
            args, text, analysis, target_dir
        )
    if args.proof_lifecycle_contract:
        receipt["proof_lifecycle_contract"] = proof_lifecycle_contract(
            args, text, analysis, target_dir
        )
    return receipt


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
    parser.add_argument(
        "--audit-target-dir",
        action="store_true",
        help="Emit read-only CARGO_TARGET_DIR/local-fallback audit findings",
    )
    parser.add_argument(
        "--active-target-dir",
        action="append",
        default=[],
        help="Target dir currently in use by another active proof lane; repeatable",
    )
    parser.add_argument(
        "--artifact-free-proof-receipt",
        action="store_true",
        help="Emit compact remote proof and artifact-retrieval fields for closeouts",
    )
    parser.add_argument(
        "--proof-lifecycle-contract",
        action="store_true",
        help="Emit remote/retrieval/local-pressure/cleanup-authorization lifecycle fields",
    )
    parser.add_argument(
        "--stale-target-candidate",
        action="append",
        default=[],
        help="Report-only stale target candidate; never deleted by this helper",
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
