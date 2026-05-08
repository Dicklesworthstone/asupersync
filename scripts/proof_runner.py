#!/usr/bin/env python3
"""
Agent-swarm safe proof runner with reservation awareness.

This script provides preflight checks before expensive validation commands,
ensuring they won't fail due to unrelated dirty surfaces or reservation conflicts.
Compatible with the validation frontier ledger schema.
"""

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

SAFE_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_REMOTE_PROGRAMS = {"cargo", "lake", "rustfmt"}
SHELL_CONTROL_TOKENS = (";", "&", "|", "<", ">", "`", "$(")
RCH_OUTCOME_SCHEMA_VERSION = "proof-runner-rch-outcome-v1"
PROOF_CONSOLE_REPORT_SCHEMA_VERSION = "proof-console-report-v1"
PROOF_STATUS_SNAPSHOT_PATH = "artifacts/proof_status_snapshot_v1.json"
VALIDATION_FRONTIER_LEDGER_PATH = "artifacts/validation_frontier_ledger_schema_v1.json"
PROOF_CONSOLE_ALLOWED_RCH_OUTCOMES = {
    "pass",
    "blocked_external",
    "failed_local",
    "blocked_coordination",
    "wrapper_hang_after_remote_exit",
    "cancelled",
}
REMOTE_EXIT_RE = re.compile(
    r"(?:Remote command finished:\s*exit=|remote exit(?: status)?[=:]\s*)(-?\d+)",
    re.IGNORECASE,
)
CARGO_LOCATION_RE = re.compile(r"^\s*-->\s+([^:\s]+):(\d+):(\d+)")
RUST_ERROR_RE = re.compile(r"^\s*error(?:\[[^\]]+\])?:\s*(.+)")
WRAPPER_RETRIEVAL_HANG_HINTS = (
    "retrieval timed out",
    "retrieval stalled",
    "timed out while retrieving",
    "stalled while retrieving",
    "wrapper timed out",
    "wrapper stalled",
)
OPERATOR_ACTION_RECIPE_SCHEMA_VERSION = "operator-action-recipe-v1"
OPERATOR_ACTION_RECIPE_PROOF_COMMAND = (
    "rch exec -- env CARGO_INCREMENTAL=0 "
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_operator_action_recipe_contract "
    "CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' "
    "cargo test -p asupersync --test operator_action_recipe_contract -- --nocapture"
)
OPERATOR_ACTION_RECIPE_IDS = (
    "rerun-proof-lane",
    "stale-in-progress-reclaim",
    "no-win-fallback-hold",
    "dirty-frontier-refusal",
    "exact-blocker-escalation",
    "agent-mail-reservation",
    "destructive-command-refusal",
)


def proof_console_markdown(report: Dict[str, Any]) -> str:
    """Render a deterministic Markdown operator proof-console report."""
    summary = report["summary"]
    lines = [
        "# Proof Console Report",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Verdict: `{report['verdict']}`",
        (
            "- Summary: "
            f"{summary['claim_count']} claims, "
            f"{summary['lane_count']} lanes, "
            f"{summary['green_claim_count']} green, "
            f"{summary['yellow_claim_count']} yellow, "
            f"{summary['red_claim_count']} red"
        ),
        "",
        "## Claims",
        "",
        "| Claim | Status | Lanes | Broad Claim |",
        "| --- | --- | --- | --- |",
    ]
    for row in report["claim_rows"]:
        lanes = ", ".join(row["manifest_lane_ids"]) or "none"
        lines.append(
            f"| `{row['claim_id']}` | `{row['status']}` | {lanes} | {str(row['broad_claim']).lower()} |"
        )

    lines.extend(
        [
            "",
            "## Lanes",
            "",
            "| Lane | Kind | Status | Guarantees |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in report["lane_rows"]:
        guarantees = ", ".join(row["guarantee_ids"]) or "none"
        lines.append(
            f"| `{row['lane_id']}` | `{row['kind']}` | `{row['status']}` | {guarantees} |"
        )

    lines.extend(["", "## Failure Reasons", ""])
    if report["failure_reasons"]:
        for reason in report["failure_reasons"]:
            lines.append(f"- `{reason['reason_id']}`: {reason['summary']}")
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def safe_command_argv(command: str) -> List[str]:
    """Convert a manifest command to argv without invoking a shell."""
    if any(ch in command for ch in ("\0", "\n", "\r")):
        raise ValueError("proof command contains forbidden control characters")
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as error:
        raise ValueError(f"invalid proof command syntax: {error}") from error

    if len(argv) < 4 or argv[:3] != ["rch", "exec", "--"]:
        raise ValueError("proof command must start with 'rch exec --'")
    if any(any(marker in token for marker in SHELL_CONTROL_TOKENS) for token in argv):
        raise ValueError("proof command contains shell control metacharacters")

    remote_index = 3
    if argv[remote_index] == "env":
        remote_index += 1
        while remote_index < len(argv) and "=" in argv[remote_index]:
            name, _value = argv[remote_index].split("=", 1)
            if not SAFE_ENV_NAME.fullmatch(name):
                raise ValueError(f"invalid environment assignment in proof command: {name}")
            remote_index += 1

    if remote_index >= len(argv):
        raise ValueError("proof command has no remote program after rch exec --")
    if argv[remote_index] not in ALLOWED_REMOTE_PROGRAMS:
        raise ValueError(f"remote proof program is not allowed: {argv[remote_index]}")
    return argv


def command_scope(command: str) -> Dict[str, Any]:
    """Extract stable package/scope hints from an rch-routed proof command."""
    try:
        argv = safe_command_argv(command)
    except ValueError:
        argv = shlex.split(command, posix=True)

    scope = {
        "program": "",
        "cargo_subcommand": "",
        "package": "",
        "target_kind": "",
        "target": "",
        "manifest_path": "",
    }
    try:
        remote_index = argv.index("--") + 1
    except ValueError:
        remote_index = 0

    if remote_index < len(argv) and argv[remote_index] == "env":
        remote_index += 1
        while remote_index < len(argv) and "=" in argv[remote_index]:
            remote_index += 1

    if remote_index >= len(argv):
        return scope

    scope["program"] = argv[remote_index]
    if argv[remote_index] != "cargo":
        return scope

    if remote_index + 1 < len(argv):
        scope["cargo_subcommand"] = argv[remote_index + 1]

    for index, token in enumerate(argv):
        if token == "-p" and index + 1 < len(argv):
            scope["package"] = argv[index + 1]
        elif token == "--manifest-path" and index + 1 < len(argv):
            scope["manifest_path"] = argv[index + 1]
        elif token in {"--test", "--bench", "--bin", "--example"} and index + 1 < len(argv):
            scope["target_kind"] = token.removeprefix("--")
            scope["target"] = argv[index + 1]

    return scope


def remote_exit_status(log_text: str) -> Optional[int]:
    """Return the last remote exit status reported by rch, if present."""
    matches = REMOTE_EXIT_RE.findall(log_text)
    if not matches:
        return None
    return int(matches[-1])


def first_cargo_blocker(log_text: str) -> Dict[str, Any]:
    """Extract the first cargo/rustc file:line blocker from captured output."""
    pending_message = ""
    for line in log_text.splitlines():
        error_match = RUST_ERROR_RE.match(line)
        if error_match:
            pending_message = error_match.group(1).strip()
            continue

        location_match = CARGO_LOCATION_RE.match(line)
        if location_match:
            return {
                "file": location_match.group(1),
                "line": int(location_match.group(2)),
                "column": int(location_match.group(3)),
                "message": pending_message,
                "raw": line.strip(),
            }

    return {
        "file": "",
        "line": 0,
        "column": 0,
        "message": pending_message,
        "raw": "",
    }


def has_wrapper_retrieval_hang(log_text: str, remote_exit: Optional[int]) -> bool:
    """Classify the common rch wrapper hang after a known remote result."""
    if remote_exit is None:
        return False
    lowered = log_text.lower()
    return any(hint in lowered for hint in WRAPPER_RETRIEVAL_HANG_HINTS)


def classify_rch_outcome(
    command: str,
    log_text: str,
    touched_files: List[str],
) -> Dict[str, Any]:
    """Convert an rch output transcript into a structured outcome row."""
    scope = command_scope(command)
    remote_exit = remote_exit_status(log_text)
    blocker = first_cargo_blocker(log_text)
    touched = {path.removeprefix("./") for path in touched_files}
    blocker_file = str(blocker["file"]).removeprefix("./")
    wrapper_hang = has_wrapper_retrieval_hang(log_text, remote_exit)

    if wrapper_hang:
        outcome_class = "wrapper_hang_after_remote_exit"
        decision = "pass" if remote_exit == 0 else "blocked-external"
        summary = "rch wrapper retrieval stalled after remote command result was known"
    elif remote_exit == 0:
        outcome_class = "pass"
        decision = "pass"
        summary = "remote proof command passed"
    elif blocker_file and touched and blocker_file not in touched:
        outcome_class = "blocked_external"
        decision = "blocked-external"
        summary = f"first cargo blocker is outside touched files: {blocker_file}"
    else:
        outcome_class = "failed_local"
        decision = "failed-local"
        summary = "remote proof command failed on the touched proof surface"

    return {
        "schema_version": RCH_OUTCOME_SCHEMA_VERSION,
        "command": command,
        "command_scope": scope,
        "remote_exit_status": remote_exit,
        "outcome_class": outcome_class,
        "decision": decision,
        "first_blocker": blocker,
        "touched_files": touched_files,
        "summary": summary,
    }


def operator_action_recipes() -> List[Dict[str, Any]]:
    """Return deterministic operator recipes for shared-main proof work."""
    common_log_fields = [
        "command",
        "command_scope.package",
        "command_scope.target",
        "remote_exit_status",
        "first_blocker.file",
        "first_blocker.line",
        "fallback_no_win_reason",
        "operator_verdict",
        "reservation_policy",
    ]
    common_br = [
        "br ready --json",
        "br list --status in_progress --json",
        "br show <bead-id> --json",
    ]
    common_bv = [
        "bv --robot-triage",
        "bv --robot-alerts",
    ]
    reservation_policy = (
        "Reserve every touched source, test, fixture, and artifact path with Agent Mail "
        "before edits; mutate .beads only with an exclusive .beads reservation."
    )

    def recipe(
        recipe_id: str,
        title: str,
        preconditions: List[str],
        artifact_leaf: str,
        operator_verdict: str,
        fallback_no_win_reason: str,
        safe_execute: bool = False,
    ) -> Dict[str, Any]:
        return {
            "schema_version": OPERATOR_ACTION_RECIPE_SCHEMA_VERSION,
            "recipe_id": recipe_id,
            "title": title,
            "preconditions": preconditions,
            "proof_command_shape": OPERATOR_ACTION_RECIPE_PROOF_COMMAND,
            "allowed_br_commands": common_br,
            "allowed_bv_commands": common_bv,
            "artifact_paths": [
                f"artifacts/operator-recipes/{artifact_leaf}.json",
                f"tests/artifacts/operator-recipes/{artifact_leaf}.log",
            ],
            "expected_log_fields": common_log_fields,
            "first_blocker_line_required": True,
            "fallback_no_win_reason": fallback_no_win_reason,
            "operator_verdict": operator_verdict,
            "reservation_policy": reservation_policy,
            "tracker_payload_recommendation": {
                "mutates_tracker": False,
                "mode": "recommendation-only",
                "requires_exclusive_beads_reservation": True,
            },
            "safe_execute": safe_execute,
            "execute_effects": [] if safe_execute else ["disabled"],
            "destructive_command_policy": {
                "contains_raw_destructive_command_text": False,
                "requires_explicit_user_authorization": True,
                "default_verdict": "refuse",
            },
        }

    return [
        recipe(
            "rerun-proof-lane",
            "Rerun the exact rch proof lane before widening scope",
            [
                "A prior rch proof command exists in the bead, artifact, or mail thread.",
                "The touched file set has not widened since the prior proof attempt.",
                "No peer reservation conflicts overlap the touched paths.",
            ],
            "rerun-proof-lane",
            "pass",
            "not-applicable",
            safe_execute=False,
        ),
        recipe(
            "stale-in-progress-reclaim",
            "Reopen a stale in-progress bead with evidence",
            [
                "br or raw issue evidence shows an in-progress bead with stale activity.",
                "Agent Mail has no recent owner activity for the bead thread.",
                "The reclaim comment names the stale owner and last observed timestamp.",
            ],
            "stale-in-progress-reclaim",
            "blocked-external",
            "tracker-lock-or-owner-activity-prevents-safe-reclaim",
            safe_execute=False,
        ),
        recipe(
            "no-win-fallback-hold",
            "Record a no-win receipt without claiming improvement",
            [
                "The rch proof reached a known remote exit or first blocker.",
                "The result does not prove a speedup or green status.",
                "The receipt records no p50, p95, p999, throughput, or readiness claim.",
            ],
            "no-win-fallback-hold",
            "no-win",
            "proof-reached-frontier-without-usable-win",
            safe_execute=False,
        ),
        recipe(
            "dirty-frontier-refusal",
            "Refuse to run broad proof across unrelated dirty files",
            [
                "git status shows dirty paths outside the requested or reserved surface.",
                "The dirty paths are not owned by the current agent reservation.",
                "The refusal includes the first external dirty path and owner when known.",
            ],
            "dirty-frontier-refusal",
            "refuse",
            "dirty-frontier-outside-owned-surface",
            safe_execute=True,
        ),
        recipe(
            "exact-blocker-escalation",
            "Escalate the first exact blocker line instead of retrying blindly",
            [
                "The rch transcript contains a remote exit status or cargo blocker.",
                "The first blocker file and line are known.",
                "The blocker is outside the touched files or outside the bead scope.",
            ],
            "exact-blocker-escalation",
            "blocked-external",
            "first-blocker-outside-owned-surface",
            safe_execute=False,
        ),
        recipe(
            "agent-mail-reservation",
            "Reserve and announce the source surface before edits",
            [
                "The intended edit paths are known.",
                "Agent Mail is available for the project.",
                "The announcement names paths, bead id, proof lane, and non-overlap scope.",
            ],
            "agent-mail-reservation",
            "pass",
            "not-applicable",
            safe_execute=False,
        ),
        recipe(
            "destructive-command-refusal",
            "Refuse irreversible operations without explicit user authorization",
            [
                "A requested operation could delete, overwrite, or strand shared-main work.",
                "The user has not supplied exact written authorization for the operation.",
                "The response records refusal and a non-destructive alternative.",
            ],
            "destructive-command-refusal",
            "refuse",
            "irreversible-operation-not-authorized",
            safe_execute=True,
        ),
    ]


def find_operator_action_recipe(recipe_id: str) -> Dict[str, Any]:
    """Return an operator recipe by id, or raise a deterministic error."""
    for recipe in operator_action_recipes():
        if recipe["recipe_id"] == recipe_id:
            return recipe
    raise ValueError(f"unknown operator recipe: {recipe_id}")


class ProofLaneManifest:
    """Wrapper for the proof lane manifest."""

    def __init__(self, manifest_path: str = "artifacts/proof_lane_manifest_v1.json"):
        self.path = Path(manifest_path)
        with open(self.path) as f:
            self.data = json.load(f)

    def get_lane(self, lane_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific lane by ID."""
        for lane in self.data["lanes"]:
            if lane["lane_id"] == lane_id:
                return lane
        return None

    def list_lane_ids(self) -> List[str]:
        """List all available lane IDs."""
        return [lane["lane_id"] for lane in self.data["lanes"]]


class ValidationFrontierRecord:
    """Builder for validation frontier ledger records."""

    def __init__(self, command: str, touched_files: List[str]):
        self.command = command
        self.timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.touched_files = touched_files
        self.decision = "pass"
        self.error_class = ""
        self.first_failure = {
            "crate_or_surface": "",
            "target": "",
            "file": "",
            "line": 0
        }
        self.likely_owner = ""
        self.likely_bead = None
        self.supplemental_proof_command = ""
        self.summary = ""

    def as_blocked_external(
        self,
        error_class: str,
        file: str,
        summary: str,
        owner: str = "shared-main external blocker",
        supplemental: str = "",
        line: int = 0
    ) -> Dict[str, Any]:
        """Mark as externally blocked."""
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "decision": "blocked-external",
            "error_class": error_class,
            "first_failure": {
                "crate_or_surface": "coordination",
                "target": "preflight",
                "file": file,
                "line": line
            },
            "likely_owner": owner,
            "likely_bead": self.likely_bead,
            "supplemental_proof_command": supplemental,
            "summary": summary
        }

    def as_pass(self, supplemental: str = "") -> Dict[str, Any]:
        """Mark as passed."""
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "decision": "pass",
            "error_class": "",
            "first_failure": {
                "crate_or_surface": "",
                "target": "",
                "file": "",
                "line": 0
            },
            "likely_owner": "local_change",
            "likely_bead": self.likely_bead,
            "supplemental_proof_command": supplemental,
            "summary": "preflight checks passed"
        }

    def as_failed_local(
        self,
        error_class: str,
        file: str,
        summary: str,
        line: int = 0,
        target: str = "",
    ) -> Dict[str, Any]:
        """Mark as a local proof failure."""
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "decision": "failed-local",
            "error_class": error_class,
            "first_failure": {
                "crate_or_surface": "cargo",
                "target": target,
                "file": file,
                "line": line,
            },
            "likely_owner": "local_change",
            "likely_bead": self.likely_bead,
            "supplemental_proof_command": "",
            "summary": summary,
        }


class GitStatus:
    """Git working tree analysis."""

    def __init__(self, repo_root: str = "."):
        self.repo_root = Path(repo_root)
        self._status_lines = None

    def _get_status(self) -> List[str]:
        """Get git status --short output."""
        if self._status_lines is None:
            try:
                result = subprocess.run(
                    ["git", "status", "--short"],
                    capture_output=True,
                    text=True,
                    cwd=self.repo_root,
                    check=True
                )
                self._status_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            except subprocess.CalledProcessError:
                self._status_lines = []
        return self._status_lines

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        return len(self._get_status()) > 0

    def get_uncommitted_files(self) -> List[str]:
        """Get list of uncommitted files."""
        files = []
        for line in self._get_status():
            if len(line) >= 3:
                # Git status format: XY filename
                files.append(line[3:])
        return files

    def get_staged_files(self) -> List[str]:
        """Get list of staged files."""
        staged = []
        for line in self._get_status():
            if len(line) >= 3 and line[0] != ' ' and line[0] != '?':
                staged.append(line[3:])
        return staged


class AgentMailChecker:
    """Agent Mail reservation checker."""

    def __init__(
        self,
        project_key: str,
        agent_name: str = "unknown",
        reservation_snapshot: Optional[str] = None
    ):
        self.project_key = project_key
        self.agent_name = agent_name
        self.reservation_snapshot = Path(reservation_snapshot) if reservation_snapshot else None
        self.last_check = {
            "source": "not_configured",
            "classifications": []
        }

    def check_file_reservations(self, file_paths: List[str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check if any files have active reservations.
        Returns (has_conflicts, conflicts_list).
        """
        if not self.reservation_snapshot:
            self.last_check = {
                "source": "not_configured",
                "classifications": []
            }
            return False, []

        try:
            snapshot = json.loads(self.reservation_snapshot.read_text())
        except Exception as error:
            conflict = {
                "path": str(self.reservation_snapshot),
                "path_pattern": str(self.reservation_snapshot),
                "classification": "unavailable",
                "summary": f"reservation snapshot unavailable: {error}"
            }
            self.last_check = {
                "source": "snapshot",
                "classifications": [conflict]
            }
            return True, [conflict]

        reservations = self._extract_reservations(snapshot)
        classifications = [
            self._classify_reservation(reservation, file_paths)
            for reservation in reservations
        ]
        classifications = [item for item in classifications if item is not None]
        conflicts = [
            item for item in classifications
            if item["classification"] in {"peer-active", "tracker-only", "unknown-owner", "unavailable"}
        ]
        self.last_check = {
            "source": "snapshot",
            "classifications": classifications
        }
        return bool(conflicts), conflicts

    def _extract_reservations(self, snapshot: Any) -> List[Dict[str, Any]]:
        """Extract reservation rows from known snapshot shapes."""
        if isinstance(snapshot, list):
            return [item for item in snapshot if isinstance(item, dict)]
        if not isinstance(snapshot, dict):
            return []
        for key in ("reservations", "active_reservations", "granted"):
            rows = snapshot.get(key)
            if isinstance(rows, list):
                return [item for item in rows if isinstance(item, dict)]
        return []

    def _classify_reservation(
        self,
        reservation: Dict[str, Any],
        file_paths: List[str]
    ) -> Optional[Dict[str, Any]]:
        pattern = (
            reservation.get("path_pattern")
            or reservation.get("path")
            or reservation.get("pattern")
            or reservation.get("glob")
        )
        if not pattern:
            return None

        touched_file = self._first_matching_file(str(pattern), file_paths)
        if not touched_file:
            return None

        holder = (
            reservation.get("agent_name")
            or reservation.get("holder")
            or reservation.get("owner")
            or reservation.get("agent")
        )
        expires_ts = reservation.get("expires_ts") or reservation.get("expires_at") or ""
        released_ts = reservation.get("released_ts") or reservation.get("released_at")

        if released_ts or self._is_expired(expires_ts):
            classification = "expired"
        elif not holder:
            classification = "unknown-owner"
        elif holder == self.agent_name:
            classification = "owned-active"
        elif self._is_tracker_path(touched_file) or self._is_tracker_path(str(pattern)):
            classification = "tracker-only"
        else:
            classification = "peer-active"

        return {
            "path": touched_file,
            "path_pattern": str(pattern),
            "holder": holder or "",
            "expires_ts": expires_ts,
            "classification": classification,
            "summary": self._summary(classification, str(pattern), touched_file, holder, expires_ts)
        }

    def _first_matching_file(self, pattern: str, file_paths: List[str]) -> Optional[str]:
        normalized_pattern = pattern.removeprefix("./")
        for file_path in file_paths:
            normalized_file = file_path.removeprefix("./")
            if (
                normalized_file == normalized_pattern
                or fnmatch.fnmatchcase(normalized_file, normalized_pattern)
                or fnmatch.fnmatchcase(normalized_pattern, normalized_file)
            ):
                return normalized_file
        return None

    def _is_expired(self, expires_ts: Any) -> bool:
        if not expires_ts:
            return False
        try:
            timestamp = str(expires_ts).replace("Z", "+00:00")
            expires_at = datetime.fromisoformat(timestamp)
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at <= datetime.now(timezone.utc)

    def _is_tracker_path(self, path: str) -> bool:
        return path in {".beads/issues.jsonl", ".beads/beads.db"} or path.startswith(".beads/")

    def _summary(
        self,
        classification: str,
        pattern: str,
        touched_file: str,
        holder: Optional[str],
        expires_ts: Any
    ) -> str:
        if classification == "owned-active":
            return f"owned-active reservation covers {touched_file}"
        if classification == "expired":
            return f"expired reservation for {pattern} no longer blocks {touched_file}"
        if classification == "unknown-owner":
            return f"unknown-owner reservation blocks {touched_file}"
        if classification == "tracker-only":
            return f"tracker-only reservation held by {holder} blocks {touched_file} until {expires_ts}"
        if classification == "peer-active":
            return f"peer-active reservation held by {holder} blocks {touched_file} until {expires_ts}"
        return f"{classification} reservation for {pattern} affects {touched_file}"


class BuildSlotChecker:
    """Fixture-backed Agent Mail build-slot admission checker."""

    def __init__(
        self,
        project_key: str,
        agent_name: str = "unknown",
        build_slot: str = "proof-runner-rch",
        build_slot_snapshot: Optional[str] = None,
        skip_build_slot_check: bool = False
    ):
        self.project_key = project_key
        self.agent_name = agent_name
        self.build_slot = build_slot
        self.build_slot_snapshot = Path(build_slot_snapshot) if build_slot_snapshot else None
        self.skip_build_slot_check = skip_build_slot_check
        self.last_check = {
            "source": "not_requested",
            "slot": build_slot,
            "classifications": [],
            "release_after_command": None
        }

    def check_build_slot(
        self,
        lane: Dict[str, Any],
        execute: bool
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check build-slot admission for execute mode.
        Returns (has_conflicts, conflicts_list).
        """
        command = lane.get("command", "")
        if self.skip_build_slot_check or not execute or "rch exec --" not in command:
            self.last_check = {
                "source": "not_required",
                "slot": self.build_slot,
                "classifications": [],
                "release_after_command": None
            }
            return False, []

        if not self.build_slot_snapshot:
            conflict = {
                "slot": self.build_slot,
                "classification": "unavailable",
                "holder": "",
                "expires_ts": "",
                "summary": "build-slot snapshot unavailable for execute mode"
            }
            self.last_check = {
                "source": "not_configured",
                "slot": self.build_slot,
                "classifications": [conflict],
                "release_after_command": None
            }
            return True, [conflict]

        try:
            snapshot = json.loads(self.build_slot_snapshot.read_text())
        except Exception as error:
            conflict = {
                "slot": self.build_slot,
                "classification": "unavailable",
                "holder": "",
                "expires_ts": "",
                "summary": f"build-slot snapshot unavailable: {error}"
            }
            self.last_check = {
                "source": "snapshot",
                "slot": self.build_slot,
                "classifications": [conflict],
                "release_after_command": None
            }
            return True, [conflict]

        classifications = self._classify_snapshot(snapshot)
        active_owned = [
            item for item in classifications
            if item["classification"] in {"acquired", "renewed", "owned-active"}
        ]
        conflicts = [
            item for item in classifications
            if item["classification"] in {"peer-active", "unknown-owner", "unavailable"}
        ]

        release_after_command = None
        if active_owned:
            release_after_command = (
                "release_build_slot("
                f"project_key={self.project_key!r}, agent_name={self.agent_name!r}, "
                f"slot={self.build_slot!r})"
            )
        elif not conflicts:
            conflicts = [{
                "slot": self.build_slot,
                "classification": "missing-owned-active",
                "holder": "",
                "expires_ts": "",
                "summary": f"no owned active build slot for {self.build_slot}"
            }]

        self.last_check = {
            "source": "snapshot",
            "slot": self.build_slot,
            "classifications": classifications or conflicts,
            "release_after_command": release_after_command
        }
        return bool(conflicts), conflicts

    def _classify_snapshot(self, snapshot: Any) -> List[Dict[str, Any]]:
        rows = self._slot_rows(snapshot)
        classifications = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            slot = self._slot_name(row)
            if slot and slot != self.build_slot:
                continue
            classifications.append(self._classify_row(row))
        return classifications

    def _slot_rows(self, snapshot: Any) -> List[Dict[str, Any]]:
        if isinstance(snapshot, list):
            return [item for item in snapshot if isinstance(item, dict)]
        if not isinstance(snapshot, dict):
            return []

        rows: List[Dict[str, Any]] = []
        for key in ("acquired", "renewed", "released"):
            value = snapshot.get(key)
            if isinstance(value, dict):
                row = dict(value)
                row.setdefault("state", key)
                rows.append(row)
        for key in ("build_slots", "slots", "active_slots", "leases", "granted"):
            value = snapshot.get(key)
            if isinstance(value, list):
                rows.extend(item for item in value if isinstance(item, dict))
        conflicts = snapshot.get("conflicts")
        if isinstance(conflicts, list):
            for conflict in conflicts:
                if not isinstance(conflict, dict):
                    continue
                holders = conflict.get("holders")
                if isinstance(holders, list) and holders:
                    for holder in holders:
                        if isinstance(holder, dict):
                            row = dict(holder)
                            row.setdefault("slot", conflict.get("slot", self.build_slot))
                            row.setdefault("state", "conflict")
                            rows.append(row)
                else:
                    row = dict(conflict)
                    row.setdefault("state", "conflict")
                    rows.append(row)
        return rows

    def _classify_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        holder = self._holder_name(row)
        expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
        state = str(row.get("state") or row.get("status") or row.get("classification") or "")
        released_ts = row.get("released_ts") or row.get("released_at")

        if released_ts or state == "released":
            classification = "released"
        elif self._is_expired(expires_ts):
            classification = "expired"
        elif not holder:
            classification = "unknown-owner"
        elif holder == self.agent_name and state == "renewed":
            classification = "renewed"
        elif holder == self.agent_name and state in {"acquired", "granted"}:
            classification = "acquired"
        elif holder == self.agent_name:
            classification = "owned-active"
        else:
            classification = "peer-active"

        return {
            "slot": self._slot_name(row) or self.build_slot,
            "classification": classification,
            "holder": holder or "",
            "expires_ts": expires_ts,
            "summary": self._summary(classification, holder, expires_ts)
        }

    def _slot_name(self, row: Dict[str, Any]) -> str:
        for key in ("slot", "build_slot", "slot_name", "name"):
            value = row.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def _holder_name(self, row: Dict[str, Any]) -> str:
        for key in ("agent_name", "agent", "holder", "owner"):
            value = row.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def _is_expired(self, expires_ts: Any) -> bool:
        if not expires_ts:
            return False
        try:
            timestamp = str(expires_ts).replace("Z", "+00:00")
            expires_at = datetime.fromisoformat(timestamp)
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at <= datetime.now(timezone.utc)

    def _summary(self, classification: str, holder: str, expires_ts: str) -> str:
        if classification in {"acquired", "renewed", "owned-active"}:
            return f"{classification} build slot held by {holder} until {expires_ts}"
        if classification == "peer-active":
            return f"peer-active build slot held by {holder} until {expires_ts}"
        if classification == "expired":
            return f"expired build slot no longer grants admission for {self.build_slot}"
        if classification == "released":
            return f"released build slot no longer grants admission for {self.build_slot}"
        if classification == "unknown-owner":
            return f"unknown-owner build slot blocks {self.build_slot}"
        return f"{classification} build slot for {self.build_slot}"


class ProofRunner:
    """Main proof runner logic."""

    def __init__(
        self,
        repo_root: str = ".",
        agent_name: str = "unknown",
        reservation_snapshot: Optional[str] = None,
        build_slot_snapshot: Optional[str] = None,
        build_slot: str = "proof-runner-rch",
        skip_dirty_check: bool = False,
        skip_build_slot_check: bool = False
    ):
        self.repo_root = Path(repo_root).resolve()
        self.manifest = ProofLaneManifest()
        self.git = GitStatus(repo_root)
        self.agent_mail = AgentMailChecker(str(self.repo_root), agent_name, reservation_snapshot)
        self.build_slots = BuildSlotChecker(
            str(self.repo_root),
            agent_name,
            build_slot,
            build_slot_snapshot,
            skip_build_slot_check
        )
        self.skip_dirty_check = skip_dirty_check

    def _repo_json(self, relative_path: str) -> Dict[str, Any]:
        with (self.repo_root / relative_path).open(encoding="utf-8") as handle:
            return json.load(handle)

    def _repo_hash(self, relative_path: str) -> str:
        digest = hashlib.sha256()
        with (self.repo_root / relative_path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"

    def _load_rch_outcomes(self, paths: List[str]) -> List[Dict[str, Any]]:
        outcomes = []
        for path in paths:
            with Path(path).open(encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict) and isinstance(payload.get("rch_outcome"), dict):
                outcomes.append(payload["rch_outcome"])
            elif isinstance(payload, dict) and isinstance(payload.get("rch_outcomes"), list):
                outcomes.extend(
                    item for item in payload["rch_outcomes"] if isinstance(item, dict)
                )
            elif isinstance(payload, dict):
                outcomes.append(payload)
            else:
                raise ValueError(f"rch outcome file must contain an object: {path}")
        return outcomes

    def proof_console_report(
        self,
        generated_at: str = "",
        rch_outcome_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate the deterministic operator proof-console report."""
        snapshot = self._repo_json(PROOF_STATUS_SNAPSHOT_PATH)
        manifest = self.manifest.data
        rch_outcomes = self._load_rch_outcomes(rch_outcome_paths or [])
        lanes = sorted(manifest.get("lanes", []), key=lambda row: row.get("lane_id", ""))
        lane_ids = {lane.get("lane_id", "") for lane in lanes}
        guarantee_ids = {
            guarantee
            for lane in lanes
            for guarantee in lane.get("guarantee_ids", [])
            if isinstance(guarantee, str)
        }
        outcome_by_command = {
            outcome.get("command", ""): outcome
            for outcome in rch_outcomes
            if isinstance(outcome.get("command"), str)
        }

        if not generated_at:
            created_date = snapshot.get("created_date", "1970-01-01")
            generated_at = f"{created_date}T00:00:00Z"

        claim_rows = []
        unsupported_broad_claim_count = 0
        stale_blocker_count = 0
        for claim in sorted(
            snapshot.get("claim_categories", []), key=lambda row: row.get("claim_id", "")
        ):
            manifest_lane_ids = [
                lane
                for lane in claim.get("manifest_lane_ids", [])
                if isinstance(lane, str)
            ]
            manifest_guarantee_ids = [
                guarantee
                for guarantee in claim.get("manifest_guarantee_ids", [])
                if isinstance(guarantee, str)
            ]
            broad_claim = (
                not manifest_lane_ids
                or any(lane not in lane_ids for lane in manifest_lane_ids)
                or any(guarantee not in guarantee_ids for guarantee in manifest_guarantee_ids)
            )
            if broad_claim:
                unsupported_broad_claim_count += 1

            blocked_frontier = claim.get("blocked_frontier")
            if claim.get("status") == "red_blocked_external" and isinstance(
                blocked_frontier, dict
            ):
                first_failure = blocked_frontier.get("first_failure", {})
                if (
                    blocked_frontier.get("generated_at", "") < generated_at
                    or not first_failure.get("file")
                    or int(first_failure.get("line") or 0) == 0
                ):
                    stale_blocker_count += 1

            claim_rows.append(
                {
                    "claim_id": claim.get("claim_id", ""),
                    "category": claim.get("category", ""),
                    "status": claim.get("status", ""),
                    "manifest_lane_ids": manifest_lane_ids,
                    "manifest_guarantee_ids": manifest_guarantee_ids,
                    "proof_commands": [
                        command
                        for command in claim.get("proof_commands", [])
                        if isinstance(command, str)
                    ],
                    "blocked_frontier": blocked_frontier,
                    "doc_claim_markers": claim.get("doc_claim_markers", {}),
                    "broad_claim": broad_claim,
                }
            )

        blocked_lane_ids = {
            lane
            for claim in claim_rows
            if claim["status"] == "red_blocked_external"
            for lane in claim["manifest_lane_ids"]
        }
        lane_rows = []
        for lane in lanes:
            command = lane.get("command", "")
            outcome = outcome_by_command.get(command)
            if outcome:
                decision = outcome.get("decision", "")
                if decision == "pass":
                    status = "pass"
                elif decision == "blocked-external":
                    status = "blocked_external"
                elif decision == "failed-local":
                    status = "failed_local"
                else:
                    status = "not_run"
            elif lane.get("lane_id") in blocked_lane_ids:
                status = "blocked_external"
            else:
                status = "not_run"

            lane_rows.append(
                {
                    "lane_id": lane.get("lane_id", ""),
                    "kind": lane.get("kind", ""),
                    "command": command,
                    "guarantee_ids": lane.get("guarantee_ids", []),
                    "expected_signal": lane.get("expected_signal", ""),
                    "status": status,
                    "explicit_not_covered": lane.get("explicit_not_covered", ""),
                }
            )

        unclassified_rch_outcome_count = sum(
            1
            for outcome in rch_outcomes
            if outcome.get("outcome_class") not in PROOF_CONSOLE_ALLOWED_RCH_OUTCOMES
        )
        green_claim_count = sum(1 for claim in claim_rows if claim["status"] == "green")
        yellow_claim_count = sum(
            1 for claim in claim_rows if str(claim["status"]).startswith("yellow_")
        )
        red_claim_count = sum(
            1 for claim in claim_rows if claim["status"] == "red_blocked_external"
        )

        failure_reasons = []
        for claim in claim_rows:
            if claim["broad_claim"]:
                failure_reasons.append(
                    {
                        "reason_id": "unsupported-broad-claim",
                        "claim_id": claim["claim_id"],
                        "summary": "claim references missing manifest lane or guarantee coverage",
                    }
                )
        if stale_blocker_count:
            failure_reasons.append(
                {
                    "reason_id": "stale-blocker-row",
                    "summary": "one or more red blocker rows lack fresh file and line evidence",
                }
            )
        if unclassified_rch_outcome_count:
            failure_reasons.append(
                {
                    "reason_id": "unclassified-rch-outcome",
                    "summary": "one or more rch outcomes could not be mapped to an operator class",
                }
            )

        return {
            "schema_version": PROOF_CONSOLE_REPORT_SCHEMA_VERSION,
            "generated_at": generated_at,
            "generator": {
                "name": "scripts/proof_runner.py",
                "mode": "proof-console-report",
            },
            "source_artifact_hashes": {
                "artifacts/proof_lane_manifest_v1.json": self._repo_hash(
                    "artifacts/proof_lane_manifest_v1.json"
                ),
                "artifacts/proof_status_snapshot_v1.json": self._repo_hash(
                    PROOF_STATUS_SNAPSHOT_PATH
                ),
                "artifacts/validation_frontier_ledger_schema_v1.json": self._repo_hash(
                    VALIDATION_FRONTIER_LEDGER_PATH
                ),
            },
            "summary": {
                "claim_count": len(claim_rows),
                "lane_count": len(lane_rows),
                "green_claim_count": green_claim_count,
                "yellow_claim_count": yellow_claim_count,
                "red_claim_count": red_claim_count,
                "stale_blocker_count": stale_blocker_count,
                "unsupported_broad_claim_count": unsupported_broad_claim_count,
                "unclassified_rch_outcome_count": unclassified_rch_outcome_count,
            },
            "claim_rows": claim_rows,
            "lane_rows": lane_rows,
            "rch_outcomes": rch_outcomes,
            "failure_reasons": failure_reasons,
            "verdict": "fail_closed" if failure_reasons else "pass",
        }

    def analyze_preflight(
        self,
        lane_id: str,
        touched_files: List[str],
        execute: bool = False
    ) -> Tuple[bool, ValidationFrontierRecord]:
        """
        Analyze preflight conditions for a proof lane.
        Returns (can_proceed, frontier_record).
        """
        lane = self.manifest.get_lane(lane_id)
        if not lane:
            record = ValidationFrontierRecord(f"proof-runner --lane={lane_id}", touched_files)
            return False, record.as_blocked_external(
                "unknown_proof_lane",
                "artifacts/proof_lane_manifest_v1.json",
                f"unknown lane {lane_id}",
                supplemental="br ready --json"
            )

        command = lane["command"]
        record = ValidationFrontierRecord(command, touched_files)

        has_slot_conflicts, slot_conflicts = self.build_slots.check_build_slot(lane, execute)
        if has_slot_conflicts and slot_conflicts:
            conflict = slot_conflicts[0]
            supplemental = self._generate_narrow_proof(touched_files, lane)
            return False, record.as_blocked_external(
                "build_slot_conflict"
                if conflict.get("classification") in {"peer-active", "unknown-owner"}
                else "build_slot_unavailable",
                f"build-slot:{conflict.get('slot', 'unknown')}",
                f"build-slot admission blocked ({conflict.get('classification', 'unknown')}): {conflict.get('summary', 'unknown')}",
                owner=conflict.get("holder", "") or "Agent Mail build-slot admission",
                supplemental=supplemental
            )

        # Check file reservations before dirty state so explicit peer locks win.
        has_conflicts, conflicts = self.agent_mail.check_file_reservations(touched_files)
        if has_conflicts and conflicts:
            conflict = conflicts[0]
            supplemental = self._generate_narrow_proof(touched_files, lane)
            return False, record.as_blocked_external(
                "file_reservation_conflict",
                conflict.get("path", "unknown"),
                f"reservation conflict ({conflict.get('classification', 'unknown')}): {conflict.get('summary', 'unknown')}",
                supplemental=supplemental
            )

        # Check for uncommitted changes
        if not self.skip_dirty_check:
            uncommitted = self.git.get_uncommitted_files()
            if uncommitted:
                unrelated_files = [f for f in uncommitted if f not in touched_files]
                if unrelated_files:
                    # Has unrelated dirty files - suggest narrow proof
                    supplemental = self._generate_narrow_proof(touched_files, lane)
                    return False, record.as_blocked_external(
                        "peer_dirty_index_conflict",
                        unrelated_files[0],
                        f"unrelated dirty files present: {', '.join(unrelated_files[:3])}",
                        supplemental=supplemental
                    )

        # Check for staged changes from other agents
        if not self.skip_dirty_check:
            staged = self.git.get_staged_files()
            if staged:
                unrelated_staged = [f for f in staged if f not in touched_files]
                if unrelated_staged:
                    supplemental = self._generate_narrow_proof(touched_files, lane)
                    return False, record.as_blocked_external(
                        "peer_dirty_index_conflict",
                        unrelated_staged[0],
                        f"unrelated staged paths present: {', '.join(unrelated_staged[:3])}",
                        supplemental=supplemental
                    )

        # All checks passed
        supplemental = self._generate_narrow_proof(touched_files, lane)
        return True, record.as_pass(supplemental=supplemental)

    def _generate_narrow_proof(self, touched_files: List[str], lane: Dict[str, Any]) -> str:
        """Generate a narrow supplemental proof command."""
        lane_kind = lane.get("kind", "unknown")

        if lane_kind == "format_frontier":
            # For formatting, check only the touched files
            if len(touched_files) == 1:
                return f"rch exec -- rustfmt --edition 2024 --check {touched_files[0]}"
            else:
                return f"rch exec -- rustfmt --edition 2024 --check {' '.join(touched_files[:5])}"

        elif lane_kind in ["compile_frontier", "test_frontier"]:
            # For compilation/tests, try to narrow to specific targets
            rust_files = [f for f in touched_files if f.endswith('.rs')]
            if rust_files:
                # If we have specific test files, run just those
                if any('test' in f for f in rust_files):
                    test_files = [f for f in rust_files if 'test' in f]
                    if test_files:
                        test_name = Path(test_files[0]).stem
                        return f"rch exec -- cargo test {test_name} -- --nocapture"

                # Otherwise, try library check
                return "rch exec -- cargo check --lib"

        elif lane_kind == "lint_frontier":
            # For linting, check only specific files if possible
            rust_files = [f for f in touched_files if f.endswith('.rs')]
            if rust_files and len(rust_files) <= 3:
                return f"rch exec -- cargo clippy --lib -- -D warnings"

        # Fallback: basic format check
        return f"rch exec -- rustfmt --edition 2024 --check {' '.join(touched_files[:3])}"

    def run_preflight(
        self,
        lane_id: str,
        touched_files: List[str],
        execute: bool = False,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """Run preflight analysis and return results."""
        can_proceed, record = self.analyze_preflight(lane_id, touched_files, execute=execute)

        result = {
            "preflight_passed": can_proceed,
            "lane_id": lane_id,
            "command_would_run": self.manifest.get_lane(lane_id)["command"] if self.manifest.get_lane(lane_id) else "",
            "build_slot_check": self.build_slots.last_check,
            "reservation_check": self.agent_mail.last_check,
            "validation_frontier_record": record,
            "recommendation": "proceed" if can_proceed else "use_supplemental"
        }

        return result

    def suggest_lanes_for_changes(self, touched_files: List[str]) -> List[str]:
        """Suggest appropriate proof lanes based on touched files."""
        suggestions = []

        # Always suggest formatting check
        suggestions.append("rustfmt-check")

        # If Rust files were touched, suggest compilation and linting
        rust_files = [f for f in touched_files if f.endswith('.rs')]
        if rust_files:
            suggestions.append("all-targets-check")
            suggestions.append("clippy-all-targets")

            # If it's library code, suggest lib tests
            lib_files = [f for f in rust_files if f.startswith('src/') and not f.startswith('tests/')]
            if lib_files:
                suggestions.append("lib-tests")

        # If Cargo.toml was touched, suggest dependency checks
        if any('Cargo.toml' in f for f in touched_files):
            suggestions.append("default-production-tokio-tree")

        # If docs were touched, suggest doc build
        doc_files = [f for f in touched_files if any(word in f.lower() for word in ['readme', 'doc', '.md'])]
        if doc_files:
            suggestions.append("rustdoc-api")

        return suggestions

    def classify_rch_log(
        self,
        command: str,
        log_path: str,
        touched_files: List[str],
    ) -> Dict[str, Any]:
        """Classify a saved rch transcript as a machine-readable proof outcome."""
        log_text = Path(log_path).read_text(encoding="utf-8")
        outcome = classify_rch_outcome(command, log_text, touched_files)
        record = ValidationFrontierRecord(command, touched_files)
        blocker = outcome["first_blocker"]
        scope = outcome["command_scope"]

        if outcome["decision"] == "pass":
            frontier = record.as_pass()
        elif outcome["decision"] == "blocked-external":
            frontier = record.as_blocked_external(
                outcome["outcome_class"],
                blocker.get("file", "") or "rch-wrapper",
                outcome["summary"],
                line=int(blocker.get("line") or 0),
            )
        else:
            frontier = record.as_failed_local(
                outcome["outcome_class"],
                blocker.get("file", ""),
                outcome["summary"],
                line=int(blocker.get("line") or 0),
                target=scope.get("target") or scope.get("cargo_subcommand") or "",
            )

        return {
            "schema_version": RCH_OUTCOME_SCHEMA_VERSION,
            "rch_outcome": outcome,
            "validation_frontier_record": frontier,
        }

    def list_operator_recipes(self) -> Dict[str, Any]:
        """List deterministic shared-main operator recipes."""
        return {
            "schema_version": OPERATOR_ACTION_RECIPE_SCHEMA_VERSION,
            "recipes": operator_action_recipes(),
        }

    def operator_recipe(self, recipe_id: str, mode: str) -> Dict[str, Any]:
        """Render a recipe in dry-run mode or execute a safe no-op scenario."""
        recipe = find_operator_action_recipe(recipe_id)
        if mode == "execute" and not recipe["safe_execute"]:
            raise ValueError(f"execute mode is disabled for operator recipe: {recipe_id}")

        return {
            "schema_version": OPERATOR_ACTION_RECIPE_SCHEMA_VERSION,
            "mode": mode,
            "recipe": recipe,
            "would_execute": mode == "dry-run",
            "executed": mode == "execute",
            "side_effects": [],
            "mutates_tracker": False,
            "operator_verdict": recipe["operator_verdict"],
            "recommended_tracker_payload": recipe["tracker_payload_recommendation"],
        }


def main():
    parser = argparse.ArgumentParser(
        description="Agent-swarm safe proof runner with reservation awareness"
    )
    parser.add_argument(
        "--lane",
        help="Proof lane ID from the manifest"
    )
    parser.add_argument(
        "--touched-files",
        nargs="+",
        default=[],
        help="Files that motivated this validation attempt"
    )
    parser.add_argument(
        "--output",
        choices=["json", "human"],
        default="json",
        help="Output format"
    )
    parser.add_argument(
        "--list-lanes",
        action="store_true",
        help="List available proof lanes"
    )
    parser.add_argument(
        "--suggest-lanes",
        action="store_true",
        help="Suggest lanes for the touched files"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the proof command if preflight passes"
    )
    parser.add_argument(
        "--classify-rch-log",
        help="Classify a saved rch output transcript instead of running lane preflight"
    )
    parser.add_argument(
        "--list-operator-recipes",
        action="store_true",
        help="List deterministic shared-main operator action recipes"
    )
    parser.add_argument(
        "--operator-recipe",
        default="",
        help="Render or execute one operator action recipe by id"
    )
    parser.add_argument(
        "--operator-mode",
        choices=["dry-run", "execute"],
        default="dry-run",
        help="Operator recipe mode"
    )
    parser.add_argument(
        "--proof-console-report",
        action="store_true",
        help="Emit the deterministic operator proof-console report"
    )
    parser.add_argument(
        "--proof-console-generated-at",
        default="",
        help="Override generated_at for deterministic proof-console fixtures"
    )
    parser.add_argument(
        "--proof-console-rch-outcome",
        action="append",
        default=[],
        help="JSON rch outcome produced by --classify-rch-log to include in the proof console"
    )
    parser.add_argument(
        "--command",
        default="",
        help="Original rch command for --classify-rch-log"
    )
    parser.add_argument(
        "--agent-name",
        default=os.environ.get("AGENT_NAME", "unknown"),
        help="Agent name used to distinguish owned reservations"
    )
    parser.add_argument(
        "--reservation-snapshot",
        help="JSON snapshot of Agent Mail file reservations for fixture-backed checks"
    )
    parser.add_argument(
        "--build-slot-snapshot",
        help="JSON snapshot of Agent Mail build-slot admission for fixture-backed execute checks"
    )
    parser.add_argument(
        "--build-slot",
        default="proof-runner-rch",
        help="Build slot name required for rch-backed execute mode"
    )
    parser.add_argument(
        "--skip-dirty-check",
        action="store_true",
        help="Skip git dirty-state checks; intended for reservation classifier fixtures"
    )
    parser.add_argument(
        "--skip-build-slot-check",
        action="store_true",
        help="Skip build-slot admission checks; intended only for non-rch fixtures"
    )

    args = parser.parse_args()

    try:
        runner = ProofRunner(
            agent_name=args.agent_name,
            reservation_snapshot=args.reservation_snapshot,
            build_slot_snapshot=args.build_slot_snapshot,
            build_slot=args.build_slot,
            skip_dirty_check=args.skip_dirty_check,
            skip_build_slot_check=args.skip_build_slot_check
        )

        if args.list_lanes:
            lanes = runner.manifest.list_lane_ids()
            if args.output == "json":
                print(json.dumps({"available_lanes": lanes}, indent=2))
            else:
                print("Available proof lanes:")
                for lane in lanes:
                    print(f"  {lane}")
            return 0

        if args.suggest_lanes:
            suggestions = runner.suggest_lanes_for_changes(args.touched_files)
            if args.output == "json":
                print(json.dumps({"suggested_lanes": suggestions, "touched_files": args.touched_files}, indent=2))
            else:
                print(f"Suggested lanes for {args.touched_files}:")
                for lane in suggestions:
                    print(f"  {lane}")
            return 0

        if args.classify_rch_log:
            if not args.command:
                parser.error("--command is required with --classify-rch-log")
            result = runner.classify_rch_log(
                args.command,
                args.classify_rch_log,
                args.touched_files,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                outcome = result["rch_outcome"]
                print(f"Outcome: {outcome['outcome_class']}")
                print(f"Decision: {outcome['decision']}")
                print(f"Summary: {outcome['summary']}")
            return 0

        if args.list_operator_recipes:
            result = runner.list_operator_recipes()
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print("Available operator recipes:")
                for recipe in result["recipes"]:
                    print(f"  {recipe['recipe_id']}")
            return 0

        if args.operator_recipe:
            result = runner.operator_recipe(args.operator_recipe, args.operator_mode)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                recipe = result["recipe"]
                print(f"Recipe: {recipe['recipe_id']}")
                print(f"Mode: {result['mode']}")
                print(f"Verdict: {result['operator_verdict']}")
            return 0

        if args.proof_console_report:
            result = runner.proof_console_report(
                generated_at=args.proof_console_generated_at,
                rch_outcome_paths=args.proof_console_rch_outcome,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(proof_console_markdown(result), end="")
            return 0

        # Validate required arguments for proof analysis
        if not args.lane:
            parser.error("--lane is required when not using --list-lanes or --suggest-lanes")

        # Run preflight analysis
        result = runner.run_preflight(args.lane, args.touched_files, execute=args.execute, output_format=args.output)

        if args.output == "json":
            print(json.dumps(result, indent=2))
        else:
            if result["preflight_passed"]:
                print(f"✅ Preflight PASSED for lane {args.lane}")
                print(f"Command: {result['command_would_run']}")
                if args.execute:
                    print("Executing...")
                    # Execute the command
                    lane = runner.manifest.get_lane(args.lane)
                    if lane:
                        argv = safe_command_argv(lane["command"])
                        return subprocess.call(argv)
            else:
                record = result["validation_frontier_record"]
                print(f"❌ Preflight BLOCKED for lane {args.lane}")
                print(f"Reason: {record['summary']}")
                print(f"Blocker file: {record['first_failure']['file']}")
                print(f"Suggested supplemental proof: {record['supplemental_proof_command']}")
                return 1

        return 0 if result["preflight_passed"] else 1

    except Exception as e:
        if args.output == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
