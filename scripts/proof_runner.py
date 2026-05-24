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
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

SAFE_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_REMOTE_PROGRAMS = {"cargo", "lake", "rustfmt"}
REMOTE_REQUIRED_VALUES = {"1", "true", "yes", "on"}
SHELL_CONTROL_TOKENS = (";", "&", "|", "<", ">", "`", "$(")
FORBIDDEN_VALIDATION_COMMAND_POLICY = (
    "validation commands must not contain shell control or irreversible "
    "git/filesystem operations"
)
RCH_OUTCOME_SCHEMA_VERSION = "proof-runner-rch-outcome-v1"
PROOF_CONSOLE_REPORT_SCHEMA_VERSION = "proof-console-report-v1"
PROOF_STATUS_DASHBOARD_SCHEMA_VERSION = "proof-status-dashboard-v1"
FAILURE_CORPUS_REPLAY_SCHEMA_VERSION = "failure-corpus-replay-result-v1"
RELEASE_PROOF_PACK_SCHEMA_VERSION = "release-proof-pack-v1"
DISK_PRESSURE_SCHEMA_VERSION = "proof-runner-disk-pressure-v1"
DEFAULT_DISK_MIN_FREE_BYTES = 1_073_741_824
DEFAULT_DEV_SHM_MIN_FREE_BYTES = 268_435_456
PROOF_STATUS_SNAPSHOT_PATH = "artifacts/proof_status_snapshot_v1.json"
FAILURE_CORPUS_MANIFEST_PATH = "artifacts/failure_corpus_manifest_v1.json"
VALIDATION_FRONTIER_LEDGER_PATH = "artifacts/validation_frontier_ledger_schema_v1.json"
RELEASE_PROOF_PACK_SOURCE_ARTIFACTS = (
    "artifacts/proof_lane_manifest_v1.json",
    PROOF_STATUS_SNAPSHOT_PATH,
    VALIDATION_FRONTIER_LEDGER_PATH,
    "artifacts/conformance_registry_contract_v1.json",
    "artifacts/adapter_certification_matrix_v1.json",
    "artifacts/release_proof_pack_contract_v1.json",
)
PROOF_CONSOLE_ALLOWED_RCH_OUTCOMES = {
    "pass",
    "blocked_external",
    "failed_local",
    "blocked_coordination",
    "wrapper_hang_after_remote_exit",
    "rch-control-plane-inconsistent",
    "cancelled",
}
TRACKER_STATUS_BUCKETS = (
    "blocked",
    "closed",
    "in_progress",
    "open",
    "tombstone",
    "unknown",
)
REMOTE_EXIT_RE = re.compile(
    r"(?:Remote command finished:\s*exit=|remote exit(?: status)?[=:]\s*)(-?\d+)",
    re.IGNORECASE,
)
RCH_LOCAL_FALLBACK_RE = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
ASUPERSYNC_BEAD_RE = re.compile(
    r"\b(?:br-)?(?P<bead>asupersync-[a-z0-9]+(?:\.\d+)?)\b",
    re.IGNORECASE,
)
CARGO_LOCATION_RE = re.compile(r"^\s*-->\s+([^:\s]+):(\d+):(\d+)")
CARGO_SHORT_ERROR_RE = re.compile(
    r"^(?P<file>[^:\s][^:\n]*):(?P<line>\d+):(?P<column>\d+):\s+"
    r"error(?:\[(?P<code>[^\]]+)\])?:\s*(?P<message>.+)$"
)
RUST_ERROR_RE = re.compile(
    r"^\s*error(?:\[(?P<code>[^\]]+)\])?:\s*(?P<message>.+)"
)
RUSTFMT_DIFF_RE = re.compile(r"^Diff in (?P<file>[^:\n]+):(?P<line>\d+):", re.MULTILINE)
TRUNCATED_OUTPUT_RE = re.compile(r"truncated (?:after|output)|output truncated", re.IGNORECASE)
CLIPPY_LINT_RE = re.compile(
    r"(?:rust-clippy/[^\s#]+#|clippy::)(?P<lint>[A-Za-z0-9_-]+)"
)
ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b"
)
SHA256_VALUE_RE = re.compile(r"sha256:[0-9a-fA-F]{64}")
RCH_COMMAND_FIELD_RE = re.compile(r"command=RCH_REQUIRE_REMOTE[^\n]*")
WORKER_FIELD_RE = re.compile(r"\bworker=[A-Za-z0-9_.-]+")
ACTIVE_PROJECT_EXCLUSION_RE = re.compile(r"active_project_exclusion=\d+")
DURATION_VALUE_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|us|ns|s)\b")
TMP_PATH_RE = re.compile(r"/tmp/[A-Za-z0-9._/\-]+")
WRAPPER_RETRIEVAL_HANG_HINTS = (
    "retrieval timed out",
    "retrieval stalled",
    "timed out while retrieving",
    "stalled while retrieving",
    "wrapper timed out",
    "wrapper stalled",
)
RCH_CONTROL_PLANE_INCONSISTENT_CLASS = "rch-control-plane-inconsistent"
RCH_CONTROL_PLANE_CONTINUE_RECOMMENDATION = (
    "continue repo work if validation does not depend on this worker"
)
RCH_WORKER_ENABLE_RE = re.compile(
    r"\brch\s+workers\s+(?P<action>enable|disable|probe)\s+(?P<worker>[A-Za-z0-9_.-]+)"
)
RCH_WORKER_NOT_FOUND_RE = re.compile(
    r"worker(?:\s+|[-_])not(?:\s+|[-_])found(?::|\s)+(?:worker\s+)?(?P<worker>[A-Za-z0-9_.-]+)?",
    re.IGNORECASE,
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
DISK_HEALTHY_NEXT_ACTION = "run requested proof lane as planned"
DISK_SAFE_NEXT_ACTION = (
    "defer Cargo-heavy validation or capture an artifact-free proof receipt; "
    "do not delete files automatically"
)
DISK_CLEANUP_PERMISSION_RECORD = "cleanup requires explicit user permission"
FALLBACK_RANKING_SCHEMA_VERSION = "proof-runner-fallback-bead-ranking-v1"
FALLBACK_CARGO_HEAVY_WARNING = (
    "local disk pressure detected; prefer disk-safe fallback work or an artifact-free proof receipt before Cargo-heavy validation"
)
AUTOPILOT_PLAN_SCHEMA_VERSION = "proof-runner-autopilot-plan-v1"
COMPILE_FRONTIER_SHARDS_SCHEMA_VERSION = "proof-runner-compile-frontier-shards-v1"


def _non_negative_int(value: Any) -> int:
    # Coerce disk fixture fields to non-negative integers.
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def disk_usage_surface(path: str) -> Dict[str, Any]:
    # Return a normalized disk-usage row for one local path.
    disk_path = Path(path)
    if not disk_path.exists():
        return {
            "path": path,
            "available": False,
            "free_bytes": 0,
            "total_bytes": 0,
            "used_bytes": 0,
        }
    usage = shutil.disk_usage(disk_path)
    return {
        "path": path,
        "available": True,
        "free_bytes": int(usage.free),
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
    }


def normalize_disk_surface(raw: Any, default_path: str) -> Dict[str, Any]:
    # Normalize fixture and live disk rows to one schema.
    row = raw if isinstance(raw, dict) else {}
    return {
        "path": str(row.get("path") or default_path),
        "available": bool(row.get("available", True)),
        "free_bytes": _non_negative_int(row.get("free_bytes")),
        "total_bytes": _non_negative_int(row.get("total_bytes")),
        "used_bytes": _non_negative_int(row.get("used_bytes")),
    }


def disk_pressure_snapshot(snapshot_path: Optional[str] = None) -> Dict[str, Any]:
    # Load a fixture-backed or live local disk-pressure snapshot.
    if snapshot_path:
        raw = json.loads(Path(snapshot_path).read_text())
        raw_root = raw.get("root", {}) if isinstance(raw, dict) else {}
        raw_dev_shm = raw.get("dev_shm", {}) if isinstance(raw, dict) else {}
        return {
            "source": "fixture",
            "root": normalize_disk_surface(raw_root, "/"),
            "dev_shm": normalize_disk_surface(raw_dev_shm, "/dev/shm"),
        }

    return {
        "source": "live",
        "root": disk_usage_surface("/"),
        "dev_shm": disk_usage_surface("/dev/shm"),
    }


def classify_disk_pressure(
    command: str,
    snapshot: Dict[str, Any],
    min_free_bytes: int,
    dev_shm_min_free_bytes: int,
) -> Dict[str, Any]:
    # Classify local free space and emit non-deleting proof-path guidance.
    root = snapshot["root"]
    dev_shm = snapshot["dev_shm"]
    root_low = root["available"] and root["free_bytes"] < min_free_bytes
    dev_shm_low = dev_shm["available"] and dev_shm["free_bytes"] < dev_shm_min_free_bytes

    if root_low and dev_shm_low:
        classification = "low-root-and-dev-shm-space"
    elif root_low:
        classification = "low-root-space"
    elif dev_shm_low:
        classification = "low-dev-shm-space"
    else:
        classification = "healthy"

    command_uses_custom_target_dir = "CARGO_TARGET_DIR=" in command
    disk_healthy = classification == "healthy"
    custom_target_dir_permitted = disk_healthy or not command_uses_custom_target_dir
    if disk_healthy:
        preferred_next_action = DISK_HEALTHY_NEXT_ACTION
        cargo_target_dir_guidance = "lane-specific CARGO_TARGET_DIR is acceptable"
        proof_receipt_guidance = "artifact retrieval may proceed normally"
        recommendation = "run_requested_proof_lane"
    else:
        preferred_next_action = DISK_SAFE_NEXT_ACTION
        cargo_target_dir_guidance = "keep lane-specific CARGO_TARGET_DIR on any later Cargo rerun"
        proof_receipt_guidance = "prefer artifact-free proof receipt"
        recommendation = "use_disk_safe_proof_path"

    return {
        "schema_version": DISK_PRESSURE_SCHEMA_VERSION,
        "source": snapshot["source"],
        "classification": classification,
        "thresholds": {
            "root_min_free_bytes": min_free_bytes,
            "dev_shm_min_free_bytes": dev_shm_min_free_bytes,
        },
        "surfaces": {"root": root, "dev_shm": dev_shm},
        "command_uses_custom_target_dir": command_uses_custom_target_dir,
        "custom_target_dir_validation_permitted": custom_target_dir_permitted,
        "execution_permitted": custom_target_dir_permitted,
        "recommendation": recommendation,
        "guidance": {
            "preferred_next_action": preferred_next_action,
            "cargo_target_dir_guidance": cargo_target_dir_guidance,
            "proof_receipt_guidance": proof_receipt_guidance,
            "cleanup_permission_record": DISK_CLEANUP_PERMISSION_RECORD,
            "cleanup_requires_explicit_user_permission": True,
            "automatic_cleanup_performed": False,
            "deletion_command_recommended": False,
        },
    }


def _string_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def normalize_repo_path(path: str) -> str:
    """Normalize repo-relative paths for comparisons without stripping filenames."""
    return str(path).replace("\\", "/").removeprefix("./").rstrip("/")


def fallback_bead_rows_from_snapshot(snapshot_path: str) -> List[Dict[str, Any]]:
    raw = json.loads(Path(snapshot_path).read_text())
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        rows = raw.get("beads") or raw.get("ready") or raw.get("issues") or []
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def fallback_validation_text(bead: Dict[str, Any]) -> str:
    parts = [
        bead.get("title", ""),
        bead.get("description", ""),
        bead.get("command", ""),
        bead.get("validation_command", ""),
        bead.get("proof_command", ""),
    ]
    parts.extend(_string_list(bead.get("labels")))
    parts.extend(_string_list(bead.get("validation")))
    parts.extend(_string_list(bead.get("validation_commands")))
    parts.extend(_string_list(bead.get("proof_commands")))
    return " ".join(part for part in parts if part).lower()


def fallback_validation_commands(bead: Dict[str, Any]) -> List[str]:
    commands = []
    for key in ("command", "validation_command", "proof_command"):
        value = bead.get(key)
        if isinstance(value, str) and value.strip():
            commands.append(value.strip())
    for key in ("validation", "validation_commands", "proof_commands"):
        commands.extend(command.strip() for command in _string_list(bead.get(key)) if command.strip())
    return commands


def _first_non_assignment(argv: List[str], start: int = 0) -> int:
    index = start
    while index < len(argv) and "=" in argv[index]:
        name, _value = argv[index].split("=", 1)
        if not SAFE_ENV_NAME.fullmatch(name):
            break
        index += 1
    return index


def proof_target_slug(raw: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_").lower()
    return slug or "supplemental"


def rch_cargo_command(target_slug: str, cargo_args: str) -> str:
    return (
        "RCH_REQUIRE_REMOTE=1 rch exec -- env "
        f"CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_proof_runner_{proof_target_slug(target_slug)} "
        f"cargo {cargo_args}"
    )


def command_routes_cargo_through_rch(command: str) -> bool:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return False

    if any(any(marker in token for marker in SHELL_CONTROL_TOKENS) for token in argv):
        return False

    if "cargo" not in argv:
        return True

    program_index = _first_non_assignment(argv)
    if program_index >= len(argv):
        return False
    if argv[program_index:program_index + 3] != ["rch", "exec", "--"]:
        return False
    command_requires_remote = any(
        assignment.startswith("RCH_REQUIRE_REMOTE=")
        and assignment.split("=", 1)[1].lower() in REMOTE_REQUIRED_VALUES
        for assignment in argv[:program_index]
    )

    remote_index = program_index + 3
    command_uses_target_dir = False
    if remote_index < len(argv) and argv[remote_index] == "env":
        env_start = remote_index + 1
        remote_index = _first_non_assignment(argv, env_start)
        command_uses_target_dir = any(
            arg.startswith("CARGO_TARGET_DIR=")
            for arg in argv[env_start:remote_index]
        )
    return (
        remote_index < len(argv)
        and argv[remote_index] == "cargo"
        and command_uses_target_dir
        and command_requires_remote
    )


def _effective_program_tokens(argv: List[str]) -> List[str]:
    """Return command tokens after leading env assignments."""
    index = _first_non_assignment(argv)
    if index < len(argv) and argv[index] == "env":
        index = _first_non_assignment(argv, index + 1)
    return argv[index:]


def _rch_remote_program_tokens(argv: List[str]) -> List[str]:
    """Return rch remote command tokens, or an empty list for non-rch commands."""
    tokens = _effective_program_tokens(argv)
    for index in range(len(tokens) - 2):
        if tokens[index:index + 3] == ["rch", "exec", "--"]:
            return _effective_program_tokens(tokens[index + 3:])
    return []


def _git_branch_creates_non_main_ref(tokens: List[str]) -> bool:
    if len(tokens) < 3 or tokens[:2] != ["git", "branch"]:
        return False
    for token in tokens[2:]:
        if token.startswith("-"):
            continue
        return token != "main"
    return False


def forbidden_validation_command_reasons(command: str) -> List[str]:
    """Return reasons a fallback validation command must not be recommended."""
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as error:
        return [f"invalid-command-syntax: {error}"]

    reasons = []
    if any(any(marker in token for marker in SHELL_CONTROL_TOKENS) for token in argv):
        reasons.append("shell-control-metacharacters")

    candidates = [_effective_program_tokens(argv)]
    remote_tokens = _rch_remote_program_tokens(argv)
    if remote_tokens:
        candidates.append(remote_tokens)

    for tokens in candidates:
        if not tokens:
            continue
        program = tokens[0]
        if program == "rm":
            reasons.append("forbidden-file-deletion")
        elif tokens[:3] == ["git", "reset", "--hard"]:
            reasons.append("forbidden-git-reset-hard")
        elif len(tokens) >= 3 and tokens[:2] == ["git", "clean"] and any(
            flag in {"-fd", "-df", "-ffd", "-fdf"} or (
                flag.startswith("-") and "f" in flag and "d" in flag
            )
            for flag in tokens[2:]
        ):
            reasons.append("forbidden-git-clean")
        elif tokens[:3] == ["git", "worktree", "add"]:
            reasons.append("forbidden-git-worktree-add")
        elif tokens[:3] == ["git", "checkout", "-b"]:
            reasons.append("forbidden-git-checkout-branch")
        elif tokens[:3] == ["git", "switch", "-c"]:
            reasons.append("forbidden-git-switch-branch")
        elif _git_branch_creates_non_main_ref(tokens):
            reasons.append("forbidden-git-branch-non-main")
        elif len(tokens) >= 2 and tokens[:2] == ["git", "push"]:
            reasons.append("forbidden-git-push")

    return sorted(set(reasons))


def fallback_disk_safety(bead: Dict[str, Any]) -> str:
    explicit = str(bead.get("disk_safety", "")).strip().lower()
    if explicit in {"disk-safe", "cargo-heavy", "neutral"}:
        return explicit
    if bead.get("disk_safe") is True:
        return "disk-safe"
    if bead.get("cargo_heavy") is True or bead.get("disk_safe") is False:
        return "cargo-heavy"

    text = fallback_validation_text(bead)
    disk_safe_terms = (
        "artifact-free",
        "no-artifact",
        "script-only",
        "fixture-only",
        "docs",
        "documentation",
        "plan-space",
    )
    cargo_heavy_terms = (
        "rch exec -- cargo",
        " cargo test",
        " cargo clippy",
        " cargo check",
        " cargo bench",
        "cargo-heavy",
    )
    if any(term in text for term in cargo_heavy_terms):
        return "cargo-heavy"
    if any(term in text for term in disk_safe_terms):
        return "disk-safe"
    return "neutral"


def fallback_touched_files(bead: Dict[str, Any]) -> List[str]:
    """Return the declared file surface for one fallback bead candidate."""
    for key in ("touched_files", "files", "paths", "source_files", "validation_files"):
        files = _string_list(bead.get(key))
        if files:
            return [normalize_repo_path(path) for path in files if path]
    return []


def rank_fallback_beads_for_disk(
    beads: List[Dict[str, Any]],
    disk_preflight: Dict[str, Any],
    reservation_checker: Optional["AgentMailChecker"] = None,
) -> List[Dict[str, Any]]:
    disk_low = disk_preflight["classification"] != "healthy"
    class_rank = {"disk-safe": 0, "neutral": 1, "cargo-heavy": 2}
    ranked = []
    for input_order, bead in enumerate(beads):
        disk_safety = fallback_disk_safety(bead)
        warning = FALLBACK_CARGO_HEAVY_WARNING if disk_low and disk_safety == "cargo-heavy" else ""
        touched_files = fallback_touched_files(bead)
        unsafe_validation_reasons = []
        for command in fallback_validation_commands(bead):
            reasons = forbidden_validation_command_reasons(command)
            if not command_routes_cargo_through_rch(command):
                reasons.append("cargo-validation-not-remote-rch-routed")
            if reasons:
                unsafe_validation_reasons.append(
                    {
                        "command": command,
                        "reasons": sorted(set(reasons)),
                    }
                )
        unsafe_validation_commands = [
            row["command"] for row in unsafe_validation_reasons
        ]
        reservation_overlaps = []
        if reservation_checker and touched_files:
            reservation_checker.check_file_reservations(touched_files)
            reservation_overlaps = list(reservation_checker.last_check["classifications"])
        peer_overlaps = [
            row for row in reservation_overlaps
            if row["classification"] == "peer-active"
        ]
        hard_overlaps = [
            row for row in reservation_overlaps
            if row["classification"] in {"tracker-only", "unknown-owner", "unavailable"}
        ]
        ranked.append({
            "id": str(bead.get("id", "")),
            "title": str(bead.get("title", "")),
            "priority": _non_negative_int(bead.get("priority", 2)),
            "input_order": input_order,
            "eligible": not hard_overlaps and not unsafe_validation_commands,
            "disk_safety": disk_safety,
            "disk_pressure_warning": warning,
            "touched_files": touched_files,
            "reservation_overlaps": reservation_overlaps,
            "reservation_demoted": bool(peer_overlaps),
            "reservation_hard_blocked": bool(hard_overlaps),
            "unsafe_validation_blocked": bool(unsafe_validation_commands),
            "unsafe_validation_commands": unsafe_validation_commands,
            "unsafe_validation_reasons": unsafe_validation_reasons,
            "validation_command_policy": (
                "cargo validation must route through "
                "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo; "
                f"{FORBIDDEN_VALIDATION_COMMAND_POLICY}"
            ),
            "reservation_warning": (
                f"peer-active reservation overlaps {peer_overlaps[0]['path']} held by {peer_overlaps[0]['holder']}"
                if peer_overlaps else ""
            ),
            "reservation_blocker": hard_overlaps[0] if hard_overlaps else None,
            "validation_hint": str(
                bead.get("validation_command")
                or bead.get("proof_command")
                or bead.get("command")
                or ""
            ),
        })
    def sort_key(row: Dict[str, Any]) -> Tuple[int, int, int, int, int]:
        disk_rank = class_rank[row["disk_safety"]] if disk_low else 0
        hard_rank = 1 if row["reservation_hard_blocked"] else 0
        unsafe_rank = 1 if row["unsafe_validation_blocked"] else 0
        peer_rank = 1 if row["reservation_demoted"] else 0
        return (hard_rank, unsafe_rank, disk_rank, peer_rank, row["input_order"])

    if disk_low:
        return sorted(ranked, key=sort_key)
    return sorted(ranked, key=sort_key)


def compile_frontier_file_groups(
    blockers: List[Dict[str, Any]],
    touched_files: List[str],
    reservation_checker: Optional["AgentMailChecker"] = None,
) -> List[Dict[str, Any]]:
    """Group rustc blockers by file and annotate reservation/touched state."""
    touched = {normalize_repo_path(path) for path in touched_files}
    grouped: Dict[str, Dict[str, Any]] = {}
    for input_order, blocker in enumerate(blockers):
        file_path = normalize_repo_path(str(blocker.get("file", "")))
        if not file_path:
            continue
        if file_path not in grouped:
            grouped[file_path] = {
                "file": file_path,
                "input_order": input_order,
                "diagnostic_count": 0,
                "first_blocker": {
                    "file": file_path,
                    "line": int(blocker.get("line") or 0),
                    "column": int(blocker.get("column") or 0),
                    "message": str(blocker.get("message") or ""),
                    "code": str(blocker.get("code") or ""),
                },
                "error_codes": [],
                "messages": [],
                "touched_by_request": file_path in touched,
                "reservation_overlaps": [],
                "reservation_state": "unchecked",
                "eligible_for_new_slice": True,
            }
        group = grouped[file_path]
        group["diagnostic_count"] += 1
        code = str(blocker.get("code") or "")
        if code and code not in group["error_codes"]:
            group["error_codes"].append(code)
        message = str(blocker.get("message") or "")
        if message and message not in group["messages"]:
            group["messages"].append(message)

    groups = sorted(grouped.values(), key=lambda row: row["input_order"])
    for group in groups:
        if reservation_checker is None:
            group["reservation_state"] = "not_configured"
            continue
        reservation_checker.check_file_reservations([group["file"]])
        overlaps = list(reservation_checker.last_check["classifications"])
        group["reservation_overlaps"] = overlaps
        active_conflicts = [
            row for row in overlaps
            if row["classification"] in {"peer-active", "tracker-only", "unknown-owner", "unavailable"}
        ]
        if active_conflicts:
            group["eligible_for_new_slice"] = False
            group["reservation_state"] = active_conflicts[0]["classification"]
        elif any(row["classification"] == "owned-active" for row in overlaps):
            group["reservation_state"] = "owned-active"
        elif any(row["classification"] == "expired" for row in overlaps):
            group["reservation_state"] = "expired"
        else:
            group["reservation_state"] = "free"
    return groups


def compile_frontier_shard_suggestions(
    file_groups: List[Dict[str, Any]],
    command: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split file groups into actionable and reservation-blocked shard rows."""
    suggestions = []
    blocked = []
    eligible_groups = [
        group for group in file_groups
        if group["eligible_for_new_slice"]
    ]
    eligible_groups = sorted(
        eligible_groups,
        key=lambda group: (
            0 if group["touched_by_request"] else 1,
            group["input_order"],
        ),
    )
    for rank, group in enumerate(eligible_groups, start=1):
        suggestions.append({
            "rank": rank,
            "candidate_title": f"Fix compile frontier in {group['file']}",
            "touched_files": [group["file"]],
            "reservation_paths": [group["file"]],
            "first_blocker": group["first_blocker"],
            "diagnostic_count": group["diagnostic_count"],
            "error_codes": group["error_codes"],
            "reservation_state": group["reservation_state"],
            "validation_hint": command,
        })
    for group in file_groups:
        if not group["eligible_for_new_slice"]:
            blocked.append({
                "candidate_title": f"Fix compile frontier in {group['file']}",
                "touched_files": [group["file"]],
                "reservation_paths": [group["file"]],
                "first_blocker": group["first_blocker"],
                "diagnostic_count": group["diagnostic_count"],
                "error_codes": group["error_codes"],
                "reservation_state": group["reservation_state"],
                "reservation_overlaps": group["reservation_overlaps"],
                "validation_hint": command,
            })
    return suggestions, blocked


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """Serialize JSON in the byte-stable form used by generated proof packs."""
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def payload_hash(payload: Dict[str, Any]) -> str:
    """Return a sha256 digest for canonical JSON payload bytes."""
    return f"sha256:{hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}"


def file_hash(path: Path) -> str:
    """Return a sha256 digest for a file without loading it all at once."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _int_or_zero(value: Any) -> int:
    """Coerce external JSON number fields to int for fail-closed evidence checks."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def scrub_failure_corpus_text(raw_text: str, repo_root: Path) -> str:
    """Scrub nondeterministic proof-failure text for replayable corpus entries."""
    scrubbed = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    repo = repo_root.as_posix().rstrip("/")
    scrubbed = scrubbed.replace(repo, "[REPO]")
    scrubbed = ISO_TIMESTAMP_RE.sub("[TIMESTAMP]", scrubbed)
    scrubbed = SHA256_VALUE_RE.sub("sha256:[HASH]", scrubbed)
    scrubbed = RCH_COMMAND_FIELD_RE.sub("command=[RCH_COMMAND]", scrubbed)
    scrubbed = WORKER_FIELD_RE.sub("worker=[WORKER]", scrubbed)
    scrubbed = ACTIVE_PROJECT_EXCLUSION_RE.sub(
        "active_project_exclusion=[COUNT]",
        scrubbed,
    )
    scrubbed = DURATION_VALUE_RE.sub("[DURATION]", scrubbed)
    scrubbed = TMP_PATH_RE.sub("[TMP]", scrubbed)
    return scrubbed


def minimize_failure_corpus_lines(scrubbed_text: str, markers: List[str]) -> List[str]:
    """Return the stable replay lines that prove the stored failure still matches."""
    lines = [line for line in scrubbed_text.splitlines() if line.strip()]
    matched = [
        line
        for line in lines
        if any(marker and marker in line for marker in markers)
    ]
    if matched:
        return matched
    return lines[:1]


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


def proof_status_dashboard_markdown(dashboard: Dict[str, Any]) -> str:
    """Render a compact deterministic Markdown proof-status dashboard."""
    summary = dashboard["summary"]
    lines = [
        "# Proof Status Dashboard",
        "",
        f"- Schema: `{dashboard['schema_version']}`",
        f"- Generated at: `{dashboard['generated_at']}`",
        f"- Verdict: `{dashboard['verdict']}`",
        (
            "- Summary: "
            f"{summary['claim_count']} claims, "
            f"{summary['lane_count']} lanes, "
            f"{summary['green_claim_count']} green, "
            f"{summary['yellow_claim_count']} yellow, "
            f"{summary['red_claim_count']} red, "
            f"{summary['not_run_lane_count']} not-run lanes"
        ),
        "",
        "## Claim Status",
        "",
        "| Claim | Status | Blocker | Action |",
        "| --- | --- | --- | --- |",
    ]
    for row in dashboard["claim_status_rows"]:
        blocker = row["current_blocker"]
        if blocker:
            blocker_text = "{}:{}".format(blocker.get("file", ""), blocker.get("line", 0))
        else:
            blocker_text = "none"
        lines.append(
            "| `{}` | `{}` | `{}` | {} |".format(
                row["claim_id"],
                row["status"],
                blocker_text,
                row["operator_action"],
            )
        )

    lines.extend(["", "## Failure Reasons", ""])
    if dashboard["failure_reasons"]:
        for reason in dashboard["failure_reasons"]:
            lines.append(f"- `{reason['reason_id']}`: {reason['summary']}")
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def release_proof_pack_markdown(pack: Dict[str, Any]) -> str:
    """Render a compact deterministic Markdown summary for release proof packs."""
    summary = pack["summary"]
    lines = [
        "# Release Proof Pack",
        "",
        f"- Schema: `{pack['schema_version']}`",
        f"- Generated at: `{pack['generated_at']}`",
        f"- Verdict: `{pack['verdict']}`",
        (
            "- Summary: "
            f"{summary['source_artifact_count']} source artifacts, "
            f"{summary['proof_lane_count']} proof lanes, "
            f"{summary['proof_command_count']} proof commands, "
            f"{summary['rch_outcome_count']} rch outcomes"
        ),
        "",
        "## Source Artifacts",
        "",
        "| Artifact | Status | Bytes |",
        "| --- | --- | ---: |",
    ]
    for row in pack["source_artifacts"]:
        lines.append(f"| `{row['path']}` | `{row['status']}` | {row['bytes']} |")

    lines.extend(["", "## Failure Reasons", ""])
    if pack["failure_reasons"]:
        for reason in pack["failure_reasons"]:
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

    if any(any(marker in token for marker in SHELL_CONTROL_TOKENS) for token in argv):
        raise ValueError("proof command contains shell control metacharacters")

    program_index = _first_non_assignment(argv)
    if len(argv) - program_index < 4 or argv[program_index:program_index + 3] != ["rch", "exec", "--"]:
        raise ValueError("proof command must start with 'rch exec --'")
    for assignment in argv[:program_index]:
        name, _value = assignment.split("=", 1)
        if not SAFE_ENV_NAME.fullmatch(name):
            raise ValueError(f"invalid leading environment assignment in proof command: {name}")

    remote_index = program_index + 3
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
    if program_index:
        return ["env", *argv[:program_index], *argv[program_index:]]
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


def has_rch_remote_required_refusal(log_text: str) -> bool:
    """Return true when RCH_REQUIRE_REMOTE refused local fallback before proof."""
    lowered = log_text.lower()
    return (
        "remote required; refusing local fallback" in lowered
        or "remote worker admission refused" in lowered
        or (
            "rch_require_remote=1" in lowered
            and "local fallback refused" in lowered
        )
    )


def has_rch_local_fallback(log_text: str) -> bool:
    """Return true when rch reports a local fallback instead of remote proof."""
    return bool(RCH_LOCAL_FALLBACK_RE.search(log_text))


def empty_blocker(message: str = "", code: str = "") -> Dict[str, Any]:
    """Return a neutral blocker shape for classifier fallbacks."""
    return {
        "file": "",
        "line": 0,
        "column": 0,
        "message": message,
        "code": code,
        "raw": "",
    }


def has_blocker_location(blocker: Dict[str, Any]) -> bool:
    """Return true when a blocker identifies a concrete file/surface."""
    return bool(normalize_repo_path(str(blocker.get("file", ""))))


def first_rustc_json_blocker(log_text: str) -> Dict[str, Any]:
    """Extract the first rustc --message-format=json error diagnostic."""
    for line in log_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if payload.get("reason") != "compiler-message":
            continue
        message = payload.get("message") or {}
        if message.get("level") != "error":
            continue
        spans = [span for span in message.get("spans") or [] if isinstance(span, dict)]
        primary = next((span for span in spans if span.get("is_primary")), None)
        if primary is None and spans:
            primary = spans[0]
        if primary is None:
            continue
        code = message.get("code") or {}
        return {
            "file": str(primary.get("file_name", "")),
            "line": int(primary.get("line_start") or 0),
            "column": int(primary.get("column_start") or 0),
            "message": str(message.get("message", "")),
            "code": str(code.get("code") or ""),
            "raw": stripped,
        }
    return empty_blocker()


def first_rustfmt_blocker(log_text: str) -> Dict[str, Any]:
    """Extract the first rustfmt --check diff location."""
    match = RUSTFMT_DIFF_RE.search(log_text)
    if not match:
        return empty_blocker()
    file = normalize_repo_path(match.group("file"))
    line = int(match.group("line"))
    return {
        "file": file,
        "line": line,
        "column": 0,
        "message": f"rustfmt diff in {file}:{line}",
        "code": "rustfmt_diff",
        "raw": match.group(0).strip(),
    }


def first_cargo_blocker(log_text: str) -> Dict[str, Any]:
    """Extract the first cargo/rustc file:line blocker from captured output."""
    pending_message = ""
    pending_code = ""
    for line in log_text.splitlines():
        short_match = CARGO_SHORT_ERROR_RE.match(line.strip())
        if short_match:
            return {
                "file": short_match.group("file"),
                "line": int(short_match.group("line")),
                "column": int(short_match.group("column")),
                "message": short_match.group("message").strip(),
                "code": short_match.group("code") or "",
                "raw": line.strip(),
            }

        error_match = RUST_ERROR_RE.match(line)
        if error_match:
            pending_message = error_match.group("message").strip()
            pending_code = error_match.group("code") or ""
            continue

        location_match = CARGO_LOCATION_RE.match(line)
        if location_match:
            return {
                "file": location_match.group(1),
                "line": int(location_match.group(2)),
                "column": int(location_match.group(3)),
                "message": pending_message,
                "code": pending_code,
                "raw": line.strip(),
            }

    return empty_blocker(pending_message, pending_code)


def rustc_json_blockers(log_text: str) -> List[Dict[str, Any]]:
    """Extract all rustc --message-format=json error diagnostics."""
    blockers = []
    for line in log_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if payload.get("reason") != "compiler-message":
            continue
        message = payload.get("message") or {}
        if message.get("level") != "error":
            continue
        spans = [span for span in message.get("spans") or [] if isinstance(span, dict)]
        primary = next((span for span in spans if span.get("is_primary")), None)
        if primary is None and spans:
            primary = spans[0]
        if primary is None:
            continue
        code = message.get("code") or {}
        blockers.append({
            "file": str(primary.get("file_name", "")),
            "line": int(primary.get("line_start") or 0),
            "column": int(primary.get("column_start") or 0),
            "message": str(message.get("message", "")),
            "code": str(code.get("code") or ""),
            "raw": stripped,
        })
    return blockers


def rustc_text_blockers(log_text: str) -> List[Dict[str, Any]]:
    """Extract all rustc text diagnostics that include a file location."""
    blockers = []
    pending_message = ""
    pending_code = ""
    for line in log_text.splitlines():
        short_match = CARGO_SHORT_ERROR_RE.match(line.strip())
        if short_match:
            blockers.append({
                "file": short_match.group("file"),
                "line": int(short_match.group("line")),
                "column": int(short_match.group("column")),
                "message": short_match.group("message").strip(),
                "code": short_match.group("code") or "",
                "raw": line.strip(),
            })
            pending_message = ""
            pending_code = ""
            continue

        error_match = RUST_ERROR_RE.match(line)
        if error_match:
            pending_message = error_match.group("message").strip()
            pending_code = error_match.group("code") or ""
            continue

        location_match = CARGO_LOCATION_RE.match(line)
        if location_match:
            blockers.append({
                "file": location_match.group(1),
                "line": int(location_match.group(2)),
                "column": int(location_match.group(3)),
                "message": pending_message,
                "code": pending_code,
                "raw": line.strip(),
            })
            pending_message = ""
            pending_code = ""
    return blockers


def all_rustc_blockers(log_text: str) -> List[Dict[str, Any]]:
    """Return all rustc blockers from JSON or text logs, preserving first-seen order."""
    json_blockers = rustc_json_blockers(log_text)
    if json_blockers:
        return json_blockers
    return rustc_text_blockers(log_text)


def first_output_blocker(log_text: str) -> Dict[str, Any]:
    """Extract the first structured, formatter, or rustc text blocker."""
    for candidate in (
        first_rustc_json_blocker(log_text),
        first_rustfmt_blocker(log_text),
        first_cargo_blocker(log_text),
    ):
        if has_blocker_location(candidate):
            return candidate
    return first_cargo_blocker(log_text)


def clippy_lint_code(log_text: str) -> str:
    """Return a stable clippy lint code when rust-clippy names one."""
    match = CLIPPY_LINT_RE.search(log_text)
    if not match:
        return ""
    lint = match.group("lint").replace("-", "_")
    return f"clippy::{lint}"


def diagnostic_error_class(
    command: str,
    log_text: str,
    blocker: Dict[str, Any],
    outcome_class: str,
) -> str:
    """Classify the diagnostic surface separately from pass/fail ownership."""
    scope = command_scope(command)
    if outcome_class == "pass":
        return "none"
    if has_rch_remote_required_refusal(log_text) or blocker.get("file") == "rch-local-fallback":
        return "rch_admission_refusal"
    if blocker.get("file") == "rch-control-plane":
        return RCH_CONTROL_PLANE_INCONSISTENT_CLASS
    if first_rustfmt_blocker(log_text).get("file") or scope.get("program") == "rustfmt":
        return "rustfmt_diff"
    if TRUNCATED_OUTPUT_RE.search(log_text):
        return "truncated_rustc_output"
    if scope.get("cargo_subcommand") == "clippy" or clippy_lint_code(log_text):
        return "clippy_lint_wall"
    if has_blocker_location(blocker) or blocker.get("message"):
        return "rustc_compile_error"
    return outcome_class


def diagnostic_target(scope: Dict[str, Any], diagnostic_class: str) -> Tuple[str, str]:
    """Return crate_or_surface and target for the frontier first_failure row."""
    if diagnostic_class == "rch_admission_refusal":
        return "rch", "remote-admission"
    if diagnostic_class == "rustfmt_diff":
        return "rustfmt", "format-check"
    surface = scope.get("package") or scope.get("program") or "cargo"
    if scope.get("target"):
        kind = scope.get("target_kind") or "target"
        return surface, f'{kind} "{scope["target"]}"'
    return surface, scope.get("cargo_subcommand") or scope.get("program") or ""


def has_wrapper_retrieval_hang(log_text: str, remote_exit: Optional[int]) -> bool:
    """Classify the common rch wrapper hang after a known remote result."""
    if remote_exit is None:
        return False
    lowered = log_text.lower()
    return any(hint in lowered for hint in WRAPPER_RETRIEVAL_HANG_HINTS)


def default_rch_control_plane() -> Dict[str, Any]:
    """Return the neutral control-plane receipt embedded in every rch outcome."""
    return {
        "classification": "none",
        "worker": "",
        "action": "",
        "action_error": "",
        "listed_healthy": False,
        "probed_healthy": False,
        "recommendation": "",
    }


def detect_rch_control_plane_inconsistency(log_text: str) -> Optional[Dict[str, Any]]:
    """Detect list/probe healthy evidence that disagrees with an action failure."""
    lowered = log_text.lower()
    not_found = RCH_WORKER_NOT_FOUND_RE.search(log_text)
    if not not_found:
        return None

    command_matches = list(RCH_WORKER_ENABLE_RE.finditer(log_text))
    command_match = command_matches[-1] if command_matches else None
    worker = (
        (command_match.group("worker") if command_match else "")
        or (not_found.group("worker") or "")
    )
    if not worker:
        return None

    action = command_match.group("action") if command_match else "control-plane-action"
    listed_healthy = bool(
        re.search(
            rf'"(?:name|worker|host)"\s*:\s*"{re.escape(worker)}"[\s\S]*?'
            r'"(?:status|health)"\s*:\s*"(?:healthy|ready|online|available)"',
            log_text,
            re.IGNORECASE,
        )
    )
    probed_healthy = (
        f"workers probe {worker}".lower() in lowered
        and any(token in lowered for token in ("healthy", "reachable", "available", "online"))
    )
    if not (listed_healthy or probed_healthy):
        return None

    return {
        "classification": RCH_CONTROL_PLANE_INCONSISTENT_CLASS,
        "worker": worker,
        "action": action,
        "action_error": not_found.group(0).strip(),
        "listed_healthy": listed_healthy,
        "probed_healthy": probed_healthy,
        "recommendation": RCH_CONTROL_PLANE_CONTINUE_RECOMMENDATION,
    }


def classify_rch_outcome(
    command: str,
    log_text: str,
    touched_files: List[str],
) -> Dict[str, Any]:
    """Convert an rch output transcript into a structured outcome row."""
    scope = command_scope(command)
    remote_exit = remote_exit_status(log_text)
    blocker = first_output_blocker(log_text)
    touched = {normalize_repo_path(path) for path in touched_files}
    blocker_file = normalize_repo_path(str(blocker["file"]))
    wrapper_hang = has_wrapper_retrieval_hang(log_text, remote_exit)
    control_plane = detect_rch_control_plane_inconsistency(log_text)

    if has_rch_remote_required_refusal(log_text):
        outcome_class = "blocked_external"
        decision = "blocked-external"
        summary = "RCH_REQUIRE_REMOTE=1 remote worker admission refused; local fallback refused"
        blocker = {
            "file": "rch",
            "line": 0,
            "column": 0,
            "message": summary,
            "code": "rch_admission_refusal",
            "raw": summary,
        }
    elif has_rch_local_fallback(log_text):
        outcome_class = "failed_local"
        decision = "failed-local"
        summary = "rch local fallback detected; refusing local cargo execution"
        blocker = {
            "file": "rch-local-fallback",
            "line": 0,
            "column": 0,
            "message": summary,
            "code": "rch_admission_refusal",
            "raw": summary,
        }
    elif control_plane:
        outcome_class = RCH_CONTROL_PLANE_INCONSISTENT_CLASS
        decision = "blocked-external"
        summary = (
            "rch worker control-plane disagrees with list/probe evidence; "
            f"{RCH_CONTROL_PLANE_CONTINUE_RECOMMENDATION}"
        )
        blocker = {
            "file": "rch-control-plane",
            "line": 0,
            "column": 0,
            "message": control_plane["action_error"],
            "code": RCH_CONTROL_PLANE_INCONSISTENT_CLASS,
            "raw": control_plane["action_error"],
        }
    elif wrapper_hang:
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

    diagnostic_class = diagnostic_error_class(command, log_text, blocker, outcome_class)
    if diagnostic_class == "rustfmt_diff":
        summary = blocker.get("message") or summary
    elif diagnostic_class in {
        "clippy_lint_wall",
        "rustc_compile_error",
        "truncated_rustc_output",
    } and blocker.get("message"):
        summary = blocker["message"]

    outcome = {
        "schema_version": RCH_OUTCOME_SCHEMA_VERSION,
        "command": command,
        "command_scope": scope,
        "remote_exit_status": remote_exit,
        "outcome_class": outcome_class,
        "diagnostic_class": diagnostic_class,
        "decision": decision,
        "first_blocker": blocker,
        "touched_files": touched_files,
        "control_plane": control_plane or default_rch_control_plane(),
        "summary": summary,
    }
    outcome["rch_result"] = rch_result_from_outcome(outcome)
    return outcome


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


def infer_proof_lane_id(command: str, fallback: str = "manual") -> str:
    """Best-effort stable lane id for saved transcripts outside manifest preflight."""
    scope = command_scope(command)
    program = scope.get("program", "")
    subcommand = scope.get("cargo_subcommand", "")
    if program == "rustfmt" or "cargo fmt" in command:
        return "rustfmt-check"
    if program == "cargo":
        if subcommand == "clippy":
            return "clippy-all-targets"
        if subcommand == "test":
            if scope.get("target"):
                return "lib-tests"
            return "lib-tests"
        if subcommand == "check":
            if "--all-targets" in command:
                return "all-targets-check"
            return "production-lib-check"
        if subcommand == "doc":
            return "rustdoc-api"
        if subcommand == "tree" and "-i tokio" in command:
            return "default-production-tokio-tree"
    return fallback


def default_dirty_tree_summary() -> Dict[str, Any]:
    """Neutral dirty-tree receipt for fixture-only records."""
    return {
        "tracked_modified": [],
        "deleted": [],
        "untracked": [],
        "staged": [],
        "overlaps_touched_files": False,
        "touched_dirty_files": [],
    }


def default_rch_result() -> Dict[str, Any]:
    """Neutral RCH receipt for non-rch preflight records."""
    return {
        "admission": "not-applicable",
        "worker": None,
        "local_fallback_refused": False,
    }


def rch_result_from_outcome(outcome: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize RCH admission state from a classified transcript."""
    outcome_class = str(outcome.get("outcome_class", ""))
    remote_exit = outcome.get("remote_exit_status")
    control_plane = outcome.get("control_plane") or {}
    if (
        outcome.get("diagnostic_class") == "rch_admission_refusal"
        or outcome.get("first_blocker", {}).get("file") in {"rch", "rch-local-fallback"}
    ):
        admission = "local-fallback-refused"
        local_fallback_refused = True
    elif outcome_class == RCH_CONTROL_PLANE_INCONSISTENT_CLASS:
        admission = "remote-refused"
        local_fallback_refused = False
    elif remote_exit is not None:
        admission = "remote-executed"
        local_fallback_refused = False
    else:
        admission = "not-applicable"
        local_fallback_refused = False

    worker = str(control_plane.get("worker") or "")
    return {
        "admission": admission,
        "worker": worker or None,
        "local_fallback_refused": local_fallback_refused,
    }


def exit_status_from_decision(decision: str, remote_exit_status: Optional[int]) -> int:
    """Use the remote exit when known; otherwise provide deterministic status."""
    if remote_exit_status is not None:
        return int(remote_exit_status)
    return 0 if decision == "pass" else 1


def blocker_object(file: str, line: int, error_class: str, summary: str) -> Dict[str, Any]:
    """Normalize a first-blocker object for validation frontier records."""
    return {
        "file": normalize_repo_path(file),
        "line": int(line or 0),
        "error_class": error_class,
        "summary": summary,
    }


def affected_files_from_blocker(file: str) -> List[str]:
    """Return source paths implicated by a blocker, excluding coordination sentinels."""
    normalized = normalize_repo_path(file)
    if not normalized:
        return []
    if normalized.startswith(("rch-", "build-slot:")):
        return []
    return [normalized]


def bead_id_from_text(text: str) -> Optional[str]:
    """Extract the first asupersync bead id from commit subjects or closeout text."""
    match = ASUPERSYNC_BEAD_RE.search(text or "")
    if not match:
        return None
    return match.group("bead").lower()


def default_blocker_origin(path: str = "") -> Dict[str, Any]:
    """Return the stable empty shape for blocker origin metadata."""
    return {
        "source": "unmapped",
        "path": normalize_repo_path(path),
        "commit": "",
        "commit_full": "",
        "subject": "",
        "author": "",
        "author_email": "",
        "bead_id": None,
        "bead_commit": "",
        "bead_subject": "",
        "bead_author": "",
    }


def blocker_origin_from_git_log_line(path: str, line: str) -> Dict[str, Any]:
    """Parse one git-log row into deterministic blocker provenance metadata."""
    parts = (line or "").rstrip("\n").split("\x1f", 3)
    if len(parts) != 4 or not parts[0].strip():
        return default_blocker_origin(path)
    commit_full, author, author_email, subject = (part.strip() for part in parts)
    return {
        "source": "git-log",
        "path": normalize_repo_path(path),
        "commit": commit_full[:12],
        "commit_full": commit_full,
        "subject": subject,
        "author": author,
        "author_email": author_email,
        "bead_id": bead_id_from_text(subject),
        "bead_commit": commit_full[:12] if bead_id_from_text(subject) else "",
        "bead_subject": subject if bead_id_from_text(subject) else "",
        "bead_author": author if bead_id_from_text(subject) else "",
    }


def blocker_origin_from_git_log_lines(path: str, lines: List[str]) -> Dict[str, Any]:
    """Parse recent git-log rows, preserving latest commit and first bead-bearing subject."""
    parsed = [
        blocker_origin_from_git_log_line(path, line)
        for line in lines
        if (line or "").strip()
    ]
    if not parsed:
        return default_blocker_origin(path)
    origin = parsed[0]
    if origin.get("bead_id"):
        return origin
    for candidate in parsed[1:]:
        if candidate.get("bead_id"):
            origin["bead_id"] = candidate["bead_id"]
            origin["bead_commit"] = candidate["commit"]
            origin["bead_subject"] = candidate["subject"]
            origin["bead_author"] = candidate["author"]
            break
    return origin


def error_buckets_from_blocker(
    error_class: str,
    file: str,
    line: int,
    summary: str,
    owner: str,
    likely_bead: Optional[str],
    touched_files: List[str],
    error_code: str = "",
    blocker_origin: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build the stable one-bucket summary used by ASW-1 ledger records."""
    normalized = normalize_repo_path(file)
    if not normalized:
        return []
    touched = {normalize_repo_path(path) for path in touched_files}
    module = normalized.removesuffix(".rs").replace("/", "::")
    origin = blocker_origin or default_blocker_origin(normalized)
    return [
        {
            "file": normalized,
            "module": module,
            "error_code": error_code or error_class,
            "count": 1,
            "first_line": int(line or 0),
            "summary": summary,
            "likely_owner": owner,
            "likely_bead": likely_bead,
            "blocker_origin": origin,
            "owned_slice_overlap": normalized in touched,
        }
    ]


def closeout_summary_from_frontier(
    outcome: Dict[str, Any],
    frontier: Dict[str, Any],
) -> Dict[str, Any]:
    """Build deterministic Beads/Agent Mail closeout text from a classified run."""
    green_proof_claimed = bool(frontier.get("green_proof_claimed"))
    first_blocker = frontier.get("first_blocker") or {}
    blocker_file = normalize_repo_path(str(first_blocker.get("file") or ""))
    blocker_line = int(first_blocker.get("line") or 0)
    if blocker_file:
        blocker_ref = f"{blocker_file}:{blocker_line}" if blocker_line else blocker_file
    else:
        blocker_ref = "none"

    proof_claim = "green-proof" if green_proof_claimed else "no-green-proof"
    bead_id = frontier.get("likely_bead") or None
    blocker_origin = frontier.get("blocker_origin") or default_blocker_origin(blocker_file)
    likely_owner = str(frontier.get("likely_owner") or "")
    decision = str(frontier.get("decision") or "")
    error_class = str(frontier.get("error_class") or "")
    proof_lane_id = str(frontier.get("proof_lane_id") or "")
    command = str(frontier.get("command") or outcome.get("command") or "")
    rch_result = frontier.get("rch_result") or {}
    rch_admission = str(rch_result.get("admission") or "not-applicable")
    remote_exit_status = outcome.get("remote_exit_status")
    summary = str(frontier.get("summary") or outcome.get("summary") or "")
    prefix = "PASS" if green_proof_claimed else "NO_GREEN_PROOF"

    beads_comment = (
        f"{prefix} bead={bead_id or 'unmapped'} lane={proof_lane_id} "
        f"decision={decision} error_class={error_class} "
        f"first_blocker={blocker_ref} rch_admission={rch_admission} "
        f"origin_commit={blocker_origin.get('commit') or 'unmapped'} "
        f"remote_exit={remote_exit_status if remote_exit_status is not None else 'unknown'} "
        f"green_proof_claimed={str(green_proof_claimed).lower()}"
    )
    agent_mail_body = (
        f"{beads_comment}\n"
        f"Summary: {summary}\n"
        f"Command: {command}"
    )

    return {
        "schema_version": "proof-runner-closeout-summary-v1",
        "bead_id": bead_id,
        "likely_owner": likely_owner,
        "proof_lane_id": proof_lane_id,
        "decision": decision,
        "error_class": error_class,
        "proof_claim": proof_claim,
        "green_proof_claimed": green_proof_claimed,
        "source_log_path": outcome.get("source_log_path"),
        "source_log_sha256": outcome.get("source_log_sha256"),
        "remote_exit_status": remote_exit_status,
        "rch_admission": rch_admission,
        "worker": rch_result.get("worker"),
        "blocker_origin": blocker_origin,
        "first_blocker": frontier.get("first_blocker"),
        "affected_files": frontier.get("affected_files") or [],
        "beads_comment": beads_comment,
        "agent_mail_body": agent_mail_body,
    }


class ValidationFrontierRecord:
    """Builder for validation frontier ledger records."""

    def __init__(
        self,
        command: str,
        touched_files: List[str],
        proof_lane_id: str = "manual",
        commit: str = "unknown",
        dirty_tree_summary: Optional[Dict[str, Any]] = None,
        rch_result: Optional[Dict[str, Any]] = None,
        exit_status: Optional[int] = None,
        likely_bead: Optional[str] = None,
        likely_owner: str = "",
        blocker_origin: Optional[Dict[str, Any]] = None,
    ):
        self.command = command
        self.proof_lane_id = proof_lane_id
        self.commit = commit
        self.timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.touched_files = [normalize_repo_path(path) for path in touched_files]
        self.dirty_tree_summary = dirty_tree_summary or default_dirty_tree_summary()
        self.rch_result = rch_result or default_rch_result()
        self.exit_status = exit_status
        self.decision = "pass"
        self.error_class = ""
        self.first_failure = {
            "crate_or_surface": "",
            "target": "",
            "file": "",
            "line": 0
        }
        self.likely_owner = likely_owner
        self.likely_bead = likely_bead
        self.blocker_origin = blocker_origin or default_blocker_origin()
        self.supplemental_proof_command = ""
        self.summary = ""

    def _likely_owner(self, default: str) -> str:
        """Return an explicit owner hint when supplied, otherwise the classifier default."""
        return self.likely_owner or default

    def _base(
        self,
        decision: str,
        error_class: str,
        first_failure: Dict[str, Any],
        first_blocker: Optional[Dict[str, Any]],
        likely_owner: str,
        supplemental: str,
        summary: str,
        error_buckets: Optional[List[Dict[str, Any]]] = None,
        affected_files: Optional[List[str]] = None,
        exit_status: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Render the shared ASW-1 validation frontier record shape."""
        status = self.exit_status if self.exit_status is not None else exit_status
        return {
            "command": self.command,
            "proof_lane_id": self.proof_lane_id,
            "commit": self.commit,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "dirty_tree_summary": self.dirty_tree_summary,
            "rch_result": self.rch_result,
            "exit_status": exit_status_from_decision(decision, status),
            "decision": decision,
            "error_class": error_class,
            "first_blocker": first_blocker,
            "first_failure": first_failure,
            "error_buckets": error_buckets or [],
            "affected_files": affected_files or [],
            "likely_owner": likely_owner,
            "likely_bead": self.likely_bead,
            "blocker_origin": self.blocker_origin,
            "external_to_narrow_fuzz_target_work": decision == "blocked-external",
            "green_proof_claimed": decision == "pass",
            "supplemental_proof_command": supplemental,
            "summary": summary,
        }

    def as_blocked_external(
        self,
        error_class: str,
        file: str,
        summary: str,
        owner: str = "shared-main external blocker",
        supplemental: str = "",
        line: int = 0,
        target: str = "preflight",
        crate_or_surface: str = "coordination",
        exit_status: Optional[int] = None,
        blocker_message: str = "",
        error_code: str = "",
    ) -> Dict[str, Any]:
        """Mark as externally blocked."""
        normalized_file = normalize_repo_path(file)
        blocker_summary = blocker_message or summary
        owner = self._likely_owner(owner)
        first_blocker = blocker_object(normalized_file, line, error_class, blocker_summary)
        return self._base(
            "blocked-external",
            error_class,
            {
                "crate_or_surface": crate_or_surface,
                "target": target,
                "file": normalized_file,
                "line": line,
            },
            first_blocker,
            owner,
            supplemental,
            summary,
            error_buckets_from_blocker(
                error_class,
                normalized_file,
                line,
                blocker_summary,
                owner,
                self.likely_bead,
                self.touched_files,
                error_code=error_code,
                blocker_origin=self.blocker_origin,
            ),
            affected_files_from_blocker(normalized_file),
            exit_status=exit_status,
        )

    def as_pass(self, supplemental: str = "") -> Dict[str, Any]:
        """Mark as passed."""
        owner = self._likely_owner("local_change")
        return self._base(
            "pass",
            "none",
            {
                "crate_or_surface": "",
                "target": "",
                "file": "",
                "line": 0,
            },
            None,
            owner,
            supplemental,
            "preflight checks passed",
            exit_status=0,
        )

    def as_failed_local(
        self,
        error_class: str,
        file: str,
        summary: str,
        line: int = 0,
        target: str = "",
        crate_or_surface: str = "cargo",
        exit_status: Optional[int] = None,
        blocker_message: str = "",
        error_code: str = "",
    ) -> Dict[str, Any]:
        """Mark as a local proof failure."""
        normalized_file = normalize_repo_path(file)
        blocker_summary = blocker_message or summary
        first_blocker = blocker_object(normalized_file, line, error_class, blocker_summary)
        owner = self._likely_owner("local_change")
        return self._base(
            "failed-local",
            error_class,
            {
                "crate_or_surface": crate_or_surface,
                "target": target,
                "file": normalized_file,
                "line": line,
            },
            first_blocker,
            owner,
            "",
            summary,
            error_buckets_from_blocker(
                error_class,
                normalized_file,
                line,
                blocker_summary,
                owner,
                self.likely_bead,
                self.touched_files,
                error_code=error_code,
                blocker_origin=self.blocker_origin,
            ),
            affected_files_from_blocker(normalized_file),
            exit_status=exit_status,
        )


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
                self._status_lines = [
                    line for line in result.stdout.splitlines() if line.strip()
                ]
            except subprocess.CalledProcessError:
                self._status_lines = []
        return self._status_lines

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        return len(self._get_status()) > 0

    def _status_paths(self, line: str) -> List[str]:
        """Return dirty path endpoints for one git status --short row."""
        if len(line) < 3:
            return []
        status = line[:2]
        path = line[3:]
        if ("R" in status or "C" in status) and " -> " in path:
            paths = []
            for part in path.split(" -> ", 1):
                normalized = normalize_repo_path(part.strip())
                if normalized and normalized not in paths:
                    paths.append(normalized)
            return paths
        normalized = normalize_repo_path(path)
        return [normalized] if normalized else []

    def get_uncommitted_files(self) -> List[str]:
        """Get list of uncommitted files."""
        files = []
        for line in self._get_status():
            files.extend(self._status_paths(line))
        return files

    def get_staged_files(self) -> List[str]:
        """Get list of staged files."""
        staged = []
        for line in self._get_status():
            if len(line) >= 3 and line[0] != ' ' and line[0] != '?':
                staged.extend(self._status_paths(line))
        return staged

    def head_commit(self) -> str:
        """Return the current commit for validation frontier receipts."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short=12", "HEAD"],
                capture_output=True,
                text=True,
                cwd=self.repo_root,
                check=True,
            )
        except subprocess.CalledProcessError:
            return "unknown"
        return result.stdout.strip() or "unknown"

    def recent_commit_hint_for_path(self, path: str) -> Dict[str, Any]:
        """Return the most recent commit metadata for a blocker path when available."""
        normalized = normalize_repo_path(path)
        if not normalized or normalized.startswith(("rch-", "build-slot:")):
            return default_blocker_origin(normalized)
        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "-20",
                    "--format=%H%x1f%an%x1f%ae%x1f%s",
                    "--",
                    normalized,
                ],
                capture_output=True,
                text=True,
                cwd=self.repo_root,
                check=True,
            )
        except subprocess.CalledProcessError:
            return default_blocker_origin(normalized)
        return blocker_origin_from_git_log_lines(normalized, result.stdout.splitlines())

    def dirty_tree_summary(self, touched_files: List[str]) -> Dict[str, Any]:
        """Summarize dirty shared-main state without mutating the index."""
        tracked_modified = []
        deleted = []
        untracked = []
        staged = []

        for line in self._get_status():
            if len(line) < 3:
                continue
            status = line[:2]
            paths = self._status_paths(line)
            if not paths:
                continue
            if status == "??":
                untracked.extend(paths)
                continue
            if "D" in status:
                deleted.extend(paths)
            if status[0] != " " and status[0] != "?":
                staged.extend(paths)
            if status.strip("D "):
                tracked_modified.extend(paths)

        touched = {normalize_repo_path(path) for path in touched_files}
        all_dirty = set(tracked_modified) | set(deleted) | set(untracked) | set(staged)
        touched_dirty = sorted(path for path in all_dirty if path in touched)
        return {
            "tracked_modified": sorted(set(tracked_modified)),
            "deleted": sorted(set(deleted)),
            "untracked": sorted(set(untracked)),
            "staged": sorted(set(staged)),
            "overlaps_touched_files": bool(touched_dirty),
            "touched_dirty_files": touched_dirty,
        }


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

    def snapshot_status(self) -> Dict[str, Any]:
        """Return top-level reservation snapshot configuration metadata."""
        if self.reservation_snapshot:
            return {"source": "snapshot", "enabled": True}
        return {"source": self.last_check["source"], "enabled": False}

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
        normalized_pattern = self._normalize_reservation_path(pattern)
        for file_path in file_paths:
            normalized_file = self._normalize_reservation_path(file_path)
            if self._paths_overlap(normalized_pattern, normalized_file):
                return normalized_file
        return None

    def _normalize_reservation_path(self, path: str) -> str:
        return normalize_repo_path(path)

    def _paths_overlap(self, pattern: str, file_path: str) -> bool:
        if not pattern or not file_path:
            return False
        if (
            file_path == pattern
            or fnmatch.fnmatchcase(file_path, pattern)
            or fnmatch.fnmatchcase(pattern, file_path)
        ):
            return True
        pattern_is_glob = self._has_glob_magic(pattern)
        file_is_glob = self._has_glob_magic(file_path)
        return (
            not pattern_is_glob and file_path.startswith(f"{pattern}/")
        ) or (
            not file_is_glob and pattern.startswith(f"{file_path}/")
        )

    def _has_glob_magic(self, path: str) -> bool:
        return any(char in path for char in "*?[")

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
        return path in {".beads", ".beads/issues.jsonl", ".beads/beads.db"} or path.startswith(".beads/")

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
        skip_build_slot_check: bool = False,
        disk_preflight_snapshot: Optional[str] = None,
        disk_min_free_bytes: int = DEFAULT_DISK_MIN_FREE_BYTES,
        disk_dev_shm_min_free_bytes: int = DEFAULT_DEV_SHM_MIN_FREE_BYTES,
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
        self.disk_preflight_snapshot = disk_preflight_snapshot
        self.disk_min_free_bytes = max(int(disk_min_free_bytes), 0)
        self.disk_dev_shm_min_free_bytes = max(int(disk_dev_shm_min_free_bytes), 0)

    def _frontier_record(
        self,
        command: str,
        touched_files: List[str],
        proof_lane_id: str,
        rch_result: Optional[Dict[str, Any]] = None,
        exit_status: Optional[int] = None,
        likely_bead: Optional[str] = None,
        likely_owner: str = "",
        blocker_origin: Optional[Dict[str, Any]] = None,
    ) -> ValidationFrontierRecord:
        """Build a frontier record with live shared-main context attached."""
        normalized_touched = [normalize_repo_path(path) for path in touched_files]
        return ValidationFrontierRecord(
            command,
            normalized_touched,
            proof_lane_id=proof_lane_id,
            commit=self.git.head_commit(),
            dirty_tree_summary=self.git.dirty_tree_summary(normalized_touched),
            rch_result=rch_result,
            exit_status=exit_status,
            likely_bead=likely_bead,
            likely_owner=likely_owner,
            blocker_origin=blocker_origin,
        )

    def _path_for_read(self, path: str) -> Path:
        source = Path(path)
        if source.is_absolute():
            return source
        return self.repo_root / source

    def _display_path(self, path: str) -> str:
        source = self._path_for_read(path)
        try:
            return source.relative_to(self.repo_root).as_posix()
        except ValueError:
            return source.as_posix()

    def _json_file(self, path: str) -> Dict[str, Any]:
        with self._path_for_read(path).open(encoding="utf-8") as handle:
            return json.load(handle)

    def _file_hash(self, path: str) -> str:
        return file_hash(self._path_for_read(path))

    def _repo_json(self, relative_path: str) -> Dict[str, Any]:
        return self._json_file(relative_path)

    def _repo_hash(self, relative_path: str) -> str:
        return self._file_hash(relative_path)

    def _repo_artifact_row(self, relative_path: str) -> Dict[str, Any]:
        path = self.repo_root / relative_path
        if not path.exists():
            return {
                "path": relative_path,
                "copy_path": f"source_artifacts/{relative_path}",
                "status": "missing",
                "sha256": "",
                "bytes": 0,
            }
        return {
            "path": relative_path,
            "copy_path": f"source_artifacts/{relative_path}",
            "status": "included",
            "sha256": self._repo_hash(relative_path),
            "bytes": path.stat().st_size,
        }

    def _tracker_summary(self) -> Dict[str, Any]:
        tracker_path = ".beads/issues.jsonl"
        row = self._repo_artifact_row(tracker_path)
        counts: Dict[str, int] = {status: 0 for status in TRACKER_STATUS_BUCKETS}
        valid_issue_count = 0
        if row["status"] == "included":
            with (self.repo_root / tracker_path).open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    status = str(payload.get("status", "unknown"))
                    if status not in counts:
                        status = "unknown"
                    counts[status] += 1
                    valid_issue_count += 1
        return {
            "path": tracker_path,
            "status": row["status"],
            "sha256": row["sha256"],
            "valid_issue_count": valid_issue_count,
            "status_counts": dict(sorted(counts.items())),
            "raw_issue_rows_embedded": False,
        }

    def _conformance_registry_summary(self) -> Dict[str, Any]:
        contract = self._repo_json("artifacts/conformance_registry_contract_v1.json")
        surfaces = [
            row for row in contract.get("reference_surfaces", []) if isinstance(row, dict)
        ]
        unwired_surfaces = [
            row for row in surfaces if row.get("reference_status") != "live_reference_wired"
        ]
        return {
            "contract_version": contract.get("contract_version", ""),
            "active_module_count": contract.get("active_module_count", 0),
            "dormant_module_count": contract.get("dormant_module_count", 0),
            "reference_surface_count": len(surfaces),
            "unwired_reference_surface_count": len(unwired_surfaces),
            "unwired_fail_closed_count": sum(
                1
                for row in unwired_surfaces
                if row.get("fail_closed_without_live_reference") is True
            ),
        }

    def _adapter_matrix_summary(self) -> Dict[str, Any]:
        matrix = self._repo_json("artifacts/adapter_certification_matrix_v1.json")
        adapters = [row for row in matrix.get("adapters", []) if isinstance(row, dict)]
        categories = sorted(
            {
                str(row.get("category", ""))
                for row in adapters
                if isinstance(row.get("category"), str) and row.get("category")
            }
        )
        return {
            "contract_version": matrix.get("contract_version", ""),
            "adapter_count": len(adapters),
            "category_count": len(categories),
            "categories": categories,
            "fail_closed_adapter_count": sum(
                1
                for row in adapters
                if row.get("fail_closed_without_full_reference") is True
            ),
            "proof_command_count": sum(
                len(row.get("proof_commands", []))
                for row in adapters
                if isinstance(row.get("proof_commands"), list)
            ),
        }

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

    def _rch_outcome_provenance_failures(
        self,
        rch_outcomes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        failures = []
        for index, outcome in enumerate(rch_outcomes):
            source_log_path = outcome.get("source_log_path")
            source_log_sha256 = outcome.get("source_log_sha256")
            source_log_bytes = outcome.get("source_log_bytes")
            missing_fields = [
                field
                for field, value in (
                    ("source_log_path", source_log_path),
                    ("source_log_sha256", source_log_sha256),
                    ("source_log_bytes", source_log_bytes),
                )
                if value in ("", None)
            ]
            if isinstance(source_log_bytes, bool) or not isinstance(source_log_bytes, int):
                if "source_log_bytes" not in missing_fields:
                    missing_fields.append("source_log_bytes")
            if missing_fields:
                failures.append(
                    {
                        "reason_id": "missing-rch-log-provenance",
                        "summary": "rch outcome lacks source log path, hash, or byte count",
                        "outcome_index": index,
                        "command": outcome.get("command", ""),
                        "missing_fields": missing_fields,
                    }
                )
                continue

            source_path = Path(str(source_log_path))
            if not source_path.is_absolute():
                source_path = self.repo_root / source_path
            if not source_path.exists():
                failures.append(
                    {
                        "reason_id": "missing-rch-log",
                        "summary": "rch outcome references a source log that is not present",
                        "outcome_index": index,
                        "command": outcome.get("command", ""),
                        "source_log_path": str(source_log_path),
                    }
                )
                continue

            actual_sha256 = file_hash(source_path)
            actual_bytes = source_path.stat().st_size
            if actual_sha256 != source_log_sha256 or actual_bytes != source_log_bytes:
                failures.append(
                    {
                        "reason_id": "stale-rch-log",
                        "summary": "rch outcome source log hash or byte count changed",
                        "outcome_index": index,
                        "command": outcome.get("command", ""),
                        "source_log_path": str(source_log_path),
                        "expected_sha256": source_log_sha256,
                        "actual_sha256": actual_sha256,
                        "expected_bytes": source_log_bytes,
                        "actual_bytes": actual_bytes,
                    }
                )
        return failures

    def _rch_log_rows(self, rch_outcomes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return deterministic copy rows for source rch logs bundled in a pack."""
        rows = []
        for index, outcome in enumerate(rch_outcomes):
            source_log_path = str(outcome.get("source_log_path", ""))
            source_log_sha256 = str(outcome.get("source_log_sha256", ""))
            source_log_bytes = int(outcome.get("source_log_bytes") or 0)
            if not source_log_path or not source_log_sha256 or source_log_bytes <= 0:
                continue
            command = str(outcome.get("command", ""))
            digest = hashlib.sha256(
                f"{index}\0{command}\0{source_log_sha256}".encode("utf-8")
            ).hexdigest()[:16]
            rows.append(
                {
                    "path": f"rch_logs/{index:02d}-{digest}.log",
                    "source_log_path": source_log_path,
                    "command": command,
                    "outcome_class": outcome.get("outcome_class", ""),
                    "decision": outcome.get("decision", ""),
                    "sha256": source_log_sha256,
                    "bytes": source_log_bytes,
                }
            )
        return rows

    def proof_console_report(
        self,
        generated_at: str = "",
        rch_outcome_paths: Optional[List[str]] = None,
        proof_status_snapshot_path: str = PROOF_STATUS_SNAPSHOT_PATH,
    ) -> Dict[str, Any]:
        """Generate the deterministic operator proof-console report."""
        snapshot = self._json_file(proof_status_snapshot_path)
        snapshot_display_path = self._display_path(proof_status_snapshot_path)
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
            current_blocker: Dict[str, Any] = {}
            blocker_status = "not_applicable"
            if claim.get("status") == "red_blocked_external":
                blocker_status = "stale"
            if claim.get("status") == "red_blocked_external" and isinstance(
                blocked_frontier, dict
            ):
                first_failure = blocked_frontier.get("first_failure", {})
                if not isinstance(first_failure, dict):
                    first_failure = {}
                current_blocker = {
                    "file": str(first_failure.get("file", "")),
                    "line": _int_or_zero(first_failure.get("line")),
                    "column": _int_or_zero(first_failure.get("column")),
                    "code": str(first_failure.get("code", "")),
                    "message": str(first_failure.get("message", "")),
                    "command": str(blocked_frontier.get("command", "")),
                    "proof_lane_id": str(blocked_frontier.get("proof_lane_id", "")),
                    "generated_at": str(blocked_frontier.get("generated_at", "")),
                }
                if (
                    current_blocker["generated_at"] < generated_at
                    or not current_blocker["file"]
                    or current_blocker["line"] == 0
                ):
                    stale_blocker_count += 1
                else:
                    blocker_status = "fresh"
            elif claim.get("status") == "red_blocked_external":
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
                    "current_blocker": current_blocker,
                    "blocker_status": blocker_status,
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
                snapshot_display_path: self._file_hash(proof_status_snapshot_path),
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

    def proof_status_dashboard(
        self,
        generated_at: str = "",
        rch_outcome_paths: Optional[List[str]] = None,
        proof_status_snapshot_path: str = PROOF_STATUS_SNAPSHOT_PATH,
    ) -> Dict[str, Any]:
        """Generate the concise manifest-backed proof-claim status dashboard."""
        report = self.proof_console_report(
            generated_at=generated_at,
            rch_outcome_paths=rch_outcome_paths,
            proof_status_snapshot_path=proof_status_snapshot_path,
        )
        failure_ids_by_claim: Dict[str, List[str]] = {}
        for reason in report["failure_reasons"]:
            claim_id = str(reason.get("claim_id", ""))
            if claim_id:
                failure_ids_by_claim.setdefault(claim_id, []).append(
                    str(reason.get("reason_id", ""))
                )

        claim_status_rows = []
        for row in report["claim_rows"]:
            claim_id = str(row["claim_id"])
            status = str(row["status"])
            failure_reason_ids = failure_ids_by_claim.get(claim_id, [])
            if row["broad_claim"]:
                operator_action = (
                    "repair proof_status_snapshot_v1.json or proof_lane_manifest_v1.json "
                    "before citing this claim"
                )
            elif status == "red_blocked_external" and row["blocker_status"] != "fresh":
                operator_action = (
                    "rerun or classify the exact rch lane and refresh blocked_frontier "
                    "with file and line evidence"
                )
            elif status == "red_blocked_external":
                operator_action = "cite only the recorded first blocker until the lane is fixed"
            elif status == "green":
                operator_action = "run the exact manifest lane before citing fresh proof"
            elif status.startswith("yellow_"):
                operator_action = "cite only the scoped frontier guarantee named by the manifest"
            else:
                operator_action = "classify this claim status before citing it"

            claim_status_rows.append(
                {
                    "claim_id": claim_id,
                    "category": row["category"],
                    "status": status,
                    "manifest_lane_ids": row["manifest_lane_ids"],
                    "manifest_guarantee_ids": row["manifest_guarantee_ids"],
                    "proof_commands": row["proof_commands"],
                    "current_blocker": row["current_blocker"],
                    "blocker_status": row["blocker_status"],
                    "broad_claim": row["broad_claim"],
                    "failure_reason_ids": failure_reason_ids,
                    "operator_action": operator_action,
                }
            )

        lane_status_rows = [
            {
                "lane_id": row["lane_id"],
                "kind": row["kind"],
                "status": row["status"],
                "command": row["command"],
                "guarantee_ids": row["guarantee_ids"],
                "expected_signal": row["expected_signal"],
                "explicit_not_covered": row["explicit_not_covered"],
            }
            for row in report["lane_rows"]
        ]

        summary = dict(report["summary"])
        summary.update(
            {
                "blocked_claim_count": summary["red_claim_count"],
                "not_run_lane_count": sum(
                    1 for row in lane_status_rows if row["status"] == "not_run"
                ),
                "fail_closed_reason_count": len(report["failure_reasons"]),
            }
        )

        return {
            "schema_version": PROOF_STATUS_DASHBOARD_SCHEMA_VERSION,
            "generated_at": report["generated_at"],
            "generator": {
                "name": "scripts/proof_runner.py",
                "mode": "proof-status-dashboard",
            },
            "source_report_schema_version": report["schema_version"],
            "source_artifact_hashes": report["source_artifact_hashes"],
            "summary": summary,
            "claim_status_rows": claim_status_rows,
            "lane_status_rows": lane_status_rows,
            "rch_outcomes": report["rch_outcomes"],
            "failure_reasons": report["failure_reasons"],
            "verdict": report["verdict"],
        }

    def failure_corpus_replay(
        self,
        case_id: str = "",
        manifest_path: str = FAILURE_CORPUS_MANIFEST_PATH,
    ) -> Dict[str, Any]:
        """Replay one stored deterministic failure corpus entry without external services."""
        manifest = self._json_file(manifest_path)
        cases = [
            case for case in manifest.get("cases", []) if isinstance(case, dict)
        ]
        if not cases:
            raise ValueError("failure corpus manifest must contain at least one case")
        selected = None
        for case in cases:
            if not case_id or case.get("case_id") == case_id:
                selected = case
                break
        if selected is None:
            raise ValueError(f"failure corpus case not found: {case_id}")

        scrubbed_text = scrub_failure_corpus_text(
            str(selected.get("raw_event_log", "")),
            self.repo_root,
        )
        expected_scrubbed = str(selected.get("expected_scrubbed_log", ""))
        expected_markers = [
            marker
            for marker in selected.get("expected_markers", [])
            if isinstance(marker, str)
        ]
        minimized_lines = minimize_failure_corpus_lines(scrubbed_text, expected_markers)
        missing_markers = [
            marker for marker in expected_markers if marker not in scrubbed_text
        ]
        failure_reasons = []
        if scrubbed_text != expected_scrubbed:
            failure_reasons.append(
                {
                    "reason_id": "scrubbed-log-mismatch",
                    "summary": "scrubbed failure log differs from the stored golden text",
                }
            )
        if missing_markers:
            failure_reasons.append(
                {
                    "reason_id": "missing-replay-marker",
                    "summary": "stored failure log no longer contains required replay markers",
                    "missing_markers": missing_markers,
                }
            )
        if selected.get("external_services_required") is not False:
            failure_reasons.append(
                {
                    "reason_id": "external-service-required",
                    "summary": "failure corpus replay cases must be deterministic local fixtures",
                }
            )

        return {
            "schema_version": FAILURE_CORPUS_REPLAY_SCHEMA_VERSION,
            "manifest_contract_version": manifest.get("contract_version", ""),
            "case_id": selected.get("case_id", ""),
            "title": selected.get("title", ""),
            "failure_kind": selected.get("failure_kind", ""),
            "external_services_required": selected.get(
                "external_services_required",
                None,
            ),
            "first_failure": selected.get("first_failure", {}),
            "replay_command": selected.get("replay", {}).get("command", ""),
            "scrubbed_log": scrubbed_text,
            "scrubbed_log_sha256": payload_hash({"scrubbed_log": scrubbed_text}),
            "minimized_replay_lines": minimized_lines,
            "stage_log_count": len(
                [
                    stage
                    for stage in selected.get("stage_logs", [])
                    if isinstance(stage, dict)
                ]
            ),
            "failure_reasons": failure_reasons,
            "verdict": "fail_closed" if failure_reasons else "pass",
        }

    def failure_corpus_scrub_file(self, input_path: str) -> Dict[str, Any]:
        """Scrub one raw failure transcript and return its minimized marker lines."""
        raw_text = self._path_for_read(input_path).read_text(encoding="utf-8")
        scrubbed_text = scrub_failure_corpus_text(raw_text, self.repo_root)
        markers = [
            "remote required",
            "refusing local fallback",
            "active_project_exclusion=[COUNT]",
            "error:",
            "failed-local",
            "blocked-external",
        ]
        return {
            "schema_version": "failure-corpus-scrub-result-v1",
            "input_path": self._display_path(input_path),
            "scrubbed_text": scrubbed_text,
            "minimized_replay_lines": minimize_failure_corpus_lines(
                scrubbed_text,
                markers,
            ),
            "verdict": "pass",
        }

    def release_proof_pack(
        self,
        generated_at: str = "",
        rch_outcome_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate a deterministic release proof-pack index."""
        proof_console = self.proof_console_report(
            generated_at=generated_at,
            rch_outcome_paths=rch_outcome_paths,
        )
        if not generated_at:
            generated_at = proof_console["generated_at"]

        source_artifacts = [
            self._repo_artifact_row(path) for path in RELEASE_PROOF_PACK_SOURCE_ARTIFACTS
        ]
        manifest = self.manifest.data
        lanes = sorted(manifest.get("lanes", []), key=lambda row: row.get("lane_id", ""))
        proof_commands = [
            {
                "lane_id": lane.get("lane_id", ""),
                "command": lane.get("command", ""),
                "guarantee_ids": lane.get("guarantee_ids", []),
                "expected_signal": lane.get("expected_signal", ""),
            }
            for lane in lanes
        ]
        missing_artifacts = [
            row["path"] for row in source_artifacts if row["status"] != "included"
        ]
        failure_reasons = []
        if missing_artifacts:
            failure_reasons.append(
                {
                    "reason_id": "missing-source-artifact",
                    "summary": "one or more required source artifacts are missing",
                    "paths": missing_artifacts,
                }
            )
        if proof_console["verdict"] != "pass":
            failure_reasons.append(
                {
                    "reason_id": "proof-console-not-pass",
                    "summary": "embedded proof console report is not passing",
                    "verdict": proof_console["verdict"],
                }
            )
        rch_outcome_provenance_failures = self._rch_outcome_provenance_failures(
            proof_console["rch_outcomes"]
        )
        failure_reasons.extend(rch_outcome_provenance_failures)
        rch_log_rows = self._rch_log_rows(proof_console["rch_outcomes"])

        embedded_reports = {
            "proof_console_report_v1": proof_console,
        }
        embedded_report_rows = [
            {
                "path": "reports/proof_console_report_v1.json",
                "schema_version": proof_console["schema_version"],
                "sha256": payload_hash(proof_console),
                "bytes": len(canonical_json_bytes(proof_console)),
            }
        ]

        return {
            "schema_version": RELEASE_PROOF_PACK_SCHEMA_VERSION,
            "generated_at": generated_at,
            "generator": {
                "name": "scripts/proof_runner.py",
                "mode": "release-proof-pack",
            },
            "source_artifacts": source_artifacts,
            "embedded_report_rows": embedded_report_rows,
            "rch_log_rows": rch_log_rows,
            "embedded_reports": embedded_reports,
            "proof_commands": proof_commands,
            "summaries": {
                "proof_console": proof_console["summary"],
                "conformance_registry": self._conformance_registry_summary(),
                "adapter_certification_matrix": self._adapter_matrix_summary(),
                "tracker": self._tracker_summary(),
            },
            "summary": {
                "source_artifact_count": len(source_artifacts),
                "missing_source_artifact_count": len(missing_artifacts),
                "proof_lane_count": len(lanes),
                "proof_command_count": len(proof_commands),
                "rch_outcome_count": len(proof_console["rch_outcomes"]),
                "rch_log_count": len(rch_log_rows),
                "rch_outcome_provenance_failure_count": len(
                    rch_outcome_provenance_failures
                ),
            },
            "failure_reasons": failure_reasons,
            "verdict": "fail_closed" if failure_reasons else "pass",
        }

    def write_release_proof_pack(self, output_dir: str, pack: Dict[str, Any]) -> Dict[str, Any]:
        """Write the proof-pack index and copied source artifacts to a directory."""
        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        written_files = []

        index_path = root / "index.json"
        index_path.write_bytes(canonical_json_bytes(pack))
        written_files.append("index.json")

        for name, report in pack["embedded_reports"].items():
            if name != "proof_console_report_v1":
                continue
            report_path = root / "reports" / "proof_console_report_v1.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_bytes(canonical_json_bytes(report))
            written_files.append("reports/proof_console_report_v1.json")

        for row in pack["source_artifacts"]:
            if row["status"] != "included":
                continue
            destination = root / row["copy_path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repo_root / row["path"], destination)
            written_files.append(row["copy_path"])

        for row in pack.get("rch_log_rows", []):
            if not isinstance(row, dict):
                continue
            source_log_path = row.get("source_log_path", "")
            copy_path = row.get("path", "")
            if not source_log_path or not copy_path:
                continue
            destination = root / str(copy_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(str(source_log_path)), destination)
            written_files.append(str(copy_path))

        return {
            "output_dir": str(root),
            "index_path": str(index_path),
            "written_files": sorted(written_files),
        }

    def verify_release_proof_pack_dir(self, pack_dir: str) -> Dict[str, Any]:
        """Verify a written release proof-pack directory against its index."""
        root = Path(pack_dir)
        index_path = root / "index.json"
        failure_reasons = []

        if not index_path.exists():
            return {
                "schema_version": "release-proof-pack-verification-v1",
                "pack_dir": str(root),
                "index_path": str(index_path),
                "pack_schema_version": "",
                "summary": {
                    "source_artifact_count": 0,
                    "embedded_report_count": 0,
                    "missing_file_count": 1,
                    "stale_file_count": 0,
                },
                "failure_reasons": [
                    {
                        "reason_id": "missing-index",
                        "summary": "release proof pack index.json is missing",
                        "path": "index.json",
                    }
                ],
                "verdict": "fail_closed",
            }

        with index_path.open(encoding="utf-8") as handle:
            pack = json.load(handle)

        missing_file_count = 0
        stale_file_count = 0
        rch_log_count = 0
        for row in pack.get("source_artifacts", []):
            if not isinstance(row, dict) or row.get("status") != "included":
                continue
            copy_path = str(row.get("copy_path", ""))
            actual_path = root / copy_path
            if not copy_path or not actual_path.exists():
                missing_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "missing-source-artifact-copy",
                        "summary": "included source artifact copy is missing",
                        "path": copy_path,
                        "source_path": row.get("path", ""),
                    }
                )
                continue
            actual_sha256 = file_hash(actual_path)
            actual_bytes = actual_path.stat().st_size
            if actual_sha256 != row.get("sha256") or actual_bytes != row.get("bytes"):
                stale_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "stale-source-artifact-copy",
                        "summary": "source artifact copy hash or byte count changed",
                        "path": copy_path,
                        "source_path": row.get("path", ""),
                        "expected_sha256": row.get("sha256", ""),
                        "actual_sha256": actual_sha256,
                        "expected_bytes": row.get("bytes", 0),
                        "actual_bytes": actual_bytes,
                    }
                )

        for row in pack.get("embedded_report_rows", []):
            if not isinstance(row, dict):
                continue
            report_path = str(row.get("path", ""))
            actual_path = root / report_path
            if not report_path or not actual_path.exists():
                missing_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "missing-embedded-report",
                        "summary": "embedded report file is missing",
                        "path": report_path,
                    }
                )
                continue
            actual_sha256 = file_hash(actual_path)
            actual_bytes = actual_path.stat().st_size
            if actual_sha256 != row.get("sha256") or actual_bytes != row.get("bytes"):
                stale_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "stale-embedded-report",
                        "summary": "embedded report hash or byte count changed",
                        "path": report_path,
                        "expected_sha256": row.get("sha256", ""),
                        "actual_sha256": actual_sha256,
                        "expected_bytes": row.get("bytes", 0),
                        "actual_bytes": actual_bytes,
                    }
                )

        for row in pack.get("rch_log_rows", []):
            if not isinstance(row, dict):
                continue
            rch_log_count += 1
            log_path = str(row.get("path", ""))
            actual_path = root / log_path
            if not log_path or not actual_path.exists():
                missing_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "missing-rch-log-copy",
                        "summary": "bundled rch source log copy is missing",
                        "path": log_path,
                        "source_log_path": row.get("source_log_path", ""),
                    }
                )
                continue
            actual_sha256 = file_hash(actual_path)
            actual_bytes = actual_path.stat().st_size
            if actual_sha256 != row.get("sha256") or actual_bytes != row.get("bytes"):
                stale_file_count += 1
                failure_reasons.append(
                    {
                        "reason_id": "stale-rch-log-copy",
                        "summary": "bundled rch source log hash or byte count changed",
                        "path": log_path,
                        "source_log_path": row.get("source_log_path", ""),
                        "expected_sha256": row.get("sha256", ""),
                        "actual_sha256": actual_sha256,
                        "expected_bytes": row.get("bytes", 0),
                        "actual_bytes": actual_bytes,
                    }
                )

        return {
            "schema_version": "release-proof-pack-verification-v1",
            "pack_dir": str(root),
            "index_path": str(index_path),
            "pack_schema_version": pack.get("schema_version", ""),
            "summary": {
                "source_artifact_count": len(
                    [
                        row
                        for row in pack.get("source_artifacts", [])
                        if isinstance(row, dict) and row.get("status") == "included"
                    ]
                ),
                "embedded_report_count": len(
                    [
                        row
                        for row in pack.get("embedded_report_rows", [])
                        if isinstance(row, dict)
                    ]
                ),
                "missing_file_count": missing_file_count,
                "stale_file_count": stale_file_count,
                "rch_log_count": rch_log_count,
            },
            "failure_reasons": failure_reasons,
            "verdict": "fail_closed" if failure_reasons else "pass",
        }

    def release_proof_pack_e2e_smoke(
        self,
        command: str,
        output_dir: str,
        generated_at: str = "",
        touched_files: Optional[List[str]] = None,
        log_fixture: str = "",
    ) -> Dict[str, Any]:
        """Run or fixture-replay one rch command, write a pack, then verify it."""
        touched_files = touched_files or []
        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        log_dir = root / "rch_logs"
        outcome_dir = root / "rch_outcomes"
        pack_dir = root / "pack"
        log_dir.mkdir(parents=True, exist_ok=True)
        outcome_dir.mkdir(parents=True, exist_ok=True)

        safe_command_argv(command)
        log_path = log_dir / "smoke_000.log"
        if log_fixture:
            log_path.write_text(Path(log_fixture).read_text(encoding="utf-8"), encoding="utf-8")
            return_code = 0
            execution_mode = "fixture"
        else:
            completed = subprocess.run(
                safe_command_argv(command),
                cwd=self.repo_root,
                text=True,
                capture_output=True,
            )
            log_path.write_text(
                "\n".join(
                    [
                        f"$ {command}",
                        "",
                        "[stdout]",
                        completed.stdout,
                        "[stderr]",
                        completed.stderr,
                    ]
                ),
                encoding="utf-8",
            )
            return_code = completed.returncode
            execution_mode = "rch"

        classified = self.classify_rch_log(command, str(log_path), touched_files)
        outcome = classified["rch_outcome"]
        if (
            return_code == 0
            and outcome.get("remote_exit_status") is None
            and outcome.get("decision") == "failed-local"
            and outcome.get("first_blocker", {}).get("file") != "rch-local-fallback"
        ):
            outcome["outcome_class"] = "pass"
            outcome["decision"] = "pass"
            outcome["summary"] = "rch command exited 0 without a remote-exit marker"
            classified["validation_frontier_record"] = ValidationFrontierRecord(
                command,
                touched_files,
                proof_lane_id=infer_proof_lane_id(command, "rch-smoke"),
                commit=self.git.head_commit(),
                dirty_tree_summary=self.git.dirty_tree_summary(touched_files),
                rch_result=rch_result_from_outcome(outcome),
                exit_status=0,
            ).as_pass()
        outcome_path = outcome_dir / "smoke_000.json"
        outcome_path.write_bytes(canonical_json_bytes(classified))
        proof_pack = self.release_proof_pack(
            generated_at=generated_at,
            rch_outcome_paths=[str(outcome_path)],
        )
        write_result = self.write_release_proof_pack(str(pack_dir), proof_pack)
        verification = self.verify_release_proof_pack_dir(str(pack_dir))

        failure_reasons = []
        if return_code != 0:
            failure_reasons.append(
                {
                    "reason_id": "smoke-rch-command-failed",
                    "summary": "release proof-pack smoke rch command exited nonzero",
                    "command": command,
                    "return_code": return_code,
                }
            )
        if classified["rch_outcome"]["decision"] != "pass":
            failure_reasons.append(
                {
                    "reason_id": "smoke-rch-outcome-not-pass",
                    "summary": "release proof-pack smoke rch outcome was not classified as pass",
                    "command": command,
                    "decision": classified["rch_outcome"]["decision"],
                    "outcome_class": classified["rch_outcome"]["outcome_class"],
                }
            )
        if proof_pack["verdict"] != "pass":
            failure_reasons.append(
                {
                    "reason_id": "smoke-proof-pack-not-pass",
                    "summary": "release proof pack generated by smoke did not pass",
                    "verdict": proof_pack["verdict"],
                }
            )
        if verification["verdict"] != "pass":
            failure_reasons.append(
                {
                    "reason_id": "smoke-verification-not-pass",
                    "summary": "written release proof pack directory did not verify",
                    "verdict": verification["verdict"],
                }
            )

        return {
            "schema_version": "release-proof-pack-e2e-smoke-v1",
            "execution_mode": execution_mode,
            "output_dir": str(root),
            "pack_dir": str(pack_dir),
            "smoke_commands": [
                {
                    "command": command,
                    "return_code": return_code,
                    "log_path": str(log_path),
                    "outcome_path": str(outcome_path),
                    "outcome_class": classified["rch_outcome"]["outcome_class"],
                    "decision": classified["rch_outcome"]["decision"],
                    "source_log_sha256": classified["rch_outcome"]["source_log_sha256"],
                    "source_log_bytes": classified["rch_outcome"]["source_log_bytes"],
                }
            ],
            "proof_pack": proof_pack,
            "write_result": write_result,
            "verification": verification,
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
            record = self._frontier_record(
                f"proof-runner --lane={lane_id}",
                touched_files,
                lane_id,
                exit_status=1,
            )
            return False, record.as_blocked_external(
                "unknown_proof_lane",
                "artifacts/proof_lane_manifest_v1.json",
                f"unknown lane {lane_id}",
                supplemental="br ready --json"
            )

        command = lane["command"]
        record = self._frontier_record(command, touched_files, lane_id)

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
            touched_set = {normalize_repo_path(path) for path in touched_files}
            uncommitted = self.git.get_uncommitted_files()
            if uncommitted:
                unrelated_files = [
                    f for f in uncommitted if normalize_repo_path(f) not in touched_set
                ]
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
            touched_set = {normalize_repo_path(path) for path in touched_files}
            staged = self.git.get_staged_files()
            if staged:
                unrelated_staged = [
                    f for f in staged if normalize_repo_path(f) not in touched_set
                ]
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
                        return rch_cargo_command(
                            f"test_{test_name}",
                            f"test {test_name} -- --nocapture",
                        )

                # Otherwise, try library check
                return rch_cargo_command("lib_check", "check --lib")

        elif lane_kind == "lint_frontier":
            # For linting, check only specific files if possible
            rust_files = [f for f in touched_files if f.endswith('.rs')]
            if rust_files and len(rust_files) <= 3:
                return rch_cargo_command("lib_clippy", "clippy --lib -- -D warnings")

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
        lane = self.manifest.get_lane(lane_id)
        command = lane["command"] if lane else ""
        disk_preflight = classify_disk_pressure(
            command,
            disk_pressure_snapshot(self.disk_preflight_snapshot),
            self.disk_min_free_bytes,
            self.disk_dev_shm_min_free_bytes,
        )
        recommendation = "proceed" if can_proceed else "use_supplemental"
        if disk_preflight["recommendation"] == "use_disk_safe_proof_path":
            recommendation = "use_supplemental"

        result = {
            "preflight_passed": can_proceed,
            "lane_id": lane_id,
            "command_would_run": command,
            "build_slot_check": self.build_slots.last_check,
            "reservation_check": self.agent_mail.last_check,
            "disk_pressure_preflight": disk_preflight,
            "validation_frontier_record": record,
            "recommendation": recommendation
        }

        return result


    def rank_fallback_beads(self, snapshot_path: str) -> Dict[str, Any]:
        beads = fallback_bead_rows_from_snapshot(snapshot_path)
        disk_preflight = classify_disk_pressure(
            "",
            disk_pressure_snapshot(self.disk_preflight_snapshot),
            self.disk_min_free_bytes,
            self.disk_dev_shm_min_free_bytes,
        )
        disk_low = disk_preflight["classification"] != "healthy"
        ranked_beads = rank_fallback_beads_for_disk(beads, disk_preflight, self.agent_mail)
        return {
            "schema_version": FALLBACK_RANKING_SCHEMA_VERSION,
            "source": "fixture",
            "rank_policy": (
                "input-order-when-healthy; disk-safe-neutral-cargo-heavy-when-low; "
                "bare Cargo validation commands hard-block; peer-active reservation overlaps demote; "
                "tracker/unknown reservations hard-block"
            ),
            "disk_pressure_preflight": disk_preflight,
            "warning_wording": FALLBACK_CARGO_HEAVY_WARNING,
            "reservation_snapshot": self.agent_mail.snapshot_status(),
            "summary": {
                "input_bead_count": len(beads),
                "disk_pressure_active": disk_low,
                "cargo_heavy_warning_count": sum(
                    1 for row in ranked_beads
                    if row["disk_pressure_warning"]
                ),
                "reservation_demotion_count": sum(
                    1 for row in ranked_beads
                    if row["reservation_demoted"]
                ),
                "reservation_hard_block_count": sum(
                    1 for row in ranked_beads
                    if row["reservation_hard_blocked"]
                ),
                "unsafe_validation_block_count": sum(
                    1 for row in ranked_beads
                    if row["unsafe_validation_blocked"]
                ),
            },
            "ranked_fallback_beads": ranked_beads,
        }

    def autopilot_proof_plan(
        self,
        touched_files: List[str],
        fallback_snapshot_path: str,
    ) -> Dict[str, Any]:
        fallback_ranking = self.rank_fallback_beads(fallback_snapshot_path)
        ranked_fallbacks = fallback_ranking["ranked_fallback_beads"]
        selected_fallback = next(
            (row for row in ranked_fallbacks if row["eligible"]),
            None,
        )
        return {
            "schema_version": AUTOPILOT_PLAN_SCHEMA_VERSION,
            "mode": "dry-run",
            "touched_files": touched_files,
            "suggested_lanes": self.suggest_lanes_for_changes(touched_files),
            "disk_pressure_preflight": fallback_ranking["disk_pressure_preflight"],
            "fallback_ranking": fallback_ranking,
            "selected_fallback_bead": selected_fallback,
            "decision": "use_fallback_bead" if selected_fallback else "no_fallback_candidate",
            "no_mutation": {
                "executes_proof_commands": False,
                "mutates_beads": False,
                "mutates_agent_mail": False,
                "deletes_files": False,
                "requires_explicit_cleanup_permission": True,
            },
        }

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
        likely_bead: Optional[str] = None,
        likely_owner: str = "",
    ) -> Dict[str, Any]:
        """Classify a saved rch transcript as a machine-readable proof outcome."""
        source_log = Path(log_path)
        log_text = source_log.read_text(encoding="utf-8")
        outcome = classify_rch_outcome(command, log_text, touched_files)
        outcome["source_log_path"] = str(source_log)
        outcome["source_log_sha256"] = file_hash(source_log)
        outcome["source_log_bytes"] = source_log.stat().st_size
        blocker = outcome["first_blocker"]
        blocker_origin = self.git.recent_commit_hint_for_path(str(blocker.get("file", "")))
        inferred_bead = likely_bead or blocker_origin.get("bead_id")
        record = self._frontier_record(
            command,
            touched_files,
            infer_proof_lane_id(command, "rch-classified"),
            rch_result=rch_result_from_outcome(outcome),
            exit_status=outcome.get("remote_exit_status"),
            likely_bead=inferred_bead,
            likely_owner=likely_owner,
            blocker_origin=blocker_origin,
        )
        scope = outcome["command_scope"]
        diagnostic_class = str(outcome.get("diagnostic_class") or outcome["outcome_class"])
        crate_or_surface, target = diagnostic_target(scope, diagnostic_class)
        error_code = str(blocker.get("code", ""))
        if diagnostic_class == "clippy_lint_wall":
            error_code = clippy_lint_code(log_text) or error_code
        if not error_code:
            error_code = diagnostic_class

        if outcome["decision"] == "pass":
            frontier = record.as_pass()
        elif outcome["decision"] == "blocked-external":
            frontier = record.as_blocked_external(
                diagnostic_class,
                blocker.get("file", "") or "rch-wrapper",
                outcome["summary"],
                line=int(blocker.get("line") or 0),
                target=target or scope.get("target") or scope.get("cargo_subcommand") or "rch",
                crate_or_surface=crate_or_surface,
                blocker_message=blocker.get("message", ""),
                error_code=error_code,
            )
        else:
            frontier = record.as_failed_local(
                diagnostic_class,
                blocker.get("file", ""),
                outcome["summary"],
                line=int(blocker.get("line") or 0),
                target=target or scope.get("target") or scope.get("cargo_subcommand") or "",
                crate_or_surface=crate_or_surface,
                blocker_message=blocker.get("message", ""),
                error_code=error_code,
            )

        return {
            "schema_version": RCH_OUTCOME_SCHEMA_VERSION,
            "rch_outcome": outcome,
            "validation_frontier_record": frontier,
            "closeout_summary": closeout_summary_from_frontier(outcome, frontier),
        }

    def plan_compile_frontier_shards(
        self,
        command: str,
        log_path: str,
        touched_files: List[str],
    ) -> Dict[str, Any]:
        """Plan reservation-aware file shards from a cargo/rch compile transcript."""
        source_log = Path(log_path)
        log_text = source_log.read_text(encoding="utf-8")
        blockers = all_rustc_blockers(log_text)
        file_groups = compile_frontier_file_groups(
            blockers,
            touched_files,
            self.agent_mail,
        )
        suggested, blocked = compile_frontier_shard_suggestions(file_groups, command)
        first_touched = next(
            (group["first_blocker"] for group in file_groups if group["touched_by_request"]),
            None,
        )
        first_external = next(
            (group["first_blocker"] for group in file_groups if not group["touched_by_request"]),
            None,
        )
        return {
            "schema_version": COMPILE_FRONTIER_SHARDS_SCHEMA_VERSION,
            "command": command,
            "command_scope": command_scope(command),
            "source_log_path": str(source_log),
            "source_log_sha256": file_hash(source_log),
            "source_log_bytes": source_log.stat().st_size,
            "touched_files": [normalize_repo_path(path) for path in touched_files],
            "total_diagnostics": sum(group["diagnostic_count"] for group in file_groups),
            "file_group_count": len(file_groups),
            "first_blocker": file_groups[0]["first_blocker"] if file_groups else empty_blocker(),
            "first_touched_blocker": first_touched or empty_blocker(),
            "first_external_blocker": first_external or empty_blocker(),
            "reservation_snapshot": self.agent_mail.snapshot_status(),
            "file_groups": file_groups,
            "suggested_shards": suggested,
            "blocked_shards": blocked,
            "summary": {
                "suggested_count": len(suggested),
                "blocked_count": len(blocked),
                "touched_group_count": sum(
                    1 for group in file_groups if group["touched_by_request"]
                ),
                "external_group_count": sum(
                    1 for group in file_groups if not group["touched_by_request"]
                ),
                "green_proof_claimed": False,
                "mutates_beads": False,
                "mutates_agent_mail": False,
                "deletes_files": False,
            },
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
        "--rank-fallback-beads",
        action="store_true",
        help="Rank fallback bead candidates using disk pressure"
    )
    parser.add_argument(
        "--autopilot-proof-plan",
        action="store_true",
        help="Build a dry-run proof plan from touched files, disk pressure, and fallback candidates"
    )
    parser.add_argument(
        "--fallback-bead-snapshot",
        default="",
        help="JSON fixture containing fallback bead candidates"
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
        "--plan-compile-frontier-shards",
        help="Plan reservation-aware file shards from a saved cargo/rch compile transcript"
    )
    parser.add_argument(
        "--bead-id",
        "--likely-bead",
        dest="bead_id",
        default="",
        help="Bead id to attach to --classify-rch-log frontier and closeout output"
    )
    parser.add_argument(
        "--likely-owner",
        default="",
        help="Owner hint to attach to --classify-rch-log frontier and closeout output"
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
        "--proof-status-dashboard",
        action="store_true",
        help="Emit the concise manifest-backed proof-claim status dashboard"
    )
    parser.add_argument(
        "--proof-status-snapshot",
        default=PROOF_STATUS_SNAPSHOT_PATH,
        help="Proof status snapshot JSON used by proof-console and dashboard modes"
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
        "--failure-corpus-replay",
        default="",
        help="Replay one deterministic failure corpus case by id without external services"
    )
    parser.add_argument(
        "--failure-corpus-manifest",
        default=FAILURE_CORPUS_MANIFEST_PATH,
        help="Failure corpus manifest JSON used by --failure-corpus-replay"
    )
    parser.add_argument(
        "--failure-corpus-scrub-input",
        default="",
        help="Scrub one raw failure transcript and emit deterministic replay lines"
    )
    parser.add_argument(
        "--release-proof-pack",
        action="store_true",
        help="Emit a deterministic release proof-pack index"
    )
    parser.add_argument(
        "--release-proof-pack-e2e-smoke",
        action="store_true",
        help="Run or fixture-replay an rch command, write a release proof pack, and verify it"
    )
    parser.add_argument(
        "--release-proof-pack-generated-at",
        default="",
        help="Override generated_at for deterministic release proof-pack fixtures"
    )
    parser.add_argument(
        "--release-proof-pack-rch-outcome",
        action="append",
        default=[],
        help="JSON rch outcome produced by --classify-rch-log to include in the release proof pack"
    )
    parser.add_argument(
        "--release-proof-pack-output-dir",
        default="",
        help="Write the release proof pack to this directory"
    )
    parser.add_argument(
        "--release-proof-pack-smoke-log-fixture",
        default="",
        help="Use a saved rch transcript for release proof-pack smoke tests instead of running rch"
    )
    parser.add_argument(
        "--verify-release-proof-pack-dir",
        default="",
        help="Verify a written release proof pack directory"
    )
    parser.add_argument(
        "--command",
        default="",
        help="Original rch command for --classify-rch-log or --plan-compile-frontier-shards"
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
    parser.add_argument(
        "--disk-preflight-snapshot",
        default="",
        help="JSON snapshot of local disk pressure for fixture-backed checks"
    )
    parser.add_argument(
        "--disk-min-free-bytes",
        type=int,
        default=DEFAULT_DISK_MIN_FREE_BYTES,
        help="Minimum acceptable free bytes on / before preferring disk-safe proofs"
    )
    parser.add_argument(
        "--disk-dev-shm-min-free-bytes",
        type=int,
        default=DEFAULT_DEV_SHM_MIN_FREE_BYTES,
        help="Minimum acceptable free bytes on /dev/shm before preferring disk-safe proofs"
    )

    args = parser.parse_args()

    try:
        runner = ProofRunner(
            agent_name=args.agent_name,
            reservation_snapshot=args.reservation_snapshot,
            build_slot_snapshot=args.build_slot_snapshot,
            build_slot=args.build_slot,
            skip_dirty_check=args.skip_dirty_check,
            skip_build_slot_check=args.skip_build_slot_check,
            disk_preflight_snapshot=args.disk_preflight_snapshot or None,
            disk_min_free_bytes=args.disk_min_free_bytes,
            disk_dev_shm_min_free_bytes=args.disk_dev_shm_min_free_bytes,
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

        if args.rank_fallback_beads:
            if not args.fallback_bead_snapshot:
                parser.error("--fallback-bead-snapshot is required with --rank-fallback-beads")
            result = runner.rank_fallback_beads(args.fallback_bead_snapshot)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                for row in result["ranked_fallback_beads"]:
                    warning = " warning={}".format(row["disk_pressure_warning"]) if row["disk_pressure_warning"] else ""
                    print("{} {}{}".format(row["id"], row["disk_safety"], warning))
            return 0

        if args.autopilot_proof_plan:
            if not args.fallback_bead_snapshot:
                parser.error("--fallback-bead-snapshot is required with --autopilot-proof-plan")
            result = runner.autopilot_proof_plan(args.touched_files, args.fallback_bead_snapshot)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                selected = result["selected_fallback_bead"] or {}
                print("decision={}".format(result["decision"]))
                print("selected_fallback_bead={}".format(selected.get("id", "")))
                print("disk_pressure={}".format(result["disk_pressure_preflight"]["classification"]))
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

        if args.plan_compile_frontier_shards:
            if not args.command:
                parser.error("--command is required with --plan-compile-frontier-shards")
            result = runner.plan_compile_frontier_shards(
                args.command,
                args.plan_compile_frontier_shards,
                args.touched_files,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(
                    "diagnostics={} groups={} suggested={} blocked={}".format(
                        result["total_diagnostics"],
                        result["file_group_count"],
                        result["summary"]["suggested_count"],
                        result["summary"]["blocked_count"],
                    )
                )
                for row in result["suggested_shards"]:
                    print(
                        "{}. {} errors={} reservation={}".format(
                            row["rank"],
                            row["reservation_paths"][0],
                            row["diagnostic_count"],
                            row["reservation_state"],
                        )
                    )
            return 0

        if args.classify_rch_log:
            if not args.command:
                parser.error("--command is required with --classify-rch-log")
            result = runner.classify_rch_log(
                args.command,
                args.classify_rch_log,
                args.touched_files,
                likely_bead=args.bead_id or None,
                likely_owner=args.likely_owner,
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
                proof_status_snapshot_path=args.proof_status_snapshot,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(proof_console_markdown(result), end="")
            return 0

        if args.proof_status_dashboard:
            result = runner.proof_status_dashboard(
                generated_at=args.proof_console_generated_at,
                rch_outcome_paths=args.proof_console_rch_outcome,
                proof_status_snapshot_path=args.proof_status_snapshot,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(proof_status_dashboard_markdown(result), end="")
            return 0

        if args.failure_corpus_replay:
            result = runner.failure_corpus_replay(
                case_id=args.failure_corpus_replay,
                manifest_path=args.failure_corpus_manifest,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Failure corpus case: {result['case_id']}")
                print(f"Verdict: {result['verdict']}")
                for line in result["minimized_replay_lines"]:
                    print(f"  {line}")
            return 0 if result["verdict"] == "pass" else 1

        if args.failure_corpus_scrub_input:
            result = runner.failure_corpus_scrub_file(args.failure_corpus_scrub_input)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(result["scrubbed_text"], end="")
            return 0

        if args.release_proof_pack:
            result = runner.release_proof_pack(
                generated_at=args.release_proof_pack_generated_at,
                rch_outcome_paths=args.release_proof_pack_rch_outcome,
            )
            response: Dict[str, Any] = {"proof_pack": result}
            if args.release_proof_pack_output_dir:
                response["write_result"] = runner.write_release_proof_pack(
                    args.release_proof_pack_output_dir,
                    result,
                )
            if args.output == "json":
                print(json.dumps(response, indent=2))
            else:
                print(release_proof_pack_markdown(result), end="")
            return 0 if result["verdict"] == "pass" else 1

        if args.release_proof_pack_e2e_smoke:
            if not args.command:
                parser.error("--command is required with --release-proof-pack-e2e-smoke")
            if not args.release_proof_pack_output_dir:
                parser.error(
                    "--release-proof-pack-output-dir is required with "
                    "--release-proof-pack-e2e-smoke"
                )
            result = runner.release_proof_pack_e2e_smoke(
                command=args.command,
                output_dir=args.release_proof_pack_output_dir,
                generated_at=args.release_proof_pack_generated_at,
                touched_files=args.touched_files,
                log_fixture=args.release_proof_pack_smoke_log_fixture,
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Verdict: {result['verdict']}")
                for reason in result["failure_reasons"]:
                    print(f"- {reason['reason_id']}: {reason['summary']}")
            return 0 if result["verdict"] == "pass" else 1

        if args.verify_release_proof_pack_dir:
            result = runner.verify_release_proof_pack_dir(
                args.verify_release_proof_pack_dir
            )
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Verdict: {result['verdict']}")
                for reason in result["failure_reasons"]:
                    print(f"- {reason['reason_id']}: {reason['summary']}")
            return 0 if result["verdict"] == "pass" else 1

        # Validate required arguments for proof analysis
        if not args.lane:
            parser.error(
                "--lane is required when not using a report/list/suggest mode"
            )

        # Run preflight analysis
        result = runner.run_preflight(args.lane, args.touched_files, execute=args.execute, output_format=args.output)

        if args.output == "json":
            print(json.dumps(result, indent=2))
        else:
            if result["preflight_passed"]:
                print(f"✅ Preflight PASSED for lane {args.lane}")
                print(f"Command: {result['command_would_run']}")
                disk_preflight = result["disk_pressure_preflight"]
                if args.execute and not disk_preflight["execution_permitted"]:
                    guidance = disk_preflight["guidance"]
                    print("Disk-pressure preflight blocked custom target-dir execution")
                    print(f"Classification: {disk_preflight['classification']}")
                    print(f"Next action: {guidance['preferred_next_action']}")
                    return 1
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
