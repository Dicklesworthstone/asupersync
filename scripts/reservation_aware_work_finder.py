#!/usr/bin/env python3
"""Emit a non-mutating reservation-aware work finder receipt.

The helper ranks ready beads and approved fallback-lane candidates while
respecting active file reservations and dirty shared-main paths. It never
claims beads, reserves files, edits code, sends Agent Mail, runs Cargo, or
mutates git state.
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
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_session_handoff cargo test -p asupersync --test session_handoff_receipt_contract",
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
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_proof_receipt_inventory cargo test -p asupersync --test proof_receipt_inventory_contract",
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
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent>_proof_runner cargo test -p asupersync --test proof_runner_contract",
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
RCH_LOCAL_FALLBACK_RE = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
DISK_CRITICAL_BYTES = 1 * 1024 * 1024 * 1024
DISK_LOW_BYTES = 5 * 1024 * 1024 * 1024


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
                "proof_commands": [
                    str(command)
                    for command in row.get("proof_commands", [])
                    if isinstance(command, str) and command
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

    remote_index = program_index + 3
    if remote_index < len(argv) and lowered[remote_index] == "env":
        remote_index = _first_non_assignment(argv, remote_index + 1)
    return remote_index < len(argv) and lowered[remote_index] == "cargo"


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
                            "reason": "Cargo proof commands must be routed through rch exec",
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


def classify_candidate(
    candidate: dict[str, Any],
    reservations: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    agent: str,
    disk_pressure: dict[str, Any],
) -> dict[str, Any]:
    paths = candidate["paths"]
    blockers = []
    blockers.extend(lane_blockers(candidate))
    blockers.extend(proof_command_blockers(candidate))
    blockers.extend(disk_pressure_blockers(candidate, disk_pressure))
    blockers.extend(bead_blockers(candidate))
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
            "reason": "first unblocked candidate by kind and priority",
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
            "reason": "critical disk pressure leaves no safe work candidate; ask for explicit cleanup authorization",
        }
    if candidates:
        first = sorted(candidates, key=candidate_sort_key)[0]
        return {
            "category": "blocked-no-safe-work",
            "candidate_id": first["candidate_id"],
            "lane": first["lane"],
            "title": first["title"],
            "paths": first["paths"],
            "reason": "all candidates are blocked by reservations, dirty paths, or policy",
        }
    return {
        "category": "blocked-no-candidates",
        "candidate_id": "",
        "lane": "",
        "title": "",
        "paths": [],
        "reason": "no ready beads or fallback candidates were provided",
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
            "reason": recommendation_row["reason"],
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


def live_probe(
    repo_path: Path,
    timeout: float,
    reservations: Any,
    candidates: Any,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    ready_status, ready = run_json(repo_path, ["br", "ready", "--json"], timeout)
    df_status, raw_df = run_text(repo_path, ["df", "-B1", "/", "/tmp"], timeout)
    return {
        "beads": {
            "ready": ready if ready_status == "ok" and isinstance(ready, list) else [],
            "status": ready_status,
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
    disk_pressure = disk_pressure_from_source(source)
    candidates = ready_candidates(source) + fallback_candidates(source)
    classified = [
        classify_candidate(candidate, reservations, dirty, agent, disk_pressure)
        for candidate in sorted(candidates, key=candidate_sort_key)
    ]
    disk_pressure["non_build_fallback_candidates"] = disk_pressure_non_build_candidates(classified)
    rec = recommendation(classified, disk_pressure)
    blocked = [row for row in classified if row["status"] == "blocked"]
    ready = [row for row in classified if row["status"] != "blocked"]
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
        },
        "recommendation": rec,
        "closeout_handoff": closeout_handoff,
        "disk_pressure": disk_pressure,
        "candidates": classified,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find safe ready or fallback work without mutation.")
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Current agent name")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument("--reservation-snapshot", type=Path, help="Optional Agent Mail reservation snapshot")
    parser.add_argument("--candidate-snapshot", type=Path, help="Optional fallback candidate snapshot")
    parser.add_argument("--output", choices=["json"], default="json")
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
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
