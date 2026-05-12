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
        path = normalize_path(str(item.get("path") or ""))
        if path:
            entries.append(
                {
                    "path": path,
                    "status": str(item.get("status") or ""),
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
) -> dict[str, Any]:
    paths = candidate["paths"]
    blockers = []
    blockers.extend(lane_blockers(candidate))
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


def recommendation(candidates: list[dict[str, Any]]) -> dict[str, Any]:
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
            entries.append({"status": line[:2], "path": line[3:]})
    return entries


def live_probe(
    repo_path: Path,
    timeout: float,
    reservations: Any,
    candidates: Any,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    ready_status, ready = run_json(repo_path, ["br", "ready", "--json"], timeout)
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
    candidates = ready_candidates(source) + fallback_candidates(source)
    classified = [
        classify_candidate(candidate, reservations, dirty, agent)
        for candidate in sorted(candidates, key=candidate_sort_key)
    ]
    rec = recommendation(classified)
    blocked = [row for row in classified if row["status"] == "blocked"]
    ready = [row for row in classified if row["status"] != "blocked"]

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
