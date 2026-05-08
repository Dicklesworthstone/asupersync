#!/usr/bin/env python3
"""Build a non-mutating lease queue for fuzz manifest edits.

The helper consumes fixture-shaped proposal, manifest, and Agent Mail
reservation snapshots. It never edits fuzz/Cargo.toml, reserves files, runs
cargo, or mutates Beads; it only renders a deterministic queue receipt.
"""

import argparse
import datetime as dt
import fnmatch
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "fuzz-manifest-lease-queue-v1"
INPUT_SCHEMA_VERSION = "fuzz-manifest-lease-queue-input-v1"
DEFAULT_MANIFEST_PATH = "fuzz/Cargo.toml"


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


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_path(path: str) -> str:
    return path.strip().lstrip("./")


def normalize_name(value: Any) -> str:
    return str(value or "").strip()


def matches_pattern(path: str, pattern: str) -> bool:
    path = normalize_path(path)
    pattern = normalize_path(pattern)
    if not path or not pattern:
        return False
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3].rstrip("/") + "/")
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path)
    return path == pattern or path.startswith(pattern.rstrip("/") + "/")


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def reservation_pattern(row: dict[str, Any]) -> str:
    return normalize_path(
        str(row.get("path_pattern") or row.get("path") or row.get("pattern") or row.get("glob") or "")
    )


def reservation_holder(row: dict[str, Any]) -> str:
    return normalize_name(
        row.get("agent_name") or row.get("holder") or row.get("owner") or row.get("agent")
    )


def active_reservation(row: dict[str, Any], generated_at: str) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires_ts = str(row.get("expires_ts") or row.get("expires_at") or "")
    if not expires_ts:
        return True
    expires = parse_timestamp(expires_ts)
    generated = parse_timestamp(generated_at)
    if expires is None or generated is None:
        return True
    return expires > generated


def normalize_existing_targets(data: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in as_list(data.get("current_manifest_targets")):
        if isinstance(item, str):
            name = item.strip()
            path = f"fuzz/fuzz_targets/{name}.rs" if name else ""
        elif isinstance(item, dict):
            name = normalize_name(item.get("name") or item.get("target_name"))
            path = normalize_path(str(item.get("path") or item.get("target_path") or ""))
        else:
            continue
        if name:
            rows.append({"name": name, "path": path})
    return sorted(rows, key=lambda row: (row["name"], row["path"]))


def proposal_id(row: dict[str, Any]) -> str:
    explicit = normalize_name(row.get("proposal_id") or row.get("id"))
    if explicit:
        return explicit
    bead = normalize_name(row.get("bead_id"))
    agent = normalize_name(row.get("agent"))
    target = normalize_name(row.get("target_name"))
    return ":".join(part for part in [bead, agent, target] if part) or "unnamed-proposal"


def normalize_proposals(data: dict[str, Any], manifest_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in as_list(data.get("proposals")):
        if not isinstance(item, dict):
            continue
        target_name = normalize_name(item.get("target_name") or item.get("name"))
        target_path = normalize_path(
            str(item.get("target_path") or item.get("path") or f"fuzz/fuzz_targets/{target_name}.rs")
        )
        if not target_name:
            continue
        rows.append(
            {
                "proposal_id": proposal_id(item),
                "agent": normalize_name(item.get("agent")),
                "bead_id": normalize_name(item.get("bead_id")),
                "target_name": target_name,
                "target_path": target_path,
                "manifest_path": normalize_path(str(item.get("manifest_path") or manifest_path)),
                "priority": int(item.get("priority", 2)),
                "created_ts": str(item.get("created_ts") or ""),
                "notes": str(item.get("notes") or ""),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["priority"],
            row["created_ts"],
            row["agent"],
            row["target_name"],
            row["proposal_id"],
        ),
    )


def normalize_reservations(data: dict[str, Any], generated_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source_key in ("reservations", "active_reservations", "file_reservations", "granted"):
        for item in as_list(data.get(source_key)):
            if not isinstance(item, dict):
                continue
            pattern = reservation_pattern(item)
            if not pattern:
                continue
            rows.append(
                {
                    "path_pattern": pattern,
                    "holder": reservation_holder(item),
                    "exclusive": bool(item.get("exclusive", True)),
                    "expires_ts": str(item.get("expires_ts") or item.get("expires_at") or ""),
                    "reason": str(item.get("reason") or ""),
                    "active": active_reservation(item, generated_at),
                    "source_key": source_key,
                }
            )
    return sorted(rows, key=lambda row: (row["path_pattern"], row["holder"], row["expires_ts"]))


def duplicate_values(rows: list[dict[str, Any]], key: str) -> set[str]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "")
        if value:
            counts[value] = counts.get(value, 0) + 1
    return {value for value, count in counts.items() if count > 1}


def reservations_for_path(
    reservations: list[dict[str, Any]],
    path: str,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    return [
        row
        for row in reservations
        if (row["active"] or not active_only) and row["exclusive"] and matches_pattern(path, row["path_pattern"])
    ]


def reservation_blocker(kind: str, reservation: dict[str, Any]) -> dict[str, str]:
    holder = reservation["holder"] or "unknown"
    return {
        "kind": kind,
        "holder": holder,
        "path_pattern": reservation["path_pattern"],
        "expires_ts": reservation["expires_ts"],
        "reason": reservation["reason"],
    }


def manifest_status(
    manifest_reservations: list[dict[str, Any]],
    proposal_agents: set[str],
) -> dict[str, Any]:
    if not manifest_reservations:
        return {"status": "free", "holder": "", "expires_ts": ""}
    holders = sorted({row["holder"] or "unknown" for row in manifest_reservations})
    proposal_holders = [holder for holder in holders if holder in proposal_agents]
    if len(holders) == 1 and proposal_holders:
        holder = proposal_holders[0]
        row = manifest_reservations[0]
        return {
            "status": "held-by-proposal-agent",
            "holder": holder,
            "expires_ts": row["expires_ts"],
        }
    row = manifest_reservations[0]
    return {
        "status": "blocked-by-active-reservation",
        "holder": holders[0],
        "expires_ts": row["expires_ts"],
    }


def hard_blockers_for(
    proposal: dict[str, Any],
    existing_names: set[str],
    existing_paths: set[str],
    duplicate_names: set[str],
    duplicate_paths: set[str],
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    if proposal["target_name"] in existing_names:
        blockers.append(
            {
                "kind": "duplicate-manifest-target",
                "detail": proposal["target_name"],
            }
        )
    if proposal["target_path"] in existing_paths:
        blockers.append(
            {
                "kind": "duplicate-manifest-path",
                "detail": proposal["target_path"],
            }
        )
    if proposal["target_name"] in duplicate_names:
        blockers.append(
            {
                "kind": "duplicate-proposal-target",
                "detail": proposal["target_name"],
            }
        )
    if proposal["target_path"] in duplicate_paths:
        blockers.append(
            {
                "kind": "duplicate-proposal-path",
                "detail": proposal["target_path"],
            }
        )
    return blockers


def proposal_row(
    proposal: dict[str, Any],
    queue_position: int | None,
    status: str,
    action: str,
    blockers: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "proposal_id": proposal["proposal_id"],
        "agent": proposal["agent"],
        "bead_id": proposal["bead_id"],
        "target_name": proposal["target_name"],
        "target_path": proposal["target_path"],
        "manifest_path": proposal["manifest_path"],
        "priority": proposal["priority"],
        "created_ts": proposal["created_ts"],
        "queue_position": queue_position,
        "status": status,
        "recommended_action": action,
        "blockers": blockers,
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    generated_at = args.generated_at or str(data.get("generated_at") or utc_now())
    manifest_path = normalize_path(str(data.get("manifest_path") or DEFAULT_MANIFEST_PATH))

    existing_targets = normalize_existing_targets(data)
    proposals = normalize_proposals(data, manifest_path)
    reservations = normalize_reservations(data, generated_at)

    existing_names = {row["name"] for row in existing_targets}
    existing_paths = {row["path"] for row in existing_targets if row["path"]}
    duplicate_names = duplicate_values(proposals, "target_name")
    duplicate_paths = duplicate_values(proposals, "target_path")
    proposal_agents = {row["agent"] for row in proposals if row["agent"]}

    manifest_reservations = reservations_for_path(reservations, manifest_path)
    manifest = manifest_status(manifest_reservations, proposal_agents)
    manifest_holder = manifest["holder"]

    preliminary: list[tuple[dict[str, Any], list[dict[str, str]]]] = []
    for proposal in proposals:
        blockers = hard_blockers_for(
            proposal,
            existing_names,
            existing_paths,
            duplicate_names,
            duplicate_paths,
        )
        target_reservations = reservations_for_path(reservations, proposal["target_path"])
        for reservation in target_reservations:
            holder = reservation["holder"]
            if holder and holder == proposal["agent"]:
                continue
            blockers.append(reservation_blocker("target-file-reservation", reservation))
        if manifest["status"] == "blocked-by-active-reservation":
            blockers.append(reservation_blocker("manifest-reservation", manifest_reservations[0]))
        elif (
            manifest["status"] == "held-by-proposal-agent"
            and manifest_holder
            and manifest_holder != proposal["agent"]
        ):
            blockers.append(reservation_blocker("manifest-reservation", manifest_reservations[0]))
        preliminary.append((proposal, blockers))

    eligible_ids = {
        proposal["proposal_id"]
        for proposal, blockers in preliminary
        if not blockers
    }
    ordered_eligible = [proposal for proposal in proposals if proposal["proposal_id"] in eligible_ids]
    position_by_id = {
        proposal["proposal_id"]: index
        for index, proposal in enumerate(ordered_eligible, start=1)
    }

    queue: list[dict[str, Any]] = []
    for proposal, blockers in preliminary:
        position = position_by_id.get(proposal["proposal_id"])
        if blockers:
            first_kind = blockers[0]["kind"]
            if "duplicate" in first_kind:
                status = f"blocked-{first_kind}"
                action = "coordinate-or-rename-before-reserving"
            elif first_kind == "manifest-reservation":
                status = "wait-for-manifest-reservation"
                action = "wait-for-or-coordinate-manifest-lease"
            elif first_kind == "target-file-reservation":
                status = "wait-for-target-reservation"
                action = "wait-for-or-coordinate-target-lease"
            else:
                status = "blocked"
                action = "resolve-blockers-before-reserving"
        elif position == 1 and manifest["status"] == "held-by-proposal-agent":
            status = "ready-with-owned-manifest-reservation"
            action = "reserve-target-if-needed-then-edit-manifest"
        elif position == 1:
            status = "ready-to-reserve"
            action = "reserve-manifest-and-target-before-editing"
        else:
            status = "queued-after-earlier-proposal"
            action = "wait-for-earlier-queue-position"
        queue.append(proposal_row(proposal, position, status, action, blockers))

    ready_now = [
        row["proposal_id"]
        for row in queue
        if row["status"] in {"ready-to-reserve", "ready-with-owned-manifest-reservation"}
    ]
    blocked = [row for row in queue if row["status"].startswith("blocked-")]
    waiting = [row for row in queue if row["status"].startswith("wait-")]

    action_items: list[str] = []
    for row in queue:
        if row["blockers"]:
            blocker = row["blockers"][0]
            action_items.append(
                f"{row['proposal_id']}: {row['recommended_action']} ({blocker['kind']})"
            )
    if not proposals:
        action_items.append("provide at least one fuzz target proposal")
    if ready_now:
        action_items.append(f"next safe proposal: {ready_now[0]}")

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": str(data.get("schema_version") or ""),
        "generated_at": generated_at,
        "generated_date": current_date(generated_at),
        "manifest_path": manifest_path,
        "source_counts": {
            "current_manifest_targets": len(existing_targets),
            "proposals": len(proposals),
            "reservations": len(reservations),
            "active_reservations": sum(1 for row in reservations if row["active"]),
            "duplicate_target_names": len(duplicate_names),
            "duplicate_target_paths": len(duplicate_paths),
        },
        "manifest_reservation": manifest,
        "queue": queue,
        "ready_now": ready_now,
        "blocked_proposals": [row["proposal_id"] for row in blocked],
        "waiting_proposals": [row["proposal_id"] for row in waiting],
        "summary": {
            "passes": bool(proposals) and not blocked,
            "ready_count": len(ready_now),
            "queued_count": sum(1 for row in queue if row["status"] == "queued-after-earlier-proposal"),
            "blocked_count": len(blocked),
            "waiting_count": len(waiting),
        },
        "action_items": action_items,
        "non_mutating": True,
        "forbidden_actions": {
            "edits_fuzz_manifest": False,
            "creates_fuzz_target": False,
            "runs_cargo": False,
            "runs_rch": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_agent_mail_mutation": False,
            "runs_destructive_command": False,
        },
        "safety_notes": [
            "receipt is fixture-backed and does not call Agent Mail",
            "manifest and target reservations must be acquired by the operator before editing",
            "fuzz/Cargo.toml and fuzz target files are intentionally not modified",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a deterministic, non-mutating fuzz manifest lease queue."
    )
    parser.add_argument("--input", required=True, help="Fixture JSON input")
    parser.add_argument("--generated-at", help="Stable ISO timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    receipt = build_receipt(args)
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
