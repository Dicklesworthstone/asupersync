#!/usr/bin/env python3
"""Emit a non-mutating swarm heatmap for shared-main coordination.

The helper correlates agent activity, file reservations, dirty git paths, and
announced CARGO_TARGET_DIR values. It reads fixtures or optional snapshots and
never edits files, mutates Beads, sends Agent Mail, runs Cargo, branches, or
stages changes.
"""

import argparse
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-heatmap-v1"
CONFLICT_GRAPH_SCHEMA_VERSION = "semantic-conflict-graph-v1"
TRACKER_PATHS = {".beads/issues.jsonl", ".beads/beads.db", ".beads/beads.db-wal"}
TARGET_DIR_RE = re.compile(r"CARGO_TARGET_DIR(?:=|:)\s*`?([^`\s,;)]+)")
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


def timestamp_key(value: str) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return ""
    return parsed.isoformat()


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


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
            return value
    return ""


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").rstrip("/")


def has_glob_magic(path: str) -> bool:
    return any(char in path for char in "*?[")


def path_matches(pattern: str, path: str) -> bool:
    pattern = normalize_path(pattern)
    path = normalize_path(path)
    if not pattern or not path:
        return False
    if pattern == path or fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path):
        return True
    pattern_is_glob = has_glob_magic(pattern)
    path_is_glob = has_glob_magic(path)
    return (not pattern_is_glob and path.startswith(f"{pattern}/")) or (
        not path_is_glob and pattern.startswith(f"{path}/")
    )


def path_overlaps(left: str, right: str) -> bool:
    return path_matches(left, right) or path_matches(right, left)


def is_active_reservation(row: dict[str, Any], now: str) -> bool:
    if row.get("released_ts") or row.get("released_at"):
        return False
    expires_at = parse_timestamp(str(row.get("expires_ts") or row.get("expires_at") or ""))
    now_ts = parse_timestamp(now) or dt.datetime.now(dt.timezone.utc)
    return expires_at is None or expires_at > now_ts


def reservation_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(
        agent_mail,
        ("reservations", "active_reservations", "file_reservations", "granted"),
    )
    rows.extend(rows_from(source, ("reservations", "active_reservations")))
    return rows


def message_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(agent_mail, ("messages", "inbox", "threads"))
    rows.extend(rows_from(source, ("messages", "inbox", "threads")))
    return rows


def agent_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    agent_mail = source.get("agent_mail", {}) if isinstance(source, dict) else {}
    rows = rows_from(agent_mail, ("agents",))
    rows.extend(rows_from(source, ("agents",)))
    return rows


def bead_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    return rows_from(source, ("beads", "issues", "bead_assignments"))


def proof_lane_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows = rows_from(source, ("proof_lanes", "proof_surfaces"))
    validation = source.get("validation_frontier", {}) if isinstance(source, dict) else {}
    rows.extend(rows_from(validation, ("proof_lanes", "proof_surfaces")))
    return rows


def validation_blocker_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows = rows_from(source, ("validation_frontier_blockers", "blockers"))
    validation = source.get("validation_frontier", {}) if isinstance(source, dict) else {}
    rows.extend(rows_from(validation, ("blockers", "validation_frontier_blockers")))
    return rows


def dirty_entries(source: dict[str, Any]) -> list[dict[str, str]]:
    dirty = source.get("dirty_tree", {}) if isinstance(source, dict) else {}
    rows = dirty.get("entries") if isinstance(dirty, dict) else []
    entries: list[dict[str, str]] = []
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        for path in status_paths(status, str(item.get("path") or "")):
            entries.append({"status": status, "path": path})
    return sorted(entries, key=lambda row: row["path"])


def normalize_reservation(row: dict[str, Any], generated_at: str) -> dict[str, Any]:
    pattern = row_pattern(row)
    holder = holder_name(row)
    active = is_active_reservation(row, generated_at)
    released = bool(row.get("released_ts") or row.get("released_at"))
    if released:
        classification = "released"
    elif active:
        classification = "active"
    else:
        classification = "expired"
    return {
        "id": str(row.get("id") or ""),
        "path_pattern": pattern,
        "holder": holder or "unknown",
        "exclusive": bool(row.get("exclusive", True)),
        "expires_ts": str(row.get("expires_ts") or row.get("expires_at") or ""),
        "released": released,
        "classification": classification,
    }


def active_reservations(reservations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in reservations
        if row["classification"] == "active" and row["exclusive"] and row["path_pattern"]
    ]


def message_text(row: dict[str, Any]) -> str:
    return "\n".join(
        str(row.get(key, ""))
        for key in ("subject", "body_md", "body", "message", "thread_id", "paths", "target_dir")
    )


def target_dirs_for_agent(agent: str, messages: list[dict[str, Any]], agents: list[dict[str, Any]]) -> list[str]:
    dirs: set[str] = set()
    for row in agents:
        if holder_name(row) != agent:
            continue
        for key in ("target_dir", "cargo_target_dir"):
            value = row.get(key)
            if isinstance(value, str) and value:
                dirs.add(value)
        values = row.get("target_dirs")
        if isinstance(values, list):
            dirs.update(str(value) for value in values if isinstance(value, str) and value)
    for row in messages:
        if holder_name(row) != agent:
            continue
        text = message_text(row)
        dirs.update(match.group(1).strip("`'\"").rstrip(".") for match in TARGET_DIR_RE.finditer(text))
    return sorted(dirs)


def latest_activity(agent: str, messages: list[dict[str, Any]], agents: list[dict[str, Any]]) -> str:
    candidates: list[str] = []
    for row in agents:
        if holder_name(row) == agent:
            for key in ("last_active_ts", "last_seen_ts", "updated_at", "created_ts"):
                value = row.get(key)
                if isinstance(value, str) and value:
                    candidates.append(value)
    for row in messages:
        if holder_name(row) == agent:
            value = row.get("created_ts") or row.get("created_at")
            if isinstance(value, str) and value:
                candidates.append(value)
    return max(candidates, key=timestamp_key) if candidates else ""


def reservation_owner_for_path(path: str, reservations: list[dict[str, Any]]) -> dict[str, Any] | None:
    for row in reservations:
        if path_matches(row["path_pattern"], path):
            return row
    return None


def message_owner_for_path(path: str, messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [row for row in messages if path in message_text(row)]
    if not matches:
        return None
    return max(matches, key=lambda row: timestamp_key(str(row.get("created_ts") or row.get("created_at") or "")))


def dirty_rows(
    entries: list[dict[str, str]],
    agent: str,
    reservations: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in entries:
        path = entry["path"]
        reservation = reservation_owner_for_path(path, reservations)
        message = message_owner_for_path(path, messages)
        owner = reservation["holder"] if reservation else holder_name(message or {})
        source = "reservation" if reservation else "message" if message else "none"
        if path in TRACKER_PATHS:
            classification = "tracker-state"
            stay_off = True
        elif owner == agent:
            classification = "self-owned"
            stay_off = False
        elif owner:
            classification = "peer-owned"
            stay_off = True
        else:
            classification = "unattributed"
            stay_off = True
        rows.append(
            {
                "path": path,
                "status": entry["status"],
                "owner": owner,
                "owner_source": source,
                "classification": classification,
                "stay_off": stay_off,
            }
        )
    return rows


def reservation_overlaps(reservations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overlaps: list[dict[str, Any]] = []
    for left_index, left in enumerate(reservations):
        for right in reservations[left_index + 1 :]:
            if left["holder"] == right["holder"]:
                continue
            if not path_overlaps(left["path_pattern"], right["path_pattern"]):
                continue
            overlaps.append(
                {
                    "left_holder": left["holder"],
                    "left_path_pattern": left["path_pattern"],
                    "right_holder": right["holder"],
                    "right_path_pattern": right["path_pattern"],
                    "severity": "warning",
                }
            )
    return sorted(
        overlaps,
        key=lambda row: (
            row["left_path_pattern"],
            row["right_path_pattern"],
            row["left_holder"],
            row["right_holder"],
        ),
    )


def stay_off_surfaces(
    active: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    agent: str,
) -> list[dict[str, str]]:
    surfaces: list[dict[str, str]] = []
    for row in active:
        if row["holder"] == agent:
            continue
        surfaces.append(
            {
                "path": row["path_pattern"],
                "holder": row["holder"],
                "reason": "active peer reservation",
            }
        )
    for row in dirty:
        if not row["stay_off"]:
            continue
        holder = str(row.get("owner") or "unknown")
        surfaces.append(
            {
                "path": row["path"],
                "holder": holder,
                "reason": f"dirty {row['classification']}",
            }
        )
    unique = {(row["path"], row["holder"]): row for row in surfaces}
    return [unique[key] for key in sorted(unique)]


def open_surfaces(source: dict[str, Any], stay_off: list[dict[str, str]]) -> list[str]:
    blocked = [row["path"] for row in stay_off]
    candidates = source.get("candidate_surfaces", []) if isinstance(source, dict) else []
    open_paths = []
    for value in candidates if isinstance(candidates, list) else []:
        path = str(value)
        if path and not any(path_overlaps(path, blocked_path) for blocked_path in blocked):
            open_paths.append(path)
    return sorted(set(open_paths))


def active_agent_rows(
    reservations: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    agents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    names: set[str] = set()
    names.update(row["holder"] for row in reservations if row["holder"] != "unknown")
    names.update(row["owner"] for row in dirty if row["owner"])
    names.update(holder_name(row) for row in messages if holder_name(row))
    names.update(holder_name(row) for row in agents if holder_name(row))

    rows = []
    for name in sorted(names):
        agent_reservations = [row["path_pattern"] for row in reservations if row["holder"] == name]
        agent_dirty = [row["path"] for row in dirty if row["owner"] == name]
        agent_target_dirs = target_dirs_for_agent(name, messages, agents)
        if not agent_reservations and not agent_dirty and not agent_target_dirs:
            continue
        rows.append(
            {
                "name": name,
                "last_activity_ts": latest_activity(name, messages, agents),
                "active_reservations": agent_reservations,
                "dirty_paths": agent_dirty,
                "target_dirs": agent_target_dirs,
            }
        )
    return rows


def stable_id(kind: str, value: str) -> str:
    normalized = normalize_path(value) or "unknown"
    return f"{kind}:{normalized}"


def row_paths(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("path", "path_pattern", "pattern"):
        value = row.get(key)
        if isinstance(value, str) and value:
            paths.append(normalize_path(value))
    for key in ("paths", "touched_paths", "path_patterns", "surfaces"):
        values = row.get(key)
        if isinstance(values, list):
            paths.extend(normalize_path(str(value)) for value in values if str(value))
    return sorted(set(path for path in paths if path))


def proof_lane_id(row: dict[str, Any]) -> str:
    for key in ("lane_id", "id", "name", "proof_lane"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    paths = row_paths(row)
    return paths[0] if paths else "unknown"


def bead_id(row: dict[str, Any]) -> str:
    for key in ("id", "bead_id", "issue_id"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def reservation_node_id(row: dict[str, Any]) -> str:
    return stable_id("reservation", row["id"] or row["path_pattern"])


def contact_name_for_node(node: dict[str, Any]) -> str:
    owner = str(node.get("owner") or "")
    if owner:
        return owner
    if node.get("kind") == "agent":
        return str(node.get("label") or "")
    return ""


def upsert_node(nodes: dict[str, dict[str, Any]], node: dict[str, Any]) -> None:
    node_id = str(node.get("id") or "")
    if not node_id:
        return
    existing = nodes.get(node_id)
    if existing is None:
        nodes[node_id] = node
        return
    for key, value in node.items():
        if key not in existing or existing[key] in ("", [], None):
            existing[key] = value


def add_edge(
    edges: list[dict[str, Any]],
    source: str,
    target: str,
    kind: str,
    reason: str,
    severity: str = "info",
    path: str = "",
) -> None:
    if not source or not target:
        return
    edges.append(
        {
            "source": source,
            "target": target,
            "kind": kind,
            "reason": reason,
            "severity": severity,
            "path": normalize_path(path),
        }
    )


def lane_blockers(
    lane_paths: list[str],
    active: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for lane_path in lane_paths:
        for reservation in active:
            pattern = reservation["path_pattern"]
            if path_overlaps(lane_path, pattern):
                rows.append(
                    {
                        "node": reservation_node_id(reservation),
                        "kind": "reservation",
                        "path": pattern,
                        "owner": reservation["holder"],
                    }
                )
        for dirty_row in dirty:
            path = dirty_row["path"]
            if dirty_row["stay_off"] and path_overlaps(lane_path, path):
                rows.append(
                    {
                        "node": stable_id("dirty", path),
                        "kind": "dirty_path",
                        "path": path,
                        "owner": dirty_row.get("owner") or "unknown",
                    }
                )
        for blocker in blockers:
            for blocker_path in row_paths(blocker):
                if path_overlaps(lane_path, blocker_path):
                    rows.append(
                        {
                            "node": stable_id("validation_blocker", blocker_path),
                            "kind": "validation_blocker",
                            "path": blocker_path,
                            "owner": str(blocker.get("owner") or blocker.get("assignee") or "unknown"),
                        }
                    )
    unique = {(row["node"], row["path"], row["kind"]): row for row in rows}
    return [unique[key] for key in sorted(unique)]


def build_semantic_conflict_graph(
    source: dict[str, Any],
    agent: str,
    reservations: list[dict[str, Any]],
    active: list[dict[str, Any]],
    dirty: list[dict[str, Any]],
    active_agents: list[dict[str, Any]],
    overlaps: list[dict[str, Any]],
    open_surface_paths: list[str],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    upsert_node(nodes, {"id": stable_id("agent", agent), "kind": "agent", "label": agent})
    for row in active_agents:
        name = str(row.get("name") or "")
        upsert_node(nodes, {"id": stable_id("agent", name), "kind": "agent", "label": name})

    reservation_nodes_by_path = {
        reservation["path_pattern"]: reservation_node_id(reservation)
        for reservation in reservations
        if reservation["path_pattern"]
    }
    for reservation in reservations:
        node_id = reservation_node_id(reservation)
        upsert_node(
            nodes,
            {
                "id": node_id,
                "kind": "reservation",
                "path": reservation["path_pattern"],
                "owner": reservation["holder"],
                "classification": reservation["classification"],
            },
        )
        owner_id = stable_id("agent", reservation["holder"])
        upsert_node(nodes, {"id": owner_id, "kind": "agent", "label": reservation["holder"]})
        add_edge(edges, owner_id, node_id, "owns", "agent holds file reservation", path=reservation["path_pattern"])
        if reservation["classification"] == "expired":
            add_edge(
                edges,
                node_id,
                owner_id,
                "stale_owner",
                "reservation is expired but still informative history",
                severity="warning",
                path=reservation["path_pattern"],
            )

    for dirty_row in dirty:
        node_id = stable_id("dirty", dirty_row["path"])
        upsert_node(
            nodes,
            {
                "id": node_id,
                "kind": "dirty_path",
                "path": dirty_row["path"],
                "owner": dirty_row.get("owner") or "",
                "classification": dirty_row["classification"],
            },
        )
        owner = str(dirty_row.get("owner") or "")
        if owner:
            owner_id = stable_id("agent", owner)
            upsert_node(nodes, {"id": owner_id, "kind": "agent", "label": owner})
            add_edge(edges, owner_id, node_id, "owns", "agent owns dirty path evidence", path=dirty_row["path"])
        else:
            unknown_id = stable_id("agent", "unknown")
            upsert_node(nodes, {"id": unknown_id, "kind": "agent", "label": "unknown"})
            add_edge(
                edges,
                node_id,
                unknown_id,
                "unknown_owner",
                "dirty path has no reservation or message owner",
                severity="warning",
                path=dirty_row["path"],
            )

        if dirty_row["stay_off"]:
            reservation = reservation_owner_for_path(dirty_row["path"], active)
            if reservation is not None:
                add_edge(
                    edges,
                    reservation_node_id(reservation),
                    node_id,
                    "conflicts_with",
                    "active reservation overlaps dirty path",
                    severity="error",
                    path=dirty_row["path"],
                )

    for overlap in overlaps:
        add_edge(
            edges,
            reservation_nodes_by_path.get(
                overlap["left_path_pattern"],
                stable_id("reservation", overlap["left_path_pattern"]),
            ),
            reservation_nodes_by_path.get(
                overlap["right_path_pattern"],
                stable_id("reservation", overlap["right_path_pattern"]),
            ),
            "conflicts_with",
            "exclusive reservations overlap",
            severity=overlap["severity"],
            path=overlap["left_path_pattern"],
        )

    for bead in bead_rows(source):
        current_bead_id = bead_id(bead)
        node_id = stable_id("bead", current_bead_id)
        assignee = str(bead.get("assignee") or bead.get("owner") or "")
        upsert_node(
            nodes,
            {
                "id": node_id,
                "kind": "bead",
                "label": current_bead_id,
                "owner": assignee,
                "status": str(bead.get("status") or ""),
            },
        )
        if assignee:
            owner_id = stable_id("agent", assignee)
            upsert_node(nodes, {"id": owner_id, "kind": "agent", "label": assignee})
            add_edge(edges, owner_id, node_id, "owns", "agent is assigned bead")

    blockers = validation_blocker_rows(source)
    for blocker in blockers:
        for path in row_paths(blocker):
            node_id = stable_id("validation_blocker", path)
            owner = str(blocker.get("owner") or blocker.get("assignee") or "")
            upsert_node(
                nodes,
                {
                    "id": node_id,
                    "kind": "validation_blocker",
                    "path": path,
                    "owner": owner,
                    "lane_id": str(blocker.get("lane_id") or blocker.get("proof_lane") or ""),
                    "status": str(blocker.get("status") or blocker.get("classification") or "blocked"),
                },
            )

    for lane in proof_lane_rows(source):
        lane_id = proof_lane_id(lane)
        lane_node = stable_id("proof_lane", lane_id)
        lane_paths = row_paths(lane)
        upsert_node(
            nodes,
            {
                "id": lane_node,
                "kind": "proof_lane",
                "label": lane_id,
                "paths": lane_paths,
                "release_blocking": bool(lane.get("release_blocking", True)),
            },
        )
        blockers_for_lane = lane_blockers(lane_paths, active, dirty, blockers)
        if blockers_for_lane:
            for blocker in blockers_for_lane:
                add_edge(
                    edges,
                    blocker["node"],
                    lane_node,
                    "blocks_proof",
                    f"{blocker['kind']} overlaps proof lane",
                    severity="error",
                    path=blocker["path"],
                )
        else:
            for lane_path in lane_paths:
                clean_node = stable_id("surface", lane_path)
                upsert_node(nodes, {"id": clean_node, "kind": "surface", "path": lane_path, "classification": "clean"})
                add_edge(
                    edges,
                    lane_node,
                    clean_node,
                    "clean_surface",
                    "proof lane path has no current reservation or dirty blocker",
                    path=lane_path,
                )

    for path in open_surface_paths:
        node_id = stable_id("surface", path)
        upsert_node(nodes, {"id": node_id, "kind": "surface", "path": path, "classification": "clean"})

    conflict_kinds = {"conflicts_with", "blocks_proof", "stale_owner", "unknown_owner"}
    conflict_edges = [edge for edge in edges if edge["kind"] in conflict_kinds]
    counts_by_kind: dict[str, int] = {}
    for edge in conflict_edges:
        counts_by_kind[edge["kind"]] = counts_by_kind.get(edge["kind"], 0) + 1
    dominant = "none"
    if counts_by_kind:
        dominant = sorted(counts_by_kind.items(), key=lambda item: (-item[1], item[0]))[0][0]

    contact_targets = sorted(
        {
            contact_name_for_node(nodes.get(edge["source"], {}))
            for edge in conflict_edges
        }
        | {
            contact_name_for_node(nodes.get(edge["target"], {}))
            for edge in conflict_edges
        }
    )
    contact_targets = [name for name in contact_targets if name and name not in {agent, "unknown"}]
    clean_lanes = sorted(
        {
            edge["source"].removeprefix("proof_lane:")
            for edge in edges
            if edge["kind"] == "clean_surface"
        }
    )

    deduped_edges = {
        (
            edge["source"],
            edge["target"],
            edge["kind"],
            edge["path"],
        ): edge
        for edge in edges
    }
    return {
        "schema_version": CONFLICT_GRAPH_SCHEMA_VERSION,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(deduped_edges),
            "conflict_count": len(conflict_edges),
            "dominant_conflict_class": dominant,
            "owner_contact_targets": contact_targets,
            "suggested_narrow_proof": clean_lanes[0] if clean_lanes else "",
            "clean_surfaces": open_surface_paths,
        },
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": [
            deduped_edges[key]
            for key in sorted(
                deduped_edges,
                key=lambda item: (item[2], item[0], item[1], item[3]),
            )
        ],
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


def parse_status_lines(raw: str) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        if len(line) >= 4:
            status = line[:2]
            for path in status_paths(status, line[3:]):
                entries.append({"status": status, "path": path})
    return entries


def status_paths(status: str, path: str) -> list[str]:
    if not path:
        return []
    if ("R" in status or "C" in status) and " -> " in path:
        return [part for part in path.split(" -> ", 1) if part]
    return [path]


def live_probe(
    repo_path: Path,
    timeout: float,
    agents: Any,
    reservations: Any,
    messages: Any,
) -> dict[str, Any]:
    status, raw_status = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)
    return {
        "agents": rows_from(agents, ("agents",)),
        "agent_mail": {
            "available": bool(agents or reservations or messages),
            "status": "snapshot" if agents or reservations or messages else "snapshot-unavailable",
            "reservations": rows_from(reservations, ("reservations", "active_reservations", "granted")),
            "messages": rows_from(messages, ("messages", "inbox", "threads")),
        },
        "dirty_tree": {
            "status": status,
            "entries": parse_status_lines(raw_status if status == "ok" else ""),
        },
    }


def build_heatmap(
    source: dict[str, Any],
    repo_path: str,
    agent: str,
    generated_at: str,
) -> dict[str, Any]:
    reservations = [normalize_reservation(row, generated_at) for row in reservation_rows(source)]
    active = active_reservations(reservations)
    messages = message_rows(source)
    agents = agent_rows(source)
    dirty = dirty_rows(dirty_entries(source), agent, active, messages)
    stay_off = stay_off_surfaces(active, dirty, agent)
    active_agents = active_agent_rows(active, dirty, messages, agents)
    overlaps = reservation_overlaps(active)
    open_surface_paths = open_surfaces(source, stay_off)
    target_dirs = sorted(
        {
            target_dir
            for row in active_agents
            for target_dir in row["target_dirs"]
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": agent,
        "repo_path": repo_path,
        "summary": {
            "active_agents": len(active_agents),
            "active_reservations": len(active),
            "expired_or_released_reservations": sum(
                1 for row in reservations if row["classification"] != "active"
            ),
            "dirty_paths": len(dirty),
            "stay_off_surfaces": len(stay_off),
            "target_dirs": len(target_dirs),
        },
        "active_agents": active_agents,
        "reservations": {
            "active": active,
            "expired_or_released": [
                row for row in reservations if row["classification"] != "active"
            ],
            "overlaps": overlaps,
        },
        "dirty_paths": dirty,
        "target_dirs": target_dirs,
        "suggested_stay_off_surfaces": stay_off,
        "suggested_open_surfaces": open_surface_paths,
        "semantic_conflict_graph": build_semantic_conflict_graph(
            source=source,
            agent=agent,
            reservations=reservations,
            active=active,
            dirty=dirty,
            active_agents=active_agents,
            overlaps=overlaps,
            open_surface_paths=open_surface_paths,
        ),
        "subsystems": {
            "git": str(source.get("dirty_tree", {}).get("status", "ok")),
            "agent_mail": str(source.get("agent_mail", {}).get("status", "fixture")),
        },
        "safety": {
            "mutating_commands_executed": False,
            "beads_mutated": False,
            "cargo_executed": False,
            "agent_mail_mutated": False,
            "branch_or_worktree_operations": False,
            "forbidden_command_tokens": [],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a read-only shared-main swarm heatmap.")
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="unknown", help="Current agent name")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument("--agents-snapshot", type=Path, help="Optional Agent Mail agents JSON snapshot")
    parser.add_argument("--reservation-snapshot", type=Path, help="Optional reservation JSON snapshot")
    parser.add_argument("--message-snapshot", type=Path, help="Optional Agent Mail messages JSON snapshot")
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
            agents=load_json(args.agents_snapshot),
            reservations=load_json(args.reservation_snapshot),
            messages=load_json(args.message_snapshot),
        )
    receipt = build_heatmap(
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
