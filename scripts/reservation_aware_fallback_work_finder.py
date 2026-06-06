#!/usr/bin/env python3
"""Emit deterministic shared-main fallback-work recommendations.

The helper is intentionally read-only. It consumes an explicit fixture or
contract artifact and writes JSON or Markdown to stdout. It does not run Cargo,
inspect Git, mutate beads, query Agent Mail, or rewrite artifacts.
"""

import argparse
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "reservation-aware-fallback-work-finder-v1"
FIXTURE_SCHEMA_VERSION = "reservation-aware-fallback-work-finder-fixture-v1"
CONTRACT_SCHEMA_VERSION = "reservation-aware-fallback-work-finder-contract-v1"

BASE_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-reserved-paths",
    "do-not-override-agent-mail-reservations",
    "do-not-accept-local-cargo-fallback",
]

GLOBAL_NON_CLAIMS = [
    "The finder recommends a next action; it does not certify source correctness.",
    "Fixture-derived reservation state does not override live Agent Mail reservations.",
    "No recommendation authorizes branch/worktree creation or editing peer-owned paths.",
    "Cargo validation remains remote-required through RCH; local fallback is never proof.",
]

TRACKER_PREFIXES = (".beads/", ".agent-mail/", "agent-mail/")

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "blocked-by-active-reservation": {
        "severity": 90,
        "recommended_action": "coordinate-or-wait-for-reservation",
        "operator_action": "Coordinate with the reservation holder or wait; do not edit the overlapped files.",
    },
    "source-peer-dirt": {
        "severity": 85,
        "recommended_action": "avoid-peer-source-dirt",
        "operator_action": "Treat peer-owned source dirt as off-limits and choose another safe lane.",
    },
    "no-useful-bead": {
        "severity": 80,
        "recommended_action": "stop-with-explicit-blocker",
        "operator_action": "Stop with the named blocker instead of inventing untracked source work.",
    },
    "stale-in-progress-candidate": {
        "severity": 70,
        "recommended_action": "reopen-stale-in-progress",
        "operator_action": "Reopen or adopt the stale in-progress bead only when inactivity and reservations allow it.",
    },
    "epic-only-ready-queue": {
        "severity": 60,
        "recommended_action": "create-child-bead-before-source-work",
        "operator_action": "Create or select a concrete child bead before touching source files.",
    },
    "planning-fallback-recommended": {
        "severity": 50,
        "recommended_action": "create-planning-fallback-bead",
        "operator_action": "Create a bounded planning/test-only fallback bead on the approved surfaces.",
    },
    "claimable-ready-task": {
        "severity": 40,
        "recommended_action": "claim-ready-task",
        "operator_action": "Claim the ready non-epic task and reserve exactly its touched paths.",
    },
    "tracker-only-dirt": {
        "severity": 30,
        "recommended_action": "proceed-with-tracker-only-closeout",
        "operator_action": "Proceed with tracker-only closeout while leaving all source dirt untouched.",
    },
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def load_fixture(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: fixture must be a JSON object")
    fixture = value.get("fixture") if isinstance(value.get("fixture"), dict) else value
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: fixture schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    return fixture


def is_tracker_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in TRACKER_PREFIXES)


def issue_paths(issue: dict[str, Any]) -> list[str]:
    paths = string_list(issue.get("touched_paths"))
    if paths:
        return sorted(set(paths))
    return sorted(set(string_list(issue.get("files"))))


def reservation_paths(reservation: dict[str, Any]) -> list[str]:
    return sorted(set(string_list(reservation.get("paths"))))


def active_peer_reservations(
    scenario: dict[str, Any],
    self_agent: str,
) -> list[dict[str, Any]]:
    active_statuses = {"active", "held", "open", "reserved"}
    peers: list[dict[str, Any]] = []
    for reservation in dict_list(scenario.get("active_reservations")):
        status = string(reservation.get("status")) or "active"
        holder = string(reservation.get("agent")) or string(reservation.get("holder"))
        if status in active_statuses and holder and holder != self_agent:
            peers.append(reservation)
    return peers


def path_matches(pattern: str, path: str) -> bool:
    if pattern == path:
        return True
    if pattern.endswith("/") and path.startswith(pattern):
        return True
    if fnmatch.fnmatchcase(path, pattern):
        return True
    return fnmatch.fnmatchcase(pattern, path)


def reservation_overlaps(
    paths: list[str],
    reservations: list[dict[str, Any]],
) -> list[str]:
    overlaps: list[str] = []
    for path in paths:
        for reservation in reservations:
            holder = string(reservation.get("agent")) or string(reservation.get("holder"))
            for pattern in reservation_paths(reservation):
                if path_matches(pattern, path):
                    overlaps.append(f"{path} via {pattern} held by {holder}")
    return sorted(set(overlaps))


def reservation_avoid_paths(reservations: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for reservation in reservations:
        paths.extend(reservation_paths(reservation))
    return sorted(set(paths))


def dirty_paths(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_list(scenario.get("dirty_paths"))


def dirty_path_strings(entries: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            string(entry.get("path"))
            for entry in entries
            if string(entry.get("path"))
        }
    )


def source_dirty_entries(
    scenario: dict[str, Any],
    self_agent: str,
) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for entry in dirty_paths(scenario):
        path = string(entry.get("path"))
        owner = string(entry.get("owner")) or string(entry.get("agent"))
        if path and not is_tracker_path(path) and owner and owner != self_agent:
            sources.append(entry)
    return sources


def tracker_dirty_entries(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    trackers: list[dict[str, Any]] = []
    for entry in dirty_paths(scenario):
        path = string(entry.get("path"))
        if path and is_tracker_path(path):
            trackers.append(entry)
    return trackers


def is_epic(issue: dict[str, Any]) -> bool:
    issue_type = string(issue.get("issue_type")).lower()
    labels = [label.lower() for label in string_list(issue.get("labels"))]
    return issue_type == "epic" or "epic" in labels


def candidate_stale_issue(
    scenario: dict[str, Any],
    threshold_hours: int,
    peer_reservations: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    candidates: list[tuple[int, dict[str, Any], list[str]]] = []
    for issue in dict_list(scenario.get("in_progress_issues")):
        idle_hours = int_value(issue.get("idle_hours"))
        overlaps = reservation_overlaps(issue_paths(issue), peer_reservations)
        if idle_hours >= threshold_hours and not overlaps:
            candidates.append((idle_hours, issue, overlaps))
    if not candidates:
        return None, []
    _, issue, overlaps = sorted(candidates, key=lambda item: (-item[0], string(item[1].get("id"))))[0]
    return issue, overlaps


def base_forbidden(extra: list[str] | None = None) -> list[str]:
    actions = list(BASE_FORBIDDEN_ACTIONS)
    if extra:
        actions.extend(extra)
    return sorted(set(actions))


def row_for(
    scenario: dict[str, Any],
    classification: str,
    *,
    safe_to_start_work: bool,
    claim_issue_id: str | None = None,
    reopen_issue_id: str | None = None,
    create_new_bead: bool = False,
    edit_allowed_paths: list[str] | None = None,
    avoid_paths: list[str] | None = None,
    forbidden_actions: list[str] | None = None,
    blockers: list[str] | None = None,
    reservation_overlaps: list[str] | None = None,
    tracker_dirty_paths: list[str] | None = None,
    source_dirty_paths: list[str] | None = None,
) -> dict[str, Any]:
    catalog = CLASSIFICATION_CATALOG[classification]
    return {
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": catalog["severity"],
        "recommended_action": catalog["recommended_action"],
        "safe_to_start_work": safe_to_start_work,
        "claim_issue_id": claim_issue_id,
        "reopen_issue_id": reopen_issue_id,
        "create_new_bead": create_new_bead,
        "edit_allowed_paths": sorted(set(edit_allowed_paths or [])),
        "avoid_paths": sorted(set(avoid_paths or [])),
        "forbidden_actions": base_forbidden(forbidden_actions),
        "blockers": sorted(set(blockers or [])),
        "reservation_overlaps": sorted(set(reservation_overlaps or [])),
        "tracker_dirty_paths": sorted(set(tracker_dirty_paths or [])),
        "source_dirty_paths": sorted(set(source_dirty_paths or [])),
        "operator_action": catalog["operator_action"],
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def classify_scenario(
    scenario: dict[str, Any],
    self_agent: str,
    stale_threshold_hours: int,
) -> dict[str, Any]:
    peer_reservations = active_peer_reservations(scenario, self_agent)
    source_dirty = source_dirty_entries(scenario, self_agent)
    tracker_dirty = tracker_dirty_entries(scenario)
    ready_issues = dict_list(scenario.get("ready_issues"))
    non_epic_ready = [issue for issue in ready_issues if not is_epic(issue)]
    epic_ready = [issue for issue in ready_issues if is_epic(issue)]

    if non_epic_ready:
        issue = non_epic_ready[0]
        touched_paths = issue_paths(issue)
        overlaps = reservation_overlaps(touched_paths, peer_reservations)
        if overlaps:
            return row_for(
                scenario,
                "blocked-by-active-reservation",
                safe_to_start_work=False,
                avoid_paths=reservation_avoid_paths(peer_reservations) + touched_paths,
                forbidden_actions=["do-not-force-release-active-reservations"],
                blockers=[
                    f"ready issue {string(issue.get('id'))} overlaps an active peer reservation"
                ],
                reservation_overlaps=overlaps,
                source_dirty_paths=dirty_path_strings(source_dirty),
                tracker_dirty_paths=dirty_path_strings(tracker_dirty),
            )
        return row_for(
            scenario,
            "claimable-ready-task",
            safe_to_start_work=True,
            claim_issue_id=string(issue.get("id")),
            edit_allowed_paths=touched_paths,
            avoid_paths=dirty_path_strings(source_dirty),
            source_dirty_paths=dirty_path_strings(source_dirty),
            tracker_dirty_paths=dirty_path_strings(tracker_dirty),
        )

    if ready_issues and len(epic_ready) == len(ready_issues):
        epic_ids = ", ".join(string(issue.get("id")) for issue in epic_ready)
        return row_for(
            scenario,
            "epic-only-ready-queue",
            safe_to_start_work=False,
            create_new_bead=True,
            avoid_paths=reservation_avoid_paths(peer_reservations)
            + dirty_path_strings(source_dirty),
            blockers=[f"ready queue contains only epic issue(s): {epic_ids}"],
            source_dirty_paths=dirty_path_strings(source_dirty),
            tracker_dirty_paths=dirty_path_strings(tracker_dirty),
        )

    stale_issue, stale_overlaps = candidate_stale_issue(
        scenario,
        stale_threshold_hours,
        peer_reservations,
    )
    if stale_issue is not None:
        return row_for(
            scenario,
            "stale-in-progress-candidate",
            safe_to_start_work=True,
            reopen_issue_id=string(stale_issue.get("id")),
            edit_allowed_paths=issue_paths(stale_issue),
            avoid_paths=dirty_path_strings(source_dirty),
            reservation_overlaps=stale_overlaps,
            source_dirty_paths=dirty_path_strings(source_dirty),
            tracker_dirty_paths=dirty_path_strings(tracker_dirty),
        )

    if source_dirty:
        return row_for(
            scenario,
            "source-peer-dirt",
            safe_to_start_work=False,
            avoid_paths=dirty_path_strings(source_dirty)
            + reservation_avoid_paths(peer_reservations),
            forbidden_actions=["do-not-stage-peer-dirty-source"],
            blockers=["dirty source paths are owned by another active lane"],
            source_dirty_paths=dirty_path_strings(source_dirty),
            tracker_dirty_paths=dirty_path_strings(tracker_dirty),
        )

    if tracker_dirty and len(tracker_dirty) == len(dirty_paths(scenario)):
        tracker_paths = dirty_path_strings(tracker_dirty)
        return row_for(
            scenario,
            "tracker-only-dirt",
            safe_to_start_work=True,
            edit_allowed_paths=tracker_paths,
            tracker_dirty_paths=tracker_paths,
        )

    fallback_surfaces = string_list(scenario.get("approved_fallback_surfaces"))
    if fallback_surfaces:
        return row_for(
            scenario,
            "planning-fallback-recommended",
            safe_to_start_work=True,
            create_new_bead=True,
            edit_allowed_paths=fallback_surfaces,
            avoid_paths=reservation_avoid_paths(peer_reservations),
        )

    return row_for(
        scenario,
        "no-useful-bead",
        safe_to_start_work=False,
        avoid_paths=reservation_avoid_paths(peer_reservations),
        blockers=["no claimable ready task, stale candidate, tracker-only lane, or approved fallback surface"],
    )


def build_report(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    self_agent = string(fixture.get("self_agent")) or "unknown-agent"
    stale_threshold_hours = int_value(fixture.get("stale_threshold_hours"), 24)
    rows = [
        classify_scenario(scenario, self_agent, stale_threshold_hours)
        for scenario in dict_list(fixture.get("scenarios"))
    ]
    rows.sort(key=lambda row: (-int_value(row.get("severity")), string(row.get("scenario_id"))))

    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1

    summary = {
        "scenario_count": len(rows),
        "safe_to_start_work": sum(1 for row in rows if row["safe_to_start_work"]),
        "create_new_bead": sum(1 for row in rows if row["create_new_bead"]),
        "claimable_ready_tasks": sum(1 for row in rows if row["claim_issue_id"]),
        "reopen_candidates": sum(1 for row in rows if row["reopen_issue_id"]),
        "blocked_actions": sum(1 for row in rows if not row["safe_to_start_work"]),
        "highest_ranked_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "self_agent": self_agent,
        "stale_threshold_hours": stale_threshold_hours,
        "classification_catalog": CLASSIFICATION_CATALOG,
        "policy": {
            "base_forbidden_actions": list(BASE_FORBIDDEN_ACTIONS),
            "non_claims": list(GLOBAL_NON_CLAIMS),
        },
        "summary": summary,
        "rows": rows,
    }


def comma_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Reservation-Aware Fallback Work Finder",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Scenarios: {summary['scenario_count']}",
        f"- Safe to start: {summary['safe_to_start_work']}",
        f"- Blocked actions: {summary['blocked_actions']}",
        f"- Highest ranked scenario: `{summary['highest_ranked_scenario']}`",
        "",
        "| Scenario | Classification | Action | Safe | Blockers | Avoid paths |",
        "|---|---|---:|---:|---|---|",
    ]
    for row in report["rows"]:
        lines.append(
            "| {scenario} | `{classification}` | `{action}` | {safe} | {blockers} | {avoid} |".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                action=row["recommended_action"],
                safe="yes" if row["safe_to_start_work"] else "no",
                blockers=comma_or_dash(row["blockers"]),
                avoid=comma_or_dash(row["avoid_paths"]),
            )
        )

    lines.extend(
        [
            "",
            "## Forbidden Actions",
            "",
        ]
    )
    for action in report["policy"]["base_forbidden_actions"]:
        lines.append(f"- `{action}`")

    lines.extend(
        [
            "",
            "## Non-Claims",
            "",
        ]
    )
    for non_claim in report["policy"]["non_claims"]:
        lines.append(f"- {non_claim}")

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit read-only reservation-aware fallback work recommendations."
    )
    parser.add_argument(
        "--fixture",
        required=True,
        type=Path,
        help="fixture JSON or contract artifact containing a fixture object",
    )
    parser.add_argument(
        "--generated-at",
        default=utc_now(),
        help="deterministic timestamp for contract tests",
    )
    parser.add_argument(
        "--output",
        choices=["json", "markdown"],
        default="json",
        help="output format",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    fixture = load_fixture(args.fixture)
    report = build_report(fixture, args.generated_at)
    if args.output == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(markdown_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
