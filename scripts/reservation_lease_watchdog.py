#!/usr/bin/env python3
"""Emit deterministic reservation lease watchdog reports.

The helper consumes explicit fixture snapshots for Agent Mail reservations,
proof-lane envelopes, command provenance, current time, and expected remaining
proof duration. It does not query Agent Mail, run commands, mutate beads, inspect
Git state, or write artifacts.
"""

import argparse
import copy
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "reservation-lease-watchdog-report-v1"
FIXTURE_SCHEMA_VERSION = "reservation-lease-watchdog-fixture-v1"
CONTRACT_SCHEMA_VERSION = "reservation-lease-watchdog-contract-v1"

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-reserved-paths",
    "do-not-assume-expired-reservations-cover-validation",
    "do-not-hide-renewal-failure",
    "do-not-cite-local-fallback-as-rch-proof",
    "do-not-close-lane-with-missing-command-provenance",
]

GLOBAL_NON_CLAIMS = [
    "This watchdog classifies reservation coverage; it does not prove source correctness.",
    "Fixture snapshots do not override live Agent Mail reservation state.",
    "A renewal plan is not a renewal receipt; closeout evidence must include the explicit result.",
    "Cargo validation remains remote-required through RCH; local fallback is never proof.",
]

ACTIVE_STATUSES = {"active", "held", "open", "reserved"}
RENEWAL_SUCCESS_STATUSES = {"success", "succeeded", "ok", "renewed"}

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "command-provenance-missing": {
        "severity": 100,
        "coverage_admissible": False,
        "fail_closed": True,
        "recommended_action": "record-command-provenance-before-proof",
        "operator_action": "Do not run or close the proof lane until argv, env, envelope, and source fingerprint are present.",
    },
    "conflicting-reservation": {
        "severity": 95,
        "coverage_admissible": False,
        "fail_closed": True,
        "recommended_action": "coordinate-with-reservation-holder",
        "operator_action": "Stop the lane or coordinate; an active peer reservation overlaps an owned path.",
    },
    "expired-reservation": {
        "severity": 90,
        "coverage_admissible": False,
        "fail_closed": True,
        "recommended_action": "re-reserve-and-revalidate",
        "operator_action": "Do not cite the proof interval as covered; at least one owned reservation is already expired.",
    },
    "missing-reservation": {
        "severity": 85,
        "coverage_admissible": False,
        "fail_closed": True,
        "recommended_action": "reserve-missing-paths-before-validation",
        "operator_action": "Reserve every owned path before running the long proof lane.",
    },
    "renewal-failure": {
        "severity": 80,
        "coverage_admissible": False,
        "fail_closed": True,
        "recommended_action": "retry-renewal-or-stop-before-closeout",
        "operator_action": "Do not hide the failed renewal; closeout evidence is incomplete until renewal succeeds and is recorded.",
    },
    "renew-needed": {
        "severity": 50,
        "coverage_admissible": False,
        "fail_closed": False,
        "recommended_action": "renew-reservations-before-proof-continues",
        "operator_action": "Renew the listed reservations or stop before the expected proof interval outlives the leases.",
    },
    "sufficient-ttl": {
        "severity": 10,
        "coverage_admissible": True,
        "fail_closed": False,
        "recommended_action": "continue-proof-lane",
        "operator_action": "The fixture shows enough reservation TTL for the expected remaining proof interval.",
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
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def sorted_strings(values: list[str]) -> list[str]:
    return sorted(set(value for value in values if value))


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


def merge_defaults(defaults: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(defaults)
    for key, value in scenario.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_defaults(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def expanded_scenarios(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    defaults = fixture.get("scenario_defaults")
    if not isinstance(defaults, dict):
        defaults = {}
    return [
        merge_defaults(defaults, scenario)
        for scenario in dict_list(fixture.get("scenarios"))
    ]


def parse_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def seconds_between(left: dt.datetime, right: dt.datetime) -> int:
    return int((right - left).total_seconds())


def seconds_until(current: str, expires_at: str) -> int | None:
    parsed_current = parse_timestamp(current)
    parsed_expires = parse_timestamp(expires_at)
    if parsed_current is None or parsed_expires is None:
        return None
    return seconds_between(parsed_current, parsed_expires)


def coverage_until(
    current_time: str,
    expected_remaining_seconds: int,
    renewal_threshold_seconds: int,
) -> str:
    current = parse_timestamp(current_time)
    if current is None:
        return ""
    until = current + dt.timedelta(
        seconds=expected_remaining_seconds + renewal_threshold_seconds
    )
    return until.isoformat().replace("+00:00", "Z")


def path_matches(pattern: str, path: str) -> bool:
    if pattern == path:
        return True
    if pattern.endswith("/") and path.startswith(pattern):
        return True
    if fnmatch.fnmatchcase(path, pattern):
        return True
    return fnmatch.fnmatchcase(pattern, path)


def reservation_path(reservation: dict[str, Any]) -> str:
    return string(reservation.get("path")) or string(reservation.get("path_pattern"))


def reservation_holder(reservation: dict[str, Any]) -> str:
    return string(reservation.get("agent")) or string(reservation.get("holder"))


def reservation_is_active(reservation: dict[str, Any]) -> bool:
    status = string(reservation.get("status")) or "active"
    return status in ACTIVE_STATUSES


def matching_reservations(
    reservations: list[dict[str, Any]],
    path: str,
) -> list[dict[str, Any]]:
    return [
        reservation
        for reservation in reservations
        if path_matches(reservation_path(reservation), path)
    ]


def owned_reservations(
    reservations: list[dict[str, Any]],
    self_agent: str,
    path: str,
) -> list[dict[str, Any]]:
    return [
        reservation
        for reservation in matching_reservations(reservations, path)
        if reservation_holder(reservation) == self_agent
        and reservation_is_active(reservation)
        and bool_value(reservation.get("exclusive"), False)
    ]


def peer_conflicts(
    reservations: list[dict[str, Any]],
    self_agent: str,
    path: str,
) -> list[dict[str, Any]]:
    return [
        reservation
        for reservation in matching_reservations(reservations, path)
        if reservation_holder(reservation)
        and reservation_holder(reservation) != self_agent
        and reservation_is_active(reservation)
        and bool_value(reservation.get("exclusive"), False)
    ]


def command_provenance_blockers(lane: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    command = lane.get("command_provenance")
    if not isinstance(command, dict):
        return ["command_provenance:missing"]
    envelope = lane.get("proof_envelope")
    if not isinstance(envelope, dict):
        blockers.append("proof_envelope:missing")
    if not string(lane.get("bead_id")):
        blockers.append("lane:bead_id:missing")
    if not string(lane.get("command_id")):
        blockers.append("lane:command_id:missing")
    if not string_list(command.get("argv")):
        blockers.append("command_provenance:argv:missing")
    if not isinstance(command.get("env"), dict):
        blockers.append("command_provenance:env:missing")
    if not string(command.get("source_fingerprint")):
        blockers.append("command_provenance:source_fingerprint:missing")
    if not string(command.get("target_dir_class")):
        blockers.append("command_provenance:target_dir_class:missing")
    if isinstance(envelope, dict):
        for field in ["timeout_seconds", "memory_mb"]:
            if int_value(envelope.get(field), -1) <= 0:
                blockers.append(f"proof_envelope:{field}:missing")
        for field in ["remote_required", "no_local_fallback"]:
            if not bool_value(envelope.get(field), False):
                blockers.append(f"proof_envelope:{field}:must-be-true")
    return sorted_strings(blockers)


def reservation_state(
    scenario: dict[str, Any],
    self_agent: str,
) -> dict[str, Any]:
    current_time = string(scenario.get("current_time"))
    expected_remaining = int_value(scenario.get("expected_remaining_seconds"))
    renewal_threshold = int_value(scenario.get("renewal_threshold_seconds"))
    required_seconds = expected_remaining + renewal_threshold
    reservations = dict_list(scenario.get("active_reservations"))
    path_rows: list[dict[str, Any]] = []
    missing_paths: list[str] = []
    expired_paths: list[str] = []
    insufficient_ttl_paths: list[str] = []
    conflict_paths: list[str] = []
    conflict_details: list[str] = []
    ttl_values: list[int] = []

    for path in string_list(scenario.get("expected_paths")):
        owned = owned_reservations(reservations, self_agent, path)
        conflicts = peer_conflicts(reservations, self_agent, path)
        conflict_details.extend(
            f"{path} via {reservation_path(conflict)} held by {reservation_holder(conflict)}"
            for conflict in conflicts
        )
        if conflicts:
            conflict_paths.append(path)

        owned_rows: list[dict[str, Any]] = []
        best_ttl: int | None = None
        for reservation in owned:
            expires_at = string(reservation.get("expires_at"))
            ttl = seconds_until(current_time, expires_at)
            if ttl is not None:
                ttl_values.append(ttl)
                if best_ttl is None or ttl > best_ttl:
                    best_ttl = ttl
            owned_rows.append(
                {
                    "id": int_value(reservation.get("id")),
                    "path": reservation_path(reservation),
                    "holder": reservation_holder(reservation),
                    "exclusive": bool_value(reservation.get("exclusive"), False),
                    "status": string(reservation.get("status")) or "active",
                    "granted_at": string(reservation.get("granted_at")),
                    "expires_at": expires_at,
                    "ttl_remaining_seconds": ttl,
                }
            )

        if not owned:
            missing_paths.append(path)
            path_status = "missing"
        elif best_ttl is not None and best_ttl <= 0:
            expired_paths.append(path)
            path_status = "expired"
        elif best_ttl is None:
            expired_paths.append(path)
            path_status = "invalid-expiry"
        elif best_ttl < required_seconds:
            insufficient_ttl_paths.append(path)
            path_status = "renew-needed"
        else:
            path_status = "sufficient"

        path_rows.append(
            {
                "path": path,
                "status": path_status,
                "best_ttl_remaining_seconds": best_ttl,
                "required_coverage_seconds": required_seconds,
                "owned_reservations": owned_rows,
                "peer_conflicts": [
                    {
                        "id": int_value(conflict.get("id")),
                        "path": reservation_path(conflict),
                        "holder": reservation_holder(conflict),
                        "expires_at": string(conflict.get("expires_at")),
                    }
                    for conflict in conflicts
                ],
            }
        )

    return {
        "current_time": current_time,
        "expected_remaining_seconds": expected_remaining,
        "renewal_threshold_seconds": renewal_threshold,
        "required_coverage_seconds": required_seconds,
        "required_coverage_until": coverage_until(
            current_time,
            expected_remaining,
            renewal_threshold,
        ),
        "total_reservation_records": len(reservations),
        "expected_path_count": len(string_list(scenario.get("expected_paths"))),
        "owned_active_count": sum(
            len(owned_reservations(reservations, self_agent, path))
            for path in string_list(scenario.get("expected_paths"))
        ),
        "missing_paths": sorted_strings(missing_paths),
        "expired_paths": sorted_strings(expired_paths),
        "insufficient_ttl_paths": sorted_strings(insufficient_ttl_paths),
        "conflict_paths": sorted_strings(conflict_paths),
        "conflict_details": sorted_strings(conflict_details),
        "min_ttl_remaining_seconds": min(ttl_values) if ttl_values else None,
        "paths": sorted(path_rows, key=lambda row: string(row.get("path"))),
    }


def renewal_attempt_blockers(
    scenario: dict[str, Any],
    mode: str,
    renewal_needed_paths: list[str],
) -> list[str]:
    attempt = scenario.get("renewal_attempt")
    if not isinstance(attempt, dict):
        attempt = {}
    requested = bool_value(attempt.get("requested"), False)
    status = string(attempt.get("status")).lower()

    if requested and status not in RENEWAL_SUCCESS_STATUSES:
        return [
            "renewal_attempt:failed"
            if status
            else "renewal_attempt:status:missing"
        ]
    if mode == "renew" and renewal_needed_paths and not requested:
        return ["renewal_attempt:missing-explicit-result"]
    return []


def renewal_plan(
    scenario: dict[str, Any],
    renewal_needed_paths: list[str],
    *,
    classification: str,
) -> dict[str, Any]:
    ttl_seconds = int_value(scenario.get("renewal_ttl_seconds"))
    self_agent = string(scenario.get("self_agent"))
    reason = string(scenario.get("reservation_reason")) or string(
        scenario.get("scenario_id")
    )
    blocked = classification in {
        "command-provenance-missing",
        "conflicting-reservation",
        "expired-reservation",
        "missing-reservation",
        "renewal-failure",
    }
    return {
        "needed": bool(renewal_needed_paths),
        "blocked": blocked,
        "paths": sorted_strings(renewal_needed_paths),
        "ttl_seconds": ttl_seconds,
        "agent_name": self_agent,
        "reason": reason,
        "explicit_request_required": bool(renewal_needed_paths),
        "action": "blocked"
        if blocked
        else ("renew-reservations" if renewal_needed_paths else "no-op"),
    }


def classify_scenario(
    scenario: dict[str, Any],
    self_agent: str,
    mode: str,
) -> dict[str, Any]:
    lane = scenario.get("lane") if isinstance(scenario.get("lane"), dict) else {}
    provenance_gaps = command_provenance_blockers(lane)
    state = reservation_state(scenario, self_agent)
    renewal_paths = state["insufficient_ttl_paths"]
    blockers: list[str] = []

    if provenance_gaps:
        classification = "command-provenance-missing"
        blockers = provenance_gaps
    elif state["conflict_paths"]:
        classification = "conflicting-reservation"
        blockers = [
            f"reservation-conflict:{detail}"
            for detail in state["conflict_details"]
        ]
    elif state["expired_paths"]:
        classification = "expired-reservation"
        blockers = [
            f"reservation-expired:{path}" for path in state["expired_paths"]
        ]
    elif state["missing_paths"]:
        classification = "missing-reservation"
        blockers = [
            f"reservation-missing:{path}" for path in state["missing_paths"]
        ]
    else:
        renewal_gaps = renewal_attempt_blockers(scenario, mode, renewal_paths)
        if renewal_gaps:
            classification = "renewal-failure"
            blockers = renewal_gaps
        elif renewal_paths:
            classification = "renew-needed"
            blockers = [
                f"reservation-renew-needed:{path}" for path in renewal_paths
            ]
        else:
            classification = "sufficient-ttl"
            blockers = []

    catalog = CLASSIFICATION_CATALOG[classification]
    plan = renewal_plan(
        scenario,
        renewal_paths,
        classification=classification,
    )
    attempt = scenario.get("renewal_attempt")
    if not isinstance(attempt, dict):
        attempt = {}

    return {
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": catalog["severity"],
        "coverage_admissible": bool_value(catalog.get("coverage_admissible"), False),
        "fail_closed": bool_value(catalog.get("fail_closed"), False),
        "recommended_action": catalog["recommended_action"],
        "operator_action": catalog["operator_action"],
        "mode": mode,
        "lane": {
            "bead_id": string(lane.get("bead_id")),
            "command_id": string(lane.get("command_id")),
            "proof_envelope": lane.get("proof_envelope")
            if isinstance(lane.get("proof_envelope"), dict)
            else {},
            "command_provenance": lane.get("command_provenance")
            if isinstance(lane.get("command_provenance"), dict)
            else {},
        },
        "self_agent": self_agent,
        "expected_paths": sorted_strings(string_list(scenario.get("expected_paths"))),
        "reservation_summary": state,
        "renewal_plan": plan,
        "renewal_attempt": attempt,
        "blockers": sorted_strings(blockers),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def build_report(fixture: dict[str, Any], generated_at: str, mode: str) -> dict[str, Any]:
    self_agent = string(fixture.get("self_agent")) or "unknown-agent"
    rows = [
        classify_scenario(scenario, self_agent, mode)
        for scenario in expanded_scenarios(fixture)
    ]
    rows.sort(key=lambda row: (-int_value(row.get("severity")), string(row.get("scenario_id"))))
    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1

    summary = {
        "scenario_count": len(rows),
        "admissible_count": sum(1 for row in rows if row["coverage_admissible"]),
        "non_admissible_count": sum(1 for row in rows if not row["coverage_admissible"]),
        "renew_needed_count": sum(
            1 for row in rows if row["classification"] == "renew-needed"
        ),
        "fail_closed_count": sum(1 for row in rows if row["fail_closed"]),
        "renewal_request_count": sum(
            1 for row in rows if row["renewal_plan"]["needed"]
        ),
        "missing_path_count": sum(
            len(row["reservation_summary"]["missing_paths"]) for row in rows
        ),
        "conflict_count": sum(
            len(row["reservation_summary"]["conflict_paths"]) for row in rows
        ),
        "highest_severity_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "mode": mode,
        "self_agent": self_agent,
        "classification_catalog": CLASSIFICATION_CATALOG,
        "policy": {
            "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
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
        "# Reservation Lease Watchdog",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Mode: `{report['mode']}`",
        f"- Scenarios: {summary['scenario_count']}",
        f"- Admissible coverage: {summary['admissible_count']}",
        f"- Renewal requests: {summary['renewal_request_count']}",
        f"- Fail-closed rows: {summary['fail_closed_count']}",
        f"- Highest severity scenario: `{summary['highest_severity_scenario']}`",
        "",
        "| Scenario | Classification | Coverage | Action | Renewal Action | Renewal Paths | Blockers |",
        "|---|---|---:|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(
            "| {scenario} | `{classification}` | {coverage} | `{action}` | `{renewal_action}` | {paths} | {blockers} |".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                coverage="yes" if row["coverage_admissible"] else "no",
                action=row["recommended_action"],
                renewal_action=row["renewal_plan"]["action"],
                paths=comma_or_dash(row["renewal_plan"]["paths"]),
                blockers=comma_or_dash(row["blockers"]),
            )
        )

    lines.extend(["", "## Forbidden Actions", ""])
    for action in report["policy"]["forbidden_actions"]:
        lines.append(f"- `{action}`")

    lines.extend(["", "## Non-Claims", ""])
    for non_claim in report["policy"]["non_claims"]:
        lines.append(f"- {non_claim}")

    lines.append("")
    return "\n".join(lines)


def log_report(report: dict[str, Any]) -> str:
    lines = [
        "[watchdog] start fixture={fixture} generated_at={generated_at} mode={mode}".format(
            fixture=report["fixture_id"],
            generated_at=report["generated_at"],
            mode=report["mode"],
        )
    ]
    for row in report["rows"]:
        summary = row["reservation_summary"]
        lines.append(
            "[watchdog] scenario={scenario} classification={classification} coverage={coverage} "
            "expected_remaining={remaining}s required_coverage={required}s min_ttl={min_ttl}".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                coverage="admissible" if row["coverage_admissible"] else "not-admissible",
                remaining=summary["expected_remaining_seconds"],
                required=summary["required_coverage_seconds"],
                min_ttl=summary["min_ttl_remaining_seconds"],
            )
        )
        lines.append(
            "[watchdog] renewal action={action} paths={paths} blockers={blockers}".format(
                action=row["renewal_plan"]["action"],
                paths=comma_or_dash(row["renewal_plan"]["paths"]),
                blockers=comma_or_dash(row["blockers"]),
            )
        )
    lines.append("[watchdog] end")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit read-only reservation lease watchdog reports."
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
        help="UTC timestamp to embed in the report",
    )
    parser.add_argument(
        "--mode",
        choices=["dry-run", "renew"],
        default="dry-run",
        help="dry-run emits a renewal plan; renew requires explicit renewal result evidence in the fixture",
    )
    parser.add_argument(
        "--output",
        choices=["json", "markdown", "log"],
        default="json",
        help="output format",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    fixture = load_fixture(args.fixture)
    report = build_report(fixture, args.generated_at, args.mode)
    if args.output == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    elif args.output == "markdown":
        sys.stdout.write(markdown_report(report))
    else:
        sys.stdout.write(log_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
