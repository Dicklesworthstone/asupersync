#!/usr/bin/env python3
"""Emit deterministic br/bv tracker graph drift reports.

The helper is intentionally read-only. It consumes explicit fixture snapshots of
`br ready`, `br list`, `bv --robot-next`, and `bv --robot-triage` output, then
classifies whether the tracker graph is actionable, stale, divergent, or only
ready at a parent-planning surface. It does not run commands, mutate beads,
query Agent Mail, inspect Git, or rewrite artifacts.
"""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "tracker-graph-drift-report-v1"
FIXTURE_SCHEMA_VERSION = "tracker-graph-drift-fixture-v1"
CONTRACT_SCHEMA_VERSION = "tracker-graph-drift-contract-v1"

REQUIRED_COMMANDS = ["br-ready", "br-list", "bv-robot-next", "bv-robot-triage"]

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-dirty-files",
    "do-not-claim-parent-only-work-as-implementation",
    "do-not-treat-empty-bv-next-as-no-work-without-br-cross-check",
    "do-not-cite-stale-graph-snapshot-as-current",
]

GLOBAL_NON_CLAIMS = [
    "This report classifies tracker coordination state; it does not prove source correctness.",
    "Fixture snapshots do not override live br, bv, Git, or Agent Mail state.",
    "A parent-only ready queue is planning work, not authorization to edit source files.",
    "A matching br/bv recommendation still requires normal claim, reservation, validation, commit, and push workflow.",
]

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "command-provenance-failure": {
        "severity": 100,
        "recommended_action": "rerun-missing-or-failed-tracker-command",
        "operator_action": "Do not use this snapshot; rerun the failed or missing br/bv command with JSON output.",
    },
    "data-hash-mismatch": {
        "severity": 90,
        "recommended_action": "refresh-bv-snapshots",
        "operator_action": "Rerun bv robot commands from the same current graph before making a claim.",
    },
    "stale-graph-snapshot": {
        "severity": 80,
        "recommended_action": "refresh-stale-tracker-snapshot",
        "operator_action": "Refresh the stale br/bv snapshot before claiming or concluding no work exists.",
    },
    "br-ready-bv-empty-divergence": {
        "severity": 70,
        "recommended_action": "investigate-ready-queue-divergence",
        "operator_action": "Do not treat empty bv output as no work; inspect br/bv freshness and dependency state.",
    },
    "br-bv-actionable-mismatch": {
        "severity": 65,
        "recommended_action": "resolve-actionable-id-mismatch",
        "operator_action": "Do not claim until br ready and bv next agree on the actionable work or the mismatch is explained.",
    },
    "parent-only-ready-queue": {
        "severity": 55,
        "recommended_action": "create-or-select-child-bead",
        "operator_action": "Turn the parent surface into concrete child beads before editing source files.",
    },
    "consistent-actionable": {
        "severity": 30,
        "recommended_action": "claim-ready-task-with-reservations",
        "operator_action": "Claim the matching ready task and reserve its exact files before editing.",
    },
    "consistent-no-work": {
        "severity": 10,
        "recommended_action": "use-approved-planning-or-audit-fallback",
        "operator_action": "No actionable tracker work is visible in these snapshots; use an approved fallback lane.",
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


def parse_timestamp(value: str) -> dt.datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def age_seconds(now: str, then: str) -> int | None:
    parsed_now = parse_timestamp(now)
    parsed_then = parse_timestamp(then)
    if parsed_now is None or parsed_then is None:
        return None
    return max(0, int((parsed_now - parsed_then).total_seconds()))


def snapshot_timestamps(scenario: dict[str, Any]) -> dict[str, str]:
    timestamps: dict[str, str] = {}
    for key in ["br_ready", "br_list", "bv_next", "bv_triage"]:
        value = scenario.get(key)
        if isinstance(value, dict):
            timestamp = string(value.get("generated_at") or value.get("created_at"))
            if timestamp:
                timestamps[key] = timestamp
    return timestamps


def stale_inputs(
    scenario: dict[str, Any],
    generated_at: str,
    max_snapshot_age_seconds: int,
) -> list[str]:
    stale: list[str] = []
    for key, timestamp in snapshot_timestamps(scenario).items():
        age = age_seconds(generated_at, timestamp)
        if age is None:
            stale.append(f"{key}:unparseable-timestamp")
        elif age > max_snapshot_age_seconds:
            stale.append(f"{key}:age={age}s")
    return sorted(stale)


def command_failures(scenario: dict[str, Any]) -> list[str]:
    failures = string_list(scenario.get("command_failures"))
    provenance = scenario.get("command_provenance")
    if not isinstance(provenance, dict):
        return sorted(set(failures + ["missing-command-provenance"]))
    for command in REQUIRED_COMMANDS:
        row = provenance.get(command)
        if not isinstance(row, dict):
            failures.append(f"{command}:missing")
            continue
        if int_value(row.get("exit_code"), 1) != 0:
            failures.append(f"{command}:exit={int_value(row.get('exit_code'), 1)}")
        if not string(row.get("command")):
            failures.append(f"{command}:missing-command")
    return sorted(set(failures))


def bv_data_hashes(scenario: dict[str, Any]) -> list[str]:
    hashes: list[str] = []
    for key in ["bv_next", "bv_triage"]:
        value = scenario.get(key)
        if isinstance(value, dict):
            data_hash = string(value.get("data_hash"))
            if data_hash:
                hashes.append(data_hash)
    return sorted(set(hashes))


def data_hash_mismatch(scenario: dict[str, Any]) -> bool:
    hashes = bv_data_hashes(scenario)
    return len(hashes) > 1


def ready_payload(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    value = scenario.get("br_ready")
    if isinstance(value, list):
        return dict_list(value)
    if isinstance(value, dict):
        if isinstance(value.get("issues"), list):
            return dict_list(value.get("issues"))
        if isinstance(value.get("ready"), list):
            return dict_list(value.get("ready"))
    return []


def br_open_count(scenario: dict[str, Any]) -> int:
    value = scenario.get("br_list")
    if isinstance(value, dict):
        if isinstance(value.get("open_count"), int):
            return int_value(value.get("open_count"))
        issues = dict_list(value.get("issues"))
        if issues:
            return sum(1 for issue in issues if string(issue.get("status")) == "open")
    return 0


def issue_id(issue: dict[str, Any]) -> str:
    return string(issue.get("id"))


def issue_type(issue: dict[str, Any]) -> str:
    return string(issue.get("issue_type") or issue.get("type")).lower()


def is_parent_like(issue: dict[str, Any]) -> bool:
    if bool_value(issue.get("parent_only"), False):
        return True
    kind = issue_type(issue)
    labels = [label.lower() for label in string_list(issue.get("labels"))]
    touched_paths = string_list(issue.get("touched_paths") or issue.get("files"))
    if kind == "epic":
        return True
    if kind == "feature" and not touched_paths:
        return True
    return "epic" in labels or "parent-only" in labels


def bv_next_id(scenario: dict[str, Any]) -> str:
    next_value = scenario.get("bv_next")
    if not isinstance(next_value, dict):
        return ""
    for key in ["id", "issue_id"]:
        direct = string(next_value.get(key))
        if direct:
            return direct
    recommendation = next_value.get("recommendation")
    if isinstance(recommendation, dict):
        return string(recommendation.get("id") or recommendation.get("issue_id"))
    top_pick = next_value.get("top_pick")
    if isinstance(top_pick, dict):
        return string(top_pick.get("id") or top_pick.get("issue_id"))
    return ""


def bv_top_pick_ids(scenario: dict[str, Any]) -> list[str]:
    triage = scenario.get("bv_triage")
    if not isinstance(triage, dict):
        return []
    quick_ref = triage.get("triage", {}).get("quick_ref") if isinstance(triage.get("triage"), dict) else {}
    if not isinstance(quick_ref, dict):
        quick_ref = {}
    ids: list[str] = []
    for item in dict_list(quick_ref.get("top_picks")):
        item_id = string(item.get("id") or item.get("issue_id"))
        if item_id:
            ids.append(item_id)
    recommendations = triage.get("triage", {}).get("recommendations") if isinstance(triage.get("triage"), dict) else []
    for item in dict_list(recommendations):
        item_id = string(item.get("id") or item.get("issue_id"))
        if item_id:
            ids.append(item_id)
    return sorted(set(ids))


def row_for(
    scenario: dict[str, Any],
    classification: str,
    *,
    generated_at: str,
    max_snapshot_age_seconds: int,
    claim_issue_id: str = "",
    create_child_bead: bool = False,
    refresh_required: bool = False,
    blockers: list[str] | None = None,
) -> dict[str, Any]:
    ready_issues = ready_payload(scenario)
    ready_ids = [issue_id(issue) for issue in ready_issues if issue_id(issue)]
    parent_ready_ids = [issue_id(issue) for issue in ready_issues if is_parent_like(issue)]
    concrete_ready_ids = [
        issue_id(issue) for issue in ready_issues if issue_id(issue) and not is_parent_like(issue)
    ]
    catalog = CLASSIFICATION_CATALOG[classification]
    stale = stale_inputs(scenario, generated_at, max_snapshot_age_seconds)
    failures = command_failures(scenario)
    hash_values = bv_data_hashes(scenario)
    return {
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": catalog["severity"],
        "recommended_action": catalog["recommended_action"],
        "operator_action": catalog["operator_action"],
        "safe_to_claim": classification == "consistent-actionable",
        "create_child_bead": create_child_bead,
        "refresh_required": refresh_required,
        "claim_issue_id": claim_issue_id,
        "ready_issue_ids": ready_ids,
        "parent_ready_issue_ids": parent_ready_ids,
        "concrete_ready_issue_ids": concrete_ready_ids,
        "bv_next_id": bv_next_id(scenario),
        "bv_top_pick_ids": bv_top_pick_ids(scenario),
        "br_open_count": br_open_count(scenario),
        "bv_data_hashes": hash_values,
        "stale_inputs": stale,
        "command_failures": failures,
        "blockers": sorted(set(blockers or [])),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def classify_scenario(
    scenario: dict[str, Any],
    *,
    generated_at: str,
    max_snapshot_age_seconds: int,
) -> dict[str, Any]:
    failures = command_failures(scenario)
    if failures:
        return row_for(
            scenario,
            "command-provenance-failure",
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
            refresh_required=True,
            blockers=failures,
        )

    if data_hash_mismatch(scenario):
        return row_for(
            scenario,
            "data-hash-mismatch",
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
            refresh_required=True,
            blockers=["bv --robot-next and bv --robot-triage data_hash values differ"],
        )

    stale = stale_inputs(scenario, generated_at, max_snapshot_age_seconds)
    if stale:
        return row_for(
            scenario,
            "stale-graph-snapshot",
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
            refresh_required=True,
            blockers=stale,
        )

    ready_issues = ready_payload(scenario)
    concrete_ready = [issue for issue in ready_issues if not is_parent_like(issue)]
    parent_ready = [issue for issue in ready_issues if is_parent_like(issue)]
    next_id = bv_next_id(scenario)
    top_ids = bv_top_pick_ids(scenario)
    bv_ids = sorted(set(([next_id] if next_id else []) + top_ids))

    if concrete_ready:
        concrete_ids = [issue_id(issue) for issue in concrete_ready if issue_id(issue)]
        if not bv_ids:
            return row_for(
                scenario,
                "br-ready-bv-empty-divergence",
                generated_at=generated_at,
                max_snapshot_age_seconds=max_snapshot_age_seconds,
                refresh_required=True,
                blockers=["br ready lists concrete work but bv has no top pick"],
            )
        matching = sorted(set(concrete_ids).intersection(bv_ids))
        if matching:
            return row_for(
                scenario,
                "consistent-actionable",
                generated_at=generated_at,
                max_snapshot_age_seconds=max_snapshot_age_seconds,
                claim_issue_id=matching[0],
            )
        return row_for(
            scenario,
            "br-bv-actionable-mismatch",
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
            refresh_required=True,
            blockers=[
                "br ready concrete ids do not match bv next/top-pick ids",
                f"br={','.join(concrete_ids)}",
                f"bv={','.join(bv_ids)}",
            ],
        )

    if ready_issues and len(parent_ready) == len(ready_issues):
        return row_for(
            scenario,
            "parent-only-ready-queue",
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
            create_child_bead=True,
            blockers=["ready queue contains only parent-like feature or epic work"],
        )

    return row_for(
        scenario,
        "consistent-no-work",
        generated_at=generated_at,
        max_snapshot_age_seconds=max_snapshot_age_seconds,
        blockers=["no br-ready issue and no bv top pick in this fixture"],
    )


def build_report(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    max_snapshot_age_seconds = int_value(fixture.get("max_snapshot_age_seconds"), 900)
    rows = [
        classify_scenario(
            scenario,
            generated_at=generated_at,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
        )
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
        "safe_to_claim": sum(1 for row in rows if row["safe_to_claim"]),
        "create_child_bead": sum(1 for row in rows if row["create_child_bead"]),
        "refresh_required": sum(1 for row in rows if row["refresh_required"]),
        "blocked_or_unsafe": sum(1 for row in rows if not row["safe_to_claim"]),
        "highest_severity_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "max_snapshot_age_seconds": max_snapshot_age_seconds,
        "required_commands": list(REQUIRED_COMMANDS),
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
        "# Tracker Graph Drift Report",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Scenarios: {summary['scenario_count']}",
        f"- Safe to claim: {summary['safe_to_claim']}",
        f"- Create child bead: {summary['create_child_bead']}",
        f"- Refresh required: {summary['refresh_required']}",
        f"- Highest severity scenario: `{summary['highest_severity_scenario']}`",
        "",
        "| Scenario | Classification | Action | Claim | Create child | Refresh | Blockers |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for row in report["rows"]:
        lines.append(
            "| {scenario} | `{classification}` | `{action}` | {claim} | {child} | {refresh} | {blockers} |".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                action=row["recommended_action"],
                claim="yes" if row["safe_to_claim"] else "no",
                child="yes" if row["create_child_bead"] else "no",
                refresh="yes" if row["refresh_required"] else "no",
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit a read-only br/bv tracker graph drift report."
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
