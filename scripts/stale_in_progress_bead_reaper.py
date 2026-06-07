#!/usr/bin/env python3
"""Emit deterministic stale in-progress bead reaper reports.

The helper consumes explicit fixture snapshots of bead rows and Agent Mail
active-agent state. Report mode is the default and only produces dry-run
evidence. Apply mode must be requested explicitly and still only emits
deterministic post-mutation objects to stdout; it does not rewrite
`.beads/issues.jsonl`, run br/bv, inspect Git, or contact Agent Mail.
"""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "stale-in-progress-bead-reaper-report-v1"
FIXTURE_SCHEMA_VERSION = "stale-in-progress-bead-reaper-fixture-v1"
CONTRACT_SCHEMA_VERSION = "stale-in-progress-bead-reaper-contract-v1"

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-dirty-files",
    "do-not-apply-without-explicit-mode",
    "do-not-reopen-live-agent-work",
    "do-not-reopen-recently-updated-work",
    "do-not-reopen-ambiguous-ownership",
    "do-not-rewrite-beads-jsonl-in-place",
]

GLOBAL_NON_CLAIMS = [
    "This report classifies stale tracker ownership; it does not prove source correctness.",
    "Fixture snapshots do not override live br, bv, Git, or Agent Mail state.",
    "Dry-run reopen candidates are advisory until reviewed and applied through the normal tracker workflow.",
    "Apply-mode output is a deterministic mutation receipt; it does not commit, push, or reserve files.",
]

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "stale-reopen-candidate": {
        "severity": 40,
        "recommended_action": "review-and-optionally-reopen",
        "operator_action": "Review the stale evidence, then reopen only through an explicit apply workflow.",
    },
    "live-agent-excluded": {
        "severity": 80,
        "recommended_action": "leave-live-agent-claim-intact",
        "operator_action": "The assignee appears active; coordinate before touching the bead.",
    },
    "recent-update-excluded": {
        "severity": 70,
        "recommended_action": "wait-for-inactivity-threshold",
        "operator_action": "The bead is too recent to reopen under the configured threshold.",
    },
    "missing-timestamp-refused": {
        "severity": 90,
        "recommended_action": "repair-or-refresh-tracker-row",
        "operator_action": "Do not reopen rows with missing or unparseable timestamps.",
    },
    "malformed-row-refused": {
        "severity": 100,
        "recommended_action": "repair-malformed-tracker-row",
        "operator_action": "Do not mutate malformed rows; repair or refresh the tracker export first.",
    },
    "ambiguous-ownership-refused": {
        "severity": 85,
        "recommended_action": "resolve-ownership-before-reopen",
        "operator_action": "Do not reopen until the assignee can be matched to an inactive known agent.",
    },
    "non-in-progress-ignored": {
        "severity": 10,
        "recommended_action": "no-reaper-action",
        "operator_action": "The row is not in progress, so the stale reaper should ignore it.",
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


def age_seconds(generated_at: str, updated_at: str) -> int | None:
    parsed_now = parse_timestamp(generated_at)
    parsed_then = parse_timestamp(updated_at)
    if parsed_now is None or parsed_then is None:
        return None
    return max(0, int((parsed_now - parsed_then).total_seconds()))


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


def active_agent_map(fixture: dict[str, Any]) -> dict[str, dict[str, Any]]:
    agents: dict[str, dict[str, Any]] = {}
    for agent in dict_list(fixture.get("active_agents")):
        name = string(agent.get("name"))
        if name:
            agents[name] = agent
    return agents


def issue_updated_at(issue: dict[str, Any]) -> str:
    return string(issue.get("updated_at") or issue.get("last_activity_at"))


def planned_reopen_mutation(
    issue: dict[str, Any],
    generated_at: str,
    reason: str,
) -> dict[str, Any]:
    issue_id = string(issue.get("id"))
    return {
        "id": issue_id,
        "from_status": "in_progress",
        "to_status": "open",
        "clear_assignee": True,
        "updated_at": generated_at,
        "close_reason": None,
        "comment": (
            f"Reopened by stale in-progress reaper dry-run/apply receipt: {reason}"
        ),
    }


def resulting_issue(
    issue: dict[str, Any],
    mutation: dict[str, Any],
    apply_mode: bool,
) -> dict[str, Any] | None:
    if not apply_mode:
        return None
    result = dict(issue)
    result["status"] = mutation["to_status"]
    result["updated_at"] = mutation["updated_at"]
    result.pop("assignee", None)
    result["stale_reaper_applied"] = True
    result["stale_reaper_comment"] = mutation["comment"]
    return result


def malformed_reasons(issue: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not string(issue.get("id")):
        reasons.append("missing-id")
    if not string(issue.get("status")):
        reasons.append("missing-status")
    if string(issue.get("status")) == "in_progress" and "assignee" not in issue:
        reasons.append("missing-assignee-field")
    return reasons


def classify_issue(
    issue: dict[str, Any],
    fixture: dict[str, Any],
    generated_at: str,
    apply_mode: bool,
) -> dict[str, Any]:
    threshold = int_value(fixture.get("inactivity_threshold_seconds"), 604800)
    agents = active_agent_map(fixture)
    issue_id = string(issue.get("id"))
    malformed = malformed_reasons(issue)
    classification = ""
    blockers: list[str] = []
    candidate = False
    explicit_apply_required = True
    mutation: dict[str, Any] | None = None

    if malformed:
        classification = "malformed-row-refused"
        blockers = malformed
    elif string(issue.get("status")) != "in_progress":
        classification = "non-in-progress-ignored"
        explicit_apply_required = False
        blockers = [f"status={string(issue.get('status'))}"]
    else:
        updated_at = issue_updated_at(issue)
        age = age_seconds(generated_at, updated_at)
        assignee = string(issue.get("assignee"))
        if age is None:
            classification = "missing-timestamp-refused"
            blockers = ["missing-or-unparseable-updated-at"]
        elif assignee not in agents:
            classification = "ambiguous-ownership-refused"
            blockers = [f"assignee-not-in-active-agent-snapshot:{assignee or '<empty>'}"]
        elif bool_value(agents[assignee].get("active"), False):
            classification = "live-agent-excluded"
            blockers = [f"assignee-active:{assignee}"]
        elif age < threshold:
            classification = "recent-update-excluded"
            blockers = [f"age={age}s", f"threshold={threshold}s"]
        else:
            classification = "stale-reopen-candidate"
            candidate = True
            blockers = []
            reason = f"assignee={assignee}; age={age}s; threshold={threshold}s"
            mutation = planned_reopen_mutation(issue, generated_at, reason)

    catalog = CLASSIFICATION_CATALOG[classification]
    row = {
        "issue_id": issue_id,
        "title": string(issue.get("title")),
        "classification": classification,
        "severity": catalog["severity"],
        "recommended_action": catalog["recommended_action"],
        "operator_action": catalog["operator_action"],
        "status": string(issue.get("status")),
        "assignee": string(issue.get("assignee")),
        "updated_at": issue_updated_at(issue),
        "age_seconds": age_seconds(generated_at, issue_updated_at(issue)),
        "threshold_seconds": threshold,
        "candidate": candidate,
        "apply_allowed": candidate,
        "apply_mode": apply_mode,
        "applied": bool(candidate and apply_mode),
        "explicit_apply_required": explicit_apply_required,
        "planned_mutation": mutation,
        "resulting_issue": resulting_issue(issue, mutation, apply_mode) if mutation else None,
        "blockers": sorted(set(blockers)),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }
    return row


def build_report(fixture: dict[str, Any], generated_at: str, mode: str) -> dict[str, Any]:
    apply_mode = mode == "apply"
    rows = [
        classify_issue(issue, fixture, generated_at, apply_mode)
        for issue in dict_list(fixture.get("issues"))
    ]
    rows.sort(
        key=lambda row: (
            -int_value(row.get("severity")),
            string(row.get("issue_id")),
            string(row.get("title")),
        )
    )
    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1
    candidates = [row for row in rows if bool_value(row.get("candidate"))]
    refused = [
        row
        for row in rows
        if string(row.get("classification")).endswith("-refused")
        or string(row.get("classification")) in {
            "live-agent-excluded",
            "recent-update-excluded",
        }
    ]
    summary = {
        "issue_count": len(rows),
        "candidate_count": len(candidates),
        "would_reopen": len(candidates) if not apply_mode else 0,
        "applied_reopen": len(candidates) if apply_mode else 0,
        "refused_or_excluded": len(refused),
        "ignored": sum(
            1 for row in rows if string(row.get("classification")) == "non-in-progress-ignored"
        ),
        "highest_severity_issue": string(rows[0].get("issue_id")) if rows else "",
        "classification_counts": classification_counts,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "mode": mode,
        "inactivity_threshold_seconds": int_value(
            fixture.get("inactivity_threshold_seconds"), 604800
        ),
        "active_agent_snapshot_id": string(fixture.get("active_agent_snapshot_id")),
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
        "# Stale In-Progress Bead Reaper Report",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Mode: `{report['mode']}`",
        f"- Inactivity threshold: {report['inactivity_threshold_seconds']} seconds",
        f"- Issues inspected: {summary['issue_count']}",
        f"- Reopen candidates: {summary['candidate_count']}",
        f"- Would reopen: {summary['would_reopen']}",
        f"- Applied reopen: {summary['applied_reopen']}",
        f"- Refused or excluded: {summary['refused_or_excluded']}",
        f"- Highest severity issue: `{summary['highest_severity_issue']}`",
        "",
        "| Issue | Classification | Assignee | Age seconds | Action | Applied | Blockers |",
        "|---|---|---|---:|---|---:|---|",
    ]
    for row in report["rows"]:
        age = row["age_seconds"] if row["age_seconds"] is not None else "-"
        lines.append(
            "| {issue} | `{classification}` | {assignee} | {age} | `{action}` | {applied} | {blockers} |".format(
                issue=row["issue_id"] or "-",
                classification=row["classification"],
                assignee=row["assignee"] or "-",
                age=age,
                action=row["recommended_action"],
                applied="yes" if row["applied"] else "no",
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
        description="Emit a stale in-progress bead reaper report."
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
        "--mode",
        choices=["report", "apply"],
        default="report",
        help="report is dry-run only; apply emits deterministic post-mutation receipts",
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
    report = build_report(fixture, args.generated_at, args.mode)
    if args.output == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(markdown_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
