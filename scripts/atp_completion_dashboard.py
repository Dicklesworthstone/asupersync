#!/usr/bin/env python3
"""Generate the ATP completion dashboard from live Beads and proof artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "artifacts" / "atp_completion_dashboard_contract_v1.json"
ISSUES_PATH = REPO_ROOT / ".beads" / "issues.jsonl"

DONE_STATUSES = {"closed", "completed", "done", "tombstone"}
IN_PROGRESS_STATUSES = {"in_progress", "started"}
BLOCKED_STATUSES = {"blocked"}
OPEN_STATUSES = {"open", "pending", "todo"}
RELEASE_BLOCKING_STATUSES = {
    "red_blocked",
    "red_missing_bead",
    "red_missing_artifact",
    "red_open",
    "red_stale_proof",
    "yellow_in_progress",
}
WORKSTREAM_RE = re.compile(r"^ATP-([A-N])(?::|\d)\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--format",
        choices=["json", "summary", "table"],
        default="summary",
        help="Output format.",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Stable generation timestamp for tests, for example 2026-05-21T00:00:00Z.",
    )
    parser.add_argument(
        "--as-of-date",
        default=None,
        help="UTC date used for freshness checks. Defaults to today's UTC date.",
    )
    parser.add_argument(
        "--contract",
        type=Path,
        default=CONTRACT_PATH,
        help="ATP completion dashboard contract JSON.",
    )
    parser.add_argument(
        "--issues",
        type=Path,
        default=ISSUES_PATH,
        help="Beads issues JSONL export.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run dashboard helper unit tests and exit.",
    )
    return parser.parse_args()


def utc_today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def parse_date(raw: str) -> dt.date:
    return dt.date.fromisoformat(raw)


def generated_at(raw: str | None) -> str:
    if raw:
        return raw
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def repo_relative(path: Path) -> str:
    absolute = path if path.is_absolute() else (REPO_ROOT / path)
    try:
        return str(absolute.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def load_issues(path: Path) -> dict[str, dict[str, Any]]:
    issues: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        issue_id = row.get("id")
        if isinstance(issue_id, str):
            issues[issue_id] = row
    return issues


def normalize_issue_status(raw: Any) -> str:
    status = str(raw or "").strip().lower().replace("-", "_")
    if status in DONE_STATUSES:
        return "done"
    if status in IN_PROGRESS_STATUSES:
        return "in_progress"
    if status in BLOCKED_STATUSES:
        return "blocked"
    if status in OPEN_STATUSES:
        return "open"
    if not status:
        return "missing"
    return status


def active_waiver(
    gate_id: str,
    waivers: list[dict[str, Any]],
    as_of: dt.date,
) -> dict[str, Any] | None:
    for waiver in waivers:
        if waiver.get("gate_id") != gate_id:
            continue
        if waiver.get("status") != "active":
            continue
        expires = waiver.get("expires_at_utc")
        if isinstance(expires, str):
            expires_date = parse_date(expires.split("T", 1)[0])
            if expires_date < as_of:
                continue
        return waiver
    return None


def artifact_state(relative_path: str, as_of: dt.date, max_age_days: int) -> dict[str, Any]:
    path = REPO_ROOT / relative_path
    state: dict[str, Any] = {
        "path": relative_path,
        "exists": path.exists(),
        "stale": False,
        "age_days": None,
        "created_date": None,
    }
    if not path.exists():
        return state
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return state
    created_date = payload.get("created_date")
    if isinstance(created_date, str):
        created = parse_date(created_date)
        age_days = (as_of - created).days
        state["created_date"] = created_date
        state["age_days"] = age_days
        state["stale"] = age_days > max_age_days
    return state


def classify_gate(
    gate: dict[str, Any],
    issues: dict[str, dict[str, Any]],
    contract: dict[str, Any],
    as_of: dt.date,
) -> dict[str, Any]:
    gate_id = str(gate["gate_id"])
    bead_id = str(gate["bead_id"])
    issue = issues.get(bead_id)
    waiver = active_waiver(gate_id, contract.get("waivers", []), as_of)
    required_artifacts = [str(path) for path in gate.get("required_artifacts", [])]
    missing_artifacts = [
        path for path in required_artifacts if not (REPO_ROOT / path).exists()
    ]
    status = "red_missing_bead"
    first_blocker = f"required bead {bead_id} is missing from {ISSUES_PATH.relative_to(REPO_ROOT)}"
    issue_status = "missing"

    if waiver is not None:
        status = "yellow_waived"
        first_blocker = "active governance waiver"
    elif issue is not None:
        issue_status = normalize_issue_status(issue.get("status"))
        if missing_artifacts:
            status = "red_missing_artifact"
            first_blocker = f"missing artifacts: {', '.join(missing_artifacts)}"
        elif issue_status == "done":
            status = "green"
            first_blocker = ""
        elif issue_status == "in_progress":
            status = "yellow_in_progress"
            first_blocker = f"{bead_id} is still in progress"
        elif issue_status == "blocked":
            status = "red_blocked"
            first_blocker = f"{bead_id} status is blocked"
        else:
            status = "red_open"
            first_blocker = f"{bead_id} status is {issue_status}"

    return {
        "gate_id": gate_id,
        "bead_id": bead_id,
        "title": gate.get("title", ""),
        "issue_status": issue_status,
        "dashboard_status": status,
        "release_blocking": status in RELEASE_BLOCKING_STATUSES,
        "question_ids": gate.get("question_ids", []),
        "required_artifacts": required_artifacts,
        "missing_artifacts": missing_artifacts,
        "proof_command": gate.get("proof_command", ""),
        "first_blocker": first_blocker,
        "waiver": waiver,
    }


def workstream_from_title(title: str) -> str | None:
    match = WORKSTREAM_RE.match(title)
    if match is None:
        return None
    return f"ATP-{match.group(1)}"


def classify_workstreams(
    contract: dict[str, Any],
    issues: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_workstream: dict[str, list[dict[str, Any]]] = {}
    for issue in issues.values():
        title = str(issue.get("title", ""))
        workstream_id = workstream_from_title(title)
        if workstream_id:
            by_workstream.setdefault(workstream_id, []).append(issue)

    for required in contract["required_workstreams"]:
        workstream_id = str(required["workstream_id"])
        members = by_workstream.get(workstream_id, [])
        open_members = [
            issue for issue in members if normalize_issue_status(issue.get("status")) != "done"
        ]
        if not members:
            status = "red_missing_bead"
            first_blocker = f"no Beads found for {workstream_id}"
        elif open_members:
            status = "red_open"
            first = sorted(
                open_members,
                key=lambda issue: (int(issue.get("priority", 4)), str(issue.get("id", ""))),
            )[0]
            first_blocker = f"{first.get('id')}: {first.get('title')}"
        else:
            status = "green"
            first_blocker = ""
        rows.append(
            {
                "workstream_id": workstream_id,
                "title": required["title"],
                "total_beads": len(members),
                "open_beads": len(open_members),
                "dashboard_status": status,
                "release_blocking": status in RELEASE_BLOCKING_STATUSES,
                "first_blocker": first_blocker,
            }
        )
    return rows


def answer_questions(
    contract: dict[str, Any],
    gate_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    gates_by_id = {row["gate_id"]: row for row in gate_rows}
    answers: dict[str, dict[str, Any]] = {}
    for question in contract["required_questions"]:
        gate_ids = [str(gate_id) for gate_id in question["requires_gate_ids"]]
        statuses = [gates_by_id[gate_id]["dashboard_status"] for gate_id in gate_ids]
        if all(status == "green" for status in statuses):
            answer = "yes"
        elif any(status.startswith("yellow") for status in statuses):
            answer = "partial"
        else:
            answer = "no"
        blockers = [
            gates_by_id[gate_id]
            for gate_id in gate_ids
            if gates_by_id[gate_id]["dashboard_status"] != "green"
        ]
        answers[str(question["question_id"])] = {
            "question": question["question"],
            "answer": answer,
            "requires_gate_ids": gate_ids,
            "blocking_gate_ids": [row["gate_id"] for row in blockers],
            "first_blocker": blockers[0]["first_blocker"] if blockers else "",
        }
    return answers


def proof_artifacts(contract: dict[str, Any], as_of: dt.date) -> list[dict[str, Any]]:
    max_age_days = int(contract["stale_proof_policy"]["max_age_days"])
    rows = [
        artifact_state(str(path), as_of, max_age_days)
        for path in contract.get("proof_sources", [])
    ]
    for row in rows:
        row["release_blocking"] = bool(row["stale"]) and bool(
            contract["stale_proof_policy"]["stale_is_release_blocking"]
        )
    return rows


def build_dashboard(
    contract_path: Path,
    issues_path: Path,
    generated: str,
    as_of: dt.date,
) -> dict[str, Any]:
    contract = load_json(contract_path)
    issues = load_issues(issues_path)
    gate_rows = [
        classify_gate(gate, issues, contract, as_of)
        for gate in contract["required_release_gates"]
    ]
    workstream_rows = classify_workstreams(contract, issues)
    artifacts = proof_artifacts(contract, as_of)
    answers = answer_questions(contract, gate_rows)
    release_blocking_rows = [
        row
        for row in [*gate_rows, *workstream_rows, *artifacts]
        if row.get("release_blocking")
    ]
    release_blocking_count = sum(
        1 for row in release_blocking_rows
    )
    if release_blocking_rows and answers["all_done"]["answer"] == "yes":
        first = release_blocking_rows[0]
        answers["all_done"]["answer"] = "no"
        answers["all_done"]["first_blocker"] = str(
            first.get("first_blocker") or first.get("path") or "release-blocking row"
        )

    return {
        "schema_version": contract["schema_version"],
        "contract_version": contract["contract_version"],
        "generated_at": generated,
        "as_of_date": as_of.isoformat(),
        "bead_id": contract["bead_id"],
        "source_of_truth": {
            "contract": repo_relative(contract_path),
            "tracker": repo_relative(issues_path),
            "verifier": contract["verifier"],
        },
        "answers": answers,
        "summary": {
            "workstream_count": len(workstream_rows),
            "release_gate_count": len(gate_rows),
            "green_gates": sum(1 for row in gate_rows if row["dashboard_status"] == "green"),
            "release_blocking_count": release_blocking_count,
            "ready_to_close_top_epic": release_blocking_count == 0,
        },
        "workstreams": workstream_rows,
        "release_gates": gate_rows,
        "proof_artifacts": artifacts,
    }


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        f"ATP completion dashboard ({report['as_of_date']})",
        f"Ready to close top epic: {str(report['summary']['ready_to_close_top_epic']).lower()}",
        f"Release-blocking rows: {report['summary']['release_blocking_count']}",
        "",
        "Questions:",
    ]
    for question_id, answer in report["answers"].items():
        lines.append(f"- {question_id}: {answer['answer']} - {answer['first_blocker']}")
    return "\n".join(lines) + "\n"


def render_table(report: dict[str, Any]) -> str:
    lines = [
        f"# ATP Completion Dashboard - {report['generated_at']}",
        "",
        "## Release Gates",
        "| Gate | Status | Bead | First blocker |",
        "|---|---|---|---|",
    ]
    for row in report["release_gates"]:
        lines.append(
            f"| {row['gate_id']} | {row['dashboard_status']} | {row['bead_id']} | {row['first_blocker']} |"
        )
    lines.extend(
        [
            "",
            "## Workstreams",
            "| Workstream | Status | Open beads | First blocker |",
            "|---|---|---:|---|",
        ]
    )
    for row in report["workstreams"]:
        lines.append(
            f"| {row['workstream_id']} | {row['dashboard_status']} | {row['open_beads']} | {row['first_blocker']} |"
        )
    return "\n".join(lines) + "\n"


def run_self_tests() -> None:
    assert normalize_issue_status("completed") == "done"
    assert normalize_issue_status("in-progress") == "in_progress"
    assert normalize_issue_status("blocked") == "blocked"
    assert normalize_issue_status("open") == "open"
    assert workstream_from_title("ATP-A7: streams") == "ATP-A"
    assert workstream_from_title("ATP-NR7: retry") is None
    waiver = {
        "gate_id": "ATP-X",
        "status": "active",
        "expires_at_utc": "2026-05-22T00:00:00Z",
    }
    assert active_waiver("ATP-X", [waiver], parse_date("2026-05-21")) == waiver
    assert active_waiver("ATP-X", [waiver], parse_date("2026-05-23")) is None
    fresh = {
        "contract_version": "atp-completion-dashboard-contract-v1",
        "required_release_gates": [
            {
                "gate_id": "ATP-X",
                "bead_id": "missing",
                "title": "x",
                "required_artifacts": [],
            }
        ],
        "waivers": [],
    }
    classified = classify_gate(
        fresh["required_release_gates"][0],
        {},
        fresh,
        parse_date("2026-05-21"),
    )
    assert classified["dashboard_status"] == "red_missing_bead"
    missing_artifact_gate = {
        "gate_id": "ATP-Y",
        "bead_id": "present",
        "title": "y",
        "required_artifacts": [
            "target/atp-completion-dashboard-self-test/never-created-proof.json"
        ],
    }
    classified = classify_gate(
        missing_artifact_gate,
        {"present": {"id": "present", "status": "closed"}},
        fresh,
        parse_date("2026-05-21"),
    )
    assert classified["dashboard_status"] == "red_missing_artifact"
    assert classified["missing_artifacts"] == [
        "target/atp-completion-dashboard-self-test/never-created-proof.json"
    ]
    print("atp completion dashboard self-test: pass")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_tests()
        return 0

    as_of = parse_date(args.as_of_date) if args.as_of_date else utc_today()
    report = build_dashboard(
        args.contract,
        args.issues,
        generated_at(args.generated_at),
        as_of,
    )
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "table":
        sys.stdout.write(render_table(report))
    else:
        sys.stdout.write(render_summary(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
