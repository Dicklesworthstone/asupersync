#!/usr/bin/env python3
"""Run a synthetic, non-mutating swarm autopilot proof.

The proof composes existing read-only helpers against fixture input. It does
not talk to live Agent Mail, mutate Beads, run Cargo, push Git refs, or reserve
files. A scenario passes when each helper observes the expected happy-path or
blocked-path evidence.
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-autopilot-e2e-v1"
HELPERS = {
    "rch-retrieval-receipt": "scripts/rch_retrieval_receipt.py",
    "reservation-aware-work-finder": "scripts/reservation_aware_work_finder.py",
    "fuzz-oracle-bead-template": "scripts/fuzz_oracle_debt_scanner.py",
    "closeout-verifier": "scripts/closeout_verifier.py",
    "stale-in-progress-receipt": "scripts/stale_in_progress_receipt.py",
}
FORBIDDEN_ACTIONS = {
    "runs_live_agent_mail_mutation": False,
    "runs_beads_mutation": False,
    "runs_git_mutation": False,
    "runs_cargo": False,
    "runs_destructive_command": False,
    "creates_branch_or_worktree": False,
}


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


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rel(path: str | Path) -> str:
    return Path(path).as_posix()


def command_text(args: list[str]) -> str:
    return " ".join(args)


def run_json_command(repo_path: Path, args: list[str], timeout: float) -> tuple[int, Any, str, str]:
    completed = subprocess.run(
        args,
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    parsed: Any = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return completed.returncode, parsed, completed.stdout, completed.stderr


def check_value(checks: list[dict[str, Any]], name: str, observed: Any, expected: Any) -> None:
    if expected is None:
        return
    checks.append(
        {
            "check": name,
            "status": "pass" if observed == expected else "fail",
            "expected": expected,
            "observed": observed,
        }
    )


def rows_from(value: Any, key: str) -> list[dict[str, Any]]:
    rows = value.get(key) if isinstance(value, dict) else []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def candidate_status(report: dict[str, Any], candidate_id: str) -> str:
    for row in rows_from(report, "candidates"):
        if row.get("candidate_id") == candidate_id:
            return str(row.get("status") or "")
    return ""


def candidate_has_blocker(report: dict[str, Any], candidate_id: str, blocker_kind: str) -> bool:
    for row in rows_from(report, "candidates"):
        if row.get("candidate_id") != candidate_id:
            continue
        blockers = row.get("blockers") if isinstance(row.get("blockers"), list) else []
        return any(
            isinstance(blocker, dict) and blocker.get("kind") == blocker_kind
            for blocker in blockers
        )
    return False


def closeout_row_status(report: dict[str, Any], row_id: str) -> str:
    for row in rows_from(report, "rows"):
        if row.get("row_id") == row_id:
            return str(row.get("status") or "")
    return ""


def stage_command(stage: dict[str, Any], repo_path: Path, generated_at: str) -> list[str]:
    kind = str(stage.get("kind") or "")
    helper = HELPERS.get(kind)
    if helper is None:
        raise ValueError(f"unsupported stage kind: {kind}")

    args = ["python3", helper]
    if kind == "rch-retrieval-receipt":
        args.extend(["--log", rel(stage["log"])])
        args.extend(["--command", str(stage.get("command") or "")])
        if stage.get("proof_lane"):
            args.extend(["--proof-lane", str(stage["proof_lane"])])
        if stage.get("guarantee"):
            args.extend(["--guarantee", str(stage["guarantee"])])
        if stage.get("wrapper_exit_code") is not None:
            args.extend(["--wrapper-exit-code", str(stage["wrapper_exit_code"])])
        if stage.get("audit_target_dir", False):
            args.append("--audit-target-dir")
        for target_dir in stage.get("active_target_dirs", []):
            args.extend(["--active-target-dir", str(target_dir)])
        if stage.get("artifact_free_proof_receipt", False):
            args.append("--artifact-free-proof-receipt")
    elif kind == "reservation-aware-work-finder":
        args.extend(["--fixture", rel(stage["fixture"])])
        args.extend(["--repo-path", rel(repo_path)])
        args.extend(["--agent", str(stage.get("agent") or "CopperSpring")])
    elif kind == "fuzz-oracle-bead-template":
        args.extend(["--repo-root", rel(repo_path)])
        args.extend(["--root", rel(stage["root"])])
        args.extend(["--output", "bead-template"])
    elif kind == "closeout-verifier":
        args.extend(["--fixture", rel(stage["fixture"])])
        args.extend(["--repo-path", rel(repo_path)])
    elif kind == "stale-in-progress-receipt":
        args.extend(["--fixture", rel(stage["fixture"])])
        args.extend(["--repo-path", rel(repo_path)])
        args.extend(["--agent", str(stage.get("agent") or "CopperSpring")])
    args.extend(["--generated-at", generated_at])
    if "--output" not in args:
        args.extend(["--output", "json"])
    return args


def observed_values(kind: str, report: dict[str, Any]) -> dict[str, Any]:
    if kind == "rch-retrieval-receipt":
        audit = report.get("target_dir_audit") if isinstance(report, dict) else {}
        artifact_free = report.get("artifact_free_proof_receipt") if isinstance(report, dict) else {}
        if not isinstance(artifact_free, dict):
            artifact_free = {}
        retrieval = artifact_free.get("artifact_retrieval_result")
        if not isinstance(retrieval, dict):
            retrieval = {}
        remote = artifact_free.get("remote_command_result")
        if not isinstance(remote, dict):
            remote = {}
        local_disk = artifact_free.get("local_disk_pressure")
        if not isinstance(local_disk, dict):
            local_disk = {}
        return {
            "schema_version": report.get("schema_version"),
            "classification": report.get("classification"),
            "decision": report.get("decision"),
            "target_dir": report.get("target_dir"),
            "target_dir_audit_status": audit.get("status") if isinstance(audit, dict) else None,
            "remote_command_status": remote.get("status"),
            "artifact_retrieval_status": retrieval.get("status"),
            "artifact_retrieval_blocker_kind": retrieval.get("blocker_kind"),
            "local_disk_pressure_status": local_disk.get("status"),
        }
    if kind == "reservation-aware-work-finder":
        recommendation = report.get("recommendation") if isinstance(report, dict) else {}
        disk_pressure = report.get("disk_pressure") if isinstance(report, dict) else {}
        if not isinstance(disk_pressure, dict):
            disk_pressure = {}
        dirty_paths = report.get("dirty_paths") if isinstance(report, dict) else []
        if not isinstance(dirty_paths, list):
            dirty_paths = []
        cleanup_candidates = disk_pressure.get("cleanup_candidates")
        if not isinstance(cleanup_candidates, list):
            cleanup_candidates = []
        handoff = report.get("closeout_handoff") if isinstance(report, dict) else {}
        if not isinstance(handoff, dict):
            handoff = {}
        handoff_remote = handoff.get("remote_proof_result")
        if not isinstance(handoff_remote, dict):
            handoff_remote = {}
        handoff_blocker = handoff.get("artifact_retrieval_blocker")
        if not isinstance(handoff_blocker, dict):
            handoff_blocker = {}
        handoff_auth = handoff.get("authorization")
        if not isinstance(handoff_auth, dict):
            handoff_auth = {}
        return {
            "schema_version": report.get("schema_version"),
            "recommendation_category": recommendation.get("category")
            if isinstance(recommendation, dict)
            else None,
            "recommendation_candidate_id": recommendation.get("candidate_id")
            if isinstance(recommendation, dict)
            else None,
            "ready_count": report.get("summary", {}).get("ready_count")
            if isinstance(report.get("summary"), dict)
            else None,
            "blocked_count": report.get("summary", {}).get("blocked_count")
            if isinstance(report.get("summary"), dict)
            else None,
            "disk_pressure_level": disk_pressure.get("level"),
            "rch_heavy_work_allowed": disk_pressure.get("rch_heavy_work_allowed"),
            "cleanup_candidate_ids": [
                str(row.get("candidate_id") or "")
                for row in cleanup_candidates
                if isinstance(row, dict)
            ],
            "dirty_path_count": len(dirty_paths),
            "handoff_schema_version": handoff.get("schema_version"),
            "handoff_remote_status": handoff_remote.get("status"),
            "handoff_remote_classification": handoff_remote.get("classification"),
            "handoff_remote_decision": handoff_remote.get("decision"),
            "handoff_retrieval_blocker_status": handoff_blocker.get("status"),
            "handoff_retrieval_blocker_kind": handoff_blocker.get("kind"),
            "handoff_cleanup_requires_authorization": handoff_auth.get(
                "cleanup_requires_explicit_user_authorization"
            ),
            "handoff_delete_command_available": handoff_auth.get("delete_command_available"),
        }
    if kind == "fuzz-oracle-bead-template":
        return {
            "schema_version": report.get("schema_version"),
            "template_count": report.get("template_count"),
            "dry_run": report.get("dry_run"),
            "auto_create_beads": report.get("auto_create_beads"),
            "review_required": report.get("review_required"),
        }
    if kind == "closeout-verifier":
        return {
            "schema_version": report.get("schema_version"),
            "overall_status": report.get("overall_status"),
            "pass_count": report.get("summary", {}).get("pass")
            if isinstance(report.get("summary"), dict)
            else None,
            "fail_count": report.get("summary", {}).get("fail")
            if isinstance(report.get("summary"), dict)
            else None,
            "warn_count": report.get("summary", {}).get("warn")
            if isinstance(report.get("summary"), dict)
            else None,
        }
    if kind == "stale-in-progress-receipt":
        classifications = rows_from(report, "classifications")
        first = classifications[0] if classifications else {}
        proposed_action = first.get("proposed_action") if isinstance(first, dict) else {}
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        return {
            "schema_version": report.get("schema_version"),
            "total_in_progress": summary.get("total_in_progress"),
            "probably_stale": summary.get("probably_stale"),
            "closed_by_recent_commit": summary.get("closed_by_recent_commit"),
            "blocked_by_active_reservation": summary.get("blocked_by_active_reservation"),
            "first_classification": first.get("classification") if isinstance(first, dict) else None,
            "first_proposed_action_kind": proposed_action.get("kind")
            if isinstance(proposed_action, dict)
            else None,
        }
    raise ValueError(f"unsupported observation kind: {kind}")


def add_kind_specific_checks(
    kind: str,
    report: dict[str, Any],
    expectations: dict[str, Any],
    checks: list[dict[str, Any]],
) -> None:
    if kind == "reservation-aware-work-finder":
        for candidate_id, expected_status in expectations.get("candidate_statuses", {}).items():
            check_value(
                checks,
                f"candidate_status:{candidate_id}",
                candidate_status(report, candidate_id),
                expected_status,
            )
        for item in expectations.get("candidate_blockers", []):
            check_value(
                checks,
                f"candidate_blocker:{item['candidate_id']}:{item['kind']}",
                candidate_has_blocker(report, item["candidate_id"], item["kind"]),
                True,
            )
    if kind == "closeout-verifier":
        for row_id, expected_status in expectations.get("row_statuses", {}).items():
            check_value(
                checks,
                f"closeout_row_status:{row_id}",
                closeout_row_status(report, row_id),
                expected_status,
            )


def safety_findings(stage_id: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if report.get("non_mutating") is False:
        findings.append(
            {
                "stage_id": stage_id,
                "kind": "non_mutating_false",
                "field": "non_mutating",
            }
        )
    for section_name in ("forbidden_actions", "safety"):
        section = report.get(section_name)
        if not isinstance(section, dict):
            continue
        for key, value in section.items():
            if key == "forbidden_command_tokens":
                if isinstance(value, list) and value:
                    findings.append(
                        {
                            "stage_id": stage_id,
                            "kind": "forbidden_command_tokens",
                            "field": f"{section_name}.{key}",
                            "observed": value,
                        }
                    )
                continue
            if value is True:
                findings.append(
                    {
                        "stage_id": stage_id,
                        "kind": "forbidden_action_true",
                        "field": f"{section_name}.{key}",
                    }
                )
    return findings


def run_stage(
    stage: dict[str, Any],
    repo_path: Path,
    generated_at: str,
    timeout: float,
) -> dict[str, Any]:
    stage_id = str(stage.get("stage_id") or stage.get("kind") or "stage")
    kind = str(stage.get("kind") or "")
    args = stage_command(stage, repo_path, generated_at)
    command = command_text(args)
    checks: list[dict[str, Any]] = []
    try:
        exit_code, report, stdout, stderr = run_json_command(repo_path, args, timeout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return {
            "stage_id": stage_id,
            "kind": kind,
            "status": "fail",
            "command": command,
            "checks": [
                {
                    "check": "command_execution",
                    "status": "fail",
                    "expected": "json-helper-success",
                    "observed": str(error),
                }
            ],
            "observed": {},
            "stderr": str(error),
            "safety_findings": [],
        }

    if not isinstance(report, dict):
        checks.append(
            {
                "check": "json_stdout",
                "status": "fail",
                "expected": "object",
                "observed": "missing-or-malformed",
            }
        )
        report = {}
    check_value(checks, "helper_exit_code", exit_code, 0)
    expectations = stage.get("expect", {}) if isinstance(stage.get("expect"), dict) else {}
    try:
        observed = observed_values(kind, report)
    except ValueError as error:
        checks.append(
            {
                "check": "observed_values_kind",
                "status": "fail",
                "expected": "supported-stage-observer",
                "observed": str(error),
            }
        )
        observed = {}
    for key, expected in expectations.items():
        if key in {"candidate_statuses", "candidate_blockers", "row_statuses"}:
            continue
        check_value(checks, key, observed.get(key), expected)
    add_kind_specific_checks(kind, report, expectations, checks)
    findings = safety_findings(stage_id, report)
    if findings:
        checks.append(
            {
                "check": "non_mutating_stage_safety",
                "status": "fail",
                "expected": [],
                "observed": findings,
            }
        )
    status = "fail" if any(item["status"] == "fail" for item in checks) else "pass"
    return {
        "stage_id": stage_id,
        "kind": kind,
        "status": status,
        "command": command,
        "checks": checks,
        "observed": observed,
        "stderr": stderr.strip(),
        "safety_findings": findings,
        "handoff_record": report.get("closeout_handoff") if isinstance(report, dict) else None,
        "stdout_bytes": len(stdout.encode("utf-8")),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    repo_path = Path(args.repo_path).resolve()
    fixture_path = Path(args.fixture)
    fixture = load_json(fixture_path)
    if not isinstance(fixture, dict):
        raise ValueError("fixture must be a JSON object")
    generated_at = args.generated_at or utc_now()
    stages = [
        run_stage(stage, repo_path, generated_at, args.timeout)
        for stage in rows_from(fixture, "stages")
    ]
    expectation_status = "fail" if any(stage["status"] == "fail" for stage in stages) else "pass"
    safety = {
        "non_mutating": True,
        "forbidden_actions": dict(FORBIDDEN_ACTIONS),
        "stage_safety_findings": [
            finding
            for stage in stages
            for finding in stage.get("safety_findings", [])
        ],
    }
    if safety["stage_safety_findings"]:
        expectation_status = "fail"
    handoff_records = [
        stage.get("handoff_record")
        for stage in stages
        if isinstance(stage.get("handoff_record"), dict)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "fixture_path": rel(fixture_path),
        "scenario_id": str(fixture.get("scenario_id") or fixture_path.stem),
        "scenario_outcome": str(fixture.get("expected_scenario_outcome") or "unspecified"),
        "overall_status": expectation_status,
        "summary": {
            "stage_count": len(stages),
            "passed_stages": sum(1 for stage in stages if stage["status"] == "pass"),
            "failed_stages": sum(1 for stage in stages if stage["status"] == "fail"),
        },
        "stage_logs": stages,
        "handoff_record": handoff_records[0] if handoff_records else {},
        "safety": safety,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic swarm autopilot E2E proof")
    parser.add_argument("--fixture", required=True, help="Scenario fixture")
    parser.add_argument("--repo-path", default=".", help="Repository root")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-helper timeout")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        report = build_report(args)
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
