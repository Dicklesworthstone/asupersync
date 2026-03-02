#!/usr/bin/env python3
"""Generate D5 CI summary artifacts (machine-readable + markdown)."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                parsed.setdefault("_line", line_no)
                rows.append(parsed)
    return rows


def parse_iso8601_utc(raw: str) -> dt.datetime:
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    parsed = dt.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {raw}")
    return parsed.astimezone(dt.timezone.utc)


def route_owner(path: str, routes: list[dict[str, Any]], default_owner: str) -> str:
    for route in routes:
        pattern = route.get("pattern")
        owner = route.get("owner")
        if isinstance(pattern, str) and isinstance(owner, str) and fnmatch.fnmatch(path, pattern):
            return owner
    return default_owner


def run_scan(roots: list[str], terms: list[str]) -> dict[str, list[dict[str, Any]]]:
    escaped_terms = [re.escape(term) for term in terms]
    token_re = re.compile(rf"(?i)\b({'|'.join(escaped_terms)})\b")

    cmd = ["rg", "--line-number", "--no-heading", "--color", "never"]
    for term in terms:
        cmd.extend(["-e", rf"(?i)\b{re.escape(term)}\b"])
    cmd.extend(roots)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        raise RuntimeError("ripgrep scan failed")
    if proc.returncode == 1:
        return {}

    by_path: dict[str, list[dict[str, Any]]] = {}
    for row in proc.stdout.splitlines():
        parts = row.split(":", 2)
        if len(parts) != 3:
            continue
        path, line_raw, text = parts
        try:
            line = int(line_raw)
        except ValueError:
            continue
        tokens = sorted({m.group(1).lower() for m in token_re.finditer(text)})
        if not tokens:
            continue
        by_path.setdefault(path, []).append(
            {
                "line": line,
                "tokens": tokens,
                "text": text,
            }
        )
    return by_path


def no_mock_snapshot(policy_path: Path, output: Path) -> int:
    policy = load_json(policy_path)
    if policy.get("schema_version") != "no-mock-policy-v1":
        raise ValueError("unsupported no-mock policy schema")

    roots = list(policy.get("scan", {}).get("roots", ["src", "tests"]))
    terms = list(policy.get("scan", {}).get("terms", ["mock", "fake", "stub"]))
    allowlist = set(policy.get("allowlist_paths", []))
    waivers = list(policy.get("waivers", []))
    routes = list(policy.get("owner_routes", []))
    default_owner = str(policy.get("default_owner", "runtime-core"))
    now_utc = dt.datetime.now(dt.timezone.utc)

    active_waiver_by_path: dict[str, dict[str, Any]] = {}
    expired_waivers: list[dict[str, Any]] = []
    for waiver in waivers:
        path = waiver.get("path")
        status = waiver.get("status")
        expiry_raw = waiver.get("expires_at_utc")
        if not isinstance(path, str) or not isinstance(status, str) or not isinstance(expiry_raw, str):
            continue
        expiry = parse_iso8601_utc(expiry_raw)
        if status == "active":
            active_waiver_by_path[path] = waiver
            if expiry <= now_utc:
                expired_waivers.append(waiver)

    hits_by_path = run_scan(roots, terms)

    violations: list[dict[str, Any]] = []
    for path, path_hits in sorted(hits_by_path.items()):
        if path in allowlist:
            continue
        waiver = active_waiver_by_path.get(path)
        if waiver is not None and waiver not in expired_waivers:
            continue
        owner = route_owner(path, routes, default_owner)
        tokens = sorted({token for hit in path_hits for token in hit["tokens"]})
        first_line = min(hit["line"] for hit in path_hits)
        violations.append(
            {
                "path": path,
                "owner": owner,
                "first_line": first_line,
                "tokens": tokens,
                "hit_count": len(path_hits),
            }
        )

    report = {
        "schema_version": "no-mock-policy-report-v1",
        "generated_at": utc_now(),
        "policy_path": str(policy_path),
        "scan": {
            "roots": roots,
            "terms": terms,
        },
        "policy_counts": {
            "allowlist_paths": len(allowlist),
            "waivers_total": len(waivers),
            "waivers_active": sum(1 for waiver in waivers if waiver.get("status") == "active"),
        },
        "scan_counts": {
            "matching_paths": len(hits_by_path),
            "matching_hits": sum(len(path_hits) for path_hits in hits_by_path.values()),
            "violating_paths": len(violations),
            "expired_waivers": len(expired_waivers),
        },
        "expired_waivers": [
            {
                "waiver_id": waiver.get("waiver_id", "<unknown>"),
                "path": waiver.get("path"),
                "owner": waiver.get("owner", route_owner(str(waiver.get("path", "")), routes, default_owner)),
                "expires_at_utc": waiver.get("expires_at_utc"),
                "replacement_issue": waiver.get("replacement_issue"),
            }
            for waiver in expired_waivers
        ],
        "violations": violations,
        "status": "pass" if not violations and not expired_waivers else "fail",
    }

    write_json(output, report)
    print(f"No-mock policy report: {output}")
    return 0


def read_report(path: Path, required_schema: str, label: str) -> dict[str, Any]:
    payload = load_json(path)
    schema = payload.get("schema_version")
    if schema != required_schema:
        raise ValueError(f"{label} schema mismatch: expected {required_schema}, got {schema}")
    return payload


def read_previous(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    payload = load_json(path)
    if payload.get("schema_version") != "ci-summary-report-v1":
        return None
    return payload


def nested_get(payload: dict[str, Any], keys: list[str]) -> float | int | None:
    cursor: Any = payload
    for key in keys:
        if not isinstance(cursor, dict) or key not in cursor:
            return None
        cursor = cursor[key]
    if isinstance(cursor, (int, float)):
        return cursor
    return None


def delta(current: dict[str, Any], previous: dict[str, Any] | None, keys: list[str]) -> float | None:
    if previous is None:
        return None
    current_value = nested_get(current, keys)
    previous_value = nested_get(previous, keys)
    if current_value is None or previous_value is None:
        return None
    return round(float(current_value) - float(previous_value), 4)


def ci_context() -> dict[str, Any]:
    context = {
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "sha": os.getenv("GITHUB_SHA"),
        "ref": os.getenv("GITHUB_REF"),
        "workflow": os.getenv("GITHUB_WORKFLOW"),
    }
    return {key: value for key, value in context.items() if value}


def resolve_forensics_scenarios_file(
    forensics_report_path: Path, forensics_payload: dict[str, Any]
) -> Path | None:
    candidates: list[Path] = []
    raw = forensics_payload.get("scenario_log")
    if isinstance(raw, str) and raw:
        raw_path = Path(raw)
        if raw_path.is_absolute():
            candidates.append(raw_path)
        else:
            candidates.append((forensics_report_path.parent / raw_path).resolve())

    # CI artifacts intentionally copy scenarios.ndjson beside summary.json.
    candidates.append(forensics_report_path.parent / "scenarios.ndjson")
    for path in candidates:
        if path.is_file():
            return path
    return None


def collect_reproduction_instructions(
    e2e_matrix: dict[str, Any],
    forensics: dict[str, Any],
    forensics_report_path: Path,
) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []

    for row in e2e_matrix.get("suite_rows", []):
        if not isinstance(row, dict) or row.get("row_ok") is True:
            continue
        instructions.append(
            {
                "source": "e2e_matrix_suite",
                "scenario_id": row.get("scenario_id"),
                "suite": row.get("suite"),
                "artifact_path": row.get("artifact_root"),
                "replay_command": row.get("replay_command"),
                "reason": "scenario matrix row contract failed",
            }
        )

    for row in e2e_matrix.get("raptorq_rows", []):
        if not isinstance(row, dict) or row.get("row_ok") is True:
            continue
        instructions.append(
            {
                "source": "e2e_matrix_raptorq",
                "scenario_id": row.get("scenario_id"),
                "suite": "raptorq-forensics",
                "artifact_path": row.get("artifacts_expected"),
                "replay_command": row.get("replay_command"),
                "reason": "raptorq scenario matrix row contract failed",
            }
        )

    scenarios_file = resolve_forensics_scenarios_file(forensics_report_path, forensics)
    for scenario in load_ndjson(scenarios_file) if scenarios_file else []:
        status = str(scenario.get("status", "")).lower()
        tests_failed = scenario.get("tests_failed")
        exit_code = scenario.get("exit_code")
        failed = status == "fail"
        if isinstance(tests_failed, int) and tests_failed > 0:
            failed = True
        if isinstance(exit_code, int) and exit_code != 0:
            failed = True
        if not failed:
            continue
        instructions.append(
            {
                "source": "forensics_scenario",
                "scenario_id": scenario.get("scenario_id"),
                "suite": "raptorq-forensics",
                "artifact_path": scenario.get("artifact_path"),
                "log_path": scenario.get("log_path"),
                "replay_command": scenario.get("repro_command"),
                "reason": "forensics scenario failed",
            }
        )

    if forensics.get("status") == "fail" and not any(
        item.get("source") == "forensics_scenario" for item in instructions
    ):
        instructions.append(
            {
                "source": "forensics_suite",
                "scenario_id": "RQ-E2E-SUITE-D6",
                "suite": "raptorq-forensics",
                "artifact_path": forensics.get("artifact_dir"),
                "replay_command": "NO_PREFLIGHT=1 bash ./scripts/run_raptorq_e2e.sh --profile forensics",
                "reason": "forensics suite failed; inspect scenarios.ndjson for scenario-level failure metadata",
            }
        )

    return instructions


def collect_ci_matrix_reproduction_instructions(
    ci_matrix: dict[str, Any],
    ci_matrix_report_path: Path,
) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    for lane in ci_matrix.get("lanes", []):
        if not isinstance(lane, dict) or lane.get("status") == "pass":
            continue
        missing = lane.get("missing_contracts", [])
        if not isinstance(missing, list):
            missing = []
        reason = "ci lane contract failed"
        if missing:
            reason = f"ci lane contract failed: {', '.join(str(item) for item in missing)}"
        instructions.append(
            {
                "source": "ci_matrix_lane",
                "scenario_id": f"CI-LANE-{lane.get('lane_id', '<unknown-lane>')}",
                "suite": "ci-matrix-policy",
                "artifact_path": str(ci_matrix_report_path),
                "replay_command": lane.get("replay_command"),
                "reason": reason,
            }
        )
    return instructions


def compose_summary(
    coverage_report: Path,
    no_mock_report: Path,
    ci_matrix_report: Path,
    e2e_matrix_report: Path,
    forensics_report: Path,
    output_json: Path,
    output_markdown: Path,
    previous_report: Path | None,
    fail_on_nonpass: bool,
) -> int:
    coverage = read_report(coverage_report, "coverage-ratchet-report-v1", "coverage report")
    no_mock = read_report(no_mock_report, "no-mock-policy-report-v1", "no-mock report")
    ci_matrix = read_report(ci_matrix_report, "ci-matrix-policy-report-v1", "ci-matrix report")
    e2e_matrix = read_report(e2e_matrix_report, "e2e-scenario-matrix-validation-v1", "e2e matrix report")
    forensics = read_report(forensics_report, "raptorq-e2e-suite-log-v1", "forensics report")
    previous = read_previous(previous_report)

    coverage_section = {
        "status": coverage.get("status", "fail"),
        "global_line_pct": coverage.get("global_coverage", {}).get("line_pct"),
        "global_floor_pct": coverage.get("global_coverage", {}).get("floor_pct"),
        "failure_count": coverage.get("failure_count", 0),
        "failing_subsystems": [
            row.get("id")
            for row in coverage.get("subsystem_results", [])
            if row.get("status") != "pass"
        ],
    }
    no_mock_section = {
        "status": no_mock.get("status", "fail"),
        "matching_paths": no_mock.get("scan_counts", {}).get("matching_paths", 0),
        "violating_paths": no_mock.get("scan_counts", {}).get("violating_paths", 0),
        "expired_waivers": no_mock.get("scan_counts", {}).get("expired_waivers", 0),
        "allowlist_paths": no_mock.get("policy_counts", {}).get("allowlist_paths", 0),
        "active_waivers": no_mock.get("policy_counts", {}).get("waivers_active", 0),
    }
    ci_matrix_section = {
        "status": ci_matrix.get("status", "fail"),
        "lane_count": ci_matrix.get("lane_count", 0),
        "failing_lane_count": ci_matrix.get("failing_lane_count", 0),
        "failing_lane_ids": ci_matrix.get("failing_lane_ids", []),
    }
    e2e_matrix_section = {
        "status": e2e_matrix.get("status", "fail"),
        "suite_row_count": e2e_matrix.get("suite_row_count", 0),
        "raptorq_row_count": e2e_matrix.get("raptorq_row_count", 0),
        "suite_failures": e2e_matrix.get("suite_failures", 0),
        "raptorq_failures": e2e_matrix.get("raptorq_failures", 0),
    }
    forensics_section = {
        "status": forensics.get("status", "fail"),
        "profile": forensics.get("profile"),
        "selected_scenarios": forensics.get("selected_scenarios", 0),
        "passed_scenarios": forensics.get("passed_scenarios", 0),
        "failed_scenarios": forensics.get("failed_scenarios", 0),
    }
    reproduction_instructions = collect_reproduction_instructions(
        e2e_matrix=e2e_matrix,
        forensics=forensics,
        forensics_report_path=forensics_report,
    )
    reproduction_instructions.extend(
        collect_ci_matrix_reproduction_instructions(
            ci_matrix=ci_matrix,
            ci_matrix_report_path=ci_matrix_report,
        )
    )

    sections = {
        "coverage": coverage_section,
        "no_mock": no_mock_section,
        "ci_matrix": ci_matrix_section,
        "e2e_matrix": e2e_matrix_section,
        "forensics": forensics_section,
    }
    overall_status = "pass" if all(section.get("status") == "pass" for section in sections.values()) else "fail"
    if overall_status == "pass" and not reproduction_instructions:
        reproduction_status = "none_required"
    elif reproduction_instructions:
        reproduction_status = "action_required"
    else:
        reproduction_status = "insufficient_data"

    report = {
        "schema_version": "ci-summary-report-v1",
        "generated_at": utc_now(),
        "overall_status": overall_status,
        "sources": {
            "coverage_report": str(coverage_report),
            "no_mock_report": str(no_mock_report),
            "ci_matrix_report": str(ci_matrix_report),
            "e2e_matrix_report": str(e2e_matrix_report),
            "forensics_report": str(forensics_report),
            "previous_report": str(previous_report) if previous_report else None,
        },
        "sections": sections,
        "reproduction": {
            "status": reproduction_status,
            "instruction_count": len(reproduction_instructions),
            "ci_context": ci_context() or None,
            "instructions": reproduction_instructions,
        },
        "trends": {
            "coverage_global_line_pct_delta": delta(
                {"sections": sections}, previous, ["sections", "coverage", "global_line_pct"]
            ),
            "no_mock_matching_paths_delta": delta(
                {"sections": sections}, previous, ["sections", "no_mock", "matching_paths"]
            ),
            "no_mock_violating_paths_delta": delta(
                {"sections": sections}, previous, ["sections", "no_mock", "violating_paths"]
            ),
            "ci_matrix_failing_lanes_delta": delta(
                {"sections": sections}, previous, ["sections", "ci_matrix", "failing_lane_count"]
            ),
            "e2e_matrix_failures_delta": delta(
                {"sections": sections}, previous, ["sections", "e2e_matrix", "suite_failures"]
            ),
            "forensics_failed_scenarios_delta": delta(
                {"sections": sections}, previous, ["sections", "forensics", "failed_scenarios"]
            ),
        },
    }

    write_json(output_json, report)

    md_lines = [
        "# CI Summary Report",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Overall status: `{overall_status}`",
        "",
        "| Area | Status | Key Metrics | Trend |",
        "| --- | --- | --- | --- |",
        (
            "| Coverage | "
            f"`{coverage_section['status']}` | "
            f"global={coverage_section['global_line_pct']}% floor={coverage_section['global_floor_pct']}% "
            f"failures={coverage_section['failure_count']} | "
            f"delta_global={report['trends']['coverage_global_line_pct_delta']} |"
        ),
        (
            "| No-mock policy | "
            f"`{no_mock_section['status']}` | "
            f"matches={no_mock_section['matching_paths']} violations={no_mock_section['violating_paths']} "
            f"expired_waivers={no_mock_section['expired_waivers']} | "
            f"delta_violations={report['trends']['no_mock_violating_paths_delta']} |"
        ),
        (
            "| CI matrix policy | "
            f"`{ci_matrix_section['status']}` | "
            f"lanes={ci_matrix_section['lane_count']} failing={ci_matrix_section['failing_lane_count']} | "
            f"delta_failing_lanes={report['trends']['ci_matrix_failing_lanes_delta']} |"
        ),
        (
            "| E2E matrix (D4) | "
            f"`{e2e_matrix_section['status']}` | "
            f"suite_failures={e2e_matrix_section['suite_failures']} "
            f"raptorq_failures={e2e_matrix_section['raptorq_failures']} | "
            f"delta_suite_failures={report['trends']['e2e_matrix_failures_delta']} |"
        ),
        (
            "| Forensics (D3) | "
            f"`{forensics_section['status']}` | "
            f"profile={forensics_section['profile']} selected={forensics_section['selected_scenarios']} "
            f"failed={forensics_section['failed_scenarios']} | "
            f"delta_failed={report['trends']['forensics_failed_scenarios_delta']} |"
        ),
        "",
        "## Notes",
        f"- Coverage failing subsystems: `{coverage_section['failing_subsystems']}`",
        f"- CI matrix failing lanes: `{ci_matrix_section['failing_lane_ids']}`",
        "- Trend deltas are `None` when no previous D5 summary artifact was provided.",
        "",
        "## Reproduction Instructions",
        f"- Reproduction status: `{reproduction_status}`",
        f"- Instruction count: `{len(reproduction_instructions)}`",
    ]
    if reproduction_instructions:
        md_lines.append("")
        for instruction in reproduction_instructions:
            md_lines.append(
                "- "
                f"{instruction.get('suite', '<unknown-suite>')} / "
                f"{instruction.get('scenario_id', '<unknown-scenario>')}: "
                f"`{instruction.get('replay_command', '<missing-replay-command>')}` "
                f"(artifact: `{instruction.get('artifact_path', '<missing-artifact-path>')}`)"
            )
    else:
        md_lines.append("- All CI gates passed; no explicit repro commands required for this run.")
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"CI summary JSON: {output_json}")
    print(f"CI summary Markdown: {output_markdown}")

    if fail_on_nonpass and overall_status != "pass":
        print("CI summary status is non-pass")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    no_mock_parser = subparsers.add_parser(
        "no-mock-snapshot",
        help="Generate machine-readable no-mock policy snapshot.",
    )
    no_mock_parser.add_argument("--policy", required=True, type=Path)
    no_mock_parser.add_argument("--output", required=True, type=Path)

    compose_parser = subparsers.add_parser(
        "compose",
        help="Compose D5 machine-readable + markdown summary from CI artifacts.",
    )
    compose_parser.add_argument("--coverage-report", required=True, type=Path)
    compose_parser.add_argument("--no-mock-report", required=True, type=Path)
    compose_parser.add_argument("--ci-matrix-report", required=True, type=Path)
    compose_parser.add_argument("--e2e-matrix-report", required=True, type=Path)
    compose_parser.add_argument("--forensics-report", required=True, type=Path)
    compose_parser.add_argument("--output-json", required=True, type=Path)
    compose_parser.add_argument("--output-markdown", required=True, type=Path)
    compose_parser.add_argument("--previous-report", type=Path)
    compose_parser.add_argument("--fail-on-nonpass", action="store_true")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "no-mock-snapshot":
        return no_mock_snapshot(policy_path=args.policy, output=args.output)
    if args.command == "compose":
        return compose_summary(
            coverage_report=args.coverage_report,
            no_mock_report=args.no_mock_report,
            ci_matrix_report=args.ci_matrix_report,
            e2e_matrix_report=args.e2e_matrix_report,
            forensics_report=args.forensics_report,
            output_json=args.output_json,
            output_markdown=args.output_markdown,
            previous_report=args.previous_report,
            fail_on_nonpass=args.fail_on_nonpass,
        )
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
