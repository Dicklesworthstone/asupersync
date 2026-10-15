#!/usr/bin/env python3
"""Emit deterministic RCH quiet-phase progress receipts.

The helper consumes explicit RCH log fixtures, proof-lane envelopes, and command
provenance. It does not run Cargo, inspect Git, mutate beads, query Agent Mail,
or rewrite artifacts.
"""

import argparse
import copy
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-quiet-phase-receipt-v1"
FIXTURE_SCHEMA_VERSION = "rch-quiet-phase-fixture-v1"
CONTRACT_SCHEMA_VERSION = "rch-quiet-phase-contract-v1"

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-treat-quiet-progress-as-success",
    "do-not-cite-local-fallback-as-rch-proof",
    "do-not-ignore-missing-remote-worker-evidence",
    "do-not-ignore-artifact-retrieval-stalls",
    "do-not-close-lane-without-remote-exit-evidence",
    "do-not-restart-a-long-lane-without-preserving-the-log",
]

GLOBAL_NON_CLAIMS = [
    "Quiet-phase progress is liveness evidence; it does not prove source correctness.",
    "Only remote exit evidence plus proof semantics can make a proof lane citeable.",
    "Fixture snapshots do not override live RCH worker, queue, or artifact state.",
    "Local fallback is never acceptable proof for remote-required cargo validation.",
]

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "local-fallback-refused": {
        "severity": 100,
        "proof_success_citable": False,
        "progress_evidence": False,
        "recommended_action": "wait-for-remote-rch-admission",
        "operator_action": "Do not use local fallback; keep remote-required RCH and preserve the refusal log.",
    },
    "missing-remote-required-evidence": {
        "severity": 95,
        "proof_success_citable": False,
        "progress_evidence": False,
        "recommended_action": "rerun-with-remote-required-provenance",
        "operator_action": "Do not cite the lane until RCH_REQUIRE_REMOTE, worker identity, and remote command markers exist.",
    },
    "remote-command-failed": {
        "severity": 90,
        "proof_success_citable": False,
        "progress_evidence": True,
        "recommended_action": "triage-remote-command-failure",
        "operator_action": "Use the failed remote exit and first hard failure; do not report the quiet phase as success.",
    },
    "artifact-retrieval-stall": {
        "severity": 80,
        "proof_success_citable": False,
        "progress_evidence": True,
        "recommended_action": "classify-retrieval-separately-before-closeout",
        "operator_action": "Remote command evidence exists, but closeout is incomplete until artifact retrieval is resolved or explicitly separated.",
    },
    "envelope-timeout-risk": {
        "severity": 70,
        "proof_success_citable": False,
        "progress_evidence": True,
        "recommended_action": "poll-or-forecast-timeout-before-restart",
        "operator_action": "Treat the log as progress evidence only; preserve it and compare against the proof-lane envelope before restarting.",
    },
    "remote-success-with-quiet-progress": {
        "severity": 10,
        "proof_success_citable": True,
        "progress_evidence": True,
        "recommended_action": "cite-exit-zero-not-quiet-progress",
        "operator_action": "The lane is citeable because remote exit was zero and artifacts completed, not because the quiet phase looked healthy.",
    },
}

LOCAL_FALLBACK_RE = re.compile(
    r"(?i)(^\[RCH\]\s+local\b|falling back to local|executing locally|local fallback refused|remote required; refusing local fallback)"
)
SELECTED_WORKER_RE = re.compile(r"Selected worker:\s*(?P<worker>\S+)")
SYNC_START_RE = re.compile(r"Syncing project to worker\s+(?P<worker>\S+)")
SYNC_COMPLETE_RE = re.compile(
    r"Sync complete:\s*(?P<files>\d+)\s+files,\s*(?P<bytes>\d+)\s+bytes\s+in\s+(?P<elapsed_ms>\d+)ms"
)
REMOTE_COMMAND_RE = re.compile(r"Executing command remotely:\s*(?P<command>.+)$")
CRATE_PHASE_RE = re.compile(
    r"\b(?:Compiling|Checking|Finished)\s+(?P<crate>[A-Za-z0-9_.-]+)"
)
REMOTE_FINISHED_RE = re.compile(
    r"Remote command finished:\s*exit=(?P<exit>-?\d+)(?:\s+in\s+(?P<elapsed_ms>\d+)ms)?"
)
RETRIEVAL_START_RE = re.compile(r"Retrieving build artifacts|Retrieving artifacts from")
ARTIFACTS_RETRIEVED_RE = re.compile(
    r"Artifacts retrieved in\s+(?P<elapsed_ms>\d+)ms(?:\s+\((?P<files>\d+)\s+files,\s*(?P<bytes>\d+)\s+bytes\))?"
)
FINAL_REMOTE_SUMMARY_RE = re.compile(r"^\[RCH\]\s+remote\s+(?P<worker>\S+)\s+\((?P<seconds>[0-9.]+)s\)")
TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)"
)
REMOTE_REQUIRED_TRUE_VALUES = {"1", "true", "yes", "on"}


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
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
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
        if key == "env" and isinstance(value, dict):
            merged[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
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


def seconds_between(left: str, right: str) -> int | None:
    parsed_left = parse_timestamp(left)
    parsed_right = parse_timestamp(right)
    if parsed_left is None or parsed_right is None:
        return None
    return int((parsed_right - parsed_left).total_seconds())


def line_timestamp(line: str) -> str:
    match = TIMESTAMP_RE.search(line)
    return match.group("timestamp") if match else ""


def add_milestone(
    milestones: list[dict[str, Any]],
    line_no: int,
    line: str,
    kind: str,
    **extra: Any,
) -> None:
    row = {
        "line": line_no,
        "timestamp": line_timestamp(line),
        "kind": kind,
        "text": line.strip(),
    }
    row.update(extra)
    milestones.append(row)


def parse_milestones(log_text: str) -> dict[str, Any]:
    milestones: list[dict[str, Any]] = []
    local_fallback_lines: list[dict[str, Any]] = []
    selected_worker = ""
    remote_command = ""
    remote_exit: int | None = None
    remote_elapsed_ms: int | None = None
    retrieval_completed = False
    retrieval_elapsed_ms: int | None = None
    artifact_file_count: int | None = None
    artifact_bytes: int | None = None
    final_remote_seconds: float | None = None

    for line_no, line in enumerate(log_text.splitlines(), start=1):
        if LOCAL_FALLBACK_RE.search(line):
            local_fallback_lines.append({"line": line_no, "text": line.strip()})
            add_milestone(milestones, line_no, line, "local-fallback")
        if match := SELECTED_WORKER_RE.search(line):
            selected_worker = match.group("worker")
            add_milestone(
                milestones,
                line_no,
                line,
                "selected-worker",
                worker=selected_worker,
            )
        if match := SYNC_START_RE.search(line):
            add_milestone(
                milestones,
                line_no,
                line,
                "sync-start",
                worker=match.group("worker"),
            )
        if match := SYNC_COMPLETE_RE.search(line):
            add_milestone(
                milestones,
                line_no,
                line,
                "sync-complete",
                file_count=int_value(match.group("files")),
                byte_count=int_value(match.group("bytes")),
                elapsed_ms=int_value(match.group("elapsed_ms")),
            )
        if match := REMOTE_COMMAND_RE.search(line):
            remote_command = match.group("command").strip()
            add_milestone(
                milestones,
                line_no,
                line,
                "remote-command-start",
                command=remote_command,
            )
        if match := CRATE_PHASE_RE.search(line):
            crate = match.group("crate")
            if crate.startswith("asupersync"):
                add_milestone(
                    milestones,
                    line_no,
                    line,
                    "workspace-crate-phase",
                    crate=crate,
                )
        if match := REMOTE_FINISHED_RE.search(line):
            remote_exit = int_value(match.group("exit"))
            elapsed_text = match.group("elapsed_ms")
            remote_elapsed_ms = int_value(elapsed_text) if elapsed_text else None
            add_milestone(
                milestones,
                line_no,
                line,
                "remote-command-finished",
                exit_code=remote_exit,
                elapsed_ms=remote_elapsed_ms,
            )
        if RETRIEVAL_START_RE.search(line):
            add_milestone(milestones, line_no, line, "artifact-retrieval-start")
        if match := ARTIFACTS_RETRIEVED_RE.search(line):
            retrieval_completed = True
            retrieval_elapsed_ms = int_value(match.group("elapsed_ms"))
            artifact_file_count = int_value(match.group("files"), 0) if match.group("files") else None
            artifact_bytes = int_value(match.group("bytes"), 0) if match.group("bytes") else None
            add_milestone(
                milestones,
                line_no,
                line,
                "artifacts-retrieved",
                elapsed_ms=retrieval_elapsed_ms,
                file_count=artifact_file_count,
                byte_count=artifact_bytes,
            )
        if match := FINAL_REMOTE_SUMMARY_RE.search(line):
            final_remote_seconds = float(match.group("seconds"))
            add_milestone(
                milestones,
                line_no,
                line,
                "final-remote-summary",
                worker=match.group("worker"),
                elapsed_seconds=final_remote_seconds,
            )

    return {
        "milestones": milestones,
        "local_fallback_lines": local_fallback_lines,
        "selected_worker": selected_worker,
        "remote_command": remote_command,
        "remote_exit_code": remote_exit,
        "remote_elapsed_ms": remote_elapsed_ms,
        "retrieval_completed": retrieval_completed,
        "retrieval_elapsed_ms": retrieval_elapsed_ms,
        "artifact_file_count": artifact_file_count,
        "artifact_bytes": artifact_bytes,
        "final_remote_seconds": final_remote_seconds,
    }


def quiet_phases(milestones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    for milestone in milestones:
        if not string(milestone.get("timestamp")):
            continue
        if previous is not None:
            seconds = seconds_between(
                string(previous.get("timestamp")),
                string(milestone.get("timestamp")),
            )
            if seconds is not None:
                phases.append(
                    {
                        "from": string(previous.get("kind")),
                        "to": string(milestone.get("kind")),
                        "from_line": int_value(previous.get("line")),
                        "to_line": int_value(milestone.get("line")),
                        "seconds": seconds,
                    }
                )
        previous = milestone
    return phases


def longest_quiet_phase(phases: list[dict[str, Any]]) -> dict[str, Any]:
    if not phases:
        return {
            "from": "",
            "to": "",
            "from_line": 0,
            "to_line": 0,
            "seconds": 0,
        }
    return sorted(phases, key=lambda phase: (-int_value(phase.get("seconds")), string(phase.get("from"))))[0]


def command_remote_required(lane: dict[str, Any]) -> bool:
    command = lane.get("command_provenance")
    if not isinstance(command, dict):
        return False
    env = command.get("env")
    if not isinstance(env, dict):
        return False
    return string(env.get("RCH_REQUIRE_REMOTE")).lower() in REMOTE_REQUIRED_TRUE_VALUES


def envelope(lane: dict[str, Any]) -> dict[str, Any]:
    value = lane.get("proof_envelope")
    return value if isinstance(value, dict) else {}


def lane_blockers(lane: dict[str, Any], parsed: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not string(lane.get("bead_id")):
        blockers.append("lane:bead_id:missing")
    if not string(lane.get("command_id")):
        blockers.append("lane:command_id:missing")
    if not command_remote_required(lane):
        blockers.append("command_provenance:RCH_REQUIRE_REMOTE:missing")
    if not string(parsed.get("selected_worker")):
        blockers.append("rch:selected-worker:missing")
    if not string(parsed.get("remote_command")):
        blockers.append("rch:remote-command-start:missing")
    env = envelope(lane)
    if not bool_value(env.get("remote_required"), False):
        blockers.append("proof_envelope:remote_required:must-be-true")
    if not bool_value(env.get("no_local_fallback"), False):
        blockers.append("proof_envelope:no_local_fallback:must-be-true")
    if int_value(env.get("timeout_seconds"), -1) <= 0:
        blockers.append("proof_envelope:timeout_seconds:missing")
    return sorted_strings(blockers)


def classify_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    lane = scenario.get("lane") if isinstance(scenario.get("lane"), dict) else {}
    parsed = parse_milestones(string(scenario.get("log_excerpt")))
    phases = quiet_phases(parsed["milestones"])
    longest = longest_quiet_phase(phases)
    env = envelope(lane)
    quiet_warning = int_value(env.get("quiet_warning_seconds"), 600)
    timeout_seconds = int_value(env.get("timeout_seconds"), 0)
    retrieval_timeout = int_value(env.get("artifact_retrieval_timeout_seconds"), 120)
    blockers: list[str] = []
    warnings: list[str] = []

    if parsed["local_fallback_lines"]:
        classification = "local-fallback-refused"
        blockers = [
            f"local-fallback-line:{line['line']}"
            for line in parsed["local_fallback_lines"]
        ]
    else:
        remote_gaps = lane_blockers(lane, parsed)
        if remote_gaps:
            classification = "missing-remote-required-evidence"
            blockers = remote_gaps
        elif parsed["remote_exit_code"] is not None and int_value(parsed["remote_exit_code"]) != 0:
            classification = "remote-command-failed"
            blockers = [f"remote-exit={parsed['remote_exit_code']}"]
        elif (
            parsed["remote_exit_code"] == 0
            and not bool_value(parsed.get("retrieval_completed"), False)
            and any(row["kind"] == "artifact-retrieval-start" for row in parsed["milestones"])
        ):
            classification = "artifact-retrieval-stall"
            blockers = ["artifact-retrieval:started-not-completed"]
        elif int_value(longest.get("seconds")) >= timeout_seconds > 0:
            classification = "envelope-timeout-risk"
            blockers = [f"quiet-phase-seconds={int_value(longest.get('seconds'))}"]
        elif int_value(longest.get("seconds")) >= quiet_warning:
            if parsed["remote_exit_code"] == 0 and parsed["retrieval_completed"]:
                classification = "remote-success-with-quiet-progress"
            else:
                classification = "envelope-timeout-risk"
                blockers = [f"quiet-phase-seconds={int_value(longest.get('seconds'))}"]
        elif parsed["remote_exit_code"] == 0 and parsed["retrieval_completed"]:
            classification = "remote-success-with-quiet-progress"
        else:
            classification = "envelope-timeout-risk"
            blockers = ["remote-exit:missing"]

    if int_value(longest.get("seconds")) >= quiet_warning:
        warnings.append(f"quiet-phase-exceeded-warning={int_value(longest.get('seconds'))}")
    if (
        parsed["retrieval_elapsed_ms"] is not None
        and int_value(parsed["retrieval_elapsed_ms"]) > retrieval_timeout * 1000
    ):
        warnings.append(f"artifact-retrieval-slow-ms={parsed['retrieval_elapsed_ms']}")
    if parsed["remote_elapsed_ms"] is not None and timeout_seconds > 0:
        if int_value(parsed["remote_elapsed_ms"]) > timeout_seconds * 1000:
            warnings.append(f"remote-elapsed-exceeds-envelope-ms={parsed['remote_elapsed_ms']}")

    catalog = CLASSIFICATION_CATALOG[classification]
    return {
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": catalog["severity"],
        "proof_success_citable": bool_value(catalog.get("proof_success_citable"), False),
        "progress_evidence": bool_value(catalog.get("progress_evidence"), False),
        "recommended_action": catalog["recommended_action"],
        "operator_action": catalog["operator_action"],
        "lane": {
            "bead_id": string(lane.get("bead_id")),
            "command_id": string(lane.get("command_id")),
            "proof_envelope": env,
            "remote_required": command_remote_required(lane),
        },
        "markers": {
            "selected_worker": string(parsed.get("selected_worker")),
            "remote_command_present": bool(string(parsed.get("remote_command"))),
            "remote_exit_code": parsed["remote_exit_code"],
            "remote_elapsed_ms": parsed["remote_elapsed_ms"],
            "retrieval_completed": parsed["retrieval_completed"],
            "retrieval_elapsed_ms": parsed["retrieval_elapsed_ms"],
            "artifact_file_count": parsed["artifact_file_count"],
            "artifact_bytes": parsed["artifact_bytes"],
            "final_remote_seconds": parsed["final_remote_seconds"],
        },
        "quiet_phase_summary": {
            "phase_count": len(phases),
            "quiet_warning_seconds": quiet_warning,
            "timeout_seconds": timeout_seconds,
            "longest": longest,
            "phases": phases,
        },
        "milestones": parsed["milestones"],
        "warnings": sorted_strings(warnings),
        "blockers": sorted_strings(blockers),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def build_report(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    rows = [classify_scenario(scenario) for scenario in expanded_scenarios(fixture)]
    rows.sort(key=lambda row: (-int_value(row.get("severity")), string(row.get("scenario_id"))))
    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1
    summary = {
        "scenario_count": len(rows),
        "proof_success_citable_count": sum(1 for row in rows if row["proof_success_citable"]),
        "progress_evidence_count": sum(1 for row in rows if row["progress_evidence"]),
        "warning_count": sum(len(row["warnings"]) for row in rows),
        "blocker_count": sum(len(row["blockers"]) for row in rows),
        "local_fallback_count": classification_counts["local-fallback-refused"],
        "artifact_stall_count": classification_counts["artifact-retrieval-stall"],
        "highest_severity_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
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
        "# RCH Quiet-Phase Receipt",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Scenarios: {summary['scenario_count']}",
        f"- Citeable proofs: {summary['proof_success_citable_count']}",
        f"- Progress evidence rows: {summary['progress_evidence_count']}",
        f"- Warnings: {summary['warning_count']}",
        f"- Blockers: {summary['blocker_count']}",
        f"- Highest severity scenario: `{summary['highest_severity_scenario']}`",
        "",
        "| Scenario | Classification | Citeable | Progress | Longest Quiet | Action | Blockers |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for row in report["rows"]:
        lines.append(
            "| {scenario} | `{classification}` | {citeable} | {progress} | {quiet}s | `{action}` | {blockers} |".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                citeable="yes" if row["proof_success_citable"] else "no",
                progress="yes" if row["progress_evidence"] else "no",
                quiet=row["quiet_phase_summary"]["longest"]["seconds"],
                action=row["recommended_action"],
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
        description="Emit read-only RCH quiet-phase progress receipts."
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
