#!/usr/bin/env python3
"""Classify smoke-runner run_report artifacts without mutating the repo."""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "smoke-run-report-receipt-v1"
LOCAL_FALLBACK_RE = re.compile(r"(?i)local fallback|fallback to local|executing locally")
URL_QUERY_RE = re.compile(r"(https?://[^\s?#)>\]]+)\?[^ \n)>\]]+")
TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SECRET_RE = re.compile(
    r"(?i)\b(token|secret|password|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9._~/+=-]{96,}\b")
SPACE_RE = re.compile(r"\s+")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def as_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def redact(text: str, counts: dict[str, int]) -> str:
    def apply(pattern: re.Pattern[str], replacement: str, label: str, value: str) -> str:
        redacted, changed = pattern.subn(replacement, value)
        counts[label] = counts.get(label, 0) + changed
        counts["total"] = counts.get("total", 0) + changed
        return redacted

    text = apply(URL_QUERY_RE, r"\1?[REDACTED_QUERY]", "url_query", text)
    text = apply(TOKEN_RE, r"\1[REDACTED_TOKEN]", "token", text)
    text = apply(SECRET_RE, r"\1\2[REDACTED_SECRET]", "secret", text)
    text = apply(LONG_TOKEN_RE, "[REDACTED_LONG_TOKEN]", "long_token", text)
    return text


def compact(text: str, counts: dict[str, int], limit: int = 280) -> str:
    value = SPACE_RE.sub(" ", redact(text, counts)).strip()
    if len(value) <= limit:
        return value
    counts["truncated"] = counts.get("truncated", 0) + 1
    counts["total"] = counts.get("total", 0) + 1
    return value[: limit - 19].rstrip() + " [TRUNCATED]"


def rows_from(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("results")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    rows = report.get("scenarios")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def scenario_id(row: dict[str, Any], index: int) -> str:
    for key in ("scenario_id", "id", "name"):
        value = as_string(row.get(key))
        if value:
            return value
    return f"scenario-{index:03d}"


def command_for(row: dict[str, Any]) -> str:
    for key in ("executed_command", "command", "contract_command", "repro_command"):
        value = as_string(row.get(key))
        if value:
            return value
    return ""


def row_status(row: dict[str, Any]) -> str:
    status = as_string(row.get("status")).lower()
    if status:
        return status
    validation = row.get("validation_passed")
    if validation is True:
        return "passed"
    if validation is False:
        return "failed"
    return "unknown"


def row_exit_code(row: dict[str, Any]) -> int | None:
    value = row.get("exit_code")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def classify_scenario(row: dict[str, Any], report_dry_run: bool, counts: dict[str, int]) -> dict[str, Any]:
    sid = scenario_id(row, 0)
    status = row_status(row)
    command = command_for(row)
    log_excerpt = compact(as_string(row.get("log_excerpt") or row.get("message")), counts)
    exit_code = row_exit_code(row)
    text_for_fallback = " ".join([status, command, log_excerpt])
    local_fallback = bool(LOCAL_FALLBACK_RE.search(text_for_fallback))
    rch_routed = "rch exec --" in command or "rch' 'exec' '--" in command

    if local_fallback:
        classification = "local-fallback-failed"
    elif status == "dry_run" or report_dry_run:
        classification = "dry-run-only"
    elif status in {"passed", "success", "ok"} and exit_code in (None, 0):
        classification = "executed-pass"
    elif status in {"failed", "error"} or (exit_code is not None and exit_code != 0):
        classification = "executed-fail"
    else:
        classification = "unknown"

    return {
        "scenario_id": sid,
        "status": status,
        "classification": classification,
        "exit_code": exit_code,
        "rch_routed": rch_routed,
        "local_fallback_detected": local_fallback,
        "command": compact(command, counts),
        "log_excerpt": log_excerpt,
    }


def build_receipt(
    report: dict[str, Any],
    required_scenarios: list[str],
    generated_at: str,
    agent: str,
) -> dict[str, Any]:
    redaction_counts: dict[str, int] = {}
    report_dry_run = bool(report.get("dry_run"))
    scenarios = []
    for index, row in enumerate(rows_from(report)):
        classified = classify_scenario(row, report_dry_run, redaction_counts)
        if classified["scenario_id"].startswith("scenario-"):
            classified["scenario_id"] = scenario_id(row, index)
        scenarios.append(classified)

    present = {row["scenario_id"] for row in scenarios}
    missing = sorted(set(required_scenarios) - present)
    classification_counts: dict[str, int] = {}
    for row in scenarios:
        key = row["classification"]
        classification_counts[key] = classification_counts.get(key, 0) + 1
    for sid in missing:
        classification_counts["missing-required-scenario"] = (
            classification_counts.get("missing-required-scenario", 0) + 1
        )

    cues = []
    for sid in missing:
        cues.append(
            {
                "kind": "missing-required-scenario",
                "scenario_id": sid,
                "severity": "blocker",
                "message": f"required scenario {sid} is absent from run_report",
            }
        )
    for row in scenarios:
        if row["classification"] == "dry-run-only":
            cues.append(
                {
                    "kind": "dry-run-only",
                    "scenario_id": row["scenario_id"],
                    "severity": "warning",
                    "message": "dry-run output is planning evidence, not executed proof",
                }
            )
        elif row["classification"] == "local-fallback-failed":
            cues.append(
                {
                    "kind": "local-fallback",
                    "scenario_id": row["scenario_id"],
                    "severity": "blocker",
                    "message": "runner detected local cargo fallback and refused the proof",
                }
            )
        elif row["classification"] == "executed-fail":
            cues.append(
                {
                    "kind": "executed-failure",
                    "scenario_id": row["scenario_id"],
                    "severity": "blocker",
                    "message": "executed smoke scenario failed",
                }
            )
        elif not row["rch_routed"]:
            cues.append(
                {
                    "kind": "not-rch-routed",
                    "scenario_id": row["scenario_id"],
                    "severity": "blocker",
                    "message": "scenario command does not include rch exec routing",
                }
            )

    has_blocker = any(cue["severity"] == "blocker" for cue in cues)
    all_executed_pass = bool(scenarios) and not has_blocker and all(
        row["classification"] == "executed-pass" and row["rch_routed"] for row in scenarios
    )
    dry_run_only = bool(scenarios) and not has_blocker and all(
        row["classification"] == "dry-run-only" for row in scenarios
    )

    if all_executed_pass:
        verdict = "executed-proof-complete"
    elif dry_run_only:
        verdict = "dry-run-plan-only"
    elif has_blocker:
        verdict = "blocked"
    else:
        verdict = "needs-review"

    redaction_counts.setdefault("total", 0)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "agent": agent,
        "contract_version": as_string(report.get("contract_version")),
        "report_schema_version": as_string(report.get("schema_version")),
        "run_dir": compact(as_string(report.get("run_dir")), redaction_counts, limit=220),
        "dry_run": report_dry_run,
        "verdict": verdict,
        "source_counts": {
            "scenarios": len(scenarios),
            "required_scenarios": len(required_scenarios),
            "missing_required_scenarios": len(missing),
            "review_cues": len(cues),
        },
        "classification_counts": dict(sorted(classification_counts.items())),
        "missing_required_scenarios": missing,
        "scenarios": sorted(scenarios, key=lambda row: row["scenario_id"]),
        "review_cues": sorted(cues, key=lambda cue: (cue["severity"], cue["kind"], cue["scenario_id"])),
        "redaction_counts": dict(sorted(redaction_counts.items())),
        "safety": {
            "non_mutating": True,
            "reads_fixture_only": True,
            "agent_mail_mutated": False,
            "beads_mutated": False,
            "git_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "files_deleted": False,
            "live_probe_performed": False,
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path, help="run_report JSON fixture")
    parser.add_argument(
        "--required-scenario",
        action="append",
        default=[],
        help="required scenario ID; repeatable",
    )
    parser.add_argument("--generated-at", default=None, help="stable generated_at timestamp")
    parser.add_argument("--agent", default="unknown", help="agent name for receipt metadata")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = load_json(args.fixture)
    if not isinstance(report, dict):
        print("fixture root must be a JSON object", file=sys.stderr)
        return 2
    receipt = build_receipt(
        report=report,
        required_scenarios=as_string_list(args.required_scenario),
        generated_at=args.generated_at or utc_now(),
        agent=args.agent,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
