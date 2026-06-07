#!/usr/bin/env python3
"""Emit deterministic scheduler/resource pressure profiling receipts.

The helper reads a bounded contract or fixture, validates required profiling
receipt fields, and emits JSON or Markdown. It does not run benchmarks, cargo,
git, rch, beads, or Agent Mail.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "scheduler-resource-pressure-profiling-receipts-report-v1"
CONTRACT_SCHEMA_VERSION = "scheduler-resource-pressure-profiling-receipts-v1"
DEFAULT_CONTRACT_PATH = "artifacts/scheduler_resource_pressure_profiling_receipts_v1.json"
REQUIRED_COMMAND_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- env "
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

FORBIDDEN_ACTIONS = {
    "runs_cargo": False,
    "runs_rch": False,
    "runs_git_mutation": False,
    "runs_beads_mutation": False,
    "sends_agent_mail": False,
    "writes_cache": False,
    "deletes_files": False,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def resolve_path(repo_path: Path, path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return repo_path / path


def source_summary(repo_path: Path, path_text: str) -> dict[str, Any]:
    path = resolve_path(repo_path, path_text)
    errors: list[str] = []
    data: Any = {}
    if not path.exists():
        errors.append("source-missing")
    elif path.suffix == ".json":
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            errors.append(str(error))
    else:
        try:
            data = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(str(error))
    return {
        "path": path_text,
        "load_status": "ok" if not errors else "error",
        "digest": canonical_digest(data) if not errors else "",
        "errors": errors,
    }


def required_fields(contract: dict[str, Any]) -> list[str]:
    fields = [item for item in as_list(contract.get("required_receipt_fields")) if isinstance(item, str)]
    return fields or [
        "scenario_id",
        "scenario_family",
        "command",
        "environment",
        "data_hash",
        "top_hot_paths",
        "memory_observations",
        "operator_interpretation",
        "proof_boundary",
        "rch_refresh_command",
        "source_refs",
    ]


def first_hot_path(row: dict[str, Any]) -> str:
    for item in as_list(row.get("top_hot_paths")):
        hot_path = as_dict(item)
        path = as_string(hot_path.get("path"))
        symbol = as_string(hot_path.get("symbol"))
        if path and symbol:
            return f"{path}::{symbol}"
    return ""


def memory_ceiling_mb(row: dict[str, Any]) -> int:
    for item in as_list(row.get("memory_observations")):
        observation = as_dict(item)
        if observation.get("metric") == "refresh_memory_ceiling_mb":
            value = observation.get("value")
            if isinstance(value, int) and not isinstance(value, bool):
                return value
    return 0


def validate_source_refs(repo_path: Path, row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    scenario_id = as_string(row.get("scenario_id")) or "<missing>"
    for source_ref in as_list(row.get("source_refs")):
        if not isinstance(source_ref, str) or not source_ref:
            blockers.append(
                {
                    "kind": "invalid-source-ref",
                    "scenario_id": scenario_id,
                    "reason": "source_refs entries must be nonempty strings",
                }
            )
            continue
        if not resolve_path(repo_path, source_ref).exists():
            blockers.append(
                {
                    "kind": "missing-source-ref",
                    "scenario_id": scenario_id,
                    "path": source_ref,
                    "reason": "source reference path does not exist",
                }
            )


def validate_scenario(
    repo_path: Path,
    row: dict[str, Any],
    fields: list[str],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    scenario_id = as_string(row.get("scenario_id")) or "<missing>"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for field in fields:
        value = row.get(field)
        if value is None or value == "" or value == [] or value == {}:
            blockers.append(
                {
                    "kind": "missing-required-field",
                    "scenario_id": scenario_id,
                    "field": field,
                    "reason": "required profiling receipt field is missing or empty",
                }
            )

    command = as_string(row.get("command"))
    refresh_command = as_string(row.get("rch_refresh_command"))
    for field_name, value in [("command", command), ("rch_refresh_command", refresh_command)]:
        if value and not value.startswith(REQUIRED_COMMAND_PREFIX):
            blockers.append(
                {
                    "kind": "non-rch-refresh-command",
                    "scenario_id": scenario_id,
                    "field": field_name,
                    "reason": "profiling refresh commands must use remote-required rch exec",
                }
            )
        if value and "CARGO_TARGET_DIR=" not in value:
            blockers.append(
                {
                    "kind": "missing-cargo-target-dir",
                    "scenario_id": scenario_id,
                    "field": field_name,
                    "reason": "RCH refresh commands must isolate CARGO_TARGET_DIR",
                }
            )

    data_hash = as_string(row.get("data_hash"))
    if data_hash and not HASH_RE.match(data_hash):
        blockers.append(
            {
                "kind": "invalid-data-hash",
                "scenario_id": scenario_id,
                "reason": "data_hash must be sha256:<64 lowercase hex>",
            }
        )

    environment = as_dict(row.get("environment"))
    if environment:
        if environment.get("remote_required") is not True:
            blockers.append(
                {
                    "kind": "remote-not-required",
                    "scenario_id": scenario_id,
                    "reason": "environment.remote_required must be true",
                }
            )
        if environment.get("local_fallback_allowed") is not False:
            blockers.append(
                {
                    "kind": "local-fallback-allowed",
                    "scenario_id": scenario_id,
                    "reason": "environment.local_fallback_allowed must be false",
                }
            )

    proof_boundary = as_dict(row.get("proof_boundary"))
    if proof_boundary:
        if proof_boundary.get("fresh_benchmark") is not False:
            blockers.append(
                {
                    "kind": "contract-claims-fresh-benchmark",
                    "scenario_id": scenario_id,
                    "reason": "contract receipts must not claim fresh benchmark status",
                }
            )
        if proof_boundary.get("real_host_throughput_proof") is not False:
            blockers.append(
                {
                    "kind": "contract-claims-throughput-proof",
                    "scenario_id": scenario_id,
                    "reason": "contract receipts must not claim real-host throughput proof",
                }
            )

    if not first_hot_path(row):
        blockers.append(
            {
                "kind": "missing-hot-path",
                "scenario_id": scenario_id,
                "reason": "at least one top_hot_paths row must name path and symbol",
            }
        )
    if memory_ceiling_mb(row) <= 0:
        warnings.append(
            {
                "kind": "missing-memory-ceiling",
                "scenario_id": scenario_id,
                "reason": "refresh_memory_ceiling_mb was not present as a positive integer",
            }
        )

    validate_source_refs(repo_path, row, blockers)
    status = "pass" if not blockers else "blocked"
    return status, blockers, warnings


def scenario_receipt(
    repo_path: Path,
    row: dict[str, Any],
    fields: list[str],
    artifact_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    status, blockers, warnings = validate_scenario(repo_path, row, fields)
    interpretation = as_dict(row.get("operator_interpretation"))
    receipt = {
        "scenario_id": as_string(row.get("scenario_id")),
        "scenario_family": as_string(row.get("scenario_family")),
        "title": as_string(row.get("title")),
        "status": status,
        "data_hash": as_string(row.get("data_hash")),
        "command": as_string(row.get("command")),
        "rch_refresh_command": as_string(row.get("rch_refresh_command")),
        "environment": as_dict(row.get("environment")),
        "top_hot_path": first_hot_path(row),
        "top_hot_paths": as_list(row.get("top_hot_paths")),
        "memory_ceiling_mb": memory_ceiling_mb(row),
        "memory_observations": as_list(row.get("memory_observations")),
        "operator_action": as_string(interpretation.get("recommended_action")),
        "operator_interpretation": interpretation,
        "proof_boundary": as_dict(row.get("proof_boundary")),
        "source_refs": as_list(row.get("source_refs")),
        "artifact_path": artifact_path,
        "first_failure": blockers[0]["kind"] if blockers else "",
    }
    return receipt, blockers, warnings


def build_report(repo_path: Path, input_path: Path, generated_at: str, artifact_path: str) -> dict[str, Any]:
    contract = as_dict(load_json(input_path))
    fields = required_fields(contract)
    rows = [as_dict(row) for row in as_list(contract.get("scenario_catalog")) if isinstance(row, dict)]
    receipts: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for row in rows:
        receipt, row_blockers, row_warnings = scenario_receipt(repo_path, row, fields, artifact_path)
        receipts.append(receipt)
        blockers.extend(row_blockers)
        warnings.extend(row_warnings)

    source_paths = as_dict(contract.get("source_of_truth"))
    source_artifacts = [
        source_summary(repo_path, path)
        for path in source_paths.values()
        if isinstance(path, str) and path
    ]
    missing_sources = [source for source in source_artifacts if source["load_status"] != "ok"]
    for source in missing_sources:
        blockers.append(
            {
                "kind": "missing-source-artifact",
                "scenario_id": "",
                "path": source["path"],
                "reason": "source_of_truth path could not be loaded",
            }
        )

    validation_passed = not blockers
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_schema_version": as_string(contract.get("schema_version")),
        "generated_at": generated_at,
        "bead_id": as_string(contract.get("bead_id")),
        "input_path": str(input_path),
        "source_digest": canonical_digest(contract),
        "required_receipt_fields": fields,
        "required_log_fields": as_list(contract.get("required_log_fields")),
        "source_artifacts": source_artifacts,
        "scenario_receipts": receipts,
        "blockers": blockers,
        "warnings": warnings,
        "operator_summary": {
            "scenario_count": len(receipts),
            "pass_count": sum(1 for row in receipts if row["status"] == "pass"),
            "blocked_count": sum(1 for row in receipts if row["status"] == "blocked"),
            "warning_count": len(warnings),
            "validation_passed": validation_passed,
            "first_failure": blockers[0]["kind"] if blockers else "",
            "contract_receipts_are_fresh_benchmarks": False,
            "real_host_throughput_proof": False,
            "requires_rch_refresh_for_numbers": True,
        },
        "proof_boundary": as_dict(contract.get("proof_boundary")),
        "forbidden_actions": FORBIDDEN_ACTIONS,
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Scheduler Resource Pressure Profiling Receipts",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Bead: `{report['bead_id']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Validation passed: `{str(report['operator_summary']['validation_passed']).lower()}`",
        "",
        "These rows are deterministic contract receipts, not fresh benchmark results.",
        "",
        "| Scenario | Family | Status | Memory ceiling MiB | Top hot path |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for row in report["scenario_receipts"]:
        lines.append(
            "| {scenario_id} | {scenario_family} | {status} | {memory_ceiling_mb} | `{top_hot_path}` |".format(
                **row
            )
        )
    lines.extend(
        [
            "",
            "## Refresh Commands",
            "",
        ]
    )
    for row in report["scenario_receipts"]:
        lines.append(f"### {row['scenario_id']}")
        lines.append("")
        lines.append("```bash")
        lines.append(row["rch_refresh_command"])
        lines.append("```")
        lines.append("")
    if report["blockers"]:
        lines.append("## Blockers")
        lines.append("")
        for blocker in report["blockers"]:
            lines.append(
                f"- `{blocker.get('kind', '')}` scenario=`{blocker.get('scenario_id', '')}` reason={blocker.get('reason', '')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default=DEFAULT_CONTRACT_PATH, help="Contract or fixture JSON path.")
    parser.add_argument("--repo-path", default=".", help="Repository root for relative source checks.")
    parser.add_argument("--generated-at", default=utc_now(), help="Deterministic report timestamp.")
    parser.add_argument("--artifact-path", default="", help="Artifact path recorded in receipt rows.")
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    parser.add_argument("--output-path", default="", help="Optional file path for output.")
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    input_path = Path(args.fixture)
    if not input_path.is_absolute():
        input_path = repo_path / input_path
    artifact_path = args.artifact_path or str(input_path)

    report = build_report(repo_path, input_path, args.generated_at, artifact_path)
    if args.output == "json":
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        rendered = markdown_report(report)

    if args.output_path:
        Path(args.output_path).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
