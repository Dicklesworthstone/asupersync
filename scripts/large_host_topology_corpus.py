#!/usr/bin/env python3
"""Emit deterministic large-host topology corpus receipts.

The helper reads a bounded topology corpus or fixture, validates the schema,
and emits JSON or Markdown. It does not probe the host and does not run Cargo,
RCH, Git, Beads, Agent Mail, profilers, or benchmarks.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "large-host-topology-corpus-report-v1"
CONTRACT_SCHEMA_VERSION = "large-host-topology-corpus-v1"
DEFAULT_CONTRACT_PATH = "artifacts/large_host_topology_corpus_v1.json"
REQUIRED_COMMAND_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- env "

FORBIDDEN_ACTIONS = {
    "runs_cargo": False,
    "runs_rch": False,
    "runs_git_mutation": False,
    "runs_beads_mutation": False,
    "sends_agent_mail": False,
    "writes_cache": False,
    "probes_host": False,
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


def as_positive_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return 0


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


def required_profile_fields(contract: dict[str, Any]) -> list[str]:
    fields = [item for item in as_list(contract.get("required_profile_fields")) if isinstance(item, str)]
    return fields or [
        "profile_id",
        "profile_family",
        "title",
        "topology",
        "memory",
        "cgroup",
        "rch_slot_model",
        "contention_domains",
        "fallback_policy",
        "operator_interpretation",
        "proof_boundary",
        "rch_refresh_command",
        "source_refs",
    ]


def required_log_fields(contract: dict[str, Any]) -> list[str]:
    fields = [item for item in as_list(contract.get("required_log_fields")) if isinstance(item, str)]
    return fields or [
        "bead_id",
        "profile_id",
        "profile_family",
        "status",
        "physical_cores",
        "memory_gib",
        "numa_nodes",
        "rch_slots",
        "fallback_action",
        "artifact_path",
        "first_failure",
    ]


def validate_source_refs(repo_path: Path, row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    for source_ref in as_list(row.get("source_refs")):
        if not isinstance(source_ref, str) or not source_ref:
            blockers.append(
                {
                    "kind": "invalid-source-ref",
                    "profile_id": profile_id,
                    "reason": "source_refs entries must be nonempty strings",
                }
            )
            continue
        if not resolve_path(repo_path, source_ref).exists():
            blockers.append(
                {
                    "kind": "missing-source-ref",
                    "profile_id": profile_id,
                    "path": source_ref,
                    "reason": "source reference path does not exist",
                }
            )


def validate_command(profile_id: str, field_name: str, command: str, blockers: list[dict[str, Any]]) -> None:
    if not command:
        return
    if not command.startswith(REQUIRED_COMMAND_PREFIX):
        blockers.append(
            {
                "kind": "non-rch-refresh-command",
                "profile_id": profile_id,
                "field": field_name,
                "reason": "topology refresh commands must use remote-required rch exec",
            }
        )
    if "CARGO_TARGET_DIR=" not in command:
        blockers.append(
            {
                "kind": "missing-cargo-target-dir",
                "profile_id": profile_id,
                "field": field_name,
                "reason": "RCH refresh commands must isolate CARGO_TARGET_DIR",
            }
        )


def validate_topology(row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    topology = as_dict(row.get("topology"))
    if not topology:
        blockers.append(
            {
                "kind": "missing-topology",
                "profile_id": profile_id,
                "reason": "topology must declare cores, sockets, NUMA nodes, and cache domains",
            }
        )
        return

    physical_cores = as_positive_int(topology.get("physical_cores"))
    hardware_threads = as_positive_int(topology.get("hardware_threads"))
    smt = as_positive_int(topology.get("smt_threads_per_core"))
    sockets = as_positive_int(topology.get("socket_count"))
    numa_nodes = as_positive_int(topology.get("numa_nodes"))
    if min(physical_cores, hardware_threads, smt, sockets, numa_nodes) == 0:
        blockers.append(
            {
                "kind": "invalid-topology-counts",
                "profile_id": profile_id,
                "reason": "topology counts must be positive integers",
            }
        )
    elif hardware_threads < physical_cores:
        blockers.append(
            {
                "kind": "hardware-threads-less-than-cores",
                "profile_id": profile_id,
                "reason": "hardware_threads must be greater than or equal to physical_cores",
            }
        )

    cache_domains = as_list(topology.get("cache_domains"))
    if not cache_domains:
        blockers.append(
            {
                "kind": "missing-cache-domains",
                "profile_id": profile_id,
                "reason": "at least one cache domain is required",
            }
        )
    for index, domain in enumerate(cache_domains):
        domain = as_dict(domain)
        if not as_string(domain.get("domain_id")) or not as_string(domain.get("core_range")):
            blockers.append(
                {
                    "kind": "invalid-cache-domain",
                    "profile_id": profile_id,
                    "index": index,
                    "reason": "cache domain rows need domain_id and core_range",
                }
            )
        if as_positive_int(domain.get("shared_l3_mib")) == 0:
            blockers.append(
                {
                    "kind": "invalid-cache-domain-size",
                    "profile_id": profile_id,
                    "index": index,
                    "reason": "shared_l3_mib must be positive",
                }
            )


def validate_memory(row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    memory = as_dict(row.get("memory"))
    topology = as_dict(row.get("topology"))
    numa_nodes = as_positive_int(topology.get("numa_nodes"))
    if not memory:
        blockers.append(
            {
                "kind": "missing-memory",
                "profile_id": profile_id,
                "reason": "memory must declare total and per-NUMA-node capacity",
            }
        )
        return
    if as_positive_int(memory.get("total_gib")) == 0:
        blockers.append(
            {
                "kind": "invalid-memory-total",
                "profile_id": profile_id,
                "reason": "memory.total_gib must be positive",
            }
        )
    if as_positive_int(memory.get("admission_memory_ceiling_gib")) == 0:
        blockers.append(
            {
                "kind": "invalid-memory-ceiling",
                "profile_id": profile_id,
                "reason": "memory.admission_memory_ceiling_gib must be positive",
            }
        )
    per_numa = as_list(memory.get("per_numa_node_gib"))
    if numa_nodes and len(per_numa) != numa_nodes:
        blockers.append(
            {
                "kind": "per-numa-memory-count-mismatch",
                "profile_id": profile_id,
                "reason": "per_numa_node_gib length must match topology.numa_nodes",
            }
        )
    for index, value in enumerate(per_numa):
        if as_positive_int(value) == 0:
            blockers.append(
                {
                    "kind": "invalid-per-numa-memory",
                    "profile_id": profile_id,
                    "index": index,
                    "reason": "per-NUMA memory entries must be positive integers",
                }
            )


def validate_cgroup_and_slots(row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    cgroup = as_dict(row.get("cgroup"))
    slots = as_dict(row.get("rch_slot_model"))
    if not cgroup:
        blockers.append(
            {
                "kind": "missing-cgroup-envelope",
                "profile_id": profile_id,
                "reason": "cgroup must declare effective CPU and memory limits",
            }
        )
    else:
        if cgroup.get("detected_from_live_host") is not False:
            blockers.append(
                {
                    "kind": "live-host-detection-claim",
                    "profile_id": profile_id,
                    "reason": "deterministic corpus rows must not claim live host detection",
                }
            )
        for field in ["cpuset_effective_cores", "memory_max_gib", "cpu_quota_cores"]:
            if as_positive_int(cgroup.get(field)) == 0:
                blockers.append(
                    {
                        "kind": "invalid-cgroup-field",
                        "profile_id": profile_id,
                        "field": field,
                        "reason": "cgroup numeric fields must be positive",
                    }
                )
    if not slots:
        blockers.append(
            {
                "kind": "missing-rch-slot-model",
                "profile_id": profile_id,
                "reason": "rch_slot_model must declare recommended slots and heavy-lane limits",
            }
        )
    else:
        for field in ["recommended_slots", "max_parallel_heavy_lanes"]:
            if as_positive_int(slots.get(field)) == 0:
                blockers.append(
                    {
                        "kind": "invalid-rch-slot-field",
                        "profile_id": profile_id,
                        "field": field,
                        "reason": "RCH slot model fields must be positive",
                    }
                )


def validate_fallback_and_boundary(row: dict[str, Any], blockers: list[dict[str, Any]]) -> None:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    fallback = as_dict(row.get("fallback_policy"))
    if not fallback:
        blockers.append(
            {
                "kind": "missing-fallback-policy",
                "profile_id": profile_id,
                "reason": "every topology profile must declare a safe fallback",
            }
        )
    else:
        for field in ["missing_topology_action", "safe_default_profile", "operator_action"]:
            if not as_string(fallback.get(field)):
                blockers.append(
                    {
                        "kind": "invalid-fallback-policy",
                        "profile_id": profile_id,
                        "field": field,
                        "reason": "fallback policy field must be a nonempty string",
                    }
                )
        if not as_list(fallback.get("reason_codes")):
            blockers.append(
                {
                    "kind": "missing-fallback-reason-codes",
                    "profile_id": profile_id,
                    "reason": "fallback policy must include reason codes",
                }
            )

    boundary = as_dict(row.get("proof_boundary"))
    for field in ["corpus_is_live_host_measurement", "corpus_is_fresh_benchmark", "proves_real_host_throughput"]:
        if boundary.get(field) is not False:
            blockers.append(
                {
                    "kind": "invalid-proof-boundary",
                    "profile_id": profile_id,
                    "field": field,
                    "reason": "topology corpus rows must preserve non-claim boundaries",
                }
            )


def validate_profile(
    repo_path: Path,
    row: dict[str, Any],
    fields: list[str],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    profile_id = as_string(row.get("profile_id")) or "<missing>"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for field in fields:
        value = row.get(field)
        if value is None or value == "" or value == [] or value == {}:
            blockers.append(
                {
                    "kind": "missing-required-field",
                    "profile_id": profile_id,
                    "field": field,
                    "reason": "required topology profile field is missing or empty",
                }
            )

    validate_command(profile_id, "rch_refresh_command", as_string(row.get("rch_refresh_command")), blockers)
    validate_topology(row, blockers)
    validate_memory(row, blockers)
    validate_cgroup_and_slots(row, blockers)
    validate_fallback_and_boundary(row, blockers)
    validate_source_refs(repo_path, row, blockers)

    if not as_list(row.get("contention_domains")):
        warnings.append(
            {
                "kind": "missing-contention-domain-detail",
                "profile_id": profile_id,
                "reason": "no contention domains were declared",
            }
        )

    return profile_id, blockers, warnings


def profile_receipt(
    row: dict[str, Any],
    blockers: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    topology = as_dict(row.get("topology"))
    memory = as_dict(row.get("memory"))
    slots = as_dict(row.get("rch_slot_model"))
    fallback = as_dict(row.get("fallback_policy"))
    first_failure = blockers[0]["kind"] if blockers else ""
    return {
        "profile_id": as_string(row.get("profile_id")) or "<missing>",
        "profile_family": as_string(row.get("profile_family")),
        "title": as_string(row.get("title")),
        "status": "blocked" if blockers else "pass",
        "physical_cores": as_positive_int(topology.get("physical_cores")),
        "hardware_threads": as_positive_int(topology.get("hardware_threads")),
        "memory_gib": as_positive_int(memory.get("total_gib")),
        "numa_nodes": as_positive_int(topology.get("numa_nodes")),
        "rch_slots": as_positive_int(slots.get("recommended_slots")),
        "max_parallel_heavy_lanes": as_positive_int(slots.get("max_parallel_heavy_lanes")),
        "fallback_action": as_string(fallback.get("missing_topology_action")),
        "operator_action": as_string(fallback.get("operator_action")),
        "rch_refresh_command": as_string(row.get("rch_refresh_command")),
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "first_failure": first_failure,
        "profile_digest": canonical_digest(row),
    }


def build_report(contract: dict[str, Any], repo_path: Path, generated_at: str, artifact_path: str) -> dict[str, Any]:
    fields = required_profile_fields(contract)
    profile_catalog = [as_dict(row) for row in as_list(contract.get("profile_catalog"))]
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []

    if contract.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        blockers.append(
            {
                "kind": "schema-version-mismatch",
                "profile_id": "<contract>",
                "reason": f"schema_version must be {CONTRACT_SCHEMA_VERSION}",
            }
        )

    required_ids = [item for item in as_list(contract.get("required_profile_ids")) if isinstance(item, str)]
    actual_ids = [as_string(row.get("profile_id")) for row in profile_catalog]
    duplicate_ids = sorted({profile_id for profile_id in actual_ids if profile_id and actual_ids.count(profile_id) > 1})
    for profile_id in duplicate_ids:
        blockers.append(
            {
                "kind": "duplicate-profile-id",
                "profile_id": profile_id,
                "reason": "profile IDs must be unique",
            }
        )
    missing_ids = sorted(set(required_ids) - set(actual_ids))
    unexpected_ids = sorted(set(actual_ids) - set(required_ids)) if required_ids else []
    for profile_id in missing_ids:
        blockers.append(
            {
                "kind": "missing-required-profile",
                "profile_id": profile_id,
                "reason": "required_profile_ids entry is absent from profile_catalog",
            }
        )
    for profile_id in unexpected_ids:
        blockers.append(
            {
                "kind": "unexpected-profile-id",
                "profile_id": profile_id,
                "reason": "profile_catalog contains a profile not listed in required_profile_ids",
            }
        )

    for row in profile_catalog:
        profile_id, row_blockers, row_warnings = validate_profile(repo_path, row, fields)
        blockers.extend(row_blockers)
        warnings.extend(row_warnings)
        receipt = profile_receipt(row, row_blockers, row_warnings)
        receipt["profile_id"] = profile_id
        receipts.append(receipt)

    source_summaries = [
        source_summary(repo_path, path_text)
        for path_text in as_dict(contract.get("source_of_truth")).values()
        if isinstance(path_text, str)
    ]
    source_errors = [
        summary
        for summary in source_summaries
        if summary["load_status"] != "ok"
    ]
    for summary in source_errors:
        blockers.append(
            {
                "kind": "missing-source-of-truth",
                "profile_id": "<contract>",
                "path": summary["path"],
                "reason": "source_of_truth path could not be loaded",
            }
        )

    first_failure = blockers[0]["kind"] if blockers else ""
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_schema_version": contract.get("schema_version", ""),
        "bead_id": contract.get("bead_id", ""),
        "generated_at": generated_at,
        "artifact_path": artifact_path,
        "source_digest": canonical_digest(contract),
        "source_summaries": source_summaries,
        "required_log_fields": required_log_fields(contract),
        "forbidden_actions": FORBIDDEN_ACTIONS,
        "profile_receipts": receipts,
        "blockers": blockers,
        "warnings": warnings,
        "operator_summary": {
            "validation_passed": not blockers,
            "profile_count": len(receipts),
            "blocked_count": len(blockers),
            "warning_count": len(warnings),
            "first_failure": first_failure,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Large Host Topology Corpus Report",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Contract schema: `{report['contract_schema_version']}`",
        f"- Bead: `{report['bead_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Source digest: `{report['source_digest']}`",
        f"- Validation: `{'pass' if report['operator_summary']['validation_passed'] else 'blocked'}`",
        "",
        "## Profile Receipts",
        "",
        "| Profile | Family | Status | Cores | Memory GiB | NUMA nodes | RCH slots | Fallback |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["profile_receipts"]:
        lines.append(
            "| {profile_id} | {profile_family} | {status} | {physical_cores} | {memory_gib} | "
            "{numa_nodes} | {rch_slots} | {fallback_action} |".format(**row)
        )

    lines.extend(["", "## Refresh Commands", ""])
    for row in report["profile_receipts"]:
        command = row["rch_refresh_command"]
        if command:
            lines.extend([f"### `{row['profile_id']}`", "", "```bash", command, "```", ""])

    lines.extend(["## Blockers", ""])
    if report["blockers"]:
        for blocker in report["blockers"]:
            lines.append(
                "- `{kind}` profile=`{profile_id}` reason={reason}".format(
                    kind=blocker.get("kind", ""),
                    profile_id=blocker.get("profile_id", ""),
                    reason=blocker.get("reason", ""),
                )
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Non-Claims", ""])
    lines.extend(
        [
            "- This corpus is not live host measurement.",
            "- This corpus is not a benchmark report.",
            "- This corpus does not prove real-host throughput.",
            "- This corpus does not prove RCH fleet availability.",
            "- Local Cargo fallback is not admissible for heavy validation.",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default=DEFAULT_CONTRACT_PATH, help="Contract or fixture JSON path")
    parser.add_argument("--repo-path", default=".", help="Repository root used to resolve source_refs")
    parser.add_argument("--generated-at", default=utc_now(), help="Stable generated_at timestamp")
    parser.add_argument("--artifact-path", default=DEFAULT_CONTRACT_PATH, help="Artifact path recorded in output")
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    parser.add_argument("--output-path", help="Optional path to write output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()
    fixture = Path(args.fixture)
    if not fixture.is_absolute():
        fixture = repo_path / fixture
    contract = load_json(fixture)
    report = build_report(as_dict(contract), repo_path, args.generated_at, args.artifact_path)
    if args.output == "json":
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_markdown(report)

    if args.output_path:
        output_path = Path(args.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
