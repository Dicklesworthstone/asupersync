#!/usr/bin/env python3
"""Emit deterministic dry-run proof-lane admission receipts.

The decision model consumes the schema defined by
`artifacts/proof_lane_admission_input_schema_v1.json` and one concrete proof-lane
profile. It does not start builds, mutate caches, edit Beads, or send Agent
Mail; it only produces an operator receipt with stable decisions and reason
codes.
"""

import argparse
import datetime as dt
import json
import math
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-lane-admission-decision-receipt-v1"
INPUT_SCHEMA_VERSION = "proof-lane-admission-input-v1"
DEFAULT_SCHEMA_CONTRACT = "artifacts/proof_lane_admission_input_schema_v1.json"
MAX_TELEMETRY_AGE_SECONDS = 900
GIB = 1024 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def bool_value(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def u64_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def stable_strings(value: Any) -> list[str]:
    return sorted({item for item in as_list(value) if isinstance(item, str) and item})


def section(data: dict[str, Any], name: str) -> dict[str, Any]:
    return as_dict(data.get(name))


def required_sections(schema_contract: dict[str, Any]) -> list[str]:
    sections = stable_strings(schema_contract.get("required_input_sections"))
    if sections:
        return sections
    return [
        "host_profile",
        "resource_pressure",
        "disk_headroom",
        "rch_workers",
        "active_project_exclusion",
        "cargo_target_isolation",
        "agent_mail_reservations",
        "dirty_tree",
        "proof_lane",
    ]


def missing_sections(data: dict[str, Any], schema_contract: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for name in required_sections(schema_contract):
        if not isinstance(data.get(name), dict):
            missing.append(name)
    return missing


def telemetry_issue(section_name: str, payload: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    sampled_at = string_value(payload.get("telemetry_sampled_at_utc"))
    if not sampled_at and section_name != "agent-mail":
        reasons.append(f"missing-{section_name}-telemetry")
    age = payload.get("telemetry_age_seconds")
    if not isinstance(age, int) or age < 0:
        reasons.append(f"missing-{section_name}-telemetry-age")
    elif age > MAX_TELEMETRY_AGE_SECONDS:
        reasons.append("stale-telemetry")
    return reasons


def telemetry_issues(data: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    issues.extend(telemetry_issue("resource-pressure", section(data, "resource_pressure")))
    issues.extend(telemetry_issue("rch", section(data, "rch_workers")))
    issues.extend(telemetry_issue("agent-mail", section(data, "agent_mail_reservations")))
    return sorted(set(issues))


def estimated_cost(data: dict[str, Any]) -> dict[str, Any]:
    return section(section(data, "proof_lane"), "estimated_cost")


def target_dir_isolated(data: dict[str, Any]) -> bool:
    target = section(data, "cargo_target_isolation")
    template = string_value(target.get("target_dir_template"))
    command = string_value(section(data, "proof_lane").get("command_template"))
    required_tokens = ["{agent}", "{bead}", "{lane}"]
    return (
        all(token in template for token in required_tokens)
        and bool_value(target.get("agent_scoped"))
        and bool_value(target.get("bead_scoped"))
        and bool_value(target.get("lane_scoped"))
        and bool_value(target.get("forbid_shared_target_dir"))
        and "CARGO_TARGET_DIR=" in command
        and "rch exec --" in command
    )


def reservation_holders(data: dict[str, Any]) -> list[dict[str, str]]:
    holders: dict[tuple[str, str], dict[str, str]] = {}
    reservations = section(data, "agent_mail_reservations")
    for row in as_list(reservations.get("active_peer_source_reservations")):
        if not isinstance(row, dict):
            continue
        agent = string_value(row.get("agent"))
        path = string_value(row.get("path_pattern"))
        if agent and path:
            holders[(agent, path)] = {"agent": agent, "path_pattern": path}
    return [holders[key] for key in sorted(holders)]


def dirty_tree_summary(data: dict[str, Any]) -> dict[str, Any]:
    dirty = section(data, "dirty_tree")
    return {
        "classification": string_value(dirty.get("classification")) or "unknown",
        "dirty_paths": stable_strings(dirty.get("dirty_paths")),
        "peer_owned_paths": stable_strings(dirty.get("peer_owned_paths")),
        "unreserved_source_paths": stable_strings(dirty.get("unreserved_source_paths")),
    }


def worker_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lane_family = string_value(section(data, "proof_lane").get("lane_family"))
    peak_memory = u64_value(estimated_cost(data).get("memory_bytes_peak"))
    for row in as_list(section(data, "rch_workers").get("workers")):
        if not isinstance(row, dict):
            continue
        worker_id = string_value(row.get("worker_id"))
        if not worker_id:
            continue
        queue_state = string_value(row.get("queue_state")) or "unknown"
        available_memory = u64_value(row.get("available_memory_bytes"))
        cache = section(row, "cache_warmth")
        family_matches = string_value(cache.get("proof_lane_family")) == lane_family
        warmth_class = string_value(cache.get("warmth_class")) or "unknown"
        confidence = u64_value(cache.get("confidence_bps"))
        excluded = bool_value(row.get("active_project_excluded"))
        saturated = queue_state in {"busy", "saturated"} or u64_value(row.get("available_cores")) == 0
        memory_ok = peak_memory == 0 or available_memory >= peak_memory
        rows.append(
            {
                "worker_id": worker_id,
                "queue_state": queue_state,
                "available_cores": u64_value(row.get("available_cores")),
                "available_memory_bytes": available_memory,
                "active_project_excluded": excluded,
                "saturated": saturated,
                "memory_ok": memory_ok,
                "admissible": not excluded and not saturated and memory_ok,
                "warm": family_matches and warmth_class == "warm" and confidence >= 7000,
                "warmth_class": warmth_class,
                "warmth_confidence_bps": confidence,
                "target_dir_family": string_value(cache.get("target_dir_family")),
            }
        )
    return sorted(rows, key=lambda item: item["worker_id"])


def resource_pressure_summary(data: dict[str, Any]) -> dict[str, Any]:
    pressure = section(data, "resource_pressure")
    cost = estimated_cost(data)
    memory_available = u64_value(pressure.get("memory_available_bytes"))
    peak = u64_value(cost.get("memory_bytes_peak"))
    if peak == 0:
        memory_headroom_ratio_bps = None
    else:
        memory_headroom_ratio_bps = (memory_available * 10000) // peak
    cpu_busy = u64_value(pressure.get("cpu_busy_bps"))
    io_some = u64_value(pressure.get("io_some_avg10_bps"))
    if cpu_busy >= 9000 or io_some >= 7500:
        pressure_class = "high"
    elif cpu_busy >= 7500 or io_some >= 4000:
        pressure_class = "watch"
    else:
        pressure_class = "healthy"
    return {
        "class": pressure_class,
        "cpu_busy_bps": cpu_busy,
        "memory_available_bytes": memory_available,
        "memory_peak_bytes": peak,
        "memory_headroom_ratio_bps": memory_headroom_ratio_bps,
        "io_some_avg10_bps": io_some,
    }


def disk_summary(data: dict[str, Any]) -> dict[str, Any]:
    disk = section(data, "disk_headroom")
    io_bytes = u64_value(estimated_cost(data).get("io_bytes"))
    target_free = u64_value(disk.get("target_parent_free_bytes"))
    pressure_class = string_value(disk.get("pressure_class")) or "unknown"
    return {
        "pressure_class": pressure_class,
        "target_parent_free_bytes": target_free,
        "estimated_io_bytes": io_bytes,
        "sufficient_for_lane": target_free >= max(io_bytes, 2 * GIB)
        and pressure_class in {"healthy", "watch"},
    }


def suggested_command(data: dict[str, Any], worker: dict[str, Any] | None) -> str:
    command = string_value(section(data, "proof_lane").get("command_template"))
    if worker is None:
        return command
    return f"RCH_PREFERRED_WORKER={worker['worker_id']} {command}"


def split_plan(data: dict[str, Any], workers: list[dict[str, Any]]) -> dict[str, Any]:
    cost = estimated_cost(data)
    core_seconds = u64_value(cost.get("cpu_core_seconds"))
    peak_memory = u64_value(cost.get("memory_bytes_peak"))
    admissible_cores = sum(worker["available_cores"] for worker in workers if worker["admissible"])
    if admissible_cores <= 0:
        admissible_cores = max(1, u64_value(section(data, "host_profile").get("cpu_cores")) // 4)
    shards_by_cpu = max(2, math.ceil(core_seconds / 20000)) if core_seconds else 2
    shards_by_memory = max(1, math.ceil(peak_memory / max(1, 32 * GIB))) if peak_memory else 1
    shards = min(8, max(shards_by_cpu, shards_by_memory))
    return {
        "recommended_shards": shards,
        "split_reason": "oversized-proof-pack",
        "max_parallel_shards": max(1, min(shards, admissible_cores // 8 or 1)),
    }


def choose_decision(data: dict[str, Any], schema_contract: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    missing = missing_sections(data, schema_contract)
    if missing:
        return decision_row(
            data,
            "wait_for_telemetry",
            False,
            ["missing-input-section", *[f"missing-{name}" for name in missing]],
            precondition="complete-input-required",
        )

    telemetry = telemetry_issues(data)
    if telemetry:
        return decision_row(data, "wait_for_telemetry", False, telemetry, precondition="wait-for-telemetry")

    if not target_dir_isolated(data):
        return decision_row(
            data,
            "reject",
            False,
            ["target-dir-not-isolated"],
            precondition="fix-target-dir-isolation",
        )

    dirty = dirty_tree_summary(data)
    holders = reservation_holders(data)
    if dirty["peer_owned_paths"]:
        return decision_row(
            data,
            "wait_for_dirty_tree_handoff",
            False,
            ["peer-owned-dirty-path", "reservation-handoff-required"],
            precondition="wait-for-dirty-tree-handoff",
        )
    if dirty["unreserved_source_paths"]:
        return decision_row(
            data,
            "wait_for_dirty_tree_handoff",
            False,
            ["unreserved-dirty-path", "reservation-required"],
            precondition="wait-for-dirty-tree-handoff",
        )
    if holders:
        return decision_row(
            data,
            "wait_for_reservation_handoff",
            False,
            ["active-peer-reservation", "reservation-handoff-required"],
            precondition="wait-for-reservation-handoff",
        )

    disk = disk_summary(data)
    if not disk["sufficient_for_lane"]:
        return decision_row(
            data,
            "reject",
            False,
            ["low-target-dir-disk-headroom"],
            precondition="wait-for-disk-headroom",
        )

    resource = resource_pressure_summary(data)
    if (
        resource["memory_headroom_ratio_bps"] is not None
        and resource["memory_headroom_ratio_bps"] < 15000
    ):
        return decision_row(data, "queue", False, ["low-memory-headroom"], precondition="queue-for-memory")
    if resource["class"] == "high":
        return decision_row(data, "queue", False, ["local-resource-pressure"], precondition="queue-for-host")

    workers = worker_rows(data)
    cost = estimated_cost(data)
    proof_weight = string_value(cost.get("proof_weight"))
    if proof_weight in {"heavy", "oversized"} or u64_value(cost.get("cpu_core_seconds")) >= 40000:
        return decision_row(
            data,
            "split_lane",
            False,
            ["oversized-proof-pack", "split-lane-recommended"],
            precondition="split-before-admission",
            split=split_plan(data, workers),
        )

    admissible = [worker for worker in workers if worker["admissible"]]
    if not admissible:
        reason = "remote-worker-saturated" if workers else "no-rch-worker-telemetry"
        return decision_row(data, "queue", False, [reason], precondition="queue-for-worker")

    warm = sorted(
        [worker for worker in admissible if worker["warm"]],
        key=lambda worker: (-worker["warmth_confidence_bps"], worker["worker_id"]),
    )
    if warm:
        reasons.extend(["host-large-core", "warm-worker-preferred", "target-dir-isolated"])
        return decision_row(
            data,
            "use_warmed_worker",
            True,
            reasons,
            precondition="admit-now",
            worker=warm[0],
        )

    reasons.extend(["host-large-core", "worker-admissible", "target-dir-isolated"])
    return decision_row(data, "admit_now", True, reasons, precondition="admit-now", worker=admissible[0])


def decision_row(
    data: dict[str, Any],
    decision: str,
    run_now: bool,
    reasons: list[str],
    *,
    precondition: str,
    worker: dict[str, Any] | None = None,
    split: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "admission_decision": decision,
        "proof_may_run_now": run_now,
        "admitted": run_now,
        "admission_precondition": precondition,
        "reason_codes": sorted(set(reasons)),
        "recommended_worker_id": string_value(worker.get("worker_id")) if worker else "",
        "suggested_next_command": suggested_command(data, worker),
        "split_plan": split or {},
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    data = load_json(args.input)
    if not isinstance(data, dict):
        raise ValueError("input must be a JSON object")
    schema_contract = load_json(args.schema_contract)
    if not isinstance(schema_contract, dict):
        raise ValueError("schema contract must be a JSON object")
    generated_at = args.generated_at or utc_now()
    decision = choose_decision(data, schema_contract)
    workers = worker_rows(data)
    dirty = dirty_tree_summary(data)
    holders = reservation_holders(data)
    resource = resource_pressure_summary(data)
    disk = disk_summary(data)
    proof_lane = section(data, "proof_lane")
    target = section(data, "cargo_target_isolation")

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": string_value(data.get("schema_version")) or INPUT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "profile_id": string_value(data.get("profile_id")),
        "lane_id": string_value(proof_lane.get("lane_id")),
        "dry_run_only": True,
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_rch": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "sends_agent_mail": False,
            "writes_cache": False,
            "deletes_files": False,
        },
        "decision": decision,
        "dirty_tree": dirty,
        "reservation_holders": holders,
        "resource_pressure_summary": resource,
        "disk_summary": disk,
        "worker_summary": {
            "worker_count": len(workers),
            "admissible_worker_count": sum(1 for worker in workers if worker["admissible"]),
            "saturated_or_excluded_worker_count": sum(
                1 for worker in workers if worker["saturated"] or worker["active_project_excluded"]
            ),
            "warm_admissible_worker_count": sum(
                1 for worker in workers if worker["admissible"] and worker["warm"]
            ),
            "workers": workers,
        },
        "cargo_target_dir_template": string_value(target.get("target_dir_template")),
        "operator_receipt": {
            "receipt_id": f"{string_value(data.get('profile_id'))}:{string_value(proof_lane.get('lane_id'))}",
            "admission_decision": decision["admission_decision"],
            "reason_codes": decision["reason_codes"],
            "suggested_next_command": decision["suggested_next_command"],
            "reservation_holders": holders,
            "dirty_paths": dirty["dirty_paths"],
        },
        "non_coverage": [
            "does not start proof lanes",
            "does not mutate Agent Mail reservations",
            "does not mutate Beads",
            "does not prove Cargo/test success",
            "does not make cache warmth correctness evidence",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a deterministic proof-lane admission receipt")
    parser.add_argument("--input", required=True, help="Admission input JSON")
    parser.add_argument(
        "--schema-contract",
        default=DEFAULT_SCHEMA_CONTRACT,
        help="Admission input schema contract JSON",
    )
    parser.add_argument("--generated-at", default="", help="Stable UTC timestamp")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
