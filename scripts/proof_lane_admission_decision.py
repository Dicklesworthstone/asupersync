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
DEFAULT_TOPOLOGY_CORPUS_PATH = "artifacts/large_host_topology_corpus_v1.json"
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


def dirty_tree_gate(dirty: dict[str, Any], holders: list[dict[str, str]]) -> dict[str, Any]:
    blockers: list[dict[str, str]] = []
    for path in dirty["peer_owned_paths"]:
        blockers.append(
            {
                "kind": "peer_owned_dirty_path",
                "path": path,
                "required_action": "wait_for_dirty_tree_handoff",
            }
        )
    for path in dirty["unreserved_source_paths"]:
        blockers.append(
            {
                "kind": "unreserved_dirty_path",
                "path": path,
                "required_action": "reserve_or_clean_path_before_proof",
            }
        )
    for holder in holders:
        blockers.append(
            {
                "kind": "active_peer_reservation",
                "agent": holder["agent"],
                "path_pattern": holder["path_pattern"],
                "required_action": "wait_for_reservation_handoff",
            }
        )

    if dirty["peer_owned_paths"] or dirty["unreserved_source_paths"]:
        precondition = "wait-for-dirty-tree-handoff"
    elif holders:
        precondition = "wait-for-reservation-handoff"
    else:
        precondition = "clear"

    return {
        "classification": dirty["classification"],
        "blocks_admission": bool(blockers),
        "admission_precondition": precondition,
        "blockers": blockers,
    }


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


def proof_cache_warmth_summary(data: dict[str, Any]) -> dict[str, Any]:
    payload = as_dict(data.get("proof_cache_warmth"))
    lane_id = string_value(section(data, "proof_lane").get("lane_id"))
    if not payload:
        return {
            "schema_version": "proof-cache-warmth-summary-v1",
            "source_schema_version": "",
            "lane_id": lane_id,
            "classification": "no-data",
            "telemetry_state": "no-data",
            "telemetry_age_seconds": None,
            "recommended_worker_id": "",
            "warmth_basis": [],
            "reason_codes": ["missing-proof-cache-warmth-receipt"],
            "suggested_proof_command": "",
            "target_dir": "",
            "preserves_agent_isolation": False,
            "cache_warmth_is_authoritative": False,
            "proof_commands_still_required": True,
            "cache_warmth_is_correctness_evidence": False,
        }

    lanes = [row for row in as_list(payload.get("lanes")) if isinstance(row, dict)]
    matched_lane = next(
        (row for row in lanes if string_value(row.get("lane_id")) == lane_id),
        lanes[0] if lanes else {},
    )
    telemetry = as_dict(payload.get("telemetry"))
    operator = as_dict(payload.get("operator_receipt"))
    templates = as_dict(matched_lane.get("command_templates"))
    evidence = as_dict(matched_lane.get("worker_warmth_evidence"))
    recommended = [
        row for row in as_list(matched_lane.get("recommended_workers")) if isinstance(row, dict)
    ]
    first_worker = recommended[0] if recommended else {}
    classification = (
        string_value(matched_lane.get("classification"))
        or string_value(payload.get("classification"))
        or "unknown"
    )
    reasons = stable_strings(matched_lane.get("reasons") or payload.get("reason_codes"))
    if not reasons:
        reasons = ["proof-cache-warmth-receipt-present"]

    age = telemetry.get("age_seconds")
    if not isinstance(age, int) or age < 0:
        age = None

    return {
        "schema_version": "proof-cache-warmth-summary-v1",
        "source_schema_version": string_value(payload.get("schema_version")),
        "lane_id": string_value(matched_lane.get("lane_id")) or lane_id,
        "classification": classification,
        "telemetry_state": string_value(telemetry.get("state")) or "unknown",
        "telemetry_age_seconds": age,
        "recommended_worker_id": string_value(first_worker.get("worker_id")),
        "warmth_basis": stable_strings(evidence.get("warmth_basis")),
        "reason_codes": reasons,
        "suggested_proof_command": string_value(templates.get("actual_proof_command")),
        "target_dir": string_value(templates.get("target_dir")),
        "preserves_agent_isolation": bool_value(templates.get("preserves_agent_isolation"))
        or bool_value(operator.get("all_command_templates_preserve_agent_isolation")),
        "cache_warmth_is_authoritative": bool_value(operator.get("cache_warmth_is_authoritative")),
        "proof_commands_still_required": True,
        "cache_warmth_is_correctness_evidence": False,
    }


def infer_lane_class(data: dict[str, Any]) -> str:
    lane_family = string_value(section(data, "proof_lane").get("lane_family"))
    proof_weight = string_value(estimated_cost(data).get("proof_weight"))
    if proof_weight in {"heavy", "oversized"}:
        return "broad-lane"
    if lane_family in {"admission-decision-contract", "topology-admission-contract"}:
        return "focused-contract"
    if "clippy" in lane_family:
        return "full-workspace-clippy"
    if "check" in lane_family:
        return "cargo-check"
    return lane_family or "unknown"


def load_topology_corpus(path: str) -> dict[str, Any]:
    corpus = load_json(path or DEFAULT_TOPOLOGY_CORPUS_PATH)
    return corpus if isinstance(corpus, dict) else {}


def topology_profile(corpus: dict[str, Any], profile_id: str) -> dict[str, Any]:
    for row in as_list(corpus.get("profile_catalog")):
        if isinstance(row, dict) and string_value(row.get("profile_id")) == profile_id:
            return row
    return {}


def topology_guidance_summary(data: dict[str, Any]) -> dict[str, Any]:
    payload = as_dict(data.get("topology_guidance"))
    lane_id = string_value(section(data, "proof_lane").get("lane_id"))
    if not payload:
        return {
            "schema_version": "proof-lane-topology-guidance-summary-v1",
            "classification": "no-data",
            "artifact_path": "",
            "artifact_schema_version": "",
            "profile_id": "",
            "profile_family": "",
            "lane_id": lane_id,
            "requested_lane_class": infer_lane_class(data),
            "requested_contention_domain": "",
            "active_contention_domains": [],
            "recommended_policy": "fall_back_to_scalar_capacity",
            "recommended_slots": None,
            "max_parallel_heavy_lanes": None,
            "topology_reason_codes": ["topology-missing", "scalar-capacity-only"],
            "blocks_admission": False,
            "decision_hint": "none",
            "operator_action": "continue_with_scalar_capacity_only",
            "source_refs": [],
            "refresh_command": "",
            "corpus_is_live_host_measurement": False,
            "corpus_is_fresh_benchmark": False,
            "operator_guidance_only": True,
            "topology_guidance_is_correctness_evidence": False,
        }

    artifact_path = string_value(payload.get("artifact_path")) or DEFAULT_TOPOLOGY_CORPUS_PATH
    profile_id = string_value(payload.get("profile_id"))
    age = payload.get("telemetry_age_seconds")
    requested_lane_class = string_value(payload.get("requested_lane_class")) or infer_lane_class(data)
    requested_domain = string_value(payload.get("requested_contention_domain"))
    active_domains = stable_strings(payload.get("active_contention_domains"))

    base = {
        "schema_version": "proof-lane-topology-guidance-summary-v1",
        "classification": "unknown",
        "artifact_path": artifact_path,
        "artifact_schema_version": "",
        "profile_id": profile_id,
        "profile_family": "",
        "lane_id": lane_id,
        "requested_lane_class": requested_lane_class,
        "requested_contention_domain": requested_domain,
        "active_contention_domains": active_domains,
        "recommended_policy": "",
        "recommended_slots": None,
        "max_parallel_heavy_lanes": None,
        "topology_reason_codes": [],
        "blocks_admission": False,
        "decision_hint": "none",
        "operator_action": "inspect_topology_guidance",
        "source_refs": [],
        "refresh_command": "",
        "corpus_is_live_host_measurement": False,
        "corpus_is_fresh_benchmark": False,
        "operator_guidance_only": True,
        "topology_guidance_is_correctness_evidence": False,
    }

    if not isinstance(age, int) or age < 0:
        return {
            **base,
            "classification": "malformed",
            "blocks_admission": True,
            "decision_hint": "wait_for_telemetry",
            "operator_action": "refresh_topology_receipt_before_retry",
            "topology_reason_codes": ["missing-topology-telemetry-age"],
        }
    if age > MAX_TELEMETRY_AGE_SECONDS:
        return {
            **base,
            "classification": "stale",
            "blocks_admission": True,
            "decision_hint": "wait_for_telemetry",
            "operator_action": "refresh_topology_receipt_before_retry",
            "topology_reason_codes": ["stale-topology-evidence"],
        }

    try:
        corpus = load_topology_corpus(artifact_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            **base,
            "classification": "malformed",
            "blocks_admission": True,
            "decision_hint": "wait_for_telemetry",
            "operator_action": "repair_topology_corpus_before_retry",
            "topology_reason_codes": ["topology-corpus-unreadable"],
        }

    profile = topology_profile(corpus, profile_id)
    if not profile:
        return {
            **base,
            "classification": "malformed",
            "artifact_schema_version": string_value(corpus.get("schema_version")),
            "blocks_admission": True,
            "decision_hint": "wait_for_telemetry",
            "operator_action": "select_known_topology_profile",
            "topology_reason_codes": ["topology-profile-not-found"],
        }

    memory = section(profile, "memory")
    topology = section(profile, "topology")
    slot_model = section(profile, "rch_slot_model")
    fallback = section(profile, "fallback_policy")
    proof_boundary = section(profile, "proof_boundary")
    preferred_classes = set(stable_strings(slot_model.get("preferred_lane_classes")))
    avoid_classes = set(stable_strings(slot_model.get("avoid_lane_classes")))
    cache_domains = {
        string_value(row.get("domain_id"))
        for row in as_list(topology.get("cache_domains"))
        if isinstance(row, dict)
    }

    reasons = ["topology-fit"]
    classification = "fit"
    decision_hint = "none"
    blocks_admission = False
    operator_action = string_value(fallback.get("operator_action")) or "use_topology_guidance_as_advice"

    if profile_id.startswith("remote-worker-queue-contention"):
        reasons.append("remote-worker-preferred")
    if requested_lane_class in preferred_classes:
        reasons.append("topology-preferred-lane-class")
    if requested_domain and requested_domain not in cache_domains:
        reasons.append("topology-domain-not-in-profile")
        classification = "malformed"
        decision_hint = "wait_for_telemetry"
        blocks_admission = True
        operator_action = "repair_topology_domain_before_retry"
    elif requested_domain and requested_domain in active_domains:
        reasons.extend(["same-domain-contention", "split-lane-recommended"])
        classification = "contention"
        decision_hint = "queue"
        operator_action = "queue_or_split_by_topology_domain"

    memory_state = string_value(memory.get("memory_pressure_state"))
    if memory_state == "degraded" and requested_lane_class not in {"focused-contract", "short-e2e"}:
        reasons.extend(["low-memory-numa-node", "split-lane-recommended"])
        classification = "memory-constrained"
        decision_hint = "queue"
        operator_action = "queue_until_per_node_memory_headroom_is_fresh"
    if requested_lane_class in avoid_classes:
        reasons.append("topology-avoid-lane-class")
        if decision_hint == "none":
            decision_hint = "queue"
            classification = "contention"

    return {
        **base,
        "classification": classification,
        "artifact_schema_version": string_value(corpus.get("schema_version")),
        "profile_family": string_value(profile.get("profile_family")),
        "recommended_policy": operator_action,
        "recommended_slots": slot_model.get("recommended_slots"),
        "max_parallel_heavy_lanes": slot_model.get("max_parallel_heavy_lanes"),
        "topology_reason_codes": sorted(set(reasons)),
        "blocks_admission": blocks_admission,
        "decision_hint": decision_hint,
        "operator_action": operator_action,
        "source_refs": stable_strings(profile.get("source_refs")),
        "refresh_command": string_value(profile.get("rch_refresh_command")),
        "corpus_is_live_host_measurement": bool_value(
            proof_boundary.get("corpus_is_live_host_measurement")
        ),
        "corpus_is_fresh_benchmark": bool_value(
            proof_boundary.get("corpus_is_fresh_benchmark")
        ),
        "operator_guidance_only": bool_value(proof_boundary.get("operator_guidance_only")),
        "topology_guidance_is_correctness_evidence": False,
    }


def topology_admission_reasons(topology: dict[str, Any]) -> list[str]:
    return [
        reason
        for reason in stable_strings(topology.get("topology_reason_codes"))
        if reason
        in {
            "topology-fit",
            "topology-missing",
            "same-domain-contention",
            "split-lane-recommended",
            "remote-worker-preferred",
            "low-memory-numa-node",
        }
    ]


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

    topology = topology_guidance_summary(data)
    topology_reasons = topology_admission_reasons(topology)
    if bool_value(topology.get("blocks_admission")):
        return decision_row(
            data,
            "wait_for_telemetry",
            False,
            topology_reasons or stable_strings(topology.get("topology_reason_codes")),
            precondition="wait-for-topology-telemetry",
        )
    if topology["decision_hint"] == "queue":
        return decision_row(
            data,
            "queue",
            False,
            topology_reasons,
            precondition="queue-for-topology",
        )

    workers = worker_rows(data)
    cost = estimated_cost(data)
    proof_weight = string_value(cost.get("proof_weight"))
    if proof_weight in {"heavy", "oversized"} or u64_value(cost.get("cpu_core_seconds")) >= 40000:
        return decision_row(
            data,
            "split_lane",
            False,
            ["oversized-proof-pack", "split-lane-recommended", *topology_reasons],
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
        reasons.extend(
            ["host-large-core", "warm-worker-preferred", "target-dir-isolated", *topology_reasons]
        )
        return decision_row(
            data,
            "use_warmed_worker",
            True,
            reasons,
            precondition="admit-now",
            worker=warm[0],
        )

    reasons.extend(["host-large-core", "worker-admissible", "target-dir-isolated", *topology_reasons])
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


def operator_action(decision: dict[str, Any]) -> str:
    name = string_value(decision.get("admission_decision"))
    if bool_value(decision.get("proof_may_run_now")):
        return "run_suggested_command"
    if name == "split_lane":
        return "split_lane_before_admission"
    if name == "queue":
        return "queue_and_retry_after_capacity_changes"
    if name == "reject":
        return "fix_admission_precondition_before_retry"
    if name == "wait_for_telemetry":
        return "refresh_telemetry_before_retry"
    if name in {"wait_for_dirty_tree_handoff", "wait_for_reservation_handoff"}:
        return name
    return "inspect_receipt_before_retry"


def integrated_operator_receipt(
    *,
    data: dict[str, Any],
    decision: dict[str, Any],
    dirty_gate: dict[str, Any],
    holders: list[dict[str, str]],
    resource: dict[str, Any],
    disk: dict[str, Any],
    proof_cache: dict[str, Any],
    topology: dict[str, Any],
    non_coverage: list[str],
) -> dict[str, Any]:
    cache_overridden = (
        proof_cache["classification"] in {"warm", "not-warm"}
        and not bool_value(decision.get("proof_may_run_now"))
    )
    return {
        "schema_version": "proof-lane-integrated-operator-receipt-v1",
        "receipt_id": (
            f"{string_value(data.get('profile_id'))}:"
            f"{string_value(section(data, 'proof_lane').get('lane_id'))}:integrated"
        ),
        "dry_run_only": True,
        "non_mutating": True,
        "planner_output_is_proof_evidence": False,
        "cache_warmth_is_authoritative": False,
        "actual_proof_commands_still_required": True,
        "admission_decision": decision["admission_decision"],
        "proof_may_run_now": decision["proof_may_run_now"],
        "operator_action": operator_action(decision),
        "reason_codes": decision["reason_codes"],
        "suggested_next_command": decision["suggested_next_command"],
        "proof_cache_warmth": {
            **proof_cache,
            "overridden_by_admission_blockers": cache_overridden,
        },
        "topology_guidance": topology,
        "dirty_tree_gate": dirty_gate,
        "reservation_holders": holders,
        "resource_pressure_summary": resource,
        "disk_summary": disk,
        "non_coverage": non_coverage,
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
    gate = dirty_tree_gate(dirty, holders)
    resource = resource_pressure_summary(data)
    disk = disk_summary(data)
    proof_cache = proof_cache_warmth_summary(data)
    topology = topology_guidance_summary(data)
    proof_lane = section(data, "proof_lane")
    target = section(data, "cargo_target_isolation")
    non_coverage = [
        "does not start proof lanes",
        "does not mutate Agent Mail reservations",
        "does not mutate Beads",
        "does not prove Cargo/test success",
        "does not make cache warmth correctness evidence",
        "does not make topology guidance correctness evidence",
        "does not prove live host topology or throughput",
    ]

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
        "dirty_tree_gate": gate,
        "reservation_holders": holders,
        "proof_cache_warmth": proof_cache,
        "topology_guidance": topology,
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
        "integrated_operator_receipt": integrated_operator_receipt(
            data=data,
            decision=decision,
            dirty_gate=gate,
            holders=holders,
            resource=resource,
            disk=disk,
            proof_cache=proof_cache,
            topology=topology,
            non_coverage=non_coverage,
        ),
        "non_coverage": non_coverage,
    }


def format_markdown(receipt: dict[str, Any]) -> str:
    decision = as_dict(receipt.get("decision"))
    topology = as_dict(receipt.get("topology_guidance"))
    integrated = as_dict(receipt.get("integrated_operator_receipt"))
    lines = [
        "# Proof Lane Admission Decision",
        "",
        f"- profile_id: `{string_value(receipt.get('profile_id'))}`",
        f"- lane_id: `{string_value(receipt.get('lane_id'))}`",
        f"- admission_decision: `{string_value(decision.get('admission_decision'))}`",
        f"- proof_may_run_now: `{str(bool_value(decision.get('proof_may_run_now'))).lower()}`",
        f"- admission_precondition: `{string_value(decision.get('admission_precondition'))}`",
        f"- operator_action: `{string_value(integrated.get('operator_action'))}`",
        f"- suggested_next_command: `{string_value(decision.get('suggested_next_command'))}`",
        "",
        "## Reason Codes",
    ]
    for reason in stable_strings(decision.get("reason_codes")):
        lines.append(f"- `{reason}`")
    lines.extend(
        [
            "",
            "## Topology Guidance",
            f"- classification: `{string_value(topology.get('classification'))}`",
            f"- artifact_path: `{string_value(topology.get('artifact_path'))}`",
            f"- profile_id: `{string_value(topology.get('profile_id'))}`",
            f"- requested_lane_class: `{string_value(topology.get('requested_lane_class'))}`",
            f"- requested_contention_domain: `{string_value(topology.get('requested_contention_domain'))}`",
            f"- operator_guidance_only: `{str(bool_value(topology.get('operator_guidance_only'))).lower()}`",
            f"- topology_guidance_is_correctness_evidence: `{str(bool_value(topology.get('topology_guidance_is_correctness_evidence'))).lower()}`",
            "",
            "## Non Coverage",
        ]
    )
    for item in stable_strings(receipt.get("non_coverage")):
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a deterministic proof-lane admission receipt")
    parser.add_argument("--input", required=True, help="Admission input JSON")
    parser.add_argument(
        "--schema-contract",
        default=DEFAULT_SCHEMA_CONTRACT,
        help="Admission input schema contract JSON",
    )
    parser.add_argument("--generated-at", default="", help="Stable UTC timestamp")
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    if args.output == "markdown":
        print(format_markdown(receipt), end="")
    else:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
