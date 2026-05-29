#!/usr/bin/env python3
"""Emit dry-run proof-pack warmth planning receipts.

The planner is deliberately non-mutating. It reads proof-lane metadata, the
cache-key contract, and sampled rch worker telemetry, then recommends warm or
cold workers without running cargo, touching caches, or treating warmth as
proof evidence.
"""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

import proof_pack_cache_key as cache_key


SCHEMA_VERSION = "proof-pack-warmth-planner-receipt-v1"
INPUT_SCHEMA_VERSION = "proof-pack-warmth-planner-input-v1"
DEFAULT_CONTRACT_PATH = "artifacts/proof_pack_cache_key_contract_v1.json"
LANE_SLUG_RE = re.compile(r"[^A-Za-z0-9_]+")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> dt.datetime | None:
    return cache_key.parse_timestamp(value)


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def object_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def stable_string_list(value: Any) -> list[str]:
    return sorted(set(string_list(value)))


def lane_slug(lane_id: str) -> str:
    slug = LANE_SLUG_RE.sub("_", lane_id.strip()).strip("_").lower()
    return slug or "proof_lane"


def telemetry_age_seconds(generated_at: str, sampled_at: str) -> int | None:
    generated = parse_timestamp(generated_at)
    sampled = parse_timestamp(sampled_at)
    if generated is None or sampled is None:
        return None
    return max(0, int((generated - sampled).total_seconds()))


def cache_key_for(raw: dict[str, Any]) -> dict[str, Any]:
    material, ignored_env_keys = cache_key.normalize_key_material(raw)
    reasons = cache_key.refusal_reasons(material)
    digest = cache_key.canonical_digest(material)
    valid = not reasons
    return {
        "cache_key_valid": valid,
        "cache_key": f"proof-pack-cache-v1:{digest[:24]}" if valid else "",
        "cache_key_sha256": digest if valid else "",
        "key_material_digest_sha256": digest,
        "ignored_env_keys": ignored_env_keys,
        "normalized_key_material": material,
        "refusal_reasons": reasons,
    }


def worker_id(worker: dict[str, Any]) -> str:
    return string_value(worker.get("worker_id")) or string_value(worker.get("id"))


def worker_is_saturated(worker: dict[str, Any]) -> bool:
    if bool(worker.get("saturated", False)):
        return True
    available_slots = worker.get("available_slots")
    if isinstance(available_slots, int) and available_slots <= 0:
        return True
    return False


def worker_supports_lane(worker: dict[str, Any], lane: dict[str, Any]) -> bool:
    required = set(stable_string_list(lane.get("required_worker_capabilities")))
    if not required:
        return True
    capabilities = set(stable_string_list(worker.get("capabilities")))
    return required.issubset(capabilities)


def worker_warm_for(worker: dict[str, Any], lane_cache_key: str, target_dir_family: str) -> bool:
    cache_keys = set(stable_string_list(worker.get("cache_keys")))
    target_families = set(stable_string_list(worker.get("target_dir_families")))
    return lane_cache_key in cache_keys or target_dir_family in target_families


def worker_row(worker: dict[str, Any], lane_cache_key: str, target_dir_family: str) -> dict[str, Any]:
    cache_keys = set(stable_string_list(worker.get("cache_keys")))
    target_families = set(stable_string_list(worker.get("target_dir_families")))
    matches_cache_key = bool(lane_cache_key) and lane_cache_key in cache_keys
    matches_target_dir_family = target_dir_family in target_families
    return {
        "worker_id": worker_id(worker),
        "warm": matches_cache_key or matches_target_dir_family,
        "matches_cache_key": matches_cache_key,
        "matches_target_dir_family": matches_target_dir_family,
        "matching_target_dir_family": target_dir_family if matches_target_dir_family else "",
        "saturated": worker_is_saturated(worker),
        "queue_depth": worker.get("queue_depth") if isinstance(worker.get("queue_depth"), int) else None,
        "available_slots": worker.get("available_slots")
        if isinstance(worker.get("available_slots"), int)
        else None,
    }


def isolated_target_dir(operator: dict[str, Any], lane_id: str, target_dir_family: str, cache_key_value: str) -> str:
    root = string_value(operator.get("target_dir_root")) or "${TMPDIR:-/tmp}"
    agent = string_value(operator.get("agent")) or "${AGENT_NAME:-agent}"
    suffix = cache_key_value.split(":", 1)[-1][:12] if cache_key_value else "cold"
    family = lane_slug(target_dir_family)
    lane = lane_slug(lane_id)
    return f"{root}/rch_target_{agent}_{family}_{lane}_{suffix}"


def command_templates(
    operator: dict[str, Any],
    lane: dict[str, Any],
    target_dir_family: str,
    cache_key_value: str,
) -> dict[str, Any]:
    lane_command = string_value(lane.get("command"))
    target_dir = isolated_target_dir(operator, string_value(lane.get("lane_id")), target_dir_family, cache_key_value)
    return {
        "actual_proof_command": f"rch exec -- env CARGO_TARGET_DIR=\"{target_dir}\" {lane_command}",
        "target_dir": target_dir,
        "dry_run_only": True,
        "preserves_agent_isolation": True,
        "runs_now": False,
    }


def classify_lane(
    lane: dict[str, Any],
    lane_key: dict[str, Any],
    worker_rows: list[dict[str, Any]],
    telemetry_state: dict[str, Any],
) -> tuple[str, list[str], list[dict[str, Any]]]:
    if bool(lane.get("unsupported", False)):
        return "unsupported", ["unsupported-lane"], []
    if not string_value(lane.get("command")):
        return "unsupported", ["missing-proof-command"], []
    if not lane_key["cache_key_valid"]:
        return "degraded", ["invalid-cache-key", *lane_key["refusal_reasons"]], []
    if telemetry_state["state"] == "no-data":
        return "no-data", ["no-worker-telemetry"], []
    if telemetry_state["state"] == "stale":
        return "degraded", ["stale-worker-telemetry"], []

    if not worker_rows:
        return "no-data", ["no-compatible-workers"], []

    warm_available = [
        row for row in worker_rows if row["warm"] and not row["saturated"]
    ]
    if warm_available:
        return "warm", ["warm-worker-available"], sorted(warm_available, key=lambda row: row["worker_id"])

    available = [row for row in worker_rows if not row["saturated"]]
    if available:
        reasons = ["no-warm-worker"]
        if any(row["warm"] and row["saturated"] for row in worker_rows):
            reasons.append("warm-workers-saturated")
        return "not-warm", reasons, sorted(available, key=lambda row: row["worker_id"])

    if any(row["warm"] for row in worker_rows):
        return "degraded", ["warm-workers-saturated"], []
    return "degraded", ["worker-saturated"], []


def compatible_worker_rows(
    lane: dict[str, Any],
    lane_key: dict[str, Any],
    workers: list[dict[str, Any]],
    target_dir_family: str,
) -> list[dict[str, Any]]:
    if not lane_key["cache_key_valid"]:
        return []
    return [
        worker_row(worker, lane_key["cache_key"], target_dir_family)
        for worker in workers
        if worker_id(worker) and worker_supports_lane(worker, lane)
    ]


def numeric_value(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float) and value >= 0:
        return float(value)
    return None


def compile_savings_seconds(lane: dict[str, Any]) -> int | None:
    cold = numeric_value(lane.get("estimated_cold_compile_seconds"))
    warm = numeric_value(lane.get("estimated_warm_compile_seconds"))
    if cold is None or warm is None:
        return None
    return max(0, int(cold - warm))


def queue_pressure(row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {
            "class": "unknown",
            "queue_depth": None,
            "available_slots": None,
            "saturated": False,
        }
    queue_depth = row.get("queue_depth")
    available_slots = row.get("available_slots")
    saturated = bool(row.get("saturated", False))
    if saturated:
        pressure = "saturated"
    elif not isinstance(queue_depth, int) and not isinstance(available_slots, int):
        pressure = "unknown"
    elif isinstance(queue_depth, int) and queue_depth >= 4:
        pressure = "high"
    elif isinstance(available_slots, int) and available_slots >= 2 and (queue_depth is None or queue_depth <= 1):
        pressure = "low"
    else:
        pressure = "medium"
    return {
        "class": pressure,
        "queue_depth": queue_depth if isinstance(queue_depth, int) else None,
        "available_slots": available_slots if isinstance(available_slots, int) else None,
        "saturated": saturated,
    }


def observed_worker(
    recommended_workers: list[dict[str, Any]],
    worker_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if recommended_workers:
        return recommended_workers[0]
    warm_rows = sorted([row for row in worker_rows if row["warm"]], key=lambda row: row["worker_id"])
    if warm_rows:
        return warm_rows[0]
    if worker_rows:
        return sorted(worker_rows, key=lambda row: row["worker_id"])[0]
    return None


def warmth_basis(row: dict[str, Any] | None, classification: str) -> list[str]:
    if row is None:
        return []
    basis: list[str] = []
    if row.get("matches_cache_key"):
        basis.append("cache-key")
    if row.get("matches_target_dir_family"):
        basis.append("target-dir-family")
    if not basis and classification == "not-warm":
        basis.append("compatible-cold-worker")
    if not basis and classification == "degraded" and row.get("warm"):
        basis.append("warm-but-unusable")
    return basis


def savings_band(classification: str, lane: dict[str, Any], pressure: dict[str, Any]) -> tuple[str, int | None]:
    estimated_seconds = compile_savings_seconds(lane)
    if classification != "warm":
        if classification == "not-warm":
            return "none", estimated_seconds
        return "unknown", estimated_seconds
    if estimated_seconds is None:
        return "medium" if pressure["class"] in {"low", "medium"} else "low", None
    if estimated_seconds >= 300:
        return "high", estimated_seconds
    if estimated_seconds >= 60:
        return "medium", estimated_seconds
    if estimated_seconds > 0:
        return "low", estimated_seconds
    return "none", estimated_seconds


def confidence_class(classification: str, telem_state: dict[str, Any], row: dict[str, Any] | None) -> str:
    if classification == "unsupported":
        return "none"
    if telem_state["state"] != "fresh":
        return "low"
    if classification == "warm" and row is not None and row.get("matches_cache_key"):
        return "high"
    if classification in {"warm", "not-warm"} and row is not None:
        return "medium"
    return "low"


def fallback_recommendation(classification: str, reasons: list[str]) -> str:
    if classification == "warm":
        return "run-proof-on-recommended-warm-worker"
    if classification == "not-warm":
        return "run-proof-on-compatible-cold-worker"
    if classification == "unsupported":
        return "do-not-schedule-unsupported-lane"
    if "stale-worker-telemetry" in reasons:
        return "refresh-rch-telemetry-and-replan"
    if "no-worker-telemetry" in reasons or "no-compatible-workers" in reasons:
        return "collect-rch-worker-telemetry-before-selecting-worker"
    if "invalid-cache-key" in reasons:
        return "fix-cache-key-input-before-reuse"
    if "warm-workers-saturated" in reasons or "worker-saturated" in reasons:
        return "wait-for-capacity-or-run-cold-with-caveat"
    return "rerun-planner-after-input-update"


def worker_evidence_receipt(
    lane: dict[str, Any],
    lane_key: dict[str, Any],
    target_dir_family: str,
    classification: str,
    reasons: list[str],
    recommended_workers: list[dict[str, Any]],
    worker_rows: list[dict[str, Any]],
    telem_state: dict[str, Any],
) -> dict[str, Any]:
    row = observed_worker(recommended_workers, worker_rows)
    pressure = queue_pressure(row)
    band, estimated_seconds = savings_band(classification, lane, pressure)
    proof_lane_family = string_value(lane_key["normalized_key_material"].get("proof_lane_family"))
    return {
        "schema_version": "proof-pack-worker-warmth-evidence-v1",
        "observed_rch_worker_id": string_value(row.get("worker_id")) if row else "",
        "sampled_at": string_value(telem_state.get("sampled_at")),
        "proof_lane_family": proof_lane_family,
        "cache_key_fingerprint": lane_key["key_material_digest_sha256"][:16],
        "matching_target_dir_family": string_value(row.get("matching_target_dir_family")) if row else "",
        "warmth_basis": warmth_basis(row, classification),
        "queue_pressure": pressure,
        "telemetry_freshness": {
            "state": string_value(telem_state.get("state")),
            "age_seconds": telem_state.get("age_seconds"),
        },
        "estimated_compile_savings_seconds": estimated_seconds,
        "estimated_savings_band": band,
        "confidence_class": confidence_class(classification, telem_state, row),
        "fallback_recommendation": fallback_recommendation(classification, reasons),
        "cache_warmth_is_correctness_evidence": False,
    }


def telemetry_state(telemetry: dict[str, Any], generated_at: str) -> dict[str, Any]:
    workers = [item for item in as_list(telemetry.get("workers")) if isinstance(item, dict)]
    if not workers:
        return {"state": "no-data", "sampled_at": "", "age_seconds": None}
    sampled_at = string_value(telemetry.get("sampled_at"))
    age = telemetry_age_seconds(generated_at, sampled_at)
    max_age = telemetry.get("max_age_seconds")
    max_age_seconds = max_age if isinstance(max_age, int) and max_age >= 0 else 900
    if age is None or age > max_age_seconds:
        return {"state": "stale", "sampled_at": sampled_at, "age_seconds": age}
    return {"state": "fresh", "sampled_at": sampled_at, "age_seconds": age}


def contract_summary(contract: dict[str, Any], path: str) -> dict[str, Any]:
    safety = object_value(contract.get("safety_contract"))
    return {
        "path": path,
        "schema_version": string_value(contract.get("schema_version")),
        "warmed_caches_are_advisory_only": bool(safety.get("warmed_caches_are_advisory_only", False)),
        "proof_must_still_execute": bool(safety.get("proof_must_still_execute", False)),
        "branch_required": string_value(safety.get("branch_required")),
    }


def required_broader_proof_lanes(source: dict[str, Any]) -> list[dict[str, str]]:
    required: list[dict[str, str]] = []
    for item in as_list(source.get("broader_proof_lanes_still_required")):
        if not isinstance(item, dict):
            continue
        lane_id = string_value(item.get("lane_id"))
        command = string_value(item.get("command"))
        reason = string_value(item.get("reason"))
        if lane_id and command:
            required.append(
                {
                    "lane_id": lane_id,
                    "command": command,
                    "reason": reason,
                }
            )
    return required


def operator_receipt(lanes: list[dict[str, Any]], required_lanes: list[dict[str, str]]) -> dict[str, Any]:
    lane_commands = [
        {
            "lane_id": lane["lane_id"],
            "actual_proof_command": lane["command_templates"]["actual_proof_command"],
            "target_dir": lane["command_templates"]["target_dir"],
            "preserves_agent_isolation": bool(lane["command_templates"]["preserves_agent_isolation"]),
            "runs_now": bool(lane["command_templates"]["runs_now"]),
        }
        for lane in lanes
    ]
    return {
        "schema_version": "proof-pack-warmth-operator-receipt-v1",
        "dry_run_only": True,
        "planner_output_is_proof_evidence": False,
        "cache_warmth_is_authoritative": False,
        "actual_proof_commands_still_required": True,
        "all_command_templates_preserve_agent_isolation": all(
            command["preserves_agent_isolation"] for command in lane_commands
        ),
        "lane_command_templates": lane_commands,
        "broader_proof_lanes_still_required": required_lanes,
    }


def build_lane_receipt(
    lane: dict[str, Any],
    operator: dict[str, Any],
    workers: list[dict[str, Any]],
    telem_state: dict[str, Any],
) -> dict[str, Any]:
    lane_id = string_value(lane.get("lane_id"))
    target_dir_family = string_value(lane.get("target_dir_family")) or lane_slug(lane_id)
    lane_key = cache_key_for(object_value(lane.get("cache_key_input")))
    worker_rows = compatible_worker_rows(lane, lane_key, workers, target_dir_family)
    classification, reasons, recommended_workers = classify_lane(lane, lane_key, worker_rows, telem_state)
    templates = command_templates(operator, lane, target_dir_family, lane_key["cache_key"])
    evidence = worker_evidence_receipt(
        lane,
        lane_key,
        target_dir_family,
        classification,
        reasons,
        recommended_workers,
        worker_rows,
        telem_state,
    )

    return {
        "lane_id": lane_id,
        "classification": classification,
        "reasons": reasons,
        "cache_key": lane_key["cache_key"],
        "cache_key_valid": lane_key["cache_key_valid"],
        "cache_key_fingerprint": lane_key["key_material_digest_sha256"][:16],
        "target_dir_family": target_dir_family,
        "recommended_workers": recommended_workers,
        "worker_warmth_evidence": evidence,
        "command_templates": templates,
        "real_proof_requires_isolated_target_dir": True,
        "cache_warmth_is_authoritative": False,
        "normalized_key_material": lane_key["normalized_key_material"],
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    source = load_json(args.input)
    if not isinstance(source, dict):
        raise ValueError("input must be a JSON object")
    generated_at = args.generated_at or utc_now()
    contract_path = args.contract or DEFAULT_CONTRACT_PATH
    contract = load_json(contract_path)
    if not isinstance(contract, dict):
        raise ValueError("contract must be a JSON object")
    operator = object_value(source.get("operator"))
    telemetry = object_value(source.get("telemetry"))
    workers = [item for item in as_list(telemetry.get("workers")) if isinstance(item, dict)]
    telem_state = telemetry_state(telemetry, generated_at)
    lanes = [
        build_lane_receipt(lane, operator, workers, telem_state)
        for lane in as_list(source.get("proof_lanes"))
        if isinstance(lane, dict)
    ]
    required_lanes = required_broader_proof_lanes(source)

    summary = {
        "lane_count": len(lanes),
        "warm": sum(1 for lane in lanes if lane["classification"] == "warm"),
        "not_warm": sum(1 for lane in lanes if lane["classification"] == "not-warm"),
        "degraded": sum(1 for lane in lanes if lane["classification"] == "degraded"),
        "no_data": sum(1 for lane in lanes if lane["classification"] == "no-data"),
        "unsupported": sum(1 for lane in lanes if lane["classification"] == "unsupported"),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": INPUT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": cache_key.current_date(generated_at),
        "contract": contract_summary(contract, contract_path),
        "telemetry": {
            "state": telem_state["state"],
            "sampled_at": telem_state["sampled_at"],
            "age_seconds": telem_state["age_seconds"],
            "worker_count": len(workers),
        },
        "summary": summary,
        "lanes": lanes,
        "operator_receipt": operator_receipt(lanes, required_lanes),
        "dry_run_only": True,
        "non_mutating": True,
        "forbidden_actions": {
            "reads_remote_cache": False,
            "writes_remote_cache": False,
            "runs_cargo": False,
            "runs_rch": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a dry-run proof-pack warmth planner receipt")
    parser.add_argument("--input", required=True, help="Proof-pack warmth planner input JSON")
    parser.add_argument("--contract", default=DEFAULT_CONTRACT_PATH, help="Proof-pack cache-key contract JSON")
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
