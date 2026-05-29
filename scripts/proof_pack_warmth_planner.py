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
    return {
        "worker_id": worker_id(worker),
        "warm": worker_warm_for(worker, lane_cache_key, target_dir_family),
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
    workers: list[dict[str, Any]],
    telemetry_state: dict[str, Any],
) -> tuple[str, list[str], list[dict[str, Any]]]:
    lane_id = string_value(lane.get("lane_id"))
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

    target_dir_family = string_value(lane.get("target_dir_family")) or lane_slug(lane_id)
    eligible = [
        worker
        for worker in workers
        if worker_id(worker) and worker_supports_lane(worker, lane)
    ]
    if not eligible:
        return "no-data", ["no-compatible-workers"], []

    worker_rows = [
        worker_row(worker, lane_key["cache_key"], target_dir_family)
        for worker in eligible
    ]
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


def build_lane_receipt(
    lane: dict[str, Any],
    operator: dict[str, Any],
    workers: list[dict[str, Any]],
    telem_state: dict[str, Any],
) -> dict[str, Any]:
    lane_id = string_value(lane.get("lane_id"))
    target_dir_family = string_value(lane.get("target_dir_family")) or lane_slug(lane_id)
    lane_key = cache_key_for(object_value(lane.get("cache_key_input")))
    classification, reasons, recommended_workers = classify_lane(lane, lane_key, workers, telem_state)
    templates = command_templates(operator, lane, target_dir_family, lane_key["cache_key"])

    return {
        "lane_id": lane_id,
        "classification": classification,
        "reasons": reasons,
        "cache_key": lane_key["cache_key"],
        "cache_key_valid": lane_key["cache_key_valid"],
        "cache_key_fingerprint": lane_key["key_material_digest_sha256"][:16],
        "target_dir_family": target_dir_family,
        "recommended_workers": recommended_workers,
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
