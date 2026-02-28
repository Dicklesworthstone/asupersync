#!/usr/bin/env python3
"""Validate wasm worker offload policy and emit deterministic summary."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import pathlib
import sys
from typing import Any


class PolicyError(ValueError):
    """Raised when worker offload policy validation fails."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_worker_offload_policy.json",
        help="Path to worker offload policy JSON.",
    )
    parser.add_argument(
        "--summary-output",
        default="",
        help="Override summary output path.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run script self-tests and exit.",
    )
    return parser.parse_args()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in policy file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    return raw


def require_bool_map(section: dict[str, Any], keys: list[str], label: str) -> None:
    for key in keys:
        value = section.get(key)
        if not isinstance(value, bool):
            raise PolicyError(f"{label}.{key} must be bool")


def require_nonempty_str_list(section: dict[str, Any], key: str, label: str) -> list[str]:
    value = section.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PolicyError(f"{label}.{key} must be non-empty list[str]")
    if not value:
        raise PolicyError(f"{label}.{key} cannot be empty")
    return value


def require_positive_int(section: dict[str, Any], key: str, label: str) -> int:
    value = section.get(key)
    if not isinstance(value, int) or value <= 0:
        raise PolicyError(f"{label}.{key} must be positive int")
    return value


def validate_policy(policy: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if policy.get("schema_version") != "wasm-worker-offload-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    invariants = policy.get("invariants")
    if not isinstance(invariants, dict):
        raise PolicyError("invariants must be object")
    require_bool_map(
        invariants,
        [
            "structured_ownership",
            "region_close_implies_quiescence",
            "no_obligation_leaks",
            "no_ambient_authority",
        ],
        "invariants",
    )
    cancellation_protocol = invariants.get("cancellation_protocol")
    if cancellation_protocol != "request-drain-finalize":
        raise PolicyError("invariants.cancellation_protocol must be 'request-drain-finalize'")

    triggers = policy.get("offload_triggers")
    if not isinstance(triggers, dict):
        raise PolicyError("offload_triggers must be object")
    min_estimated_cpu_ns = require_positive_int(triggers, "min_estimated_cpu_ns", "offload_triggers")
    max_main_thread_slice_ns = require_positive_int(triggers, "max_main_thread_slice_ns", "offload_triggers")
    queue_backpressure_threshold = require_positive_int(
        triggers, "queue_backpressure_threshold", "offload_triggers"
    )
    max_inline_retry_count = require_positive_int(triggers, "max_inline_retry_count", "offload_triggers")
    if max_main_thread_slice_ns >= min_estimated_cpu_ns:
        raise PolicyError("offload_triggers.max_main_thread_slice_ns must be < min_estimated_cpu_ns")
    if max_inline_retry_count > 8:
        raise PolicyError("offload_triggers.max_inline_retry_count must be <= 8")
    if queue_backpressure_threshold < 16:
        raise PolicyError("offload_triggers.queue_backpressure_threshold must be >= 16")

    worker_pool = policy.get("worker_pool")
    if not isinstance(worker_pool, dict):
        raise PolicyError("worker_pool must be object")
    mode = worker_pool.get("mode")
    if mode != "bounded-dedicated-pool":
        raise PolicyError("worker_pool.mode must be 'bounded-dedicated-pool'")
    max_workers = require_positive_int(worker_pool, "max_workers", "worker_pool")
    max_inflight_jobs = require_positive_int(worker_pool, "max_inflight_jobs", "worker_pool")
    max_payload_bytes = require_positive_int(worker_pool, "max_payload_bytes", "worker_pool")
    idle_shutdown_ms = require_positive_int(worker_pool, "idle_shutdown_ms", "worker_pool")
    if max_workers > 8:
        raise PolicyError("worker_pool.max_workers must be <= 8 for browser v1 policy")
    if max_inflight_jobs < max_workers:
        raise PolicyError("worker_pool.max_inflight_jobs must be >= max_workers")
    if max_payload_bytes < 4096:
        raise PolicyError("worker_pool.max_payload_bytes must be >= 4096")

    protocol = policy.get("message_protocol")
    if not isinstance(protocol, dict):
        raise PolicyError("message_protocol must be object")
    envelope_version = protocol.get("envelope_version")
    if not isinstance(envelope_version, str) or not envelope_version:
        raise PolicyError("message_protocol.envelope_version must be non-empty string")
    required_fields = require_nonempty_str_list(protocol, "required_fields", "message_protocol")
    operations = require_nonempty_str_list(protocol, "operations", "message_protocol")
    states = require_nonempty_str_list(protocol, "states", "message_protocol")
    terminal_states = require_nonempty_str_list(protocol, "terminal_states", "message_protocol")
    missing_terminal = sorted(set(terminal_states).difference(states))
    if missing_terminal:
        raise PolicyError(
            "message_protocol.terminal_states must be subset of states "
            f"(missing: {', '.join(missing_terminal)})"
        )
    if "cancel_job" not in operations or "drain_job" not in operations or "finalize_job" not in operations:
        raise PolicyError("message_protocol.operations must include cancel_job, drain_job, finalize_job")
    if "job_id" not in required_fields or "obligation_id" not in required_fields:
        raise PolicyError("message_protocol.required_fields must include job_id and obligation_id")

    cancellation = policy.get("cancellation_contract")
    if not isinstance(cancellation, dict):
        raise PolicyError("cancellation_contract must be object")
    require_positive_int(cancellation, "request_timeout_ms", "cancellation_contract")
    require_positive_int(cancellation, "drain_timeout_ms", "cancellation_contract")
    require_positive_int(cancellation, "finalize_timeout_ms", "cancellation_contract")
    required_events = require_nonempty_str_list(
        cancellation, "required_events", "cancellation_contract"
    )
    expected_events = {
        "worker_cancel_requested",
        "worker_cancel_acknowledged",
        "worker_drain_started",
        "worker_drain_completed",
        "worker_finalize_completed",
    }
    missing_events = sorted(expected_events.difference(required_events))
    if missing_events:
        raise PolicyError(
            "cancellation_contract.required_events missing: " + ", ".join(missing_events)
        )

    ownership = policy.get("ownership_model")
    if not isinstance(ownership, dict):
        raise PolicyError("ownership_model must be object")
    require_bool_map(
        ownership,
        [
            "region_affinity_required",
            "obligation_commit_required",
            "cross_region_handoff_forbidden",
        ],
        "ownership_model",
    )
    stale_generation_behavior = ownership.get("stale_generation_behavior")
    if stale_generation_behavior != "typed-error-drop-no-panic":
        raise PolicyError(
            "ownership_model.stale_generation_behavior must be 'typed-error-drop-no-panic'"
        )

    determinism = policy.get("determinism_contract")
    if not isinstance(determinism, dict):
        raise PolicyError("determinism_contract must be object")
    require_bool_map(
        determinism,
        [
            "seed_propagation_required",
            "decision_seq_required",
            "host_turn_id_required",
            "replay_hash_required",
        ],
        "determinism_contract",
    )

    matrix = policy.get("test_matrix")
    if not isinstance(matrix, list) or not matrix:
        raise PolicyError("test_matrix must be non-empty list")
    matrix_ids: list[str] = []
    for raw in matrix:
        if not isinstance(raw, dict):
            raise PolicyError("test_matrix entries must be objects")
        matrix_id = raw.get("id")
        focus = raw.get("focus")
        required = raw.get("required")
        if not isinstance(matrix_id, str) or not matrix_id:
            raise PolicyError("test_matrix.id must be non-empty string")
        if not isinstance(focus, str) or not focus:
            raise PolicyError(f"test_matrix.{matrix_id}.focus must be non-empty string")
        if not isinstance(required, bool):
            raise PolicyError(f"test_matrix.{matrix_id}.required must be bool")
        matrix_ids.append(matrix_id)
    if len(matrix_ids) != len(set(matrix_ids)):
        raise PolicyError("test_matrix.id must be unique")

    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be object")
    summary_path = output.get("summary_path")
    if not isinstance(summary_path, str) or not summary_path:
        raise PolicyError("output.summary_path must be non-empty string")

    summary = {
        "schema_version": "wasm-worker-offload-summary-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "trigger_thresholds": {
            "min_estimated_cpu_ns": min_estimated_cpu_ns,
            "max_main_thread_slice_ns": max_main_thread_slice_ns,
            "queue_backpressure_threshold": queue_backpressure_threshold,
            "max_inline_retry_count": max_inline_retry_count,
        },
        "pool_limits": {
            "mode": mode,
            "max_workers": max_workers,
            "max_inflight_jobs": max_inflight_jobs,
            "max_payload_bytes": max_payload_bytes,
            "idle_shutdown_ms": idle_shutdown_ms,
        },
        "protocol": {
            "envelope_version": envelope_version,
            "required_fields_count": len(required_fields),
            "operations_count": len(operations),
            "state_count": len(states),
            "terminal_states": terminal_states,
        },
        "matrix_ids": sorted(matrix_ids),
    }

    return summary, summary_path


def write_summary(path: pathlib.Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> None:
    base_policy: dict[str, Any] = {
        "schema_version": "wasm-worker-offload-policy-v1",
        "invariants": {
            "structured_ownership": True,
            "region_close_implies_quiescence": True,
            "cancellation_protocol": "request-drain-finalize",
            "no_obligation_leaks": True,
            "no_ambient_authority": True,
        },
        "offload_triggers": {
            "min_estimated_cpu_ns": 2000000,
            "max_main_thread_slice_ns": 1000000,
            "queue_backpressure_threshold": 64,
            "max_inline_retry_count": 2,
        },
        "worker_pool": {
            "mode": "bounded-dedicated-pool",
            "max_workers": 2,
            "max_inflight_jobs": 64,
            "max_payload_bytes": 8192,
            "idle_shutdown_ms": 1000,
        },
        "message_protocol": {
            "envelope_version": "worker-envelope-v1",
            "required_fields": ["message_id", "job_id", "obligation_id"],
            "operations": ["spawn_job", "cancel_job", "drain_job", "finalize_job"],
            "states": ["created", "running", "completed", "failed"],
            "terminal_states": ["completed", "failed"],
        },
        "cancellation_contract": {
            "request_timeout_ms": 25,
            "drain_timeout_ms": 250,
            "finalize_timeout_ms": 250,
            "required_events": [
                "worker_cancel_requested",
                "worker_cancel_acknowledged",
                "worker_drain_started",
                "worker_drain_completed",
                "worker_finalize_completed",
            ],
        },
        "ownership_model": {
            "region_affinity_required": True,
            "obligation_commit_required": True,
            "cross_region_handoff_forbidden": True,
            "stale_generation_behavior": "typed-error-drop-no-panic",
        },
        "determinism_contract": {
            "seed_propagation_required": True,
            "decision_seq_required": True,
            "host_turn_id_required": True,
            "replay_hash_required": True,
        },
        "test_matrix": [
            {"id": "WKR-CANCEL", "focus": "cancel", "required": True}
        ],
        "output": {"summary_path": "artifacts/test_worker_summary.json"},
    }

    summary, _summary_path = validate_policy(base_policy)
    assert summary["pool_limits"]["max_workers"] == 2

    bad_policy = copy.deepcopy(base_policy)
    bad_policy["offload_triggers"]["max_main_thread_slice_ns"] = 3000000
    try:
        validate_policy(bad_policy)
    except PolicyError:
        pass
    else:
        raise AssertionError("expected offload trigger ordering validation to fail")

    bad_policy2 = copy.deepcopy(base_policy)
    bad_policy2["message_protocol"]["terminal_states"] = ["completed", "unknown"]
    try:
        validate_policy(bad_policy2)
    except PolicyError:
        pass
    else:
        raise AssertionError("expected terminal state subset validation to fail")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        print("wasm worker offload policy self-test passed")
        return 0

    policy_path = pathlib.Path(args.policy)
    policy = load_json(policy_path)
    summary, default_summary_path = validate_policy(policy)
    summary_path = pathlib.Path(args.summary_output or default_summary_path)
    write_summary(summary_path, summary)
    print(f"wrote {summary_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
