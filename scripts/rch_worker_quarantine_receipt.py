#!/usr/bin/env python3
"""Classify rch worker observations into deterministic operator guidance."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "rch-worker-quarantine-receipt-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_observations(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and isinstance(data.get("observations"), list):
        rows = data["observations"]
    else:
        raise ValueError("observations file must be a list or an object with observations[]")

    observations: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"observation {index} must be an object")
        worker = row.get("worker") or row.get("worker_id")
        if not isinstance(worker, str) or not worker.strip():
            raise ValueError(f"observation {index} must include worker")
        observations.append(row)
    return observations


def as_int(row: dict[str, Any], key: str, default: int = 0) -> int:
    value = row.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return default


def as_bool(row: dict[str, Any], key: str, default: bool = False) -> bool:
    value = row.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
    return default


def command_text(row: dict[str, Any]) -> str:
    value = row.get("command")
    return value if isinstance(value, str) else ""


def worker_name(row: dict[str, Any]) -> str:
    value = row.get("worker") or row.get("worker_id")
    return str(value)


def classify_observation(
    row: dict[str, Any],
    *,
    retrieval_slow_ms: int,
    no_capacity_wait_ms: int,
) -> dict[str, Any]:
    remote_exit = row.get("remote_exit_code")
    remote_failure = isinstance(remote_exit, int) and remote_exit != 0
    remote_success = isinstance(remote_exit, int) and remote_exit == 0
    timeout_observed = as_bool(row, "timeout_observed")
    retrieval_completed = as_bool(row, "retrieval_completed", default=True)
    retrieval_elapsed_ms = as_int(row, "retrieval_elapsed_ms", default=0)
    selected_slots = as_int(row, "selected_slots", default=1)
    queue_wait_ms = as_int(row, "queue_wait_ms", default=0)
    local_fallback = as_bool(row, "local_fallback")

    retrieval_slow = remote_success and (
        timeout_observed or not retrieval_completed or retrieval_elapsed_ms >= retrieval_slow_ms
    )
    no_capacity = selected_slots <= 0 and queue_wait_ms >= no_capacity_wait_ms

    flags: list[str] = []
    if remote_failure:
        flags.append("remote_failure")
    if retrieval_slow:
        flags.append("slow_artifact_retrieval")
    if no_capacity:
        flags.append("no_capacity")
    if local_fallback:
        flags.append("local_fallback")
    if not flags:
        flags.append("healthy_sample")

    return {
        "worker": worker_name(row),
        "command": command_text(row),
        "remote_exit_code": remote_exit,
        "remote_success": remote_success,
        "retrieval_elapsed_ms": retrieval_elapsed_ms,
        "retrieval_completed": retrieval_completed,
        "timeout_observed": timeout_observed,
        "selected_slots": selected_slots,
        "queue_wait_ms": queue_wait_ms,
        "flags": flags,
    }


def worker_guidance(classification: str) -> str:
    if classification == "quarantine":
        return "Avoid selecting this worker until fresh successful observations clear the degraded signal."
    if classification == "remote-failing":
        return "Retry the proof on a different worker before treating the failure as project evidence."
    if classification == "slow-artifact-retrieval":
        return "Remote proof may be valid, but keep pass/fail separate from artifact retrieval latency."
    if classification == "no-capacity":
        return "Do not queue new broad proofs on this worker while zero-slot wait evidence is fresh."
    return "Worker has only healthy fixture observations."


def aggregate_worker(worker: str, samples: list[dict[str, Any]]) -> dict[str, Any]:
    remote_failures = sum(1 for sample in samples if "remote_failure" in sample["flags"])
    retrieval_slow = sum(1 for sample in samples if "slow_artifact_retrieval" in sample["flags"])
    no_capacity = sum(1 for sample in samples if "no_capacity" in sample["flags"])
    local_fallback = sum(1 for sample in samples if "local_fallback" in sample["flags"])
    healthy = sum(1 for sample in samples if sample["flags"] == ["healthy_sample"])
    score = remote_failures * 3 + retrieval_slow * 2 + no_capacity + local_fallback * 3

    if remote_failures >= 2 or retrieval_slow >= 2 or score >= 4:
        classification = "quarantine"
    elif remote_failures:
        classification = "remote-failing"
    elif retrieval_slow:
        classification = "slow-artifact-retrieval"
    elif no_capacity:
        classification = "no-capacity"
    else:
        classification = "healthy"

    reasons: list[str] = []
    if remote_failures:
        reasons.append(f"{remote_failures} remote failure sample(s)")
    if retrieval_slow:
        reasons.append(f"{retrieval_slow} slow retrieval sample(s)")
    if no_capacity:
        reasons.append(f"{no_capacity} zero-slot wait sample(s)")
    if local_fallback:
        reasons.append(f"{local_fallback} local fallback sample(s)")
    if not reasons:
        reasons.append(f"{healthy} healthy sample(s)")

    return {
        "worker": worker,
        "classification": classification,
        "quarantine_recommended": classification == "quarantine",
        "score": score,
        "sample_count": len(samples),
        "healthy_samples": healthy,
        "remote_failure_count": remote_failures,
        "slow_retrieval_count": retrieval_slow,
        "no_capacity_count": no_capacity,
        "local_fallback_count": local_fallback,
        "reasons": reasons,
        "operator_guidance": worker_guidance(classification),
    }


def build_receipt(
    *,
    observations_path: Path,
    generated_at: str,
    retrieval_slow_ms: int,
    no_capacity_wait_ms: int,
) -> dict[str, Any]:
    observations = load_observations(observations_path)
    samples = [
        classify_observation(
            row,
            retrieval_slow_ms=retrieval_slow_ms,
            no_capacity_wait_ms=no_capacity_wait_ms,
        )
        for row in observations
    ]

    by_worker: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        by_worker.setdefault(sample["worker"], []).append(sample)

    workers = [aggregate_worker(worker, by_worker[worker]) for worker in sorted(by_worker)]
    quarantine_count = sum(1 for row in workers if row["quarantine_recommended"])
    degraded_count = sum(1 for row in workers if row["classification"] != "healthy")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": generated_at[:10],
        "observations_path": str(observations_path),
        "thresholds": {
            "retrieval_slow_ms": retrieval_slow_ms,
            "no_capacity_wait_ms": no_capacity_wait_ms,
        },
        "source_counts": {
            "observations": len(samples),
            "workers": len(workers),
            "degraded_workers": degraded_count,
            "quarantine_recommended": quarantine_count,
        },
        "workers": workers,
        "observation_flags": samples,
        "decision": "quarantine-suggested" if quarantine_count else "no-quarantine",
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_rch_mutation": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify rch worker observations without mutating rch, Beads, or Git."
    )
    parser.add_argument("--observations", required=True, help="JSON fixture with rch worker observations")
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument("--retrieval-slow-ms", type=int, default=120_000)
    parser.add_argument("--no-capacity-wait-ms", type=int, default=30_000)
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = build_receipt(
        observations_path=Path(args.observations),
        generated_at=args.generated_at,
        retrieval_slow_ms=args.retrieval_slow_ms,
        no_capacity_wait_ms=args.no_capacity_wait_ms,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
