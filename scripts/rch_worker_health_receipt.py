#!/usr/bin/env python3
"""Classify rch worker health observations without live probing.

The receipt turns fixture or captured rch status observations into a deterministic
fleet health summary. It does not call rch, ssh, cargo, Beads, or Agent Mail.
"""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-worker-health-receipt-v1"
DEFAULT_MIN_FREE_GB = 20.0
DEFAULT_MAX_RETRIEVAL_MS = 120_000
DEFAULT_IO_PRESSURE_AVG10 = 5.0


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def is_reachable(worker: dict[str, Any]) -> bool:
    for key in ("reachable", "probe_ok", "ssh_ok", "available"):
        if key in worker:
            return bool(worker[key])
    return True


def worker_name(worker: dict[str, Any], index: int) -> str:
    for key in ("name", "worker", "host", "id"):
        value = worker.get(key)
        if isinstance(value, str) and value:
            return value
    return f"worker-{index + 1}"


def worker_jobs(worker: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("recent_jobs", "jobs", "observations"):
        value = worker.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def pressure(worker: dict[str, Any], key: str) -> float:
    psi = worker.get("pressure")
    if isinstance(psi, dict):
        return number(psi.get(key), 0.0)
    return number(worker.get(key), 0.0)


def free_gb(worker: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = worker.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return None


def job_classification(job: dict[str, Any]) -> str:
    for key in ("classification", "status", "decision", "result"):
        value = job.get(key)
        if isinstance(value, str):
            return value
    return ""


def classify_worker(
    worker: dict[str, Any],
    index: int,
    min_free_gb: float,
    max_retrieval_ms: int,
    io_pressure_avg10: float,
) -> dict[str, Any]:
    name = worker_name(worker, index)
    jobs = worker_jobs(worker)
    root_free = free_gb(worker, "root_free_gb", "disk_free_gb", "free_gb")
    tmp_free = free_gb(worker, "tmp_free_gb", "tmpfs_free_gb")
    available = is_reachable(worker)

    counts = {
        "remote_success": 0,
        "retrieval_timeout": 0,
        "remote_failure": 0,
        "local_fallback": 0,
        "slow_retrieval": 0,
    }

    for job in jobs:
        classification = job_classification(job)
        if classification in {"remote_success", "passed", "pass"}:
            counts["remote_success"] += 1
        if classification in {"passed_after_retrieval_timeout", "artifact_timeout", "retrieval_timeout"}:
            counts["retrieval_timeout"] += 1
        if classification in {"remote_failure", "failed", "failure"}:
            counts["remote_failure"] += 1
        if classification in {"local_fallback", "fallback"}:
            counts["local_fallback"] += 1
        elapsed_ms = number(job.get("retrieval_elapsed_ms"), 0.0)
        if elapsed_ms > max_retrieval_ms:
            counts["slow_retrieval"] += 1

    low_storage_paths: list[str] = []
    if root_free is not None and root_free < min_free_gb:
        low_storage_paths.append("/")
    if tmp_free is not None and tmp_free < min_free_gb:
        low_storage_paths.append("/tmp")

    io_some_avg10 = pressure(worker, "io_some_avg10")
    memory_some_avg10 = pressure(worker, "memory_some_avg10")
    reasons: list[str] = []

    if not available:
        status = "unavailable"
        reasons.append("worker probe is unavailable")
    elif counts["local_fallback"] > 0:
        status = "quarantine-candidate"
        reasons.append("rch fell back to local execution")
    elif low_storage_paths:
        status = "quarantine-candidate"
        reasons.append(f"low storage on {', '.join(low_storage_paths)}")
    elif counts["remote_failure"] >= 2:
        status = "quarantine-candidate"
        reasons.append("repeated remote command failures")
    elif counts["retrieval_timeout"] >= 2:
        status = "quarantine-candidate"
        reasons.append("repeated artifact retrieval timeouts")
    elif counts["remote_failure"] == 1:
        status = "warn"
        reasons.append("single remote command failure")
    elif counts["retrieval_timeout"] == 1:
        status = "warn"
        reasons.append("single artifact retrieval timeout")
    elif counts["slow_retrieval"] > 0:
        status = "warn"
        reasons.append("artifact retrieval exceeded budget")
    elif io_some_avg10 >= io_pressure_avg10:
        status = "warn"
        reasons.append("I/O pressure exceeds budget")
    else:
        status = "healthy"
        reasons.append("recent observations are inside budget")

    return {
        "worker": name,
        "status": status,
        "signals": {
            **counts,
            "reachable": available,
            "root_free_gb": root_free,
            "tmp_free_gb": tmp_free,
            "io_some_avg10": io_some_avg10,
            "memory_some_avg10": memory_some_avg10,
            "job_count": len(jobs),
        },
        "reasons": reasons,
        "remediation": remediation_for(status),
    }


def remediation_for(status: str) -> list[str]:
    if status == "unavailable":
        return [
            "run `rch workers probe --all` before assigning new proof lanes",
            "route current work to a reachable worker or surface rch fleet unavailability",
        ]
    if status == "quarantine-candidate":
        return [
            "avoid scheduling expensive cargo lanes on this worker until inspected",
            "inspect `df -h / /tmp` and recent rch logs on the worker",
            "prefer a different worker or a narrower proof lane",
        ]
    if status == "warn":
        return [
            "keep the worker eligible only for narrow proof lanes",
            "watch the next rch receipt for repeated failures or retrieval stalls",
        ]
    return ["worker is eligible for normal rch proof lanes"]


def fleet_status(worker_rows: list[dict[str, Any]]) -> str:
    statuses = [row["status"] for row in worker_rows]
    if not statuses:
        return "unavailable"
    if any(status == "healthy" for status in statuses):
        if any(status in {"quarantine-candidate", "unavailable"} for status in statuses):
            return "degraded"
        return "healthy"
    if all(status == "unavailable" for status in statuses):
        return "unavailable"
    return "degraded"


def load_observations(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("observation JSON must be an object")
    return data


def observation_workers(data: dict[str, Any]) -> list[dict[str, Any]]:
    workers = data.get("workers")
    if isinstance(workers, list):
        return [item for item in workers if isinstance(item, dict)]
    worker = data.get("worker")
    if isinstance(worker, dict):
        return [worker]
    return []


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    observations = load_observations(args.observations)
    generated_at = args.generated_at or observations.get("generated_at") or utc_now()
    workers = observation_workers(observations)
    worker_rows = [
        classify_worker(
            worker,
            index,
            args.min_free_gb,
            args.max_retrieval_ms,
            args.io_pressure_avg10,
        )
        for index, worker in enumerate(workers)
    ]
    status_counts = {status: 0 for status in ("healthy", "warn", "quarantine-candidate", "unavailable")}
    for row in worker_rows:
        status_counts[row["status"]] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "observations_path": args.observations,
        "fleet_status": fleet_status(worker_rows),
        "source_counts": {
            "workers": len(worker_rows),
            "jobs": sum(row["signals"]["job_count"] for row in worker_rows),
        },
        "status_counts": status_counts,
        "workers": worker_rows,
        "safety_notes": [
            "receipt is fixture/capture based and does not probe live workers",
            "quarantine is advisory; coordinate before changing live rch worker routing",
        ],
        "non_mutating": True,
        "forbidden_actions": {
            "runs_rch": False,
            "runs_ssh": False,
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic rch worker health receipt")
    parser.add_argument("--observations", required=True, help="JSON worker observation fixture")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--min-free-gb", type=float, default=DEFAULT_MIN_FREE_GB)
    parser.add_argument("--max-retrieval-ms", type=int, default=DEFAULT_MAX_RETRIEVAL_MS)
    parser.add_argument("--io-pressure-avg10", type=float, default=DEFAULT_IO_PRESSURE_AVG10)
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
