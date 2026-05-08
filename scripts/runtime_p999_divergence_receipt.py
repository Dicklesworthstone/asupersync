#!/usr/bin/env python3
"""Compare native and lab runtime p999 latency summaries without running benchmarks."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "runtime-p999-divergence-receipt-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_measurements(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and isinstance(data.get("measurements"), list):
        rows = data["measurements"]
    else:
        raise ValueError("measurements file must be a list or an object with measurements[]")

    measurements: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"measurement {index} must be an object")
        for key in ["scenario", "mode", "p999_us"]:
            value = row.get(key)
            if value is None or value == "":
                raise ValueError(f"measurement {index} missing {key}")
        mode = str(row["mode"])
        if mode not in {"native", "lab"}:
            raise ValueError(f"measurement {index} mode must be native or lab")
        measurements.append(row)
    return measurements


def as_float(row: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = row.get(key, default)
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


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


def text_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def normalize_measurement(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "scenario": str(row["scenario"]),
        "mode": str(row["mode"]),
        "p999_us": as_float(row, "p999_us"),
        "p95_us": as_float(row, "p95_us"),
        "sample_count": as_int(row, "sample_count"),
        "status": text_value(row, "status") or "pass",
        "command": text_value(row, "command"),
        "git_sha": text_value(row, "git_sha"),
        "artifact": text_value(row, "artifact"),
    }


def guidance_for(classification: str) -> str:
    if classification == "p999-diverged":
        return "Do not cite native-vs-lab parity until this scenario is rerun and the p999 gap is explained."
    if classification == "missing-lab":
        return "Rerun the lab-mode latency fixture before claiming deterministic parity."
    if classification == "missing-native":
        return "Rerun the native-mode latency fixture before claiming production parity."
    if classification == "blocked-measurement":
        return "Treat this scenario as blocked evidence; cite the failing measurement status instead of parity."
    return "Native and lab p999 samples are within the configured divergence threshold."


def classify_pair(
    scenario: str,
    rows: list[dict[str, Any]],
    *,
    max_ratio: float,
    min_samples: int,
) -> dict[str, Any]:
    native = next((row for row in rows if row["mode"] == "native"), None)
    lab = next((row for row in rows if row["mode"] == "lab"), None)

    if native is None:
        return {
            "scenario": scenario,
            "classification": "missing-native",
            "native": None,
            "lab": lab,
            "p999_ratio": None,
            "sample_count_ok": False,
            "operator_guidance": guidance_for("missing-native"),
        }
    if lab is None:
        return {
            "scenario": scenario,
            "classification": "missing-lab",
            "native": native,
            "lab": None,
            "p999_ratio": None,
            "sample_count_ok": False,
            "operator_guidance": guidance_for("missing-lab"),
        }

    if native["status"] != "pass" or lab["status"] != "pass":
        classification = "blocked-measurement"
    else:
        denominator = max(min(native["p999_us"], lab["p999_us"]), 1.0)
        ratio = max(native["p999_us"], lab["p999_us"]) / denominator
        samples_ok = native["sample_count"] >= min_samples and lab["sample_count"] >= min_samples
        classification = "aligned" if ratio <= max_ratio and samples_ok else "p999-diverged"
        return {
            "scenario": scenario,
            "classification": classification,
            "native": native,
            "lab": lab,
            "p999_ratio": round(ratio, 4),
            "p999_delta_us": round(abs(native["p999_us"] - lab["p999_us"]), 4),
            "sample_count_ok": samples_ok,
            "operator_guidance": guidance_for(classification),
        }

    return {
        "scenario": scenario,
        "classification": classification,
        "native": native,
        "lab": lab,
        "p999_ratio": None,
        "sample_count_ok": False,
        "operator_guidance": guidance_for(classification),
    }


def build_receipt(
    *,
    measurements_path: Path,
    generated_at: str,
    max_ratio: float,
    min_samples: int,
) -> dict[str, Any]:
    measurements = [normalize_measurement(row) for row in load_measurements(measurements_path)]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in measurements:
        grouped.setdefault(row["scenario"], []).append(row)

    scenarios = [
        classify_pair(scenario, grouped[scenario], max_ratio=max_ratio, min_samples=min_samples)
        for scenario in sorted(grouped)
    ]
    divergent = sum(1 for row in scenarios if row["classification"] == "p999-diverged")
    missing = sum(1 for row in scenarios if row["classification"] in {"missing-lab", "missing-native"})
    blocked = sum(1 for row in scenarios if row["classification"] == "blocked-measurement")
    aligned = sum(1 for row in scenarios if row["classification"] == "aligned")

    decision = "passed" if divergent == 0 and missing == 0 and blocked == 0 else "needs-review"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": generated_at[:10],
        "measurements_path": str(measurements_path),
        "thresholds": {
            "max_p999_ratio": max_ratio,
            "min_samples_per_mode": min_samples,
        },
        "source_counts": {
            "measurements": len(measurements),
            "scenarios": len(scenarios),
            "aligned": aligned,
            "divergent": divergent,
            "missing_pairs": missing,
            "blocked_measurements": blocked,
        },
        "scenarios": scenarios,
        "decision": decision,
        "non_mutating": True,
        "forbidden_actions": {
            "runs_benchmarks": False,
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare native-vs-lab p999 latency summaries from checked fixtures."
    )
    parser.add_argument("--measurements", required=True, help="JSON fixture containing measurements[]")
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument("--max-p999-ratio", type=float, default=1.25)
    parser.add_argument("--min-samples-per-mode", type=int, default=1000)
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = build_receipt(
        measurements_path=Path(args.measurements),
        generated_at=args.generated_at,
        max_ratio=args.max_p999_ratio,
        min_samples=args.min_samples_per_mode,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
