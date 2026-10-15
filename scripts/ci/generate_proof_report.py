#!/usr/bin/env python3
"""Aggregate ATP proof-lane artifacts into JSON and Markdown reports."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "atp-proof-report-v1"


def load_matrix_module() -> Any:
    script_path = Path(__file__).resolve().with_name("generate_matrix.py")
    spec = importlib.util.spec_from_file_location("generate_matrix", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lane_key(mode: str, lane_id: str, platform: str) -> str:
    return f"{mode}:{lane_id}:{platform}"


def expected_entries(mode: str, platforms: list[str]) -> list[dict[str, Any]]:
    matrix_module = load_matrix_module()
    matrix = matrix_module.generate_matrix(mode, platforms)
    entries: list[dict[str, Any]] = []

    for lane_mode in ("smoke", "full", "release"):
        if lane_mode == "full" and mode not in {"full", "release"}:
            continue
        if lane_mode == "release" and mode != "release":
            continue

        for entry in matrix.get(lane_mode, []):
            lane = entry.get("lane", {})
            lane_id = str(lane.get("id", ""))
            platform = str(entry.get("platform", ""))
            entries.append(
                {
                    "key": lane_key(lane_mode, lane_id, platform),
                    "mode": lane_mode,
                    "lane_id": lane_id,
                    "platform": platform,
                    "lane_name": lane.get("name", lane_id),
                    "timeout": lane.get("timeout"),
                    "guarantees": lane.get("guarantees", []),
                }
            )

    return entries


def collect_observed(artifacts_dir: Path) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    if not artifacts_dir.exists():
        return observed

    for metadata_path in sorted(artifacts_dir.rglob("metadata.json")):
        lane_dir = metadata_path.parent
        status_path = lane_dir / "status.txt"
        metadata = read_json(metadata_path)
        status = status_path.read_text(encoding="utf-8").strip() if status_path.exists() else "MISSING"
        mode = str(metadata.get("mode", "unknown"))
        lane_id = str(metadata.get("lane_id", lane_dir.name))
        platform = str(metadata.get("platform", "unknown"))
        required_failures = int(metadata.get("required_failures", -1))
        exit_code = int(metadata.get("exit_code", -1))
        passed = status == "SUCCESS" and required_failures == 0 and exit_code == 0

        observed.append(
            {
                "key": lane_key(mode, lane_id, platform),
                "mode": mode,
                "lane_id": lane_id,
                "platform": platform,
                "status": status,
                "passed": passed,
                "required_failures": required_failures,
                "optional_skipped": int(metadata.get("optional_skipped", 0)),
                "exit_code": exit_code,
                "duration_seconds": int(metadata.get("duration_seconds", 0)),
                "metadata_path": str(metadata_path),
                "status_path": str(status_path) if status_path.exists() else None,
                "metadata_sha256": sha256_file(metadata_path),
            }
        )

    return observed


def build_report(artifacts_dir: Path, mode: str, platforms: list[str]) -> dict[str, Any]:
    expected = expected_entries(mode, platforms)
    observed = collect_observed(artifacts_dir)

    expected_by_key = {entry["key"]: entry for entry in expected}
    observed_by_key = {entry["key"]: entry for entry in observed}
    missing = [entry for entry in expected if entry["key"] not in observed_by_key]
    unexpected = [entry for entry in observed if entry["key"] not in expected_by_key]
    failed = [entry for entry in observed if not entry["passed"]]

    if missing or failed:
        overall_status = "failed"
    elif unexpected:
        overall_status = "warning"
    else:
        overall_status = "passed"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "mode": mode,
        "platforms": platforms,
        "overall_status": overall_status,
        "expected_lanes": [entry["key"] for entry in expected],
        "observed_lanes": [entry["key"] for entry in observed],
        "missing_lanes": [entry["key"] for entry in missing],
        "unexpected_lanes": [entry["key"] for entry in unexpected],
        "failed_lanes": [entry["key"] for entry in failed],
        "summary": {
            "expected": len(expected),
            "observed": len(observed),
            "missing": len(missing),
            "failed": len(failed),
            "unexpected": len(unexpected),
        },
        "expected": expected,
        "observed": observed,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATP Proof Lane Summary",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Mode: `{report['mode']}`",
        f"- Overall status: `{report['overall_status']}`",
        f"- Expected lanes: {report['summary']['expected']}",
        f"- Observed lanes: {report['summary']['observed']}",
        f"- Missing lanes: {report['summary']['missing']}",
        f"- Failed lanes: {report['summary']['failed']}",
        "",
        "## Failed Lanes",
        "",
    ]

    failed = report.get("failed_lanes", [])
    if failed:
        lines.extend(f"- `{key}`" for key in failed)
    else:
        lines.append("- None")

    lines.extend(["", "## Missing Lanes", ""])
    missing = report.get("missing_lanes", [])
    if missing:
        lines.extend(f"- `{key}`" for key in missing)
    else:
        lines.append("- None")

    lines.extend(["", "## Observed Lanes", ""])
    observed = report.get("observed", [])
    if observed:
        lines.append("| Mode | Lane | Platform | Status | Duration |")
        lines.append("| --- | --- | --- | --- | ---: |")
        for entry in observed:
            lines.append(
                "| {mode} | {lane} | {platform} | {status} | {duration}s |".format(
                    mode=entry["mode"],
                    lane=entry["lane_id"],
                    platform=entry["platform"],
                    status=entry["status"],
                    duration=entry["duration_seconds"],
                )
            )
    else:
        lines.append("- None")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--mode", choices=["smoke", "full", "release"], required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--platforms", default="linux,macos,windows")
    args = parser.parse_args()

    platforms = [part.strip() for part in args.platforms.split(",") if part.strip()]
    report = build_report(Path(args.artifacts_dir), args.mode, platforms)

    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(render_markdown(report), encoding="utf-8")

    print(f"wrote {output_path}")
    print(f"wrote {summary_path}")
    print(f"overall_status={report['overall_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
