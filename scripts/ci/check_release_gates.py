#!/usr/bin/env python3
"""Fail closed when the ATP release proof summary is incomplete or failed."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-report", required=True)
    parser.add_argument("--gate-config", required=False)
    args = parser.parse_args()

    report_path = Path(args.proof_report)
    if not report_path.exists():
        print(f"missing proof report: {report_path}")
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "atp-proof-report-v1":
        print("unsupported proof report schema")
        return 1

    if report.get("overall_status") != "passed":
        print(f"ATP release gates failed: {report.get('overall_status')}")
        return 1

    if report.get("failed_lanes"):
        print(f"failed lanes remain: {report['failed_lanes']}")
        return 1

    expected = set(report.get("expected_lanes", []))
    observed = set(report.get("observed_lanes", []))
    missing = sorted(expected - observed)
    if missing:
        print(f"missing release proof lanes: {missing}")
        return 1

    print("ATP release gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
