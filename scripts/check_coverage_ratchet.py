#!/usr/bin/env python3
"""Module/invariant-aware coverage ratchet gate for CI (D1/D2)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class FileCoverage:
    path: str
    lines_total: int
    lines_covered: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        return p.as_posix().lstrip("./")
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_llvm_cov_files(path: Path, repo_root: Path) -> list[FileCoverage]:
    payload = load_json(path)
    files: list[FileCoverage] = []
    for dataset in payload.get("data", []):
        for entry in dataset.get("files", []):
            summary = entry.get("summary", {}).get("lines", {})
            total = int(summary.get("count", 0))
            covered = int(summary.get("covered", 0))
            if total <= 0:
                continue
            normalized = normalize_path(str(entry.get("filename", "")), repo_root)
            files.append(FileCoverage(path=normalized, lines_total=total, lines_covered=covered))
    return files


def load_llvm_cov_totals(path: Path) -> tuple[int, int]:
    payload = load_json(path)
    total_count = 0
    total_covered = 0
    for dataset in payload.get("data", []):
        lines = dataset.get("totals", {}).get("lines", {})
        total_count += int(lines.get("count", 0))
        total_covered += int(lines.get("covered", 0))
    return total_count, total_covered


def starts_with_any(path: str, prefixes: list[str]) -> bool:
    for prefix in prefixes:
        normalized = prefix.lstrip("./")
        if path.startswith(normalized):
            return True
    return False


def classify_tiers(check_path: str) -> set[str]:
    path = check_path.lower()
    tiers: set[str] = set()
    if "e2e" in path or "/e2e/" in path or "_e2e" in path:
        tiers.add("e2e")
    if (
        "integration" in path
        or "conformance" in path
        or "verification" in path
        or "invariants" in path
        or "semantics" in path
        or "lifecycle" in path
        or "refinement" in path
        or "regression" in path
    ):
        tiers.add("integration")
    if not tiers:
        tiers.add("unit")
    return tiers


def pct(covered: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (covered * 100.0) / total


def resolve_active_stage(
    policy: dict[str, Any], now: datetime | None = None
) -> tuple[dict[str, float], float, str]:
    """Resolve the active ratchet stage based on current date.

    Returns (subsystem_overrides, global_floor, stage_name).
    Walks ratchet_schedule in order; the last stage whose effective_date
    is <= today wins. Overrides are merged on top of subsystem min_line_pct.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    schedule = policy.get("ratchet_schedule", [])
    if not schedule:
        return {}, float(policy.get("global_line_floor_pct", 0.0)), "default"

    active_stage = None
    for stage in schedule:
        effective = datetime.strptime(stage["effective_date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        if effective <= now:
            active_stage = stage

    if active_stage is None:
        return {}, float(policy.get("global_line_floor_pct", 0.0)), "pre-schedule"

    overrides = {k: float(v) for k, v in active_stage.get("overrides", {}).items()}
    global_floor = float(
        active_stage.get("global_line_floor_pct", policy.get("global_line_floor_pct", 0.0))
    )
    return overrides, global_floor, str(active_stage.get("stage", "unknown"))


def resolve_waivers(policy: dict[str, Any], now: datetime | None = None) -> dict[str, float]:
    """Return subsystem_id -> override_min_line_pct for active (non-expired) waivers."""
    if now is None:
        now = datetime.now(timezone.utc)

    active: dict[str, float] = {}
    for waiver in policy.get("waivers", []):
        expires = waiver.get("expires_at_utc", "")
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if exp_dt <= now:
                    continue
            except ValueError:
                continue
        sid = waiver.get("subsystem_id", "")
        override = waiver.get("override_min_line_pct")
        if sid and override is not None:
            active[sid] = float(override)
    return active


def effective_threshold(
    subsystem_id: str,
    base_threshold: float,
    stage_overrides: dict[str, float],
    waiver_overrides: dict[str, float],
) -> tuple[float, str]:
    """Compute the effective threshold for a subsystem.

    Priority: waiver > stage override > base.
    Returns (threshold, source) where source is 'waiver', 'stage', or 'base'.
    """
    if subsystem_id in waiver_overrides:
        return waiver_overrides[subsystem_id], "waiver"
    if subsystem_id in stage_overrides:
        threshold = max(base_threshold, stage_overrides[subsystem_id])
        return threshold, "stage"
    return base_threshold, "base"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--coverage-json", required=True, type=Path)
    parser.add_argument("--invariant-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    repo_root = Path(os.getcwd())
    policy = load_json(args.policy)
    files = load_llvm_cov_files(args.coverage_json, repo_root)
    total_lines, covered_lines = load_llvm_cov_totals(args.coverage_json)
    global_pct = pct(covered_lines, total_lines)

    stage_overrides, global_floor, active_stage = resolve_active_stage(policy)
    waiver_overrides = resolve_waivers(policy)

    expired_waivers: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for waiver in policy.get("waivers", []):
        expires = waiver.get("expires_at_utc", "")
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if exp_dt <= now:
                    expired_waivers.append(waiver)
            except ValueError:
                pass

    failures: list[str] = []
    subsystem_results: list[dict[str, Any]] = []
    for subsystem in policy.get("subsystems", []):
        sid = subsystem["id"]
        label = subsystem.get("label", sid)
        base_threshold = float(subsystem["min_line_pct"])
        threshold, threshold_source = effective_threshold(
            sid, base_threshold, stage_overrides, waiver_overrides
        )
        prefixes = list(subsystem.get("include_prefixes", []))
        matched = [f for f in files if starts_with_any(f.path, prefixes)]
        lines_total = sum(f.lines_total for f in matched)
        lines_covered = sum(f.lines_covered for f in matched)
        coverage_pct = pct(lines_covered, lines_total)
        meets_floor = coverage_pct >= threshold and lines_total > 0
        if not meets_floor:
            failures.append(
                f"subsystem:{sid}: coverage {coverage_pct:.2f}% below floor {threshold:.2f}% "
                f"(source={threshold_source}) or no covered lines"
            )
        subsystem_results.append(
            {
                "id": sid,
                "label": label,
                "include_prefixes": prefixes,
                "base_threshold_line_pct": base_threshold,
                "effective_threshold_line_pct": threshold,
                "threshold_source": threshold_source,
                "lines_total": lines_total,
                "lines_covered": lines_covered,
                "line_pct": round(coverage_pct, 4),
                "matched_file_count": len(matched),
                "status": "pass" if meets_floor else "fail",
            }
        )

    global_ok = global_pct >= global_floor and total_lines > 0
    if not global_ok:
        failures.append(
            f"global: coverage {global_pct:.2f}% below floor {global_floor:.2f}% or no covered lines"
        )

    invariant_payload = load_json(args.invariant_map)
    by_invariant = {
        item.get("invariant_id"): item for item in invariant_payload.get("invariant_links", [])
    }
    invariant_results: list[dict[str, Any]] = []
    for rule in policy.get("required_invariants", []):
        inv_id = rule["id"]
        min_total = int(rule.get("min_total_refs", 0))
        min_integration = int(rule.get("min_integration_refs", 0))
        min_e2e = int(rule.get("min_e2e_refs", 0))
        link = by_invariant.get(inv_id)
        checks = list(link.get("executable_checks", [])) if link else []
        tier_counts: dict[str, int] = defaultdict(int)
        for check in checks:
            for tier in classify_tiers(check):
                tier_counts[tier] += 1
        total_refs = len(checks)
        integration_refs = int(tier_counts["integration"])
        e2e_refs = int(tier_counts["e2e"])
        ok = (
            link is not None
            and total_refs >= min_total
            and integration_refs >= min_integration
            and e2e_refs >= min_e2e
        )
        if not ok:
            failures.append(
                f"invariant:{inv_id}: total={total_refs}/{min_total}, "
                f"integration={integration_refs}/{min_integration}, e2e={e2e_refs}/{min_e2e}"
            )
        invariant_results.append(
            {
                "invariant_id": inv_id,
                "link_present": link is not None,
                "checks": checks,
                "total_refs": total_refs,
                "integration_refs": integration_refs,
                "e2e_refs": e2e_refs,
                "thresholds": {
                    "min_total_refs": min_total,
                    "min_integration_refs": min_integration,
                    "min_e2e_refs": min_e2e,
                },
                "status": "pass" if ok else "fail",
            }
        )

    status = "pass" if not failures else "fail"
    report = {
        "schema_version": "coverage-ratchet-report-v1",
        "generated_at": utc_now(),
        "active_stage": active_stage,
        "policy_path": str(args.policy),
        "coverage_json_path": str(args.coverage_json),
        "invariant_map_path": str(args.invariant_map),
        "global_coverage": {
            "line_pct": round(global_pct, 4),
            "lines_total": total_lines,
            "lines_covered": covered_lines,
            "floor_pct": global_floor,
            "status": "pass" if global_ok else "fail",
        },
        "subsystem_results": subsystem_results,
        "invariant_results": invariant_results,
        "expired_waivers": expired_waivers,
        "failure_count": len(failures),
        "failures": failures,
        "status": status,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"Coverage ratchet report: {args.output}")
    print(f"Active stage: {active_stage}")
    if expired_waivers:
        print(f"Expired waivers: {len(expired_waivers)}")
        for w in expired_waivers:
            print(f"  - {w['subsystem_id']} (owner={w['owner']}, expired={w['expires_at_utc']})")
    if failures:
        print("Coverage ratchet gate FAILED:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Coverage ratchet gate PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
