#!/usr/bin/env python3
"""Continuous performance regression gate for asupersync WASM browser builds.

Validates benchmark results against:
  1. Hard budgets (immediate CI failure on any breach)
  2. Operational budgets (warn-then-block with consecutive escalation)
  3. Baseline regression (percentage-based delta detection)

Reads thresholds from .github/wasm_perf_budgets.json and baselines from
baselines/baseline_latest.json.

Emits:
  - artifacts/wasm_perf_regression_report.json  (structured gate report)
  - artifacts/wasm_perf_gate_events.ndjson      (NDJSON event log)

Usage:
  python3 scripts/check_perf_regression.py --self-test
  python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json
  python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json \\
      --baseline baselines/baseline_latest.json \\
      --current baselines/baseline_current.json

Bead: asupersync-umelq.13.5
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import pathlib
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HardBudget:
    metric_id: str
    metric: str
    unit: str
    profiles: dict[str, float]
    gate_type: str


@dataclass(frozen=True)
class OperationalBudget:
    metric_id: str
    metric: str
    unit: str
    target: float
    warn_threshold: float
    hard_threshold: float
    consecutive_warn_escalation: int


@dataclass
class MetricResult:
    metric_id: str
    metric: str
    profile: str
    value: float | None
    threshold_warn: float | None
    threshold_hard: float | None
    status: str  # pass | warn | fail | skip
    unit: str
    detail: str


@dataclass
class BaselineRegression:
    benchmark: str
    baseline_value: float
    current_value: float
    delta_pct: float
    metric: str
    status: str  # pass | regression


@dataclass
class GateReport:
    schema_version: str = "wasm-perf-regression-report-v1"
    generated_at_utc: str = ""
    git_sha: str | None = None
    gate_status: str = "pass"  # pass | warn | fail
    budget_results: list[dict[str, Any]] = field(default_factory=list)
    baseline_regressions: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Policy loading and validation
# ---------------------------------------------------------------------------

class PolicyError(ValueError):
    """Raised on invalid budget policy."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"root of {path} must be an object")
    return raw


def parse_hard_budgets(raw_list: list[dict[str, Any]]) -> list[HardBudget]:
    budgets: list[HardBudget] = []
    for entry in raw_list:
        profiles = entry.get("profiles", {})
        if not isinstance(profiles, dict):
            raise PolicyError(f"hard budget {entry.get('metric_id')}: profiles must be object")
        budgets.append(HardBudget(
            metric_id=entry["metric_id"],
            metric=entry["metric"],
            unit=entry["unit"],
            profiles={k: float(v) for k, v in profiles.items()},
            gate_type=entry.get("gate_type", "hard_fail"),
        ))
    return budgets


def parse_operational_budgets(raw_list: list[dict[str, Any]]) -> list[OperationalBudget]:
    budgets: list[OperationalBudget] = []
    for entry in raw_list:
        budgets.append(OperationalBudget(
            metric_id=entry["metric_id"],
            metric=entry["metric"],
            unit=entry["unit"],
            target=float(entry["target"]),
            warn_threshold=float(entry["warn_threshold"]),
            hard_threshold=float(entry["hard_threshold"]),
            consecutive_warn_escalation=int(entry.get("consecutive_warn_escalation", 2)),
        ))
    return budgets


def load_budgets(path: pathlib.Path) -> tuple[
    list[HardBudget],
    list[OperationalBudget],
    dict[str, Any],
    dict[str, Any],
]:
    policy = load_json(path)
    if policy.get("schema_version") != "wasm-perf-budgets-v1":
        raise PolicyError("unsupported or missing schema_version in budget policy")

    hard = parse_hard_budgets(policy.get("hard_budgets", []))
    operational = parse_operational_budgets(policy.get("operational_budgets", []))
    baseline_cfg = policy.get("baseline_regression", {})
    output_cfg = policy.get("output", {})
    return hard, operational, baseline_cfg, output_cfg


# ---------------------------------------------------------------------------
# Budget evaluation
# ---------------------------------------------------------------------------

def check_hard_budget(
    budget: HardBudget,
    profile: str,
    value: float | None,
) -> MetricResult:
    threshold = budget.profiles.get(profile)
    if threshold is None:
        return MetricResult(
            metric_id=budget.metric_id,
            metric=budget.metric,
            profile=profile,
            value=value,
            threshold_warn=None,
            threshold_hard=None,
            status="skip",
            unit=budget.unit,
            detail=f"no threshold for profile {profile}",
        )
    if value is None:
        return MetricResult(
            metric_id=budget.metric_id,
            metric=budget.metric,
            profile=profile,
            value=None,
            threshold_warn=None,
            threshold_hard=threshold,
            status="skip",
            unit=budget.unit,
            detail="no measurement available",
        )
    status = "fail" if value > threshold else "pass"
    return MetricResult(
        metric_id=budget.metric_id,
        metric=budget.metric,
        profile=profile,
        value=value,
        threshold_warn=None,
        threshold_hard=threshold,
        status=status,
        unit=budget.unit,
        detail=f"{value} {'>' if status == 'fail' else '<='} {threshold} {budget.unit}",
    )


def check_operational_budget(
    budget: OperationalBudget,
    value: float | None,
    consecutive_warn_count: int = 0,
) -> MetricResult:
    if value is None:
        return MetricResult(
            metric_id=budget.metric_id,
            metric=budget.metric,
            profile="all",
            value=None,
            threshold_warn=budget.warn_threshold,
            threshold_hard=budget.hard_threshold,
            status="skip",
            unit=budget.unit,
            detail="no measurement available",
        )

    if value > budget.hard_threshold:
        status = "fail"
        detail = f"{value} > hard threshold {budget.hard_threshold} {budget.unit}"
    elif value > budget.warn_threshold:
        if consecutive_warn_count + 1 >= budget.consecutive_warn_escalation:
            status = "fail"
            detail = (
                f"{value} > warn threshold {budget.warn_threshold} {budget.unit} "
                f"(consecutive breach #{consecutive_warn_count + 1} >= "
                f"{budget.consecutive_warn_escalation}, escalated to fail)"
            )
        else:
            status = "warn"
            detail = (
                f"{value} > warn threshold {budget.warn_threshold} {budget.unit} "
                f"(consecutive breach #{consecutive_warn_count + 1})"
            )
    else:
        status = "pass"
        detail = f"{value} <= target {budget.target} {budget.unit}"

    return MetricResult(
        metric_id=budget.metric_id,
        metric=budget.metric,
        profile="all",
        value=value,
        threshold_warn=budget.warn_threshold,
        threshold_hard=budget.hard_threshold,
        status=status,
        unit=budget.unit,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Baseline regression detection
# ---------------------------------------------------------------------------

def detect_regressions(
    baseline_path: pathlib.Path,
    current_path: pathlib.Path,
    comparison_metric: str,
    max_regression_pct: float,
) -> list[BaselineRegression]:
    if not baseline_path.exists() or not current_path.exists():
        return []

    baseline_data = load_json(baseline_path)
    current_data = load_json(current_path)

    baseline_map = {
        b["name"]: b for b in baseline_data.get("benchmarks", [])
    }
    current_map = {
        b["name"]: b for b in current_data.get("benchmarks", [])
    }

    results: list[BaselineRegression] = []
    for name, cur in sorted(current_map.items()):
        base = baseline_map.get(name)
        if base is None:
            continue
        cur_val = cur.get(comparison_metric)
        base_val = base.get(comparison_metric)
        if (
            not isinstance(cur_val, (int, float))
            or not isinstance(base_val, (int, float))
            or base_val <= 0
            or math.isnan(cur_val)
            or math.isnan(base_val)
        ):
            continue

        delta_pct = ((cur_val / base_val) - 1.0) * 100.0
        status = "regression" if delta_pct > max_regression_pct else "pass"
        results.append(BaselineRegression(
            benchmark=name,
            baseline_value=base_val,
            current_value=cur_val,
            delta_pct=round(delta_pct, 2),
            metric=comparison_metric,
            status=status,
        ))

    return results


# ---------------------------------------------------------------------------
# NDJSON event log
# ---------------------------------------------------------------------------

def emit_event(log_path: pathlib.Path, event: dict[str, Any]) -> None:
    event["ts"] = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    event["schema"] = "wasm-perf-gate-event-v1"
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Git SHA helper
# ---------------------------------------------------------------------------

def git_sha() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    budget_results: list[MetricResult],
    regressions: list[BaselineRegression],
    config: dict[str, Any],
) -> GateReport:
    counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0, "regression": 0}

    for r in budget_results:
        counts[r.status] = counts.get(r.status, 0) + 1

    for r in regressions:
        if r.status == "regression":
            counts["regression"] += 1

    if counts["fail"] > 0 or counts["regression"] > 0:
        gate_status = "fail"
    elif counts["warn"] > 0:
        gate_status = "warn"
    else:
        gate_status = "pass"

    return GateReport(
        generated_at_utc=(
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        git_sha=git_sha(),
        gate_status=gate_status,
        budget_results=[asdict(r) for r in budget_results],
        baseline_regressions=[asdict(r) for r in regressions],
        summary=counts,
        config=config,
    )


def write_report(path: pathlib.Path, report: GateReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def run_self_test() -> None:
    # Test 1: Hard budget pass
    hb = HardBudget("M-PERF-01A", "wasm size", "bytes", {"core-min": 650_000}, "hard_fail")
    r = check_hard_budget(hb, "core-min", 600_000)
    assert r.status == "pass", f"expected pass, got {r.status}"

    # Test 2: Hard budget fail
    r = check_hard_budget(hb, "core-min", 700_000)
    assert r.status == "fail", f"expected fail, got {r.status}"

    # Test 3: Hard budget skip (unknown profile)
    r = check_hard_budget(hb, "unknown-profile", 100)
    assert r.status == "skip", f"expected skip, got {r.status}"

    # Test 4: Hard budget skip (no value)
    r = check_hard_budget(hb, "core-min", None)
    assert r.status == "skip", f"expected skip, got {r.status}"

    # Test 5: Operational budget pass
    ob = OperationalBudget("M-PERF-04A", "tx p95", "us", 8.0, 8.0, 12.0, 2)
    r = check_operational_budget(ob, 7.0)
    assert r.status == "pass", f"expected pass, got {r.status}"

    # Test 6: Operational budget warn (first breach)
    r = check_operational_budget(ob, 9.0, consecutive_warn_count=0)
    assert r.status == "warn", f"expected warn, got {r.status}"

    # Test 7: Operational budget escalated to fail (second consecutive)
    r = check_operational_budget(ob, 9.0, consecutive_warn_count=1)
    assert r.status == "fail", f"expected fail (escalated), got {r.status}"

    # Test 8: Operational budget hard threshold fail
    r = check_operational_budget(ob, 13.0)
    assert r.status == "fail", f"expected fail (hard), got {r.status}"

    # Test 9: Operational budget skip (no value)
    r = check_operational_budget(ob, None)
    assert r.status == "skip", f"expected skip, got {r.status}"

    # Test 10: Report aggregation
    results = [
        MetricResult("A", "a", "p", 1, None, 2, "pass", "u", "ok"),
        MetricResult("B", "b", "p", 3, 2, 4, "warn", "u", "w"),
        MetricResult("C", "c", "p", 5, None, 4, "fail", "u", "f"),
    ]
    report = build_report(results, [], {})
    assert report.gate_status == "fail"
    assert report.summary["pass"] == 1
    assert report.summary["warn"] == 1
    assert report.summary["fail"] == 1

    # Test 11: Report with regressions
    regs = [
        BaselineRegression("bench/a", 100.0, 120.0, 20.0, "median_ns", "regression"),
    ]
    report = build_report(
        [MetricResult("A", "a", "p", 1, None, 2, "pass", "u", "ok")],
        regs,
        {},
    )
    assert report.gate_status == "fail"
    assert report.summary["regression"] == 1

    # Test 12: Report all pass
    report = build_report(
        [MetricResult("A", "a", "p", 1, None, 2, "pass", "u", "ok")],
        [BaselineRegression("bench/a", 100.0, 105.0, 5.0, "median_ns", "pass")],
        {},
    )
    assert report.gate_status == "pass"

    # Test 13: Budget policy schema validation
    import tempfile
    bad_policy = {"schema_version": "wrong"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bad_policy, f)
        f.flush()
        try:
            load_budgets(pathlib.Path(f.name))
        except PolicyError:
            pass
        else:
            raise AssertionError("expected PolicyError for bad schema_version")

    # Test 14: Baseline regression detection
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as bf:
        json.dump({
            "benchmarks": [
                {"name": "bench/fast", "median_ns": 100.0},
                {"name": "bench/slow", "median_ns": 200.0},
            ]
        }, bf)
        bf.flush()
        baseline_p = pathlib.Path(bf.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as cf:
        json.dump({
            "benchmarks": [
                {"name": "bench/fast", "median_ns": 105.0},  # +5%, pass
                {"name": "bench/slow", "median_ns": 240.0},  # +20%, regression
            ]
        }, cf)
        cf.flush()
        current_p = pathlib.Path(cf.name)

    regs = detect_regressions(baseline_p, current_p, "median_ns", 10.0)
    assert len(regs) == 2
    reg_map = {r.benchmark: r for r in regs}
    assert reg_map["bench/fast"].status == "pass"
    assert reg_map["bench/slow"].status == "regression"
    assert reg_map["bench/slow"].delta_pct == 20.0

    print("all 14 self-tests passed")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Performance regression gate for asupersync WASM builds.",
    )
    parser.add_argument(
        "--budgets",
        default=".github/wasm_perf_budgets.json",
        help="Path to budget policy JSON.",
    )
    parser.add_argument(
        "--baseline",
        default="",
        help="Path to baseline JSON (default: from policy baseline_regression.baseline_latest).",
    )
    parser.add_argument(
        "--current",
        default="",
        help="Path to current benchmark JSON (for baseline comparison).",
    )
    parser.add_argument(
        "--report-output",
        default="",
        help="Override report output path.",
    )
    parser.add_argument(
        "--profile",
        default="core-min",
        help="Budget profile to check hard budgets against (default: core-min).",
    )
    parser.add_argument(
        "--measurements",
        default="",
        help="Path to measurements JSON with metric_id -> value mapping.",
    )
    parser.add_argument(
        "--warn-history",
        default="",
        help="Path to warn history JSON tracking consecutive warn counts.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run self-tests and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        run_self_test()
        return 0

    # Load budget policy
    budgets_path = pathlib.Path(args.budgets)
    hard_budgets, operational_budgets, baseline_cfg, output_cfg = load_budgets(budgets_path)

    # Load measurements if provided
    measurements: dict[str, float] = {}
    if args.measurements:
        meas_path = pathlib.Path(args.measurements)
        if meas_path.exists():
            measurements = load_json(meas_path)

    # Load warn history for consecutive escalation
    warn_history: dict[str, int] = {}
    if args.warn_history:
        wh_path = pathlib.Path(args.warn_history)
        if wh_path.exists():
            warn_history = load_json(wh_path)

    # Determine output paths
    report_path = pathlib.Path(
        args.report_output or output_cfg.get("report_path", "artifacts/wasm_perf_regression_report.json")
    )
    event_log_path = pathlib.Path(
        output_cfg.get("event_log_path", "artifacts/wasm_perf_gate_events.ndjson")
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    event_log_path.parent.mkdir(parents=True, exist_ok=True)

    # Clear previous event log
    if event_log_path.exists():
        event_log_path.unlink()

    emit_event(event_log_path, {
        "event": "perf_gate_start",
        "budgets_path": str(budgets_path),
        "profile": args.profile,
    })

    profile = args.profile
    budget_results: list[MetricResult] = []

    # Evaluate hard budgets
    for hb in hard_budgets:
        value = measurements.get(hb.metric_id)
        result = check_hard_budget(hb, profile, value)
        budget_results.append(result)
        emit_event(event_log_path, {
            "event": "budget_check",
            "metric_id": hb.metric_id,
            "gate_type": "hard",
            "status": result.status,
            "value": result.value,
            "threshold": result.threshold_hard,
        })

    # Evaluate operational budgets
    for ob in operational_budgets:
        value = measurements.get(ob.metric_id)
        consecutive = warn_history.get(ob.metric_id, 0)
        result = check_operational_budget(ob, value, consecutive)
        budget_results.append(result)
        emit_event(event_log_path, {
            "event": "budget_check",
            "metric_id": ob.metric_id,
            "gate_type": "operational",
            "status": result.status,
            "value": result.value,
            "threshold_warn": result.threshold_warn,
            "threshold_hard": result.threshold_hard,
        })

    # Baseline regression detection
    baseline_path = pathlib.Path(
        args.baseline or baseline_cfg.get("baseline_latest", "baselines/baseline_latest.json")
    )
    current_path = pathlib.Path(args.current) if args.current else None
    comparison_metric = baseline_cfg.get("comparison_metric", "median_ns")
    max_regression_pct = float(baseline_cfg.get("max_regression_pct", 10))

    regressions: list[BaselineRegression] = []
    if current_path and current_path.exists() and baseline_path.exists():
        regressions = detect_regressions(
            baseline_path, current_path, comparison_metric, max_regression_pct
        )
        for reg in regressions:
            if reg.status == "regression":
                emit_event(event_log_path, {
                    "event": "regression_detected",
                    "benchmark": reg.benchmark,
                    "baseline": reg.baseline_value,
                    "current": reg.current_value,
                    "delta_pct": reg.delta_pct,
                    "metric": reg.metric,
                })

    # Build and write report
    config = {
        "budgets_path": str(budgets_path),
        "baseline_path": str(baseline_path),
        "current_path": str(current_path) if current_path else None,
        "profile": profile,
        "comparison_metric": comparison_metric,
        "max_regression_pct": max_regression_pct,
    }
    report = build_report(budget_results, regressions, config)
    write_report(report_path, report)

    emit_event(event_log_path, {
        "event": "perf_gate_end",
        "gate_status": report.gate_status,
        "summary": report.summary,
    })

    # Print summary
    print(f"Perf regression gate: {report.gate_status.upper()}")
    print(f"  Budget checks: {report.summary.get('pass', 0)} pass, "
          f"{report.summary.get('warn', 0)} warn, "
          f"{report.summary.get('fail', 0)} fail, "
          f"{report.summary.get('skip', 0)} skip")
    if regressions:
        reg_count = sum(1 for r in regressions if r.status == "regression")
        print(f"  Baseline regressions: {reg_count}/{len(regressions)} benchmarks")
    print(f"  Report: {report_path}")
    print(f"  Events: {event_log_path}")

    if report.gate_status == "fail":
        # Print details of failures
        for r in budget_results:
            if r.status == "fail":
                print(f"  FAIL: {r.metric_id} ({r.metric}): {r.detail}")
        for r in regressions:
            if r.status == "regression":
                print(f"  REGRESSION: {r.benchmark}: "
                      f"{r.baseline_value:.2f} -> {r.current_value:.2f} "
                      f"(+{r.delta_pct:.1f}%)")
        return 1

    if report.gate_status == "warn":
        for r in budget_results:
            if r.status == "warn":
                print(f"  WARN: {r.metric_id} ({r.metric}): {r.detail}")
        return 0

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
