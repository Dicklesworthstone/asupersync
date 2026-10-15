#!/usr/bin/env python3
"""Validate benchmark corpus policy and emit deterministic summary artifact."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import pathlib
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """Raised when corpus policy validation fails."""


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    journey: str
    framework: str
    workload: str
    profile: str
    browsers: tuple[str, ...]
    bundlers: tuple[str, ...]
    seed_set: tuple[int, ...]
    metric_ids: tuple[str, ...]
    bench_suite: tuple[str, ...]
    repro_command: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_benchmark_corpus.json",
        help="Path to benchmark corpus policy JSON.",
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
    parser.add_argument(
        "--only-scenario",
        action="append",
        default=[],
        help="Restrict summary output to one or more scenario IDs.",
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


def parse_policy_contract(
    policy: dict[str, Any],
) -> tuple[
    frozenset[str],
    frozenset[str],
    tuple[int, ...],
    frozenset[str],
    str,
    frozenset[str],
    str,
]:
    if policy.get("schema_version") != "wasm-benchmark-corpus-v1":
        raise PolicyError("unsupported or missing schema_version")

    budget_contract = policy.get("budget_contract")
    if not isinstance(budget_contract, dict):
        raise PolicyError("budget_contract must be an object")
    metric_ids = budget_contract.get("metric_ids")
    if not isinstance(metric_ids, list) or not all(
        isinstance(metric_id, str) and metric_id for metric_id in metric_ids
    ):
        raise PolicyError("budget_contract.metric_ids must be a non-empty list[str]")
    allowed_metrics = frozenset(metric_ids)
    if not allowed_metrics:
        raise PolicyError("budget_contract.metric_ids cannot be empty")

    quality_gates = policy.get("quality_gates")
    if not isinstance(quality_gates, dict):
        raise PolicyError("quality_gates must be an object")

    required_frameworks = quality_gates.get("required_frameworks")
    if not isinstance(required_frameworks, list) or not all(
        isinstance(entry, str) and entry for entry in required_frameworks
    ):
        raise PolicyError("quality_gates.required_frameworks must be list[str]")

    required_workloads = quality_gates.get("required_workloads")
    if not isinstance(required_workloads, list) or not all(
        isinstance(entry, str) and entry for entry in required_workloads
    ):
        raise PolicyError("quality_gates.required_workloads must be list[str]")

    required_seed_set = quality_gates.get("required_seed_set")
    if not isinstance(required_seed_set, list) or not all(
        isinstance(seed, int) and seed >= 0 for seed in required_seed_set
    ):
        raise PolicyError("quality_gates.required_seed_set must be list[int>=0]")
    required_seeds = tuple(required_seed_set)

    required_browsers = quality_gates.get("required_browsers")
    if not isinstance(required_browsers, list) or not all(
        isinstance(entry, str) and entry for entry in required_browsers
    ):
        raise PolicyError("quality_gates.required_browsers must be list[str]")

    defaults = policy.get("scenario_defaults")
    if not isinstance(defaults, dict):
        raise PolicyError("scenario_defaults must be an object")
    runner_prefix = defaults.get("runner_command_prefix")
    if not isinstance(runner_prefix, str) or not runner_prefix:
        raise PolicyError("scenario_defaults.runner_command_prefix must be non-empty string")
    required_log_fields = defaults.get("required_log_fields")
    if not isinstance(required_log_fields, list) or not all(
        isinstance(field, str) and field for field in required_log_fields
    ):
        raise PolicyError("scenario_defaults.required_log_fields must be list[str]")

    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be an object")
    summary_path = output.get("summary_path")
    if not isinstance(summary_path, str) or not summary_path:
        raise PolicyError("output.summary_path must be non-empty string")

    return (
        frozenset(required_frameworks),
        frozenset(required_workloads),
        required_seeds,
        frozenset(required_browsers),
        runner_prefix,
        allowed_metrics,
        summary_path,
    )


def parse_scenarios(
    policy: dict[str, Any],
    required_seed_set: tuple[int, ...],
    allowed_metrics: frozenset[str],
    runner_prefix: str,
    only_scenarios: set[str],
) -> list[Scenario]:
    raw_scenarios = policy.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise PolicyError("scenarios must be a non-empty list")

    scenarios: list[Scenario] = []
    seen_ids: set[str] = set()

    for raw in raw_scenarios:
        if not isinstance(raw, dict):
            raise PolicyError("scenario entries must be objects")
        scenario_id = raw.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise PolicyError("scenario id must be non-empty string")
        if scenario_id in seen_ids:
            raise PolicyError(f"duplicate scenario id: {scenario_id}")
        seen_ids.add(scenario_id)

        if only_scenarios and scenario_id not in only_scenarios:
            continue

        journey = raw.get("journey")
        framework = raw.get("framework")
        workload = raw.get("workload")
        profile = raw.get("profile")
        repro_command = raw.get("repro_command")
        if not isinstance(journey, str) or not journey:
            raise PolicyError(f"scenario {scenario_id}: journey must be non-empty string")
        if not isinstance(framework, str) or not framework:
            raise PolicyError(f"scenario {scenario_id}: framework must be non-empty string")
        if not isinstance(workload, str) or not workload:
            raise PolicyError(f"scenario {scenario_id}: workload must be non-empty string")
        if not isinstance(profile, str) or not profile:
            raise PolicyError(f"scenario {scenario_id}: profile must be non-empty string")
        if not isinstance(repro_command, str) or not repro_command:
            raise PolicyError(f"scenario {scenario_id}: repro_command must be non-empty string")
        if not repro_command.startswith(runner_prefix):
            raise PolicyError(
                f"scenario {scenario_id}: repro_command must start with '{runner_prefix}'"
            )

        browsers = raw.get("browsers")
        bundlers = raw.get("bundlers")
        seed_set = raw.get("seed_set")
        metric_ids = raw.get("metric_ids")
        bench_suite = raw.get("bench_suite")

        if not isinstance(browsers, list) or not all(isinstance(item, str) and item for item in browsers):
            raise PolicyError(f"scenario {scenario_id}: browsers must be list[str]")
        if not isinstance(bundlers, list) or not all(isinstance(item, str) and item for item in bundlers):
            raise PolicyError(f"scenario {scenario_id}: bundlers must be list[str]")
        if not isinstance(seed_set, list) or not all(isinstance(seed, int) and seed >= 0 for seed in seed_set):
            raise PolicyError(f"scenario {scenario_id}: seed_set must be list[int>=0]")
        if tuple(seed_set) != required_seed_set:
            raise PolicyError(
                f"scenario {scenario_id}: seed_set must exactly match required_seed_set "
                f"{list(required_seed_set)}"
            )
        if not isinstance(metric_ids, list) or not all(isinstance(metric, str) and metric for metric in metric_ids):
            raise PolicyError(f"scenario {scenario_id}: metric_ids must be list[str]")
        unknown_metrics = sorted(set(metric_ids).difference(allowed_metrics))
        if unknown_metrics:
            raise PolicyError(
                f"scenario {scenario_id}: unknown metric_ids: {', '.join(unknown_metrics)}"
            )
        if not isinstance(bench_suite, list) or not all(isinstance(bench, str) and bench for bench in bench_suite):
            raise PolicyError(f"scenario {scenario_id}: bench_suite must be list[str]")

        scenarios.append(
            Scenario(
                scenario_id=scenario_id,
                journey=journey,
                framework=framework,
                workload=workload,
                profile=profile,
                browsers=tuple(browsers),
                bundlers=tuple(bundlers),
                seed_set=tuple(seed_set),
                metric_ids=tuple(metric_ids),
                bench_suite=tuple(bench_suite),
                repro_command=repro_command,
            )
        )

    if only_scenarios and not scenarios:
        missing = ", ".join(sorted(only_scenarios))
        raise PolicyError(f"--only-scenario selected unknown scenario(s): {missing}")
    if not scenarios:
        raise PolicyError("no scenarios selected")

    return scenarios


def validate_coverage(
    scenarios: list[Scenario],
    required_frameworks: frozenset[str],
    required_workloads: frozenset[str],
    required_browsers: frozenset[str],
) -> None:
    frameworks_present = {scenario.framework for scenario in scenarios}
    workloads_present = {scenario.workload for scenario in scenarios}
    browsers_present = {browser for scenario in scenarios for browser in scenario.browsers}

    missing_frameworks = sorted(required_frameworks.difference(frameworks_present))
    if missing_frameworks:
        raise PolicyError(f"missing required framework coverage: {', '.join(missing_frameworks)}")

    missing_workloads = sorted(required_workloads.difference(workloads_present))
    if missing_workloads:
        raise PolicyError(f"missing required workload coverage: {', '.join(missing_workloads)}")

    missing_browsers = sorted(required_browsers.difference(browsers_present))
    if missing_browsers:
        raise PolicyError(f"missing required browser coverage: {', '.join(missing_browsers)}")


def build_summary(
    policy_path: pathlib.Path,
    scenarios: list[Scenario],
) -> dict[str, Any]:
    framework_counts = Counter(scenario.framework for scenario in scenarios)
    workload_counts = Counter(scenario.workload for scenario in scenarios)
    profile_counts = Counter(scenario.profile for scenario in scenarios)

    scenario_rows = []
    for scenario in sorted(scenarios, key=lambda item: item.scenario_id):
        scenario_rows.append(
            {
                "scenario_id": scenario.scenario_id,
                "journey": scenario.journey,
                "framework": scenario.framework,
                "workload": scenario.workload,
                "profile": scenario.profile,
                "metric_ids": list(scenario.metric_ids),
                "bench_suite": list(scenario.bench_suite),
                "browsers": list(scenario.browsers),
                "bundlers": list(scenario.bundlers),
                "seed_set": list(scenario.seed_set),
                "repro_command": scenario.repro_command,
            }
        )

    return {
        "schema_version": "wasm-benchmark-corpus-summary-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "policy_path": str(policy_path),
        "scenario_count": len(scenarios),
        "coverage": {
            "framework_counts": dict(sorted(framework_counts.items())),
            "workload_counts": dict(sorted(workload_counts.items())),
            "profile_counts": dict(sorted(profile_counts.items())),
        },
        "artifact_contract": {
            "budget_summary": "artifacts/wasm_budget_summary.json",
            "optimization_summary": "artifacts/wasm_optimization_pipeline_summary.json",
            "run_report_glob": "target/perf-results/perf_*/report.json",
        },
        "scenarios": scenario_rows,
    }


def write_summary(path: pathlib.Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> None:
    base_policy: dict[str, Any] = {
        "schema_version": "wasm-benchmark-corpus-v1",
        "budget_contract": {"source_document": "WASM_SIZE_PERF_BUDGETS.md", "metric_ids": ["M-PERF-01A"]},
        "quality_gates": {
            "required_frameworks": ["vanilla-js"],
            "required_workloads": ["cold-start"],
            "required_seed_set": [11, 29],
            "required_browsers": ["desktop-chromium"],
        },
        "scenario_defaults": {
            "runner_command_prefix": "rch exec -- ./scripts/run_perf_e2e.sh",
            "artifact_schema_version": "wasm-benchmark-corpus-summary-v1",
            "required_log_fields": ["scenario_id"],
        },
        "scenarios": [
            {
                "id": "WB-TEST-01",
                "journey": "test",
                "framework": "vanilla-js",
                "workload": "cold-start",
                "profile": "core-min",
                "browsers": ["desktop-chromium"],
                "bundlers": ["vite"],
                "seed_set": [11, 29],
                "metric_ids": ["M-PERF-01A"],
                "bench_suite": ["phase0_baseline"],
                "repro_command": "rch exec -- ./scripts/run_perf_e2e.sh --bench phase0_baseline --seed 11",
            }
        ],
        "output": {"summary_path": "artifacts/test_corpus_summary.json"},
    }

    (
        required_frameworks,
        required_workloads,
        required_seed_set,
        required_browsers,
        runner_prefix,
        allowed_metrics,
        _summary_path,
    ) = parse_policy_contract(base_policy)

    scenarios = parse_scenarios(base_policy, required_seed_set, allowed_metrics, runner_prefix, set())
    validate_coverage(scenarios, required_frameworks, required_workloads, required_browsers)
    summary = build_summary(pathlib.Path("policy.json"), scenarios)
    assert summary["scenario_count"] == 1

    bad_policy = copy.deepcopy(base_policy)
    bad_policy["scenarios"][0]["seed_set"] = [11]
    try:
        parse_scenarios(bad_policy, required_seed_set, allowed_metrics, runner_prefix, set())
    except PolicyError:
        pass
    else:
        raise AssertionError("expected strict seed-set validation to fail")

    bad_policy2 = copy.deepcopy(base_policy)
    bad_policy2["scenarios"][0]["framework"] = "react"
    scenarios2 = parse_scenarios(bad_policy2, required_seed_set, allowed_metrics, runner_prefix, set())
    try:
        validate_coverage(scenarios2, required_frameworks, required_workloads, required_browsers)
    except PolicyError:
        pass
    else:
        raise AssertionError("expected required-framework coverage failure")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        print("wasm benchmark corpus self-test passed")
        return 0

    policy_path = pathlib.Path(args.policy)
    policy = load_json(policy_path)
    (
        required_frameworks,
        required_workloads,
        required_seed_set,
        required_browsers,
        runner_prefix,
        allowed_metrics,
        default_summary_path,
    ) = parse_policy_contract(policy)
    scenarios = parse_scenarios(
        policy,
        required_seed_set,
        allowed_metrics,
        runner_prefix,
        set(args.only_scenario),
    )
    validate_coverage(scenarios, required_frameworks, required_workloads, required_browsers)
    summary = build_summary(policy_path, scenarios)
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
