#!/usr/bin/env python3
"""Validate deterministic TypeScript type-model policy for Browser Edition."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """Raised when policy loading or schema validation fails."""


@dataclass(frozen=True)
class Finding:
    category: str
    message: str
    severity: str
    scenario_id: str | None = None
    package_entrypoint: str = ""
    adapter_path: str = ""
    runtime_profile: str = ""
    diagnostic_category: str = "type_model"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_typescript_type_model_policy.json",
        help="Path to type-model policy JSON.",
    )
    parser.add_argument(
        "--summary-output",
        default="",
        help="Override summary output path.",
    )
    parser.add_argument(
        "--log-output",
        default="",
        help="Override NDJSON output path.",
    )
    parser.add_argument(
        "--only-scenario",
        action="append",
        default=[],
        help="Restrict validation to one or more scenario IDs.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run self-tests and exit.",
    )
    return parser.parse_args()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_policy(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in policy file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    if raw.get("schema_version") != "wasm-typescript-type-model-policy-v1":
        raise PolicyError("unsupported or missing schema_version")
    return raw


def ensure_str_list(raw: Any, field: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise PolicyError(f"{field} must be a non-empty list[str]")
    return [item.strip() for item in raw]


def to_row(finding: Finding) -> dict[str, Any]:
    return {
        "category": finding.category,
        "message": finding.message,
        "severity": finding.severity,
        "scenario_id": finding.scenario_id,
        "package_entrypoint": finding.package_entrypoint,
        "adapter_path": finding.adapter_path,
        "runtime_profile": finding.runtime_profile,
        "diagnostic_category": finding.diagnostic_category,
    }


def validate_type_surface(policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    type_surface = policy.get("type_surface")
    if not isinstance(type_surface, dict):
        raise PolicyError("type_surface must be an object")

    variants = ensure_str_list(type_surface.get("outcome_variants"), "type_surface.outcome_variants")
    expected_variants = {"ok", "err", "cancelled", "panicked"}
    if set(variants) != expected_variants:
        findings.append(
            Finding(
                category="outcome_variants",
                message=f"outcome variants must be exactly {sorted(expected_variants)}",
                severity="error",
            )
        )

    phase_order = ensure_str_list(
        type_surface.get("cancellation_phase_order"), "type_surface.cancellation_phase_order"
    )
    expected_phase_order = ["requested", "cancelling", "finalizing", "completed"]
    if phase_order != expected_phase_order:
        findings.append(
            Finding(
                category="cancellation_phase_order",
                message=f"cancellation phase order must be {expected_phase_order}",
                severity="error",
            )
        )

    required_types = ensure_str_list(type_surface.get("required_types"), "type_surface.required_types")
    for required_type in (
        "Outcome<T, E>",
        "Budget",
        "CancellationToken",
        "CancellationPhase",
        "RegionHandle",
        "TaskHandle",
    ):
        if required_type not in required_types:
            findings.append(
                Finding(
                    category="required_types",
                    message=f"missing required type {required_type}",
                    severity="error",
                )
            )

    return findings


def validate_budget(policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    budget = policy.get("budget_contract")
    if not isinstance(budget, dict):
        raise PolicyError("budget_contract must be an object")
    required_fields = ensure_str_list(budget.get("required_fields"), "budget_contract.required_fields")
    for field in ("pollQuota", "deadlineMs", "priority", "cleanupQuota"):
        if field not in required_fields:
            findings.append(Finding(category="budget_fields", message=f"missing budget field {field}", severity="error"))

    bounds = budget.get("bounds")
    if not isinstance(bounds, dict):
        raise PolicyError("budget_contract.bounds must be an object")
    for field in ("pollQuota", "deadlineMs", "priority", "cleanupQuota"):
        raw = bounds.get(field)
        if not isinstance(raw, dict):
            raise PolicyError(f"budget_contract.bounds.{field} must be an object")
        min_value = raw.get("min")
        max_value = raw.get("max")
        if not isinstance(min_value, int) or not isinstance(max_value, int):
            raise PolicyError(f"budget_contract.bounds.{field}.min/max must be integers")
        if min_value < 0 or max_value < min_value:
            findings.append(
                Finding(
                    category="budget_bounds",
                    message=f"invalid numeric bounds for {field}",
                    severity="error",
                )
            )
    return findings


def validate_ownership(policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    ownership = policy.get("ownership_contract")
    if not isinstance(ownership, dict):
        raise PolicyError("ownership_contract must be an object")
    handle_kinds = set(
        ensure_str_list(ownership.get("required_handle_kinds"), "ownership_contract.required_handle_kinds")
    )
    invariants = set(
        ensure_str_list(ownership.get("required_invariants"), "ownership_contract.required_invariants")
    )
    for kind in ("runtime", "scope", "task", "channel", "obligation"):
        if kind not in handle_kinds:
            findings.append(
                Finding(
                    category="ownership_handles",
                    message=f"missing handle kind {kind}",
                    severity="error",
                )
            )
    for invariant in (
        "single_region_owner",
        "no_orphan_tasks",
        "region_close_implies_quiescence",
        "no_obligation_leaks",
    ):
        if invariant not in invariants:
            findings.append(
                Finding(
                    category="ownership_invariants",
                    message=f"missing ownership invariant {invariant}",
                    severity="error",
                )
            )
    return findings


def validate_resolution_matrix(policy: dict[str, Any], only_scenarios: set[str]) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    matrix = policy.get("resolution_matrix")
    if not isinstance(matrix, dict):
        raise PolicyError("resolution_matrix must be an object")

    required_frameworks = set(
        ensure_str_list(matrix.get("required_frameworks"), "resolution_matrix.required_frameworks")
    )
    scenarios_raw = matrix.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise PolicyError("resolution_matrix.scenarios must be a non-empty list")

    scenarios: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    frameworks_seen: set[str] = set()
    for raw in scenarios_raw:
        if not isinstance(raw, dict):
            raise PolicyError("resolution_matrix.scenarios entries must be objects")
        scenario_id = raw.get("id")
        framework = raw.get("framework")
        entrypoint = raw.get("package_entrypoint")
        adapter_path = raw.get("adapter_path")
        runtime_profile = raw.get("runtime_profile")
        repro_command = raw.get("repro_command")
        diagnostic_category = raw.get("diagnostic_category")
        for key, value in (
            ("id", scenario_id),
            ("framework", framework),
            ("package_entrypoint", entrypoint),
            ("adapter_path", adapter_path),
            ("runtime_profile", runtime_profile),
            ("repro_command", repro_command),
            ("diagnostic_category", diagnostic_category),
        ):
            if not isinstance(value, str) or not value.strip():
                raise PolicyError(f"resolution_matrix.scenarios[*].{key} must be non-empty string")

        if scenario_id in seen_ids:
            raise PolicyError(f"duplicate scenario id: {scenario_id}")
        seen_ids.add(scenario_id)

        if only_scenarios and scenario_id not in only_scenarios:
            continue

        frameworks_seen.add(framework)
        if "typecheck" not in repro_command and "test" not in repro_command:
            findings.append(
                Finding(
                    category="resolution_repro_command",
                    message="repro_command must include typecheck or test action",
                    severity="error",
                    scenario_id=scenario_id,
                    package_entrypoint=entrypoint,
                    adapter_path=adapter_path,
                    runtime_profile=runtime_profile,
                    diagnostic_category=diagnostic_category,
                )
            )
        scenarios.append(raw)

    if only_scenarios:
        missing = sorted(only_scenarios.difference(seen_ids))
        if missing:
            raise PolicyError(f"--only-scenario selected unknown scenario(s): {', '.join(missing)}")
    else:
        missing_frameworks = sorted(required_frameworks.difference(frameworks_seen))
        for framework in missing_frameworks:
            findings.append(
                Finding(
                    category="resolution_coverage",
                    message=f"missing required framework scenario {framework}",
                    severity="error",
                )
            )

    return findings, scenarios


def validate_logging(policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    logging_cfg = policy.get("logging")
    if not isinstance(logging_cfg, dict):
        raise PolicyError("logging must be an object")
    required_fields = set(ensure_str_list(logging_cfg.get("required_fields"), "logging.required_fields"))
    for field in (
        "scenario_id",
        "step_id",
        "package_entrypoint",
        "adapter_path",
        "runtime_profile",
        "diagnostic_category",
        "repro_command",
        "outcome",
    ):
        if field not in required_fields:
            findings.append(
                Finding(
                    category="logging_fields",
                    message=f"missing logging field {field}",
                    severity="error",
                )
            )
    return findings


def write_ndjson(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_policy(policy: dict[str, Any], only_scenarios: set[str], policy_path: str, summary_path: pathlib.Path, log_path: pathlib.Path) -> bool:
    findings = []
    findings.extend(validate_type_surface(policy))
    findings.extend(validate_budget(policy))
    findings.extend(validate_ownership(policy))
    matrix_findings, scenarios = validate_resolution_matrix(policy, only_scenarios)
    findings.extend(matrix_findings)
    findings.extend(validate_logging(policy))

    findings = sorted(findings, key=lambda finding: (finding.severity, finding.category, finding.scenario_id or "", finding.message))

    rows = [to_row(finding) for finding in findings]
    rows.extend(
        {
            "category": "scenario_validated",
            "message": "type-model scenario validated",
            "severity": "info",
            "scenario_id": scenario["id"],
            "package_entrypoint": scenario["package_entrypoint"],
            "adapter_path": scenario["adapter_path"],
            "runtime_profile": scenario["runtime_profile"],
            "diagnostic_category": scenario["diagnostic_category"],
        }
        for scenario in sorted(scenarios, key=lambda row: str(row["id"]))
    )

    error_count = sum(1 for finding in findings if finding.severity == "error")
    summary = {
        "schema_version": "wasm-typescript-type-model-report-v1",
        "generated_at_utc": now_utc(),
        "policy_path": policy_path,
        "selected_scenario_count": len(scenarios),
        "finding_count": len(findings),
        "error_count": error_count,
        "passed": error_count == 0,
        "only_scenarios": sorted(only_scenarios),
        "findings": [to_row(finding) for finding in findings],
    }
    write_json(summary_path, summary)
    write_ndjson(log_path, rows)
    print(
        "WASM TypeScript type-model policy: "
        f"{'PASS' if error_count == 0 else 'FAIL'} "
        f"(errors={error_count}, scenarios={len(scenarios)})"
    )
    print(f"summary: {summary_path}")
    print(f"log: {log_path}")
    return error_count == 0


def run_self_tests() -> int:
    base = {
        "schema_version": "wasm-typescript-type-model-policy-v1",
        "type_surface": {
            "outcome_variants": ["ok", "err", "cancelled", "panicked"],
            "cancellation_phase_order": ["requested", "cancelling", "finalizing", "completed"],
            "required_types": [
                "Outcome<T, E>",
                "Budget",
                "CancellationToken",
                "CancellationPhase",
                "RegionHandle",
                "TaskHandle",
            ],
        },
        "budget_contract": {
            "required_fields": ["pollQuota", "deadlineMs", "priority", "cleanupQuota"],
            "bounds": {
                "pollQuota": {"min": 1, "max": 100},
                "deadlineMs": {"min": 0, "max": 100},
                "priority": {"min": 0, "max": 255},
                "cleanupQuota": {"min": 0, "max": 100},
            },
        },
        "ownership_contract": {
            "required_handle_kinds": ["runtime", "scope", "task", "channel", "obligation"],
            "required_invariants": [
                "single_region_owner",
                "no_orphan_tasks",
                "region_close_implies_quiescence",
                "no_obligation_leaks",
            ],
        },
        "resolution_matrix": {
            "required_frameworks": ["vanilla-ts", "react", "next"],
            "scenarios": [
                {
                    "id": "A",
                    "framework": "vanilla-ts",
                    "package_entrypoint": "@asupersync/browser",
                    "adapter_path": "none",
                    "runtime_profile": "FP-BR-DEV",
                    "repro_command": "pnpm typecheck",
                    "diagnostic_category": "type_model",
                },
                {
                    "id": "B",
                    "framework": "react",
                    "package_entrypoint": "@asupersync/react",
                    "adapter_path": "react/provider",
                    "runtime_profile": "FP-BR-DEV",
                    "repro_command": "pnpm typecheck",
                    "diagnostic_category": "type_model",
                },
                {
                    "id": "C",
                    "framework": "next",
                    "package_entrypoint": "@asupersync/next",
                    "adapter_path": "next/app-router",
                    "runtime_profile": "FP-BR-DEV",
                    "repro_command": "pnpm typecheck",
                    "diagnostic_category": "type_model",
                },
            ],
        },
        "logging": {
            "required_fields": [
                "scenario_id",
                "step_id",
                "package_entrypoint",
                "adapter_path",
                "runtime_profile",
                "diagnostic_category",
                "repro_command",
                "outcome",
            ]
        },
        "output": {"summary_path": "artifacts/x.json", "log_path": "artifacts/y.ndjson"},
    }

    assert not validate_type_surface(base)
    assert not validate_budget(base)
    assert not validate_ownership(base)
    matrix_findings, _ = validate_resolution_matrix(base, set())
    assert not matrix_findings
    assert not validate_logging(base)

    bad = json.loads(json.dumps(base))
    bad["type_surface"]["outcome_variants"] = ["ok", "err"]
    assert any(f.category == "outcome_variants" for f in validate_type_surface(bad))

    bad2 = json.loads(json.dumps(base))
    bad2["resolution_matrix"]["scenarios"] = [bad2["resolution_matrix"]["scenarios"][0]]
    bad2_findings, _ = validate_resolution_matrix(bad2, set())
    assert any(f.category == "resolution_coverage" for f in bad2_findings)

    print("WASM TypeScript type-model policy self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_tests()

    policy_path = pathlib.Path(args.policy)
    policy = load_policy(policy_path)
    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be an object")
    summary_default = output.get("summary_path")
    log_default = output.get("log_path")
    if not isinstance(summary_default, str) or not summary_default:
        raise PolicyError("output.summary_path must be non-empty string")
    if not isinstance(log_default, str) or not log_default:
        raise PolicyError("output.log_path must be non-empty string")

    summary_path = pathlib.Path(args.summary_output or summary_default)
    log_path = pathlib.Path(args.log_output or log_default)
    passed = run_policy(
        policy=policy,
        only_scenarios=set(args.only_scenario),
        policy_path=str(policy_path),
        summary_path=summary_path,
        log_path=log_path,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
