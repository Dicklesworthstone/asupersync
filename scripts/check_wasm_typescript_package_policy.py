#!/usr/bin/env python3
"""Validate deterministic TypeScript package topology policy for Browser Edition."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
import tempfile
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """Raised when policy loading or schema validation fails."""


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    message: str
    package: str | None
    scenario_id: str | None
    package_entrypoint: str
    adapter_path: str
    runtime_profile: str
    diagnostic_category: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_typescript_package_policy.json",
        help="Path to TypeScript package policy JSON.",
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
        help="Run policy validator self-tests and exit.",
    )
    return parser.parse_args()


def load_policy(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in policy file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    if raw.get("schema_version") != "wasm-typescript-package-policy-v1":
        raise PolicyError("unsupported or missing schema_version")
    return raw


def ensure_list_of_nonempty_strings(raw: Any, field: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise PolicyError(f"{field} must be a non-empty list[str]")
    return [item.strip() for item in raw]


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def finding_to_row(finding: Finding) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "category": finding.category,
        "message": finding.message,
        "package": finding.package,
        "scenario_id": finding.scenario_id,
        "package_entrypoint": finding.package_entrypoint,
        "adapter_path": finding.adapter_path,
        "runtime_profile": finding.runtime_profile,
        "diagnostic_category": finding.diagnostic_category,
    }


def append_error(
    findings: list[Finding],
    category: str,
    message: str,
    package: str | None = None,
    scenario_id: str | None = None,
    package_entrypoint: str = "",
    adapter_path: str = "",
    runtime_profile: str = "",
    diagnostic_category: str = "policy_validation",
) -> None:
    findings.append(
        Finding(
            severity="error",
            category=category,
            message=message,
            package=package,
            scenario_id=scenario_id,
            package_entrypoint=package_entrypoint,
            adapter_path=adapter_path,
            runtime_profile=runtime_profile,
            diagnostic_category=diagnostic_category,
        )
    )


def validate_topology(policy: dict[str, Any]) -> tuple[list[Finding], dict[str, dict[str, Any]]]:
    findings: list[Finding] = []
    required_packages = set(ensure_list_of_nonempty_strings(policy.get("required_packages"), "required_packages"))

    topology = policy.get("topology")
    if not isinstance(topology, dict):
        raise PolicyError("topology must be an object")

    packages_raw = topology.get("packages")
    if not isinstance(packages_raw, list) or not packages_raw:
        raise PolicyError("topology.packages must be a non-empty list")

    forbidden_prefixes = ensure_list_of_nonempty_strings(
        topology.get("forbidden_public_subpath_prefixes"),
        "topology.forbidden_public_subpath_prefixes",
    )

    package_map: dict[str, dict[str, Any]] = {}
    for raw in packages_raw:
        if not isinstance(raw, dict):
            raise PolicyError("topology.packages entries must be objects")
        name = raw.get("name")
        layer = raw.get("layer")
        stability = raw.get("stability")
        exports = raw.get("exports")
        if not isinstance(name, str) or not name:
            raise PolicyError("topology.packages[*].name must be non-empty string")
        if not isinstance(layer, str) or layer not in {"core", "sdk", "adapter"}:
            raise PolicyError(f"package {name}: invalid layer")
        if not isinstance(stability, str) or stability not in {"public", "experimental", "internal"}:
            raise PolicyError(f"package {name}: invalid stability")
        if not isinstance(exports, list) or not exports:
            raise PolicyError(f"package {name}: exports must be non-empty list")
        if name in package_map:
            raise PolicyError(f"duplicate package entry: {name}")

        for export in exports:
            if not isinstance(export, dict):
                raise PolicyError(f"package {name}: export entries must be objects")
            subpath = export.get("subpath")
            module_modes = export.get("module_modes")
            tree_shake_safe = export.get("tree_shake_safe")
            if not isinstance(subpath, str) or not subpath:
                raise PolicyError(f"package {name}: export.subpath must be non-empty string")
            if not isinstance(module_modes, list) or not all(
                isinstance(mode, str) and mode in {"esm", "cjs"} for mode in module_modes
            ):
                raise PolicyError(f"package {name}: export.module_modes must be list[esm|cjs]")
            if not isinstance(tree_shake_safe, bool):
                raise PolicyError(f"package {name}: export.tree_shake_safe must be bool")
            if stability == "public" and not tree_shake_safe:
                append_error(
                    findings,
                    category="topology_tree_shake",
                    message="public export is not marked tree_shake_safe",
                    package=name,
                    package_entrypoint=f"{name}{subpath if subpath != '.' else ''}",
                    diagnostic_category="tree_shake_regression",
                )
            for prefix in forbidden_prefixes:
                if subpath.startswith(prefix):
                    append_error(
                        findings,
                        category="topology_subpath",
                        message=f"public export uses forbidden subpath prefix {prefix}",
                        package=name,
                        package_entrypoint=f"{name}{subpath if subpath != '.' else ''}",
                        diagnostic_category="surface_expansion",
                    )

        package_map[name] = raw

    missing = sorted(required_packages.difference(package_map.keys()))
    for name in missing:
        append_error(
            findings,
            category="topology_required_package",
            message="required package missing from topology.packages",
            package=name,
            diagnostic_category="package_topology_gap",
        )

    allowed_edges_raw = topology.get("allowed_layer_edges")
    if not isinstance(allowed_edges_raw, list):
        raise PolicyError("topology.allowed_layer_edges must be a list")
    allowed_edges: set[tuple[str, str]] = set()
    for edge in allowed_edges_raw:
        if not isinstance(edge, dict):
            raise PolicyError("topology.allowed_layer_edges entries must be objects")
        from_pkg = edge.get("from")
        to_pkg = edge.get("to")
        if not isinstance(from_pkg, str) or not isinstance(to_pkg, str):
            raise PolicyError("topology.allowed_layer_edges requires from/to strings")
        allowed_edges.add((from_pkg, to_pkg))

    required_edges = {
        ("@asupersync/browser-core", "@asupersync/browser"),
        ("@asupersync/browser", "@asupersync/react"),
        ("@asupersync/browser", "@asupersync/next"),
    }
    missing_edges = sorted(required_edges.difference(allowed_edges))
    for from_pkg, to_pkg in missing_edges:
        append_error(
            findings,
            category="topology_edge",
            message="required layer edge missing",
            package=from_pkg,
            package_entrypoint=to_pkg,
            diagnostic_category="layer_boundary",
        )

    return findings, package_map


def validate_type_surface(
    policy: dict[str, Any],
    package_map: dict[str, dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    type_surface = policy.get("type_surface")
    if not isinstance(type_surface, dict):
        raise PolicyError("type_surface must be an object")

    required_symbols = ensure_list_of_nonempty_strings(
        type_surface.get("required_symbols"), "type_surface.required_symbols"
    )
    symbol_owners = type_surface.get("symbol_owners")
    if not isinstance(symbol_owners, dict):
        raise PolicyError("type_surface.symbol_owners must be an object")

    for symbol in required_symbols:
        owner = symbol_owners.get(symbol)
        if not isinstance(owner, str) or not owner:
            append_error(
                findings,
                category="type_surface_owner",
                message=f"required symbol {symbol} missing owner mapping",
                diagnostic_category="type_surface_contract",
            )
            continue
        if owner not in package_map:
            append_error(
                findings,
                category="type_surface_owner",
                message=f"symbol {symbol} owner package not found in topology",
                package=owner,
                diagnostic_category="type_surface_contract",
            )

    for symbol in symbol_owners:
        if symbol not in required_symbols:
            append_error(
                findings,
                category="type_surface_owner",
                message=f"symbol owner map includes non-required symbol {symbol}",
                package=str(symbol_owners[symbol]),
                diagnostic_category="type_surface_contract",
            )

    return findings


def validate_package_manifests(
    policy: dict[str, Any],
    package_map: dict[str, dict[str, Any]],
    workspace_root: pathlib.Path,
) -> list[Finding]:
    findings: list[Finding] = []
    topology = policy.get("topology")
    if not isinstance(topology, dict):
        raise PolicyError("topology must be an object")

    forbidden_prefixes = ensure_list_of_nonempty_strings(
        topology.get("forbidden_public_subpath_prefixes"),
        "topology.forbidden_public_subpath_prefixes",
    )

    for package_name, package_cfg in package_map.items():
        if "/" not in package_name:
            append_error(
                findings,
                category="manifest_package_name",
                message="package name must be scoped (e.g., @asupersync/browser)",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="manifest_validation",
            )
            continue

        package_dir_name = package_name.split("/", 1)[1]
        manifest_path = workspace_root / "packages" / package_dir_name / "package.json"
        if not manifest_path.exists():
            append_error(
                findings,
                category="manifest_missing",
                message=f"package manifest missing: {manifest_path}",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="manifest_validation",
            )
            continue

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            append_error(
                findings,
                category="manifest_invalid_json",
                message=f"invalid JSON in {manifest_path}: {exc}",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="manifest_validation",
            )
            continue

        if not isinstance(manifest, dict):
            append_error(
                findings,
                category="manifest_shape",
                message="manifest root must be an object",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="manifest_validation",
            )
            continue

        policy_exports = package_cfg.get("exports")
        if not isinstance(policy_exports, list):
            raise PolicyError(f"package {package_name}: topology exports must be list")

        exports_map = manifest.get("exports")
        if not isinstance(exports_map, dict):
            append_error(
                findings,
                category="manifest_exports_missing",
                message="manifest.exports must be an object",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="manifest_validation",
            )
            continue

        for manifest_subpath in exports_map:
            if not isinstance(manifest_subpath, str):
                append_error(
                    findings,
                    category="manifest_exports_invalid_subpath",
                    message="manifest export subpath key must be string",
                    package=package_name,
                    package_entrypoint=package_name,
                    diagnostic_category="manifest_validation",
                )
                continue
            for prefix in forbidden_prefixes:
                if manifest_subpath.startswith(prefix):
                    append_error(
                        findings,
                        category="manifest_forbidden_subpath",
                        message=f"manifest export uses forbidden subpath prefix {prefix}",
                        package=package_name,
                        package_entrypoint=f"{package_name}{manifest_subpath if manifest_subpath != '.' else ''}",
                        diagnostic_category="surface_expansion",
                    )

        requires_tree_shake = False
        for export_cfg in policy_exports:
            if not isinstance(export_cfg, dict):
                raise PolicyError(f"package {package_name}: topology export entry must be object")

            subpath = export_cfg.get("subpath")
            module_modes = export_cfg.get("module_modes")
            tree_shake_safe = export_cfg.get("tree_shake_safe")

            if not isinstance(subpath, str) or not subpath:
                raise PolicyError(f"package {package_name}: topology export subpath must be non-empty string")
            if not isinstance(module_modes, list) or not all(isinstance(mode, str) for mode in module_modes):
                raise PolicyError(f"package {package_name}: topology export module_modes must be list[str]")
            if not isinstance(tree_shake_safe, bool):
                raise PolicyError(f"package {package_name}: topology export tree_shake_safe must be bool")

            if tree_shake_safe:
                requires_tree_shake = True

            if subpath not in exports_map:
                append_error(
                    findings,
                    category="manifest_exports_missing_subpath",
                    message=f"manifest.exports missing required policy subpath {subpath}",
                    package=package_name,
                    package_entrypoint=f"{package_name}{subpath if subpath != '.' else ''}",
                    diagnostic_category="manifest_validation",
                )
                continue

            manifest_entry = exports_map[subpath]
            if isinstance(manifest_entry, str):
                continue

            if not isinstance(manifest_entry, dict):
                append_error(
                    findings,
                    category="manifest_exports_entry_type",
                    message=f"manifest export for {subpath} must be string or object",
                    package=package_name,
                    package_entrypoint=f"{package_name}{subpath if subpath != '.' else ''}",
                    diagnostic_category="manifest_validation",
                )
                continue

            if "esm" in module_modes and not any(key in manifest_entry for key in ("import", "default")):
                append_error(
                    findings,
                    category="manifest_exports_esm",
                    message=f"manifest export for {subpath} must define import/default for esm mode",
                    package=package_name,
                    package_entrypoint=f"{package_name}{subpath if subpath != '.' else ''}",
                    diagnostic_category="module_resolution",
                )
            if "cjs" in module_modes and not any(key in manifest_entry for key in ("require", "default")):
                append_error(
                    findings,
                    category="manifest_exports_cjs",
                    message=f"manifest export for {subpath} must define require/default for cjs mode",
                    package=package_name,
                    package_entrypoint=f"{package_name}{subpath if subpath != '.' else ''}",
                    diagnostic_category="module_resolution",
                )
            if subpath == "." and "types" not in manifest_entry:
                append_error(
                    findings,
                    category="manifest_exports_types",
                    message="manifest root export must define types field",
                    package=package_name,
                    package_entrypoint=package_name,
                    diagnostic_category="type_surface_contract",
                )

        if requires_tree_shake and manifest.get("sideEffects") is not False:
            append_error(
                findings,
                category="manifest_side_effects",
                message="tree-shake-safe package must set sideEffects=false",
                package=package_name,
                package_entrypoint=package_name,
                diagnostic_category="tree_shake_regression",
            )

    return findings


def validate_resolution_matrix(
    policy: dict[str, Any],
    package_map: dict[str, dict[str, Any]],
    only_scenarios: set[str],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    matrix = policy.get("resolution_matrix")
    if not isinstance(matrix, dict):
        raise PolicyError("resolution_matrix must be an object")

    required_frameworks = set(
        ensure_list_of_nonempty_strings(
            matrix.get("required_frameworks"), "resolution_matrix.required_frameworks"
        )
    )
    required_modes = set(
        ensure_list_of_nonempty_strings(
            matrix.get("required_module_modes"), "resolution_matrix.required_module_modes"
        )
    )
    required_bundlers = set(
        ensure_list_of_nonempty_strings(
            matrix.get("required_bundlers"), "resolution_matrix.required_bundlers"
        )
    )
    scenarios_raw = matrix.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise PolicyError("resolution_matrix.scenarios must be a non-empty list")

    scenarios: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    frameworks_seen: set[str] = set()
    modes_seen: set[str] = set()
    bundlers_seen: set[str] = set()

    for raw in scenarios_raw:
        if not isinstance(raw, dict):
            raise PolicyError("resolution_matrix.scenarios entries must be objects")
        scenario_id = raw.get("id")
        framework = raw.get("framework")
        package = raw.get("package")
        entrypoint = raw.get("entrypoint")
        module_mode = raw.get("module_mode")
        bundler = raw.get("bundler")
        adapter_path = raw.get("adapter_path")
        runtime_profile = raw.get("runtime_profile")
        install_command = raw.get("install_command")
        run_command = raw.get("run_command")

        for key, value in (
            ("id", scenario_id),
            ("framework", framework),
            ("package", package),
            ("entrypoint", entrypoint),
            ("module_mode", module_mode),
            ("bundler", bundler),
            ("adapter_path", adapter_path),
            ("runtime_profile", runtime_profile),
            ("install_command", install_command),
            ("run_command", run_command),
        ):
            if not isinstance(value, str) or not value.strip():
                raise PolicyError(f"resolution_matrix.scenarios[*].{key} must be non-empty string")

        if scenario_id in seen_ids:
            raise PolicyError(f"duplicate scenario id: {scenario_id}")
        seen_ids.add(scenario_id)

        if only_scenarios and scenario_id not in only_scenarios:
            continue

        frameworks_seen.add(framework)
        modes_seen.add(module_mode)
        bundlers_seen.add(bundler)

        if package not in package_map:
            append_error(
                findings,
                category="resolution_matrix_package",
                message="scenario references unknown package",
                package=package,
                scenario_id=scenario_id,
                package_entrypoint=entrypoint,
                adapter_path=adapter_path,
                runtime_profile=runtime_profile,
                diagnostic_category="package_resolution",
            )
        if not entrypoint.startswith(package):
            append_error(
                findings,
                category="resolution_matrix_entrypoint",
                message="entrypoint must be rooted at scenario package",
                package=package,
                scenario_id=scenario_id,
                package_entrypoint=entrypoint,
                adapter_path=adapter_path,
                runtime_profile=runtime_profile,
                diagnostic_category="package_resolution",
            )
        if module_mode not in {"esm", "cjs"}:
            append_error(
                findings,
                category="resolution_matrix_mode",
                message="module_mode must be esm|cjs",
                package=package,
                scenario_id=scenario_id,
                package_entrypoint=entrypoint,
                adapter_path=adapter_path,
                runtime_profile=runtime_profile,
                diagnostic_category="module_resolution",
            )
        if "install" not in install_command:
            append_error(
                findings,
                category="resolution_matrix_command",
                message="install_command must include install action",
                package=package,
                scenario_id=scenario_id,
                package_entrypoint=entrypoint,
                adapter_path=adapter_path,
                runtime_profile=runtime_profile,
                diagnostic_category="onboarding_command",
            )
        if "build" not in run_command and "test" not in run_command:
            append_error(
                findings,
                category="resolution_matrix_command",
                message="run_command must include build or test action",
                package=package,
                scenario_id=scenario_id,
                package_entrypoint=entrypoint,
                adapter_path=adapter_path,
                runtime_profile=runtime_profile,
                diagnostic_category="onboarding_command",
            )

        scenarios.append(raw)

    if only_scenarios:
        missing = sorted(only_scenarios.difference(seen_ids))
        if missing:
            missing_csv = ", ".join(missing)
            raise PolicyError(f"--only-scenario selected unknown scenario(s): {missing_csv}")

    if not only_scenarios:
        missing_frameworks = sorted(required_frameworks.difference(frameworks_seen))
        for framework in missing_frameworks:
            append_error(
                findings,
                category="resolution_matrix_coverage",
                message=f"required framework missing from scenarios: {framework}",
                diagnostic_category="matrix_coverage",
            )

        missing_modes = sorted(required_modes.difference(modes_seen))
        for mode in missing_modes:
            append_error(
                findings,
                category="resolution_matrix_coverage",
                message=f"required module mode missing from scenarios: {mode}",
                diagnostic_category="matrix_coverage",
            )

        missing_bundlers = sorted(required_bundlers.difference(bundlers_seen))
        for bundler in missing_bundlers:
            append_error(
                findings,
                category="resolution_matrix_coverage",
                message=f"required bundler missing from scenarios: {bundler}",
                diagnostic_category="matrix_coverage",
            )

    return findings, scenarios


def validate_logging_contract(policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    logging_cfg = policy.get("logging")
    if not isinstance(logging_cfg, dict):
        raise PolicyError("logging must be an object")
    required_fields = set(
        ensure_list_of_nonempty_strings(logging_cfg.get("required_fields"), "logging.required_fields")
    )
    expected_fields = {
        "scenario_id",
        "step_id",
        "package_entrypoint",
        "adapter_path",
        "runtime_profile",
        "diagnostic_category",
        "outcome",
        "artifact_log_path",
        "repro_command",
    }
    missing = sorted(expected_fields.difference(required_fields))
    for field in missing:
        append_error(
            findings,
            category="logging_contract",
            message=f"logging.required_fields missing required field {field}",
            diagnostic_category="logging_schema",
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


def run_policy(
    policy: dict[str, Any],
    only_scenarios: set[str],
    policy_path: str,
    workspace_root: pathlib.Path,
    summary_path: pathlib.Path,
    log_path: pathlib.Path,
) -> bool:
    topology_findings, package_map = validate_topology(policy)
    type_findings = validate_type_surface(policy, package_map)
    manifest_findings = validate_package_manifests(policy, package_map, workspace_root)
    matrix_findings, selected_scenarios = validate_resolution_matrix(policy, package_map, only_scenarios)
    logging_findings = validate_logging_contract(policy)

    findings = topology_findings + type_findings + manifest_findings + matrix_findings + logging_findings
    findings = sorted(
        findings,
        key=lambda finding: (
            finding.severity,
            finding.category,
            finding.package or "",
            finding.scenario_id or "",
            finding.message,
        ),
    )

    ndjson_rows = [finding_to_row(finding) for finding in findings]
    ndjson_rows.extend(
        {
            "severity": "info",
            "category": "scenario_validated",
            "message": "resolution scenario validated",
            "package": scenario["package"],
            "scenario_id": scenario["id"],
            "package_entrypoint": scenario["entrypoint"],
            "adapter_path": scenario["adapter_path"],
            "runtime_profile": scenario["runtime_profile"],
            "diagnostic_category": "onboarding_validation",
        }
        for scenario in sorted(selected_scenarios, key=lambda row: str(row["id"]))
    )

    failed_count = sum(1 for finding in findings if finding.severity == "error")
    passed = failed_count == 0
    summary = {
        "schema_version": "wasm-typescript-package-policy-report-v1",
        "generated_at_utc": now_utc(),
        "policy_path": policy_path,
        "selected_scenario_count": len(selected_scenarios),
        "finding_count": len(findings),
        "error_count": failed_count,
        "passed": passed,
        "only_scenarios": sorted(only_scenarios),
        "findings": [finding_to_row(finding) for finding in findings],
    }

    write_json(summary_path, summary)
    write_ndjson(log_path, ndjson_rows)

    print(
        "WASM TypeScript package policy: "
        f"{'PASS' if passed else 'FAIL'} "
        f"(errors={failed_count}, scenarios={len(selected_scenarios)})"
    )
    print(f"summary: {summary_path}")
    print(f"log: {log_path}")

    return passed


def run_self_tests() -> int:
    base_policy = {
        "schema_version": "wasm-typescript-package-policy-v1",
        "required_packages": [
            "@asupersync/browser-core",
            "@asupersync/browser",
            "@asupersync/react",
            "@asupersync/next",
        ],
        "topology": {
            "packages": [
                {
                    "name": "@asupersync/browser-core",
                    "layer": "core",
                    "stability": "public",
                    "semver_surface": "stable",
                    "exports": [
                        {"subpath": ".", "kind": "runtime-core", "tree_shake_safe": True, "module_modes": ["esm", "cjs"]}
                    ],
                },
                {
                    "name": "@asupersync/browser",
                    "layer": "sdk",
                    "stability": "public",
                    "semver_surface": "stable",
                    "exports": [
                        {"subpath": ".", "kind": "sdk", "tree_shake_safe": True, "module_modes": ["esm", "cjs"]}
                    ],
                },
                {
                    "name": "@asupersync/react",
                    "layer": "adapter",
                    "stability": "public",
                    "semver_surface": "preview",
                    "exports": [
                        {"subpath": ".", "kind": "adapter", "tree_shake_safe": True, "module_modes": ["esm", "cjs"]}
                    ],
                },
                {
                    "name": "@asupersync/next",
                    "layer": "adapter",
                    "stability": "public",
                    "semver_surface": "preview",
                    "exports": [
                        {"subpath": ".", "kind": "adapter", "tree_shake_safe": True, "module_modes": ["esm", "cjs"]}
                    ],
                },
            ],
            "forbidden_public_subpath_prefixes": ["./internal/"],
            "allowed_layer_edges": [
                {"from": "@asupersync/browser-core", "to": "@asupersync/browser"},
                {"from": "@asupersync/browser", "to": "@asupersync/react"},
                {"from": "@asupersync/browser", "to": "@asupersync/next"},
            ],
        },
        "type_surface": {
            "required_symbols": ["Outcome", "Budget", "CancellationToken", "RegionHandle"],
            "symbol_owners": {
                "Outcome": "@asupersync/browser-core",
                "Budget": "@asupersync/browser-core",
                "CancellationToken": "@asupersync/browser",
                "RegionHandle": "@asupersync/browser",
            },
        },
        "resolution_matrix": {
            "required_frameworks": ["vanilla-ts", "react", "next"],
            "required_module_modes": ["esm", "cjs"],
            "required_bundlers": ["vite", "webpack", "next-turbopack"],
            "scenarios": [
                {
                    "id": "S1",
                    "framework": "vanilla-ts",
                    "package": "@asupersync/browser",
                    "entrypoint": "@asupersync/browser",
                    "module_mode": "esm",
                    "bundler": "vite",
                    "adapter_path": "none",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
                },
                {
                    "id": "S2",
                    "framework": "vanilla-ts",
                    "package": "@asupersync/browser",
                    "entrypoint": "@asupersync/browser",
                    "module_mode": "cjs",
                    "bundler": "webpack",
                    "adapter_path": "none",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
                },
                {
                    "id": "S3",
                    "framework": "react",
                    "package": "@asupersync/react",
                    "entrypoint": "@asupersync/react",
                    "module_mode": "esm",
                    "bundler": "vite",
                    "adapter_path": "react/provider",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
                },
                {
                    "id": "S4",
                    "framework": "react",
                    "package": "@asupersync/react",
                    "entrypoint": "@asupersync/react",
                    "module_mode": "cjs",
                    "bundler": "webpack",
                    "adapter_path": "react/provider",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
                },
                {
                    "id": "S5",
                    "framework": "next",
                    "package": "@asupersync/next",
                    "entrypoint": "@asupersync/next",
                    "module_mode": "esm",
                    "bundler": "next-turbopack",
                    "adapter_path": "next/app-router",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
                },
                {
                    "id": "S6",
                    "framework": "next",
                    "package": "@asupersync/next",
                    "entrypoint": "@asupersync/next",
                    "module_mode": "cjs",
                    "bundler": "webpack",
                    "adapter_path": "next/pages-router",
                    "runtime_profile": "FP-BR-DEV",
                    "install_command": "pnpm install",
                    "run_command": "pnpm build",
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
                "outcome",
                "artifact_log_path",
                "repro_command",
            ]
        },
        "output": {
            "summary_path": "artifacts/summary.json",
            "log_path": "artifacts/log.ndjson",
        },
    }

    topology_findings, package_map = validate_topology(base_policy)
    assert not topology_findings
    assert package_map["@asupersync/browser"]["layer"] == "sdk"

    assert not validate_type_surface(base_policy, package_map)

    matrix_findings, scenarios = validate_resolution_matrix(base_policy, package_map, set())
    assert not matrix_findings
    assert len(scenarios) == 6

    assert not validate_logging_contract(base_policy)

    with tempfile.TemporaryDirectory() as tmp_dir:
        workspace_root = pathlib.Path(tmp_dir)
        manifest_payload = {
            "type": "module",
            "sideEffects": False,
            "exports": {
                ".": {
                    "types": "./dist/index.d.ts",
                    "import": "./dist/index.js",
                    "default": "./dist/index.js",
                }
            },
        }
        for package_name in (
            "@asupersync/browser-core",
            "@asupersync/browser",
            "@asupersync/react",
            "@asupersync/next",
        ):
            package_dir_name = package_name.split("/", 1)[1]
            package_dir = workspace_root / "packages" / package_dir_name
            package_dir.mkdir(parents=True, exist_ok=True)
            (package_dir / "package.json").write_text(
                json.dumps(manifest_payload, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )

        manifest_findings = validate_package_manifests(base_policy, package_map, workspace_root)
        assert not manifest_findings

        broken_manifest_path = workspace_root / "packages" / "browser" / "package.json"
        broken_manifest = json.loads(broken_manifest_path.read_text(encoding="utf-8"))
        broken_manifest["exports"] = {}
        broken_manifest_path.write_text(
            json.dumps(broken_manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        broken_findings = validate_package_manifests(base_policy, package_map, workspace_root)
        assert any(f.category == "manifest_exports_missing_subpath" for f in broken_findings)

    bad_policy = json.loads(json.dumps(base_policy))
    bad_policy["required_packages"] = [
        "@asupersync/browser-core",
        "@asupersync/browser",
        "@asupersync/react",
        "@asupersync/next",
        "@asupersync/missing",
    ]
    bad_topology_findings, _ = validate_topology(bad_policy)
    assert any(f.category == "topology_required_package" for f in bad_topology_findings)

    bad_matrix = json.loads(json.dumps(base_policy))
    bad_matrix["resolution_matrix"]["scenarios"] = [
        s for s in bad_matrix["resolution_matrix"]["scenarios"] if s["module_mode"] != "cjs"
    ]
    bad_matrix_findings, _ = validate_resolution_matrix(bad_matrix, package_map, set())
    assert any(f.category == "resolution_matrix_coverage" for f in bad_matrix_findings)

    print("WASM TypeScript package policy self-test passed")
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
        workspace_root=pathlib.Path.cwd(),
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
