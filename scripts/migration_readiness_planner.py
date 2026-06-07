#!/usr/bin/env python3
"""Inventory a Rust project for native Asupersync migration readiness.

The planner is intentionally read-only with respect to the scanned project. It
parses manifests, lockfiles, and Rust source markers, then emits deterministic
JSON plus an optional summary in a caller-provided output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "migration-readiness-inventory-v1"
OPERATOR_REPORT_SCHEMA_VERSION = "migration-readiness-operator-report-v1"
E2E_REPORT_SCHEMA_VERSION = "migration-readiness-e2e-proof-v1"
DEFAULT_JSON_NAME = "migration_readiness_inventory.json"
DEFAULT_SUMMARY_NAME = "migration_readiness_summary.md"
E2E_JSON_NAME = "migration_readiness_e2e_report.json"
E2E_SUMMARY_NAME = "migration_readiness_e2e_summary.md"
IGNORED_SOURCE_DIRS = {".git", "target", ".cargo", ".direnv", "node_modules"}

NATIVE_CRATES = {
    "asupersync": "native Asupersync runtime surface",
    "asupersync-macros": "native structured-concurrency macro surface",
    "asupersync-browser-core": "native browser boundary surface",
    "frankenlab": "native deterministic lab/testing surface",
}

RUNTIME_CRATES = {
    "tokio": ("runtime_boundary_required", "Tokio runtime usage must be removed from core code or quarantined behind compat"),
    "tokio-util": ("runtime_boundary_required", "Tokio utility usage needs a native replacement or compat quarantine"),
    "tokio-stream": ("runtime_boundary_required", "Tokio stream adapters need native stream/combinator replacement"),
    "hyper": ("compat_quarantine_candidate", "hyper runtime traits belong at an explicit boundary"),
    "hyper-util": ("compat_quarantine_candidate", "hyper-util runtime traits belong at an explicit boundary"),
    "axum": ("compat_quarantine_candidate", "axum stacks should migrate handlers or stay behind tower/hyper compat"),
    "tower": ("compat_quarantine_candidate", "tower middleware can be bridged but should not hide Cx ownership"),
    "tower-http": ("compat_quarantine_candidate", "tower-http layers need an explicit service boundary plan"),
    "tonic": ("compat_quarantine_candidate", "tonic transport should be native gRPC or a quarantined hyper boundary"),
    "reqwest": ("compat_quarantine_candidate", "reqwest clients require a boundary or native HTTP client replacement"),
    "sqlx": ("compat_quarantine_candidate", "sqlx is Tokio-shaped and needs a database boundary decision"),
    "quinn": ("compat_quarantine_candidate", "quinn should be replaced by native QUIC or isolated at the edge"),
    "h3": ("compat_quarantine_candidate", "h3 should be replaced by native HTTP/3 or isolated at the edge"),
    "rdkafka": ("compat_quarantine_candidate", "rdkafka integration needs explicit messaging boundary evidence"),
    "async-std": ("hard_blocker", "alternate async runtimes are forbidden in the native core surface"),
    "smol": ("hard_blocker", "alternate async runtimes are forbidden in the native core surface"),
}

SOURCE_MARKERS = [
    ("tokio::spawn", "runtime_boundary_required", "detached Tokio spawn must become region-owned work"),
    ("#[tokio::main]", "runtime_boundary_required", "Tokio runtime bootstrap must move to RuntimeBuilder/AppSpec"),
    ("#[tokio::test]", "runtime_boundary_required", "Tokio tests need native or compat-scoped test strategy"),
    ("tokio::time::sleep", "runtime_boundary_required", "Tokio timers should use Cx time/budget surfaces"),
    ("tokio::select!", "runtime_boundary_required", "select-style races must preserve loser drain"),
    ("tokio::sync::", "runtime_boundary_required", "Tokio sync primitives need cancel-aware Asupersync replacements"),
    ("hyper::", "compat_quarantine_candidate", "hyper usage needs a native or compat-boundary decision"),
    ("axum::", "compat_quarantine_candidate", "axum usage needs a web-surface migration plan"),
    ("tonic::", "compat_quarantine_candidate", "tonic usage needs a gRPC boundary plan"),
    ("reqwest::", "compat_quarantine_candidate", "reqwest usage needs a client boundary plan"),
    ("sqlx::", "compat_quarantine_candidate", "sqlx usage needs a database boundary plan"),
    ("async_std::", "hard_blocker", "async-std source usage is not a native Asupersync surface"),
    ("smol::", "hard_blocker", "smol source usage is not a native Asupersync surface"),
    ("std::thread::spawn", "manual_design_required", "OS thread spawning needs an ownership and shutdown plan"),
    ("asupersync::", "already_native", "native Asupersync API usage found"),
    ("&Cx", "already_native", "explicit capability context usage found"),
    ("Scope", "already_native", "structured-concurrency scope marker found"),
]

SEMANTIC_SOURCE_MARKERS = [
    {
        "marker": "async fn",
        "recommendation_class": "cx_threading_required",
        "target_surface": "Cx",
        "invariant": "No ambient authority: effects flow through explicit capabilities.",
        "rationale": "async entry points should accept `&Cx` so effects, budgets, and tracing flow through the capability context",
        "operator_action": "thread `&Cx` through the async entry point and its callees",
        "confidence": "medium",
    },
    {
        "marker": "tokio::spawn",
        "recommendation_class": "region_ownership_required",
        "target_surface": "Scope",
        "invariant": "Structured concurrency: every task is owned by exactly one region.",
        "rationale": "detached Tokio spawn sites need region-owned work so close implies quiescence",
        "operator_action": "replace detached spawn with Scope-owned work and explicit loser/drain handling",
        "confidence": "high",
    },
    {
        "marker": "tokio::time::sleep",
        "recommendation_class": "cancel_checkpoint_required",
        "target_surface": "Cx time and budget",
        "invariant": "Cancellation is a protocol: request, drain, finalize.",
        "rationale": "Tokio timers must become cancel-aware Cx time/budget checkpoints",
        "operator_action": "route sleeps, deadlines, and retry delays through Cx time/budget surfaces",
        "confidence": "high",
    },
    {
        "marker": "tokio::select!",
        "recommendation_class": "cancel_checkpoint_required",
        "target_surface": "race/select combinators",
        "invariant": "Losers are drained after races.",
        "rationale": "select-style races need explicit loser cancellation and drain semantics",
        "operator_action": "map each branch to native race/join semantics with loser drain evidence",
        "confidence": "high",
    },
    {
        "marker": "tokio::sync::mpsc",
        "recommendation_class": "capability_narrowing_required",
        "target_surface": "asupersync::channel",
        "invariant": "No obligation leaks: reservations must commit or abort.",
        "rationale": "queue ownership and backpressure should use cancel-correct channel reservations",
        "operator_action": "replace queue surfaces with two-phase reserve/send channels and explicit ownership",
        "confidence": "high",
    },
    {
        "marker": "tokio::sync::",
        "recommendation_class": "capability_narrowing_required",
        "target_surface": "asupersync::sync",
        "invariant": "Sync primitives are cancel-aware.",
        "rationale": "Tokio sync primitives hide cancellation and capability boundaries",
        "operator_action": "replace sync primitives with asupersync sync types and document wait/hold ownership",
        "confidence": "medium",
    },
    {
        "marker": "loop {",
        "recommendation_class": "cancel_checkpoint_required",
        "target_surface": "Cx cancellation checkpoints",
        "invariant": "Region close implies quiescence.",
        "rationale": "long-running loops need explicit cancellation checkpoints and shutdown ownership",
        "operator_action": "add Cx-aware cancellation checks and finalizer/drain behavior for the loop",
        "confidence": "medium",
    },
    {
        "marker": "axum::Router",
        "recommendation_class": "compat_boundary_ok",
        "target_surface": "HTTP adapter boundary",
        "invariant": "Compat code stays outside the default production runtime graph.",
        "rationale": "axum router construction can remain at an explicit HTTP adapter boundary while handlers migrate",
        "operator_action": "pin the HTTP boundary, migrate handlers to Cx, and keep proof-pack no-Tokio lanes clean",
        "confidence": "high",
    },
    {
        "marker": "tower::",
        "recommendation_class": "compat_boundary_ok",
        "target_surface": "Tower adapter boundary",
        "invariant": "Adapters cannot hide region or Cx ownership.",
        "rationale": "Tower middleware can be bridged only when the boundary is explicit and audited",
        "operator_action": "keep tower adapters quarantined and expose Cx-owned handler internals",
        "confidence": "medium",
    },
    {
        "marker": "reqwest::Client",
        "recommendation_class": "capability_narrowing_required",
        "target_surface": "HTTP client capability",
        "invariant": "No ambient authority: network effects flow through explicit capabilities.",
        "rationale": "HTTP clients should be created through explicit capability ownership rather than ambient constructors",
        "operator_action": "move outbound HTTP authority behind a Cx-provided client or native HTTP capability",
        "confidence": "high",
    },
    {
        "marker": "std::env::",
        "recommendation_class": "capability_narrowing_required",
        "target_surface": "configuration capability",
        "invariant": "No ambient authority: config reads are explicit effects.",
        "rationale": "ambient environment reads should be narrowed to explicit configuration capabilities",
        "operator_action": "load configuration through RuntimeBuilder/AppSpec and pass narrowed access through Cx",
        "confidence": "medium",
    },
    {
        "marker": "std::fs::",
        "recommendation_class": "capability_narrowing_required",
        "target_surface": "filesystem capability",
        "invariant": "No ambient authority: filesystem effects are explicit capabilities.",
        "rationale": "filesystem access needs an explicit capability boundary and deterministic test strategy",
        "operator_action": "route file I/O through a Cx-owned fs capability or deterministic test adapter",
        "confidence": "medium",
    },
    {
        "marker": "std::thread::spawn",
        "recommendation_class": "manual_design_required",
        "target_surface": "blocking/thread boundary",
        "invariant": "Region close implies quiescence.",
        "rationale": "OS threads need a manual ownership, shutdown, and capability-flow design before rewrite",
        "operator_action": "design the blocking boundary and join/abort semantics before migration",
        "confidence": "high",
    },
]

SEMANTIC_RECOMMENDATION_ORDER = {
    "cx_threading_required": 10,
    "region_ownership_required": 20,
    "cancel_checkpoint_required": 30,
    "capability_narrowing_required": 40,
    "compat_boundary_ok": 50,
    "manual_design_required": 90,
}

PROOF_COMMAND_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- "

PROOF_COMMANDS = [
    {
        "command_id": "default-production-tokio-tree",
        "graph_class": "default-production",
        "claim_scope": "default-production-tokio-free",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_default_tokio_tree cargo tree -e normal -p asupersync -i tokio",
        "expected_oracle": "stdout contains `warning: nothing to print.`",
        "covers": "Default production normal dependency graph has no tokio edge.",
        "does_not_cover": "Workspace, dev-dependency, fuzz, conformance, and asupersync-tokio-compat graphs are outside this production proof.",
        "source_paths": [
            "AGENTS.md",
            "README.md",
            "artifacts/no_tokio_feature_boundary_contract_v1.json",
            "artifacts/proof_lane_manifest_v1.json",
        ],
    },
    {
        "command_id": "metrics-production-tokio-tree",
        "graph_class": "metrics-production",
        "claim_scope": "metrics-production-tokio-free",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_metrics_tokio_tree cargo tree -e normal -p asupersync --features metrics -i tokio",
        "expected_oracle": "stdout contains `warning: nothing to print.`",
        "covers": "Optional metrics production normal dependency graph has no tokio edge.",
        "does_not_cover": "The fuzz feature deliberately enables OTLP generated messages through tonic/tokio and is not covered by this lane.",
        "source_paths": [
            "AGENTS.md",
            "README.md",
            "artifacts/no_tokio_feature_boundary_contract_v1.json",
            "artifacts/proof_lane_manifest_v1.json",
        ],
    },
    {
        "command_id": "fuzz-tokio-quarantine-tree",
        "graph_class": "fuzz-quarantine",
        "claim_scope": "fuzz-tokio-quarantine",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_fuzz_tokio_tree cargo tree -e normal -p asupersync --features fuzz -i tokio",
        "expected_oracle": "dependency path contains opentelemetry-proto, tonic or tonic-prost, and tokio",
        "covers": "The fuzz-only OTLP helper graph is expected to expose a quarantined opentelemetry-proto to tonic/tokio path.",
        "does_not_cover": "This is not a production-consumer proof and must not be used to weaken default or metrics no-tokio claims.",
        "source_paths": [
            "AGENTS.md",
            "README.md",
            "artifacts/no_tokio_feature_boundary_contract_v1.json",
            "artifacts/proof_lane_manifest_v1.json",
        ],
    },
    {
        "command_id": "workspace-normal-tokio-audit",
        "graph_class": "workspace-normal-audit",
        "claim_scope": "workspace-tokio-audit",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_workspace_tokio_tree cargo tree -e normal --workspace -i tokio",
        "expected_oracle": "tokio paths are limited to documented workspace carve-outs",
        "covers": "Workspace normal graph audit names expected scoped tokio edges in satellite crates and test/reference surfaces.",
        "does_not_cover": "Not a default production proof; expected tokio edges are allowed when documented as scoped carve-outs.",
        "source_paths": ["AGENTS.md", "README.md", "Cargo.toml", "artifacts/proof_lane_manifest_v1.json"],
    },
    {
        "command_id": "full-feature-tokio-audit",
        "graph_class": "full-feature-dev-audit",
        "claim_scope": "full-graph-tokio-audit",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_full_tokio_tree cargo tree -e features --workspace --invert tokio",
        "expected_oracle": "tokio paths are explained as scoped dev/test/fuzz/satellite audit edges",
        "covers": "Full workspace feature/dev graph audit names expected scoped tokio edges in dev/test/reference, fuzz-helper, and satellite surfaces.",
        "does_not_cover": "Not a default or metrics production proof; expected tokio edges are allowed only when documented as scoped non-production carve-outs.",
        "source_paths": [
            "AGENTS.md",
            "README.md",
            "Cargo.toml",
            "artifacts/no_tokio_feature_boundary_contract_v1.json",
            "artifacts/proof_lane_manifest_v1.json",
        ],
    },
]

PRODUCTION_PROOF_IDS = ["default-production-tokio-tree", "metrics-production-tokio-tree"]
AUDIT_PROOF_IDS = ["workspace-normal-tokio-audit", "full-feature-tokio-audit"]
QUARANTINE_PROOF_IDS = ["fuzz-tokio-quarantine-tree"]
PROOF_REQUIRED_IDS = PRODUCTION_PROOF_IDS + QUARANTINE_PROOF_IDS + AUDIT_PROOF_IDS
PROOF_ROW_CLASSIFICATIONS = {
    "runtime_boundary_required",
    "compat_quarantine_candidate",
    "hard_blocker",
}

E2E_SCENARIOS = [
    {
        "scenario_id": "native-clean",
        "fixture": "native",
        "description": "clean native Asupersync project",
        "expected_final_verdict": "ready",
        "expected_operator_status": "native_signoff_ready",
        "expected_min_inventory_rows": 1,
        "required_classifications": ["already_native", "semantic_signal"],
        "required_recommendation_classes": ["compat_boundary_ok"],
        "required_fail_closed_reasons": [],
    },
    {
        "scenario_id": "tokio-http-service",
        "fixture": "tokio_service",
        "description": "Tokio HTTP service with runtime, tower, client, and ownership markers",
        "expected_final_verdict": "needs_quarantine",
        "expected_operator_status": "manual_design_required",
        "expected_min_inventory_rows": 12,
        "required_classifications": ["runtime_boundary_required", "compat_quarantine_candidate", "semantic_signal"],
        "required_recommendation_classes": [
            "region_ownership_required",
            "cancel_checkpoint_required",
            "capability_narrowing_required",
            "manual_design_required",
        ],
        "required_fail_closed_reasons": [],
    },
    {
        "scenario_id": "mixed-compat-boundary",
        "fixture": "mixed_compat_boundary",
        "description": "mixed native handlers with explicit HTTP/Tower compat boundary rows",
        "expected_final_verdict": "needs_quarantine",
        "expected_operator_status": "quarantine_plan_ready",
        "expected_min_inventory_rows": 4,
        "required_classifications": ["already_native", "compat_quarantine_candidate", "semantic_signal"],
        "required_recommendation_classes": ["compat_boundary_ok"],
        "required_fail_closed_reasons": [],
    },
    {
        "scenario_id": "malformed-workspace",
        "fixture": "malformed",
        "description": "malformed manifest fails closed before operator signoff",
        "expected_final_verdict": "blocked",
        "expected_operator_status": "blocked",
        "expected_min_inventory_rows": 0,
        "required_classifications": [],
        "required_recommendation_classes": [],
        "required_fail_closed_reasons": ["manifest-parse-error", "inventory-report-blocked"],
    },
    {
        "scenario_id": "feature-gated-tokio-edge",
        "fixture": "workspace",
        "description": "workspace fixture with optional Tokio and transitive lockfile edge",
        "expected_final_verdict": "needs_quarantine",
        "expected_operator_status": "quarantine_plan_ready",
        "expected_min_inventory_rows": 3,
        "required_classifications": ["already_native", "runtime_boundary_required", "compat_quarantine_candidate"],
        "required_recommendation_classes": ["compat_boundary_ok", "cx_threading_required", "region_ownership_required"],
        "required_fail_closed_reasons": [],
    },
    {
        "scenario_id": "blocked-ambient-authority-service",
        "fixture": "ambient_authority_blocked",
        "description": "ambient env/fs authority plus forbidden alternate runtime fails closed",
        "expected_final_verdict": "blocked",
        "expected_operator_status": "blocked",
        "expected_min_inventory_rows": 5,
        "required_classifications": ["hard_blocker", "semantic_signal"],
        "required_recommendation_classes": ["capability_narrowing_required", "manual_design_required"],
        "required_fail_closed_reasons": ["hard-blocker-runtime-surface"],
    },
    {
        "scenario_id": "zero-evidence-empty",
        "fixture": "empty_surface",
        "description": "parseable project with no runtime or semantic evidence fails closed",
        "expected_final_verdict": "blocked",
        "expected_operator_status": "blocked",
        "expected_min_inventory_rows": 0,
        "required_classifications": [],
        "required_recommendation_classes": [],
        "required_fail_closed_reasons": [
            "zero-runtime-surface-evidence",
            "inventory-report-has-no-runtime-surface-evidence",
            "zero-semantic-recommendations",
        ],
    },
]


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def stable_hash(data: Any) -> str:
    return hashlib.sha256(stable_json(data).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def posix_rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def read_toml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")), None
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, str(error)


def normalize_crate_name(name: str) -> str:
    return name.replace("_", "-").lower()


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def bool_value(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and item})


def expand_workspace_members(root: Path, root_manifest: dict[str, Any], warnings: list[dict[str, str]]) -> list[Path]:
    manifests = {root / "Cargo.toml"}
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        return sorted(manifests)

    for member in list_strings(workspace.get("members")):
        if member.startswith("!"):
            continue
        matches = sorted(root.glob(member))
        if not matches:
            warnings.append(
                {
                    "kind": "workspace-member-glob-empty",
                    "member": member,
                    "message": "workspace member pattern did not match any path",
                }
            )
        for match in matches:
            candidate = match / "Cargo.toml"
            if candidate.exists():
                manifests.add(candidate)
    return sorted(manifests)


def discover_manifests(root: Path, warnings: list[dict[str, str]]) -> tuple[list[Path], dict[str, Any] | None, str | None]:
    root_cargo = root / "Cargo.toml"
    if not root_cargo.exists():
        return [], None, "Cargo.toml not found"

    root_manifest, error = read_toml(root_cargo)
    if error or root_manifest is None:
        return [root_cargo], None, error or "manifest parse failed"
    return expand_workspace_members(root, root_manifest, warnings), root_manifest, None


def dependency_sections(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    sections: list[tuple[str, dict[str, Any]]] = []
    for name in ("dependencies", "dev-dependencies", "build-dependencies", "workspace.dependencies"):
        if name == "workspace.dependencies":
            workspace = manifest.get("workspace")
            table = workspace.get("dependencies") if isinstance(workspace, dict) else None
        else:
            table = manifest.get(name)
        if isinstance(table, dict):
            sections.append((name, table))

    target = manifest.get("target")
    if isinstance(target, dict):
        for target_name, target_table in sorted(target.items()):
            if not isinstance(target_table, dict):
                continue
            for dep_name in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target_table.get(dep_name)
                if isinstance(table, dict):
                    sections.append((f"target.{target_name}.{dep_name}", table))
    return sections


def dependency_spec(spec: Any) -> dict[str, Any]:
    if isinstance(spec, str):
        return {
            "version": spec,
            "optional": False,
            "features": [],
            "path": "",
            "package": "",
        }
    if isinstance(spec, dict):
        return {
            "version": string_value(spec.get("version")),
            "optional": bool_value(spec.get("optional")),
            "features": list_strings(spec.get("features")),
            "path": string_value(spec.get("path")),
            "package": string_value(spec.get("package")),
        }
    return {
        "version": "",
        "optional": False,
        "features": [],
        "path": "",
        "package": "",
    }


def classify_dependency(crate_name: str) -> tuple[str, str, str]:
    normalized = normalize_crate_name(crate_name)
    if normalized in NATIVE_CRATES:
        return "already_native", "info", NATIVE_CRATES[normalized]
    if normalized in RUNTIME_CRATES:
        classification, rationale = RUNTIME_CRATES[normalized]
        severity = "blocker" if classification == "hard_blocker" else "warning"
        return classification, severity, rationale
    return "unclassified", "info", "dependency is outside the migration runtime marker set"


def dependency_inventory_rows(root: Path, manifest_path: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section, table in dependency_sections(manifest):
        for alias, spec in sorted(table.items()):
            details = dependency_spec(spec)
            crate_name = details["package"] or alias
            classification, severity, rationale = classify_dependency(crate_name)
            if classification == "unclassified":
                continue
            rows.append(
                {
                    "row_type": "dependency",
                    "path": posix_rel(manifest_path, root),
                    "section": section,
                    "name": crate_name,
                    "alias": alias if alias != crate_name else "",
                    "classification": classification,
                    "severity": severity,
                    "optional": details["optional"],
                    "feature_gated": details["optional"] or bool(details["features"]),
                    "features": details["features"],
                    "version": details["version"],
                    "path_dependency": details["path"],
                    "confidence": "high",
                    "rationale": rationale,
                    "suggested_next_probe": suggested_probe(classification),
                }
            )
    return rows


def lockfile_packages(root: Path) -> tuple[str, list[str], str]:
    lockfile = root / "Cargo.lock"
    if not lockfile.exists():
        return "missing", [], ""
    data, error = read_toml(lockfile)
    if error or data is None:
        return "parse_error", [], error or "lockfile parse failed"
    packages = data.get("package")
    if not isinstance(packages, list):
        return "present", [], ""
    names = sorted({
        string_value(package.get("name"))
        for package in packages
        if isinstance(package, dict) and string_value(package.get("name"))
    })
    return "present", names, ""


def lockfile_inventory_rows(root: Path, direct_names: set[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    status, packages, error = lockfile_packages(root)
    rows: list[dict[str, Any]] = []
    for name in packages:
        normalized = normalize_crate_name(name)
        if normalized in direct_names:
            continue
        classification, severity, rationale = classify_dependency(name)
        if classification in {"unclassified", "already_native"}:
            continue
        rows.append(
            {
                "row_type": "lockfile_package",
                "path": "Cargo.lock",
                "section": "lockfile",
                "name": name,
                "classification": classification,
                "severity": severity,
                "optional": False,
                "feature_gated": False,
                "features": [],
                "version": "",
                "path_dependency": "",
                "confidence": "medium",
                "rationale": f"transitive lockfile package: {rationale}",
                "suggested_next_probe": suggested_probe(classification),
            }
        )
    return {"status": status, "package_count": len(packages), "error": error}, rows


def suggested_probe(classification: str) -> str:
    if classification == "already_native":
        return "verify Cx flow and deterministic tests around this native surface"
    if classification == "runtime_boundary_required":
        return "inspect call sites and plan native replacement or explicit compat quarantine"
    if classification == "compat_quarantine_candidate":
        return "decide whether native replacement is practical or quarantine behind asupersync-tokio-compat"
    if classification == "hard_blocker":
        return "remove alternate runtime from native core path before migration signoff"
    if classification == "manual_design_required":
        return "design ownership, shutdown, and capability flow before rewriting code"
    return "no follow-up required"


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.rs"):
        if any(part in IGNORED_SOURCE_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def source_marker_rows(root: Path, warnings: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in source_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            warnings.append(
                {
                    "kind": "unreadable-source-file",
                    "path": posix_rel(path, root),
                    "message": "source file was not valid UTF-8",
                }
            )
            continue
        for marker, classification, rationale in SOURCE_MARKERS:
            start = 0
            while True:
                index = text.find(marker, start)
                if index < 0:
                    break
                line = text.count("\n", 0, index) + 1
                rows.append(
                    {
                        "row_type": "source_marker",
                        "path": posix_rel(path, root),
                        "line": line,
                        "marker": marker,
                        "name": marker,
                        "classification": classification,
                        "severity": "blocker" if classification == "hard_blocker" else "warning",
                        "confidence": "medium" if classification == "manual_design_required" else "high",
                        "rationale": rationale,
                        "suggested_next_probe": suggested_probe(classification),
                    }
                )
                start = index + len(marker)
    return sorted(rows, key=lambda row: (row["path"], row.get("line", 0), row["marker"]))


def semantic_signal_for_line(spec: dict[str, str], line_text: str) -> dict[str, str]:
    if spec["marker"] == "async fn" and "&Cx" in line_text:
        return {
            "recommendation_class": "compat_boundary_ok",
            "target_surface": "Cx",
            "invariant": "No ambient authority: effects flow through explicit capabilities.",
            "rationale": "async entry point already accepts `&Cx`; verify callees preserve the explicit capability flow",
            "operator_action": "keep the Cx signature and verify downstream effects do not escape it",
            "confidence": "high",
        }
    return spec


def semantic_source_marker_rows(root: Path, warnings: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in source_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.splitlines()
        for spec in SEMANTIC_SOURCE_MARKERS:
            marker = spec["marker"]
            start = 0
            while True:
                index = text.find(marker, start)
                if index < 0:
                    break
                line = text.count("\n", 0, index) + 1
                line_text = lines[line - 1].strip() if line <= len(lines) else ""
                signal = semantic_signal_for_line(spec, line_text)
                rows.append(
                    {
                        "row_type": "semantic_source_marker",
                        "path": posix_rel(path, root),
                        "line": line,
                        "marker": marker,
                        "name": marker,
                        "classification": "semantic_signal",
                        "severity": "info",
                        "confidence": signal["confidence"],
                        "recommendation_class": signal["recommendation_class"],
                        "target_asupersync_surface": signal["target_surface"],
                        "invariant_preserved": signal["invariant"],
                        "rationale": signal["rationale"],
                        "operator_action": signal["operator_action"],
                        "suggested_next_probe": "derive ordered semantic migration recommendation for this source pattern",
                    }
                )
                start = index + len(marker)
    return sorted(rows, key=lambda row: (row["path"], row.get("line", 0), row["marker"]))


def manifest_summary(root: Path, manifest_path: Path, manifest: dict[str, Any] | None, error: str | None) -> dict[str, Any]:
    if error or manifest is None:
        return {
            "path": posix_rel(manifest_path, root),
            "parse_status": "error",
            "error": error or "manifest parse failed",
            "package_name": "",
            "edition": "",
        }
    package = manifest.get("package")
    package_name = string_value(package.get("name")) if isinstance(package, dict) else ""
    edition = string_value(package.get("edition")) if isinstance(package, dict) else ""
    return {
        "path": posix_rel(manifest_path, root),
        "parse_status": "ok",
        "error": "",
        "package_name": package_name,
        "edition": edition,
    }


def counts_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = string_value(row.get(key)) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def proof_command_map() -> dict[str, dict[str, Any]]:
    return {string_value(command.get("command_id")): command for command in PROOF_COMMANDS}


def validate_proof_commands() -> list[str]:
    reasons: list[str] = []
    seen: set[str] = set()
    for command in PROOF_COMMANDS:
        command_id = string_value(command.get("command_id"))
        if not command_id:
            reasons.append("proof-command-missing-id")
            continue
        if command_id in seen:
            reasons.append(f"{command_id}:duplicate-proof-command-id")
        seen.add(command_id)

        command_text = string_value(command.get("command"))
        if not command_text:
            reasons.append(f"{command_id}:proof-command-missing")
        elif not command_text.startswith(PROOF_COMMAND_PREFIX):
            reasons.append(f"{command_id}:proof-command-not-rch-remote-required")
        if "cargo tree" not in command_text:
            reasons.append(f"{command_id}:proof-command-not-cargo-tree")
        if not string_value(command.get("expected_oracle")):
            reasons.append(f"{command_id}:expected-oracle-missing")
        if not list_strings(command.get("source_paths")):
            reasons.append(f"{command_id}:source-paths-missing")

    missing = sorted(set(PROOF_REQUIRED_IDS) - seen)
    for command_id in missing:
        reasons.append(f"{command_id}:proof-command-missing")
    return sorted(set(reasons))


def proof_command_ids_for_row(row: dict[str, Any]) -> list[str]:
    classification = string_value(row.get("classification"))
    if classification in {"runtime_boundary_required", "compat_quarantine_candidate"}:
        return PRODUCTION_PROOF_IDS + AUDIT_PROOF_IDS
    if classification == "hard_blocker":
        return PRODUCTION_PROOF_IDS + AUDIT_PROOF_IDS
    return PRODUCTION_PROOF_IDS


def proof_boundary_type(row: dict[str, Any]) -> str:
    classification = string_value(row.get("classification"))
    if classification == "runtime_boundary_required":
        return "native_rewrite_or_compat_quarantine"
    if classification == "compat_quarantine_candidate":
        return "compat_quarantine"
    if classification == "hard_blocker":
        return "remove_before_signoff"
    return "none"


def proof_source_kind(row: dict[str, Any]) -> str:
    row_type = string_value(row.get("row_type"))
    if row_type == "dependency":
        return "direct_dependency"
    if row_type == "lockfile_package":
        return "transitive_lockfile_package"
    if row_type == "source_marker":
        return "source_marker"
    return row_type or "unknown"


def owning_module_recommendation(row: dict[str, Any]) -> str:
    normalized = normalize_crate_name(string_value(row.get("name")))
    if normalized in {"tokio", "tokio-util", "tokio-stream"}:
        return "core async entry points must become Cx-threaded, region-owned native Asupersync code"
    if normalized in {"hyper", "hyper-util", "axum", "tower", "tower-http"}:
        return "HTTP/server adapter boundary owned outside the native runtime crate"
    if normalized == "tonic":
        return "gRPC adapter boundary or native asupersync::grpc replacement"
    if normalized == "reqwest":
        return "HTTP client boundary or native asupersync::http client replacement"
    if normalized == "sqlx":
        return "database adapter boundary or native asupersync::database replacement"
    if normalized in {"quinn", "h3"}:
        return "QUIC/HTTP3 adapter boundary or native transport replacement"
    if normalized == "rdkafka":
        return "messaging adapter boundary with explicit capability ownership"
    if normalized in {"async-std", "smol"}:
        return "remove alternate runtime from the native migration path"
    return "owning module must be selected during semantic migration planning"


def removal_trigger(row: dict[str, Any]) -> str:
    classification = string_value(row.get("classification"))
    if classification == "hard_blocker":
        return "removed from every native-core path before migration signoff"
    if classification == "runtime_boundary_required":
        return "all call sites are native Cx/Scope code or isolated behind an explicit compat boundary"
    if classification == "compat_quarantine_candidate":
        return "native replacement lands or adapter is proven scoped outside default and metrics production graphs"
    return "no removal trigger required"


def residual_risk(row: dict[str, Any]) -> str:
    classification = string_value(row.get("classification"))
    if classification == "hard_blocker":
        return "cannot be certified by a compat proof pack until the alternate runtime is removed"
    if classification == "runtime_boundary_required":
        return "detached runtime work can leak cancellation, timers, or task ownership if not rewritten or quarantined"
    if classification == "compat_quarantine_candidate":
        return "adapter can become architecture by accident unless default and metrics cargo-tree proofs stay clean"
    return "no proof-pack residual risk"


def proof_holdout_rows(inventory_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    command_by_id = proof_command_map()
    rows: list[dict[str, Any]] = []
    for row in inventory_rows:
        classification = string_value(row.get("classification"))
        if classification not in PROOF_ROW_CLASSIFICATIONS:
            continue
        command_ids = proof_command_ids_for_row(row)
        stale_or_missing = [
            f"{command_id}:proof-command-missing"
            for command_id in command_ids
            if command_id not in command_by_id
        ]
        rows.append(
            {
                "source_row": {
                    "row_type": string_value(row.get("row_type")),
                    "source_kind": proof_source_kind(row),
                    "path": string_value(row.get("path")),
                    "line": int(row.get("line", 0)),
                    "name": string_value(row.get("name")),
                    "classification": classification,
                    "section": string_value(row.get("section")),
                },
                "boundary_type": proof_boundary_type(row),
                "owning_module_recommendation": owning_module_recommendation(row),
                "removal_trigger": removal_trigger(row),
                "proof_command_ids": command_ids,
                "expected_oracle": "default and metrics lanes must print `warning: nothing to print.`; audit lanes may show only documented scoped Tokio paths",
                "residual_risk": residual_risk(row),
                "stale_or_missing_proof_reasons": stale_or_missing,
                "status": "blocked" if classification == "hard_blocker" else "proof_commands_ready",
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["source_row"]["path"],
            row["source_row"]["source_kind"],
            row["source_row"]["name"],
            row["source_row"]["line"],
        ),
    )


def build_proof_pack(
    inventory_rows: list[dict[str, Any]],
    parse_errors: list[str],
    manifest_count: int,
) -> dict[str, Any]:
    holdouts = proof_holdout_rows(inventory_rows)
    fail_closed_reasons = validate_proof_commands()
    if manifest_count == 0 or parse_errors:
        fail_closed_reasons.append("inventory-report-blocked")
    if not inventory_rows and not fail_closed_reasons:
        fail_closed_reasons.append("inventory-report-has-no-runtime-surface-evidence")
    if any(row["status"] == "blocked" for row in holdouts):
        fail_closed_reasons.append("hard-blocker-runtime-surface")
    for row in holdouts:
        fail_closed_reasons.extend(row["stale_or_missing_proof_reasons"])

    if fail_closed_reasons:
        status = "blocked"
    elif holdouts:
        status = "compat_quarantine_required"
    else:
        status = "native_proof_ready"

    return {
        "schema_version": "migration-readiness-proof-pack-v1",
        "source_contracts": [
            "AGENTS.md",
            "README.md",
            "artifacts/no_tokio_feature_boundary_contract_v1.json",
            "artifacts/proof_lane_manifest_v1.json",
        ],
        "summary": {
            "status": status,
            "compat_holdout_count": len(holdouts),
            "proof_command_count": len(PROOF_COMMANDS),
            "fail_closed_reason_count": len(set(fail_closed_reasons)),
            "holdout_classification_counts": counts_by(
                [row["source_row"] for row in holdouts],
                "classification",
            ),
        },
        "fail_closed_reasons": sorted(set(fail_closed_reasons)),
        "proof_commands": PROOF_COMMANDS,
        "quarantine_rows": holdouts,
    }


def semantic_source_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "row_type": string_value(row.get("row_type")),
        "path": string_value(row.get("path")),
        "line": int(row.get("line", 0)),
        "name": string_value(row.get("name")),
        "classification": string_value(row.get("classification")),
        "section": string_value(row.get("section")),
    }


def semantic_scenario_id(row: dict[str, Any], recommendation_class: str) -> str:
    source = semantic_source_row(row)
    parts = [
        recommendation_class,
        source["path"] or "root",
        source["name"] or "unknown",
        str(source["line"]),
    ]
    return ":".join(part.replace("/", ".").replace(" ", "_") for part in parts)


def semantic_recommendation(
    row: dict[str, Any],
    recommendation_class: str,
    target_surface: str,
    invariant: str,
    rationale: str,
    operator_action: str,
    confidence: str,
) -> dict[str, Any]:
    return {
        "row_type": "semantic_recommendation",
        "scenario_id": semantic_scenario_id(row, recommendation_class),
        "source_row": semantic_source_row(row),
        "recommendation_class": recommendation_class,
        "ordered_step": SEMANTIC_RECOMMENDATION_ORDER[recommendation_class],
        "target_asupersync_surface": target_surface,
        "confidence": confidence,
        "rationale": rationale,
        "operator_action": operator_action,
        "invariant_preserved": invariant,
        "residual_manual_design": recommendation_class == "manual_design_required",
    }


def semantic_recommendations_for_dependency(row: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = normalize_crate_name(string_value(row.get("name")))
    if normalized in {"tokio", "tokio-util", "tokio-stream"}:
        return [
            semantic_recommendation(
                row,
                "cx_threading_required",
                "Cx",
                "No ambient authority: effects flow through explicit capabilities.",
                "Tokio-shaped dependencies usually expose async entry points that need explicit Cx threading",
                "inventory every public async entry point and add a Cx-first signature before replacing call sites",
                "high",
            ),
            semantic_recommendation(
                row,
                "region_ownership_required",
                "Scope",
                "Structured concurrency: every task is owned by exactly one region.",
                "runtime dependencies are only safe when task ownership is explicit at the boundary",
                "move spawned work under Scope or quarantine it behind a documented compat adapter",
                "high",
            ),
        ]
    if normalized in {"hyper", "hyper-util", "axum", "tower", "tower-http"}:
        return [
            semantic_recommendation(
                row,
                "compat_boundary_ok",
                "HTTP/Tower adapter boundary",
                "Compat code stays outside the default production runtime graph.",
                "HTTP service stacks can be migrated incrementally when the adapter boundary is explicit",
                "keep the adapter thin, pass Cx into handlers, and cite the proof-pack no-Tokio lanes",
                "high",
            )
        ]
    if normalized in {"reqwest", "sqlx", "quinn", "h3", "rdkafka", "tonic"}:
        return [
            semantic_recommendation(
                row,
                "capability_narrowing_required",
                owning_module_recommendation(row),
                "No ambient authority: external effects flow through explicit capabilities.",
                "client, database, transport, and messaging crates carry effect authority that should not be ambient",
                "wrap the effect in a Cx-owned capability or keep it at a quarantined adapter boundary",
                "high",
            )
        ]
    if normalized in {"async-std", "smol"}:
        return [
            semantic_recommendation(
                row,
                "manual_design_required",
                "runtime removal plan",
                "Only one native runtime owns the core execution model.",
                "alternate async runtimes are hard blockers for a native Asupersync migration",
                "remove the runtime from native paths before semantic migration signoff",
                "high",
            )
        ]
    if normalized in NATIVE_CRATES:
        return [
            semantic_recommendation(
                row,
                "compat_boundary_ok",
                "native Asupersync surface",
                "No ambient authority: effects flow through explicit capabilities.",
                "native Asupersync dependency is already present and can anchor the migration plan",
                "verify Cx/Scope usage around this native surface and keep deterministic tests",
                "high",
            )
        ]
    return []


def semantic_recommendations_for_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    if row["row_type"] == "semantic_source_marker":
        return [
            semantic_recommendation(
                row,
                string_value(row.get("recommendation_class")),
                string_value(row.get("target_asupersync_surface")),
                string_value(row.get("invariant_preserved")),
                string_value(row.get("rationale")),
                string_value(row.get("operator_action")),
                string_value(row.get("confidence")) or "medium",
            )
        ]
    if row["row_type"] in {"dependency", "lockfile_package"}:
        return semantic_recommendations_for_dependency(row)
    if row["row_type"] == "source_marker" and row["classification"] == "manual_design_required":
        return [
            semantic_recommendation(
                row,
                "manual_design_required",
                "ownership and shutdown design",
                "Region close implies quiescence.",
                string_value(row.get("rationale")),
                "write a manual ownership, shutdown, and capability-flow design before rewriting this source pattern",
                string_value(row.get("confidence")) or "medium",
            )
        ]
    return []


def dedupe_semantic_recommendations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        by_id.setdefault(row["scenario_id"], row)
    return sorted(
        by_id.values(),
        key=lambda row: (
            row["ordered_step"],
            row["source_row"]["path"],
            row["source_row"]["line"],
            row["source_row"]["name"],
            row["recommendation_class"],
        ),
    )


def build_semantic_map(
    inventory_rows: list[dict[str, Any]],
    parse_errors: list[str],
    manifest_count: int,
) -> dict[str, Any]:
    source_match_count = len([row for row in inventory_rows if row["row_type"] == "semantic_source_marker"])
    recommendations = dedupe_semantic_recommendations(
        [
            recommendation
            for row in inventory_rows
            for recommendation in semantic_recommendations_for_row(row)
        ]
    )
    fail_closed_reasons: list[str] = []
    if manifest_count == 0 or parse_errors:
        fail_closed_reasons.append("inventory-report-blocked")
    if not recommendations and not fail_closed_reasons:
        fail_closed_reasons.append("zero-semantic-recommendations")

    manual_design_count = len([row for row in recommendations if row["residual_manual_design"]])
    if fail_closed_reasons:
        status = "blocked"
    elif manual_design_count:
        status = "manual_design_required"
    elif any(row["recommendation_class"] != "compat_boundary_ok" for row in recommendations):
        status = "semantic_plan_required"
    else:
        status = "semantic_plan_ready"

    return {
        "schema_version": "migration-readiness-semantic-map-v1",
        "source_schema": SCHEMA_VERSION,
        "source_contracts": [
            "AGENTS.md",
            "README.md",
            "scripts/migration_readiness_planner.py",
        ],
        "summary": {
            "status": status,
            "source_match_count": source_match_count,
            "recommendation_count": len(recommendations),
            "residual_manual_design_count": manual_design_count,
            "fail_closed_reason_count": len(set(fail_closed_reasons)),
            "recommendation_class_counts": counts_by(recommendations, "recommendation_class"),
            "confidence_distribution": counts_by(recommendations, "confidence"),
        },
        "fail_closed_reasons": sorted(set(fail_closed_reasons)),
        "recommendations": recommendations,
    }


def int_count(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) else 0


def confidence_score(confidence_distribution: dict[str, Any]) -> int:
    weights = {"high": 100, "medium": 70, "low": 40, "unknown": 50}
    total = 0
    weighted = 0
    for key, value in confidence_distribution.items():
        if not isinstance(value, int):
            continue
        total += value
        weighted += weights.get(key, 50) * value
    if total == 0:
        return 100
    return round(weighted / total)


def risk_score_for_classification(classification: str) -> int:
    if classification == "hard_blocker":
        return 100
    if classification == "runtime_boundary_required":
        return 80
    if classification == "compat_quarantine_candidate":
        return 65
    if classification == "manual_design_required":
        return 85
    if classification == "semantic_signal":
        return 50
    return 20


def risk_score_for_recommendation(recommendation_class: str) -> int:
    if recommendation_class == "manual_design_required":
        return 90
    if recommendation_class == "region_ownership_required":
        return 80
    if recommendation_class == "cx_threading_required":
        return 75
    if recommendation_class == "cancel_checkpoint_required":
        return 75
    if recommendation_class == "capability_narrowing_required":
        return 70
    if recommendation_class == "compat_boundary_ok":
        return 35
    return 50


def blast_radius_for_count(count: int) -> str:
    if count == 0:
        return "none"
    if count <= 2:
        return "narrow"
    if count <= 8:
        return "bounded"
    return "broad"


def source_row_key(row: dict[str, Any]) -> str:
    return ":".join(
        [
            string_value(row.get("row_type")) or "row",
            string_value(row.get("path")) or "root",
            string_value(row.get("section")),
            string_value(row.get("name")) or "unknown",
            str(int(row.get("line", 0))),
        ]
    )


def compact_source_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "row_type": string_value(row.get("row_type")),
        "path": string_value(row.get("path")),
        "line": int(row.get("line", 0)),
        "name": string_value(row.get("name")),
        "classification": string_value(row.get("classification")),
        "section": string_value(row.get("section")),
    }


def residual_risk_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    risks: dict[str, dict[str, Any]] = {}
    for reason in report["summary"]["fail_closed_reasons"]:
        risk_id = f"fail-closed:{reason}"
        risks[risk_id] = {
            "risk_id": risk_id,
            "risk_class": "fail_closed",
            "severity": "blocker",
            "risk_score": 100,
            "owner": "operator-preflight",
            "source_row": {},
            "mitigation": "fix the blocked inventory/proof input before using the migration plan for signoff",
            "proof_handles": [],
            "reason": reason,
        }

    for row in report["proof_pack"]["quarantine_rows"]:
        source = row["source_row"]
        classification = string_value(source.get("classification"))
        risk_id = f"proof:{source_row_key(source)}"
        risks.setdefault(
            risk_id,
            {
                "risk_id": risk_id,
                "risk_class": "proof_holdout",
                "severity": "blocker" if classification == "hard_blocker" else "warning",
                "risk_score": risk_score_for_classification(classification),
                "owner": string_value(row.get("owning_module_recommendation")),
                "source_row": compact_source_row(source),
                "mitigation": string_value(row.get("removal_trigger")),
                "proof_handles": list_strings(row.get("proof_command_ids")),
                "reason": string_value(row.get("residual_risk")),
            },
        )

    for row in report["semantic_map"]["recommendations"]:
        recommendation_class = string_value(row.get("recommendation_class"))
        if recommendation_class == "compat_boundary_ok":
            continue
        source = row["source_row"]
        risk_id = f"semantic:{row['scenario_id']}"
        risks.setdefault(
            risk_id,
            {
                "risk_id": risk_id,
                "risk_class": recommendation_class,
                "severity": "blocker" if recommendation_class == "manual_design_required" else "warning",
                "risk_score": risk_score_for_recommendation(recommendation_class),
                "owner": string_value(row.get("target_asupersync_surface")),
                "source_row": compact_source_row(source),
                "mitigation": string_value(row.get("operator_action")),
                "proof_handles": [],
                "reason": string_value(row.get("rationale")),
            },
        )

    return sorted(
        risks.values(),
        key=lambda row: (
            -row["risk_score"],
            row["risk_class"],
            string_value(row.get("risk_id")),
        ),
    )


def phase_status(item_count: int, blocked: bool = False) -> str:
    if blocked:
        return "blocked"
    if item_count == 0:
        return "ready"
    return "pending"


def unique_nonempty(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def phase_entry(
    phase_id: str,
    order: int,
    title: str,
    rows: list[dict[str, Any]],
    risk_score: int,
    status: str,
    operator_actions: list[str],
    raw_artifact_pointers: list[str],
    proof_command_ids: list[str] | None = None,
    recommendation_classes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "phase_id": phase_id,
        "phase_order": order,
        "title": title,
        "status": status,
        "risk_score": risk_score,
        "expected_blast_radius": blast_radius_for_count(len(rows)),
        "source_count": len(rows),
        "source_counts": counts_by(rows, "classification") if rows else {},
        "recommendation_classes": sorted(recommendation_classes or []),
        "proof_command_ids": sorted(proof_command_ids or []),
        "operator_actions": unique_nonempty(operator_actions),
        "raw_artifact_pointers": raw_artifact_pointers,
    }


def build_phase_plan(report: dict[str, Any], risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = report["summary"]
    inventory_rows = report["inventory_rows"]
    proof_pack = report["proof_pack"]
    semantic_map = report["semantic_map"]
    recommendations = semantic_map["recommendations"]

    fail_blocked = bool(summary["fail_closed_reasons"])
    hard_rows = [row for row in inventory_rows if row["classification"] == "hard_blocker"]
    rewrite_recs = [
        row
        for row in recommendations
        if row["recommendation_class"]
        in {
            "cx_threading_required",
            "region_ownership_required",
            "cancel_checkpoint_required",
            "capability_narrowing_required",
        }
    ]
    manual_recs = [
        row
        for row in recommendations
        if row["recommendation_class"] == "manual_design_required"
    ]
    compat_rows = [
        row
        for row in proof_pack["quarantine_rows"]
        if row["source_row"]["classification"] in {"runtime_boundary_required", "compat_quarantine_candidate"}
    ]
    native_rows = [row for row in inventory_rows if row["classification"] == "already_native"]

    return [
        phase_entry(
            "preflight-and-input-integrity",
            0,
            "Preflight and input integrity",
            [{"classification": "fail_closed", "reason": reason} for reason in summary["fail_closed_reasons"]],
            100 if fail_blocked else 10,
            phase_status(len(summary["fail_closed_reasons"]), fail_blocked),
            ["repair manifest, lockfile, or proof-pack inputs before using the report for signoff"]
            if fail_blocked
            else ["inputs are parseable; keep planner output read-only and deterministic"],
            ["summary.fail_closed_reasons", "manifests", "warnings", "proof_pack.fail_closed_reasons"],
            PROOF_REQUIRED_IDS,
        ),
        phase_entry(
            "remove-hard-runtime-blockers",
            10,
            "Remove hard runtime blockers",
            hard_rows,
            100 if hard_rows else 15,
            phase_status(len(hard_rows)),
            [string_value(row.get("suggested_next_probe")) for row in hard_rows]
            or ["no alternate-runtime hard blockers were detected"],
            ["inventory_rows", "proof_pack.quarantine_rows"],
        ),
        phase_entry(
            "thread-cx-region-and-capabilities",
            20,
            "Thread Cx, Scope, cancellation, and capabilities",
            [row["source_row"] for row in rewrite_recs],
            max([risk_score_for_recommendation(row["recommendation_class"]) for row in rewrite_recs] or [20]),
            phase_status(len(rewrite_recs)),
            [string_value(row.get("operator_action")) for row in rewrite_recs],
            ["semantic_map.recommendations"],
            recommendation_classes=unique_nonempty([row["recommendation_class"] for row in rewrite_recs]),
        ),
        phase_entry(
            "manual-ownership-design",
            30,
            "Manual ownership and shutdown design",
            [row["source_row"] for row in manual_recs],
            90 if manual_recs else 15,
            phase_status(len(manual_recs)),
            [string_value(row.get("operator_action")) for row in manual_recs]
            or ["no manual design rows remain"],
            ["semantic_map.recommendations"],
            recommendation_classes=["manual_design_required"] if manual_recs else [],
        ),
        phase_entry(
            "compat-quarantine-and-proof-pack",
            40,
            "Compat quarantine and proof-pack validation",
            [row["source_row"] for row in compat_rows],
            max([risk_score_for_classification(row["source_row"]["classification"]) for row in compat_rows] or [25]),
            phase_status(len(compat_rows), proof_pack["summary"]["status"] == "blocked"),
            [string_value(row.get("removal_trigger")) for row in compat_rows]
            or ["native and production proof-pack lanes can proceed without compat holdouts"],
            ["proof_pack.quarantine_rows", "proof_pack.proof_commands"],
            unique_nonempty(
                [
                    command_id
                    for row in compat_rows
                    for command_id in list_strings(row.get("proof_command_ids"))
                ]
                or PRODUCTION_PROOF_IDS
            ),
        ),
        phase_entry(
            "native-signoff-and-next-beads",
            50,
            "Native signoff and next beads",
            native_rows + risks,
            max([int(row.get("risk_score", 0)) for row in risks] or [10]),
            "ready" if summary["final_verdict"] == "ready" and not risks else "pending",
            [
                "run the remote-required proof commands before citing production no-Tokio or migration-complete claims",
                "create or claim follow-up beads for any remaining residual-risk owners",
            ],
            ["operator_report.residual_risk_rows", "proof_pack.proof_commands", "semantic_map.summary"],
            PROOF_REQUIRED_IDS,
        ),
    ]


def next_recommended_tasks(status: str, phase_plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pending = [phase for phase in phase_plan if phase["status"] in {"blocked", "pending"}]
    if not pending:
        return [
            {
                "task_id": "run-proof-pack-signoff",
                "priority": 3,
                "reason": "all report phases are ready; remote proof-pack execution is the remaining signoff action",
            }
        ]
    tasks: list[dict[str, Any]] = []
    for phase in pending[:4]:
        tasks.append(
            {
                "task_id": f"follow-up:{phase['phase_id']}",
                "priority": 1 if phase["status"] == "blocked" else 2,
                "reason": phase["title"],
                "source_count": phase["source_count"],
                "risk_score": phase["risk_score"],
            }
        )
    if status == "quarantine_plan_ready":
        tasks.append(
            {
                "task_id": "run-default-and-metrics-no-tokio-proof-lanes",
                "priority": 2,
                "reason": "compat quarantine rows need production graph proof handles before signoff",
            }
        )
    return tasks


def operator_report_status(summary: dict[str, Any], semantic_map: dict[str, Any]) -> str:
    if summary["final_verdict"] == "blocked":
        return "blocked"
    if semantic_map["summary"]["residual_manual_design_count"]:
        return "manual_design_required"
    if summary["final_verdict"] == "needs_quarantine":
        return "quarantine_plan_ready"
    if summary["final_verdict"] == "ready":
        return "native_signoff_ready"
    return summary["final_verdict"]


def build_operator_report(report: dict[str, Any]) -> dict[str, Any]:
    summary = report["summary"]
    proof_pack = report["proof_pack"]
    semantic_map = report["semantic_map"]
    risks = residual_risk_rows(report)
    phase_plan = build_phase_plan(report, risks)
    status = operator_report_status(summary, semantic_map)
    highest_risk = max([phase["risk_score"] for phase in phase_plan] + [0])
    classification_counts = summary["classification_counts"]
    semantic_summary = semantic_map["summary"]

    return {
        "schema_version": OPERATOR_REPORT_SCHEMA_VERSION,
        "source_schema": SCHEMA_VERSION,
        "source_contracts": [
            "AGENTS.md",
            "README.md",
            "scripts/migration_readiness_planner.py",
        ],
        "executive_summary": {
            "headline": f"{status}: {summary['final_verdict']}",
            "operator_interpretation": {
                "blocked": "Do not start migration work until fail-closed inputs are repaired.",
                "manual_design_required": "Manual ownership or shutdown design remains before mechanical rewrite work is safe.",
                "quarantine_plan_ready": "Proceed with ordered migration phases while keeping compat boundaries proof-backed.",
                "native_signoff_ready": "Native surfaces are present; run proof-pack lanes before final signoff claims.",
            }.get(status, "Review the phase plan before starting migration work."),
            "recommended_next_action": next_recommended_tasks(status, phase_plan)[0]["task_id"],
            "evidence_level": "remote-proof-handles-ready"
            if proof_pack["summary"]["proof_command_count"] == len(PROOF_COMMANDS)
            else "proof-handle-gap",
        },
        "summary": {
            "status": status,
            "final_verdict": summary["final_verdict"],
            "phase_count": len(phase_plan),
            "highest_risk_score": highest_risk,
            "confidence_score": confidence_score(semantic_summary["confidence_distribution"]),
            "native_count": int_count(classification_counts, "already_native"),
            "compat_or_runtime_count": int_count(classification_counts, "runtime_boundary_required")
            + int_count(classification_counts, "compat_quarantine_candidate"),
            "hard_blocker_count": int_count(classification_counts, "hard_blocker"),
            "residual_risk_count": len(risks),
            "recommendation_count": semantic_summary["recommendation_count"],
            "proof_command_count": proof_pack["summary"]["proof_command_count"],
        },
        "phase_plan": phase_plan,
        "residual_risk_rows": risks,
        "next_recommended_tasks": next_recommended_tasks(status, phase_plan),
        "generation_log": {
            "report_version": OPERATOR_REPORT_SCHEMA_VERSION,
            "input_artifact_hashes": {
                "summary": stable_hash(report["summary"]),
                "inventory_rows": stable_hash(report["inventory_rows"]),
                "proof_pack": stable_hash(report["proof_pack"]),
                "semantic_map": stable_hash(report["semantic_map"]),
            },
            "generated_output_paths": {},
            "recommendation_count": semantic_summary["recommendation_count"],
            "residual_risk_count": len(risks),
            "final_verdict": summary["final_verdict"],
        },
    }


def final_verdict(rows: list[dict[str, Any]], parse_errors: list[str], manifest_count: int) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if manifest_count == 0:
        reasons.append("no-cargo-manifest")
    if parse_errors:
        reasons.append("manifest-parse-error")
    if not rows and not reasons:
        reasons.append("zero-runtime-surface-evidence")
    if any(row["classification"] == "hard_blocker" for row in rows):
        reasons.append("hard-blocker-runtime-surface")

    if reasons:
        return "blocked", sorted(set(reasons))
    if any(row["classification"] in {"runtime_boundary_required", "compat_quarantine_candidate"} for row in rows):
        return "needs_quarantine", []
    if any(row["classification"] == "manual_design_required" for row in rows):
        return "manual_design_required", []
    return "ready", []


def build_report(project_root: Path) -> dict[str, Any]:
    root = project_root
    warnings: list[dict[str, str]] = []
    manifests, _root_manifest, root_error = discover_manifests(root, warnings)
    manifest_rows: list[dict[str, Any]] = []
    inventory_rows: list[dict[str, Any]] = []
    parse_errors: list[str] = []

    if root_error and manifests:
        parse_errors.append(root_error)
    elif root_error:
        parse_errors.append(root_error)

    for manifest_path in manifests:
        manifest, error = read_toml(manifest_path)
        manifest_rows.append(manifest_summary(root, manifest_path, manifest, error))
        if error or manifest is None:
            parse_errors.append(error or f"{posix_rel(manifest_path, root)} parse failed")
            continue
        inventory_rows.extend(dependency_inventory_rows(root, manifest_path, manifest))

    direct_names = {
        normalize_crate_name(row["name"])
        for row in inventory_rows
        if row["row_type"] == "dependency"
    }
    lockfile, lock_rows = lockfile_inventory_rows(root, direct_names)
    inventory_rows.extend(lock_rows)
    inventory_rows.extend(source_marker_rows(root, warnings))
    inventory_rows.extend(semantic_source_marker_rows(root, warnings))
    inventory_rows = sorted(
        inventory_rows,
        key=lambda row: (
            string_value(row.get("path")),
            string_value(row.get("row_type")),
            string_value(row.get("section")),
            string_value(row.get("name")),
            int(row.get("line", 0)),
        ),
    )

    if lockfile["status"] == "missing":
        warnings.append(
            {
                "kind": "lockfile-missing",
                "path": "Cargo.lock",
                "message": "lockfile missing; transitive runtime inventory is incomplete",
            }
        )
    elif lockfile["status"] == "parse_error":
        warnings.append(
            {
                "kind": "lockfile-parse-error",
                "path": "Cargo.lock",
                "message": string_value(lockfile.get("error")) or "lockfile parse failed",
            }
        )

    proof_pack = build_proof_pack(inventory_rows, parse_errors, len(manifests))
    semantic_map = build_semantic_map(inventory_rows, parse_errors, len(manifests))
    verdict, fail_closed_reasons = final_verdict(inventory_rows, parse_errors, len(manifests))
    if proof_pack["fail_closed_reasons"]:
        verdict = "blocked"
        fail_closed_reasons = sorted(set(fail_closed_reasons + proof_pack["fail_closed_reasons"]))
    if semantic_map["fail_closed_reasons"]:
        verdict = "blocked"
        fail_closed_reasons = sorted(set(fail_closed_reasons + semantic_map["fail_closed_reasons"]))
    report = {
        "schema_version": SCHEMA_VERSION,
        "project_root": root.as_posix(),
        "read_only_contract": {
            "scanned_project_mutated": False,
            "writes_require_output_root": True,
        },
        "summary": {
            "final_verdict": verdict,
            "fail_closed_reasons": fail_closed_reasons,
            "manifest_count": len(manifests),
            "inventory_row_count": len(inventory_rows),
            "classification_counts": counts_by(inventory_rows, "classification"),
            "severity_counts": counts_by(inventory_rows, "severity"),
            "warning_count": len(warnings),
        },
        "manifests": manifest_rows,
        "lockfile": lockfile,
        "warnings": sorted(warnings, key=lambda row: (row.get("kind", ""), row.get("path", ""), row.get("member", ""))),
        "inventory_rows": inventory_rows,
        "proof_pack": proof_pack,
        "semantic_map": semantic_map,
    }
    report["operator_report"] = build_operator_report(report)
    return report


def summary_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Migration Readiness Inventory",
        "",
        f"- schema_version: `{report['schema_version']}`",
        f"- final_verdict: `{summary['final_verdict']}`",
        f"- inventory_row_count: `{summary['inventory_row_count']}`",
        f"- manifest_count: `{summary['manifest_count']}`",
        "",
        "## Classification Counts",
    ]
    for key, value in summary["classification_counts"].items():
        lines.append(f"- `{key}`: {value}")
    if summary["fail_closed_reasons"]:
        lines.extend(["", "## Fail-Closed Reasons"])
        for reason in summary["fail_closed_reasons"]:
            lines.append(f"- `{reason}`")
    operator_report = report.get("operator_report")
    if isinstance(operator_report, dict):
        operator_summary = operator_report["summary"]
        executive = operator_report["executive_summary"]
        lines.extend(
            [
                "",
                "## Operator Report",
                f"- status: `{operator_summary['status']}`",
                f"- headline: {executive['headline']}",
                f"- recommended_next_action: `{executive['recommended_next_action']}`",
                f"- highest_risk_score: `{operator_summary['highest_risk_score']}`",
                f"- confidence_score: `{operator_summary['confidence_score']}`",
                f"- residual_risk_count: `{operator_summary['residual_risk_count']}`",
                "",
                "## Phase Plan",
            ]
        )
        for phase in operator_report["phase_plan"]:
            lines.append(
                f"- `{phase['phase_id']}`: status=`{phase['status']}` "
                f"risk_score=`{phase['risk_score']}` source_count=`{phase['source_count']}`"
            )
        if operator_report["residual_risk_rows"]:
            lines.extend(["", "## Residual Risks"])
            for row in operator_report["residual_risk_rows"][:10]:
                lines.append(
                    f"- `{row['risk_id']}`: severity=`{row['severity']}` "
                    f"risk_score=`{row['risk_score']}` owner=`{row['owner']}`"
                )
    proof_pack = report.get("proof_pack")
    if isinstance(proof_pack, dict):
        proof_summary = proof_pack["summary"]
        lines.extend(
            [
                "",
                "## Proof Pack",
                f"- status: `{proof_summary['status']}`",
                f"- proof_command_count: `{proof_summary['proof_command_count']}`",
                f"- compat_holdout_count: `{proof_summary['compat_holdout_count']}`",
            ]
        )
        for command in proof_pack["proof_commands"]:
            lines.append(f"- `{command['command_id']}`: {command['expected_oracle']}")
    semantic_map = report.get("semantic_map")
    if isinstance(semantic_map, dict):
        semantic_summary = semantic_map["summary"]
        lines.extend(
            [
                "",
                "## Semantic Map",
                f"- status: `{semantic_summary['status']}`",
                f"- source_match_count: `{semantic_summary['source_match_count']}`",
                f"- recommendation_count: `{semantic_summary['recommendation_count']}`",
                f"- residual_manual_design_count: `{semantic_summary['residual_manual_design_count']}`",
            ]
        )
        for key, value in semantic_summary["recommendation_class_counts"].items():
            lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Next Probes"])
    seen: set[str] = set()
    for row in report["inventory_rows"]:
        probe = string_value(row.get("suggested_next_probe"))
        if probe and probe not in seen:
            seen.add(probe)
            lines.append(f"- {probe}")
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], output_root: Path) -> dict[str, str]:
    output_root.mkdir(parents=True, exist_ok=True)
    json_path = output_root / DEFAULT_JSON_NAME
    summary_path = output_root / DEFAULT_SUMMARY_NAME
    paths = {
        "json": json_path.as_posix(),
        "summary": summary_path.as_posix(),
    }
    report["output_artifacts"] = paths
    operator_report = report.get("operator_report")
    if isinstance(operator_report, dict):
        operator_report["generation_log"]["generated_output_paths"] = paths
    json_path.write_text(stable_json(report), encoding="utf-8")
    summary_path.write_text(summary_markdown(report), encoding="utf-8")
    return paths


def e2e_fixture_root() -> Path:
    return Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "migration_readiness_planner"


def scenario_by_id() -> dict[str, dict[str, Any]]:
    return {scenario["scenario_id"]: scenario for scenario in E2E_SCENARIOS}


def select_e2e_scenarios(requested_ids: list[str]) -> list[dict[str, Any]]:
    by_id = scenario_by_id()
    if not requested_ids:
        return E2E_SCENARIOS
    unknown = sorted(set(requested_ids) - set(by_id))
    if unknown:
        raise ValueError(f"unknown scenario id(s): {', '.join(unknown)}")
    return [by_id[scenario_id] for scenario_id in requested_ids]


def fixture_fingerprint(fixture_root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    if not fixture_root.exists():
        return {
            "fixture_hash": "",
            "file_count": 0,
            "files": [],
            "missing": True,
        }
    for path in sorted(path for path in fixture_root.rglob("*") if path.is_file()):
        data = path.read_bytes()
        files.append(
            {
                "path": posix_rel(path, fixture_root),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    return {
        "fixture_hash": stable_hash(files),
        "file_count": len(files),
        "files": files,
        "missing": False,
    }


def e2e_catalog(selected: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    scenarios = selected or E2E_SCENARIOS
    fixture_root = e2e_fixture_root()
    return {
        "schema_version": "migration-readiness-e2e-scenario-catalog-v1",
        "source_schema": E2E_REPORT_SCHEMA_VERSION,
        "fixture_root": fixture_root.as_posix(),
        "scenario_count": len(scenarios),
        "scenarios": [
            {
                "scenario_id": scenario["scenario_id"],
                "fixture": scenario["fixture"],
                "description": scenario["description"],
                "expected_final_verdict": scenario["expected_final_verdict"],
                "expected_operator_status": scenario["expected_operator_status"],
            }
            for scenario in scenarios
        ],
    }


def scenario_artifact_hashes(paths: dict[str, str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for key, path_text in sorted(paths.items()):
        path = Path(path_text)
        hashes[f"{key}_sha256"] = file_sha256(path) if path.exists() else ""
    return hashes


def validation_contains_count(mapping: dict[str, Any], key: str) -> bool:
    value = mapping.get(key)
    return isinstance(value, int) and value > 0


def validate_e2e_scenario(
    scenario: dict[str, Any],
    report: dict[str, Any],
    paths: dict[str, str],
) -> tuple[str, list[str]]:
    failures: list[str] = []
    summary = report["summary"]
    operator_summary = report["operator_report"]["summary"]
    semantic_summary = report["semantic_map"]["summary"]
    classification_counts = summary["classification_counts"]
    recommendation_counts = semantic_summary["recommendation_class_counts"]
    fail_closed = set(summary["fail_closed_reasons"])
    fail_closed.update(report["proof_pack"]["fail_closed_reasons"])
    fail_closed.update(report["semantic_map"]["fail_closed_reasons"])

    if summary["final_verdict"] != scenario["expected_final_verdict"]:
        failures.append(
            f"final-verdict:{summary['final_verdict']}!=expected:{scenario['expected_final_verdict']}"
        )
    if operator_summary["status"] != scenario["expected_operator_status"]:
        failures.append(
            f"operator-status:{operator_summary['status']}!=expected:{scenario['expected_operator_status']}"
        )
    if summary["inventory_row_count"] < int(scenario["expected_min_inventory_rows"]):
        failures.append("inventory-row-count-below-minimum")
    if report["proof_pack"]["summary"]["proof_command_count"] != len(PROOF_COMMANDS):
        failures.append("proof-command-count-mismatch")
    if operator_summary["phase_count"] != 6:
        failures.append("operator-phase-count-mismatch")
    if paths and report["operator_report"]["generation_log"]["generated_output_paths"] != paths:
        failures.append("generated-output-paths-not-stamped")
    for classification in scenario["required_classifications"]:
        if not validation_contains_count(classification_counts, classification):
            failures.append(f"classification-missing:{classification}")
    for recommendation_class in scenario["required_recommendation_classes"]:
        if not validation_contains_count(recommendation_counts, recommendation_class):
            failures.append(f"recommendation-class-missing:{recommendation_class}")
    for reason in scenario["required_fail_closed_reasons"]:
        if reason not in fail_closed:
            failures.append(f"fail-closed-reason-missing:{reason}")
    return ("passed" if not failures else "failed"), failures


def e2e_result_for_scenario(
    scenario: dict[str, Any],
    mode: str,
    output_root: Path | None,
) -> dict[str, Any]:
    fixture_root = e2e_fixture_root() / scenario["fixture"]
    fingerprint = fixture_fingerprint(fixture_root)
    result: dict[str, Any] = {
        "scenario_id": scenario["scenario_id"],
        "fixture": scenario["fixture"],
        "description": scenario["description"],
        "fixture_path": fixture_root.as_posix(),
        "fixture_hash": fingerprint["fixture_hash"],
        "fixture_file_count": fingerprint["file_count"],
        "pipeline_stage_log": [
            {
                "stage": "fixture_hash",
                "scenario_id": scenario["scenario_id"],
                "fixture_hash": fingerprint["fixture_hash"],
                "file_count": fingerprint["file_count"],
            }
        ],
    }
    if mode == "dry_run":
        result.update(
            {
                "status": "planned",
                "final_verdict": "",
                "operator_status": "",
                "inventory_row_count": 0,
                "proof_command_count": 0,
                "generated_artifacts": {},
                "generated_artifact_hashes": {},
                "validation_failures": [],
            }
        )
        result["pipeline_stage_log"].append(
            {
                "stage": "dry_run",
                "scenario_id": scenario["scenario_id"],
                "final_verdict": "not-executed",
                "proof_command_count": 0,
                "generated_artifact_paths": {},
            }
        )
        return result

    report = build_report(fixture_root)
    paths: dict[str, str] = {}
    if output_root is not None:
        paths = write_outputs(report, output_root / scenario["scenario_id"])
    status, failures = validate_e2e_scenario(scenario, report, paths)
    artifact_hashes = scenario_artifact_hashes(paths)
    result.update(
        {
            "status": status,
            "final_verdict": report["summary"]["final_verdict"],
            "operator_status": report["operator_report"]["summary"]["status"],
            "inventory_row_count": report["summary"]["inventory_row_count"],
            "proof_command_count": report["proof_pack"]["summary"]["proof_command_count"],
            "residual_risk_count": report["operator_report"]["summary"]["residual_risk_count"],
            "fail_closed_reasons": report["summary"]["fail_closed_reasons"],
            "classification_counts": report["summary"]["classification_counts"],
            "recommendation_class_counts": report["semantic_map"]["summary"]["recommendation_class_counts"],
            "generated_artifacts": paths,
            "generated_artifact_hashes": artifact_hashes,
            "validation_failures": failures,
        }
    )
    result["pipeline_stage_log"].extend(
        [
            {
                "stage": "build_report",
                "scenario_id": scenario["scenario_id"],
                "fixture_hash": fingerprint["fixture_hash"],
                "inventory_row_count": report["summary"]["inventory_row_count"],
                "proof_command_count": report["proof_pack"]["summary"]["proof_command_count"],
                "final_verdict": report["summary"]["final_verdict"],
                "generated_artifact_paths": {},
            },
            {
                "stage": "write_outputs" if paths else "stdout_only",
                "scenario_id": scenario["scenario_id"],
                "fixture_hash": fingerprint["fixture_hash"],
                "inventory_row_count": report["summary"]["inventory_row_count"],
                "proof_command_count": report["proof_pack"]["summary"]["proof_command_count"],
                "final_verdict": report["summary"]["final_verdict"],
                "generated_artifact_paths": paths,
            },
            {
                "stage": "validate_expectations",
                "scenario_id": scenario["scenario_id"],
                "fixture_hash": fingerprint["fixture_hash"],
                "inventory_row_count": report["summary"]["inventory_row_count"],
                "proof_command_count": report["proof_pack"]["summary"]["proof_command_count"],
                "final_verdict": report["summary"]["final_verdict"],
                "generated_artifact_paths": paths,
                "status": status,
            },
        ]
    )
    return result


def build_e2e_report(
    selected: list[dict[str, Any]],
    mode: str,
    output_root: Path | None,
) -> dict[str, Any]:
    results = [e2e_result_for_scenario(scenario, mode, output_root) for scenario in selected]
    status_counts = counts_by(results, "status")
    failed = int_count(status_counts, "failed")
    return {
        "schema_version": E2E_REPORT_SCHEMA_VERSION,
        "source_schema": SCHEMA_VERSION,
        "source_contracts": [
            "scripts/migration_readiness_planner.py",
            "tests/migration_readiness_planner_contract.rs",
            "tests/fixtures/migration_readiness_planner",
        ],
        "mode": mode,
        "summary": {
            "overall_status": "dry_run" if mode == "dry_run" else ("passed" if failed == 0 else "failed"),
            "scenario_count": len(results),
            "status_counts": status_counts,
            "failed_count": failed,
            "proof_command_count": len(PROOF_COMMANDS),
        },
        "scenario_catalog": e2e_catalog(selected),
        "scenario_results": results,
    }


def e2e_summary_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Migration Readiness E2E Proof",
        "",
        f"- schema_version: `{report['schema_version']}`",
        f"- mode: `{report['mode']}`",
        f"- overall_status: `{report['summary']['overall_status']}`",
        f"- scenario_count: `{report['summary']['scenario_count']}`",
        "",
        "## Scenarios",
    ]
    for result in report["scenario_results"]:
        lines.append(
            f"- `{result['scenario_id']}`: status=`{result['status']}` "
            f"final_verdict=`{result['final_verdict']}` "
            f"operator_status=`{result['operator_status']}` "
            f"fixture_hash=`{result['fixture_hash']}`"
        )
        for failure in result["validation_failures"]:
            lines.append(f"  - failure: `{failure}`")
    return "\n".join(lines) + "\n"


def write_e2e_outputs(report: dict[str, Any], output_root: Path) -> dict[str, str]:
    output_root.mkdir(parents=True, exist_ok=True)
    json_path = output_root / E2E_JSON_NAME
    summary_path = output_root / E2E_SUMMARY_NAME
    paths = {
        "json": json_path.as_posix(),
        "summary": summary_path.as_posix(),
    }
    report["output_artifacts"] = paths
    json_path.write_text(stable_json(report), encoding="utf-8")
    summary_path.write_text(e2e_summary_markdown(report), encoding="utf-8")
    return paths


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", help="Rust project root to scan")
    parser.add_argument("--output-root", help="Directory where JSON and summary artifacts are written")
    parser.add_argument(
        "--fail-on-blocked",
        action="store_true",
        help="Exit 2 when the report final_verdict is blocked",
    )
    parser.add_argument("--list", action="store_true", help="List fixture-driven E2E scenarios")
    parser.add_argument("--scenario", action="append", default=[], help="E2E scenario id to include")
    parser.add_argument("--dry-run", action="store_true", help="Render the E2E plan without writing artifacts")
    parser.add_argument("--execute", action="store_true", help="Run the fixture-driven E2E proof")
    args = parser.parse_args(argv)
    if args.dry_run and args.execute:
        parser.error("--dry-run and --execute are mutually exclusive")
    e2e_mode = args.list or args.dry_run or args.execute
    if e2e_mode and args.project_root:
        parser.error("--project-root cannot be combined with --list, --dry-run, or --execute")
    if not e2e_mode and not args.project_root:
        parser.error("--project-root is required unless using --list, --dry-run, or --execute")
    if args.execute and not args.output_root:
        parser.error("--execute requires --output-root")
    if args.fail_on_blocked and e2e_mode:
        parser.error("--fail-on-blocked is only valid with --project-root")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.list:
        try:
            selected = select_e2e_scenarios(args.scenario)
        except ValueError as error:
            sys.stderr.write(f"{error}\n")
            return 2
        sys.stdout.write(stable_json(e2e_catalog(selected)))
        return 0
    if args.dry_run or args.execute:
        try:
            selected = select_e2e_scenarios(args.scenario)
        except ValueError as error:
            sys.stderr.write(f"{error}\n")
            return 2
        mode = "execute" if args.execute else "dry_run"
        output_root = Path(args.output_root) if args.output_root and args.execute else None
        report = build_e2e_report(selected, mode, output_root)
        if args.execute and output_root is not None:
            write_e2e_outputs(report, output_root)
        sys.stdout.write(stable_json(report))
        return 0 if report["summary"]["overall_status"] in {"passed", "dry_run"} else 1

    project_root = Path(args.project_root)
    report = build_report(project_root)
    if args.output_root:
        write_outputs(report, Path(args.output_root))

    sys.stdout.write(stable_json(report))
    if args.fail_on_blocked and report["summary"]["final_verdict"] == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
