#!/usr/bin/env python3
"""Inventory a Rust project for native Asupersync migration readiness.

The planner is intentionally read-only with respect to the scanned project. It
parses manifests, lockfiles, and Rust source markers, then emits deterministic
JSON plus an optional summary in a caller-provided output directory.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "migration-readiness-inventory-v1"
DEFAULT_JSON_NAME = "migration_readiness_inventory.json"
DEFAULT_SUMMARY_NAME = "migration_readiness_summary.md"
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


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


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
    verdict, fail_closed_reasons = final_verdict(inventory_rows, parse_errors, len(manifests))
    if proof_pack["fail_closed_reasons"]:
        verdict = "blocked"
        fail_closed_reasons = sorted(set(fail_closed_reasons + proof_pack["fail_closed_reasons"]))
    return {
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
    }


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
    json_path.write_text(stable_json(report), encoding="utf-8")
    summary_path.write_text(summary_markdown(report), encoding="utf-8")
    return {
        "json": json_path.as_posix(),
        "summary": summary_path.as_posix(),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, help="Rust project root to scan")
    parser.add_argument("--output-root", help="Directory where JSON and summary artifacts are written")
    parser.add_argument(
        "--fail-on-blocked",
        action="store_true",
        help="Exit 2 when the report final_verdict is blocked",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    project_root = Path(args.project_root)
    report = build_report(project_root)
    if args.output_root:
        report["output_artifacts"] = write_outputs(report, Path(args.output_root))

    sys.stdout.write(stable_json(report))
    if args.fail_on_blocked and report["summary"]["final_verdict"] == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
