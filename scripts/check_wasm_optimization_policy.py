#!/usr/bin/env python3
"""Validate wasm optimization policy and emit deterministic command summary."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import pathlib
import shlex
import sys
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """Raised when policy validation fails."""


@dataclass(frozen=True)
class CargoProfile:
    release: bool
    no_default_features: bool
    features: tuple[str, ...]


@dataclass(frozen=True)
class WasmOptProfile:
    enabled: bool
    passes: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactPaths:
    source: str
    optimized: str


@dataclass(frozen=True)
class OptimizationProfile:
    profile_id: str
    variant: str
    budget_profile: str
    cargo: CargoProfile
    rustflags: tuple[str, ...]
    wasm_opt: WasmOptProfile
    artifact: ArtifactPaths
    tradeoff: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_optimization_policy.json",
        help="Path to policy JSON.",
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
        "--only-profile",
        action="append",
        default=[],
        help="Restrict summary to one or more policy profile IDs.",
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


def parse_contract(
    policy: dict[str, Any],
) -> tuple[str, tuple[str, ...], frozenset[str], frozenset[str], str]:
    if policy.get("schema_version") != "wasm-optimization-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    budget_contract = policy.get("budget_contract")
    if not isinstance(budget_contract, dict):
        raise PolicyError("budget_contract must be an object")
    allowed_budget_profiles = budget_contract.get("allowed_budget_profiles")
    if not isinstance(allowed_budget_profiles, list) or not all(
        isinstance(entry, str) and entry for entry in allowed_budget_profiles
    ):
        raise PolicyError("budget_contract.allowed_budget_profiles must be a non-empty list[str]")
    allowed_budgets = frozenset(allowed_budget_profiles)
    if not allowed_budgets:
        raise PolicyError("budget_contract.allowed_budget_profiles cannot be empty")

    invariants = policy.get("invariants")
    if not isinstance(invariants, dict):
        raise PolicyError("invariants must be an object")
    target = invariants.get("target")
    if not isinstance(target, str) or not target:
        raise PolicyError("invariants.target must be a non-empty string")

    required_features = invariants.get("required_features")
    if not isinstance(required_features, list) or not all(
        isinstance(entry, str) and entry for entry in required_features
    ):
        raise PolicyError("invariants.required_features must be a list[str]")
    required = tuple(sorted(required_features))

    forbidden_features = invariants.get("forbidden_features")
    if not isinstance(forbidden_features, list) or not all(
        isinstance(entry, str) and entry for entry in forbidden_features
    ):
        raise PolicyError("invariants.forbidden_features must be a list[str]")
    forbidden = frozenset(forbidden_features)

    overlap = set(required).intersection(forbidden)
    if overlap:
        overlap_csv = ", ".join(sorted(overlap))
        raise PolicyError(f"required_features and forbidden_features overlap: {overlap_csv}")

    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be an object")
    summary_path = output.get("summary_path")
    if not isinstance(summary_path, str) or not summary_path:
        raise PolicyError("output.summary_path must be a non-empty string")

    return target, required, forbidden, allowed_budgets, summary_path


def parse_profiles(
    policy: dict[str, Any],
    required_features: tuple[str, ...],
    forbidden_features: frozenset[str],
    allowed_budgets: frozenset[str],
    only_profiles: set[str],
) -> list[OptimizationProfile]:
    raw_profiles = policy.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise PolicyError("profiles must be a non-empty list")

    profiles: list[OptimizationProfile] = []
    seen_ids: set[str] = set()
    seen_variants: set[str] = set()

    for raw in raw_profiles:
        if not isinstance(raw, dict):
            raise PolicyError("profiles entries must be objects")
        profile_id = raw.get("id")
        variant = raw.get("variant")
        budget_profile = raw.get("budget_profile")

        if not isinstance(profile_id, str) or not profile_id:
            raise PolicyError("profile id must be a non-empty string")
        if profile_id in seen_ids:
            raise PolicyError(f"duplicate profile id: {profile_id}")
        seen_ids.add(profile_id)

        if only_profiles and profile_id not in only_profiles:
            continue

        if not isinstance(variant, str) or variant not in {"dev", "canary", "release"}:
            raise PolicyError(
                f"profile {profile_id}: variant must be one of dev|canary|release"
            )
        if variant in seen_variants:
            raise PolicyError(f"duplicate variant detected: {variant}")
        seen_variants.add(variant)

        if not isinstance(budget_profile, str) or budget_profile not in allowed_budgets:
            raise PolicyError(
                f"profile {profile_id}: budget_profile must be one of "
                f"{', '.join(sorted(allowed_budgets))}"
            )

        cargo_raw = raw.get("cargo")
        if not isinstance(cargo_raw, dict):
            raise PolicyError(f"profile {profile_id}: cargo must be an object")
        release = cargo_raw.get("release")
        no_default_features = cargo_raw.get("no_default_features")
        features = cargo_raw.get("features")
        if not isinstance(release, bool) or not isinstance(no_default_features, bool):
            raise PolicyError(f"profile {profile_id}: cargo.release/no_default_features must be bool")
        if not isinstance(features, list) or not all(
            isinstance(entry, str) and entry for entry in features
        ):
            raise PolicyError(f"profile {profile_id}: cargo.features must be list[str]")

        feature_set = set(features)
        missing_required = [feat for feat in required_features if feat not in feature_set]
        if missing_required:
            raise PolicyError(
                f"profile {profile_id}: missing required cargo.features: "
                f"{', '.join(sorted(missing_required))}"
            )
        forbidden_present = sorted(feature_set.intersection(forbidden_features))
        if forbidden_present:
            raise PolicyError(
                f"profile {profile_id}: forbidden cargo.features present: "
                f"{', '.join(forbidden_present)}"
            )

        rustflags_raw = raw.get("rustflags")
        if not isinstance(rustflags_raw, list) or not all(
            isinstance(entry, str) and entry.startswith("-C") for entry in rustflags_raw
        ):
            raise PolicyError(f"profile {profile_id}: rustflags must be list of -C flags")
        rustflags = tuple(rustflags_raw)

        wasm_opt_raw = raw.get("wasm_opt")
        if not isinstance(wasm_opt_raw, dict):
            raise PolicyError(f"profile {profile_id}: wasm_opt must be an object")
        enabled = wasm_opt_raw.get("enabled")
        passes = wasm_opt_raw.get("passes")
        if not isinstance(enabled, bool):
            raise PolicyError(f"profile {profile_id}: wasm_opt.enabled must be bool")
        if not isinstance(passes, list) or not all(isinstance(entry, str) for entry in passes):
            raise PolicyError(f"profile {profile_id}: wasm_opt.passes must be list[str]")
        if enabled and not passes:
            raise PolicyError(f"profile {profile_id}: wasm_opt.enabled=true requires passes")
        if not enabled and passes:
            raise PolicyError(f"profile {profile_id}: wasm_opt.enabled=false requires empty passes")

        artifact_raw = raw.get("artifact")
        if not isinstance(artifact_raw, dict):
            raise PolicyError(f"profile {profile_id}: artifact must be an object")
        source = artifact_raw.get("source")
        optimized = artifact_raw.get("optimized")
        if not isinstance(source, str) or not source:
            raise PolicyError(f"profile {profile_id}: artifact.source must be non-empty string")
        if not isinstance(optimized, str) or not optimized:
            raise PolicyError(f"profile {profile_id}: artifact.optimized must be non-empty string")

        tradeoff = raw.get("tradeoff")
        if not isinstance(tradeoff, str) or not tradeoff.strip():
            raise PolicyError(f"profile {profile_id}: tradeoff must be non-empty string")

        profiles.append(
            OptimizationProfile(
                profile_id=profile_id,
                variant=variant,
                budget_profile=budget_profile,
                cargo=CargoProfile(
                    release=release,
                    no_default_features=no_default_features,
                    features=tuple(sorted(feature_set)),
                ),
                rustflags=rustflags,
                wasm_opt=WasmOptProfile(enabled=enabled, passes=tuple(passes)),
                artifact=ArtifactPaths(source=source, optimized=optimized),
                tradeoff=tradeoff.strip(),
            )
        )

    if only_profiles and not profiles:
        missing = ", ".join(sorted(only_profiles))
        raise PolicyError(f"--only-profile selected unknown profile(s): {missing}")

    if not profiles:
        raise PolicyError("no profiles selected")

    return profiles


def render_cargo_command(target: str, profile: OptimizationProfile) -> str:
    parts = ["cargo", "build", "-p", "asupersync", "--target", target]
    if profile.cargo.release:
        parts.append("--release")
    if profile.cargo.no_default_features:
        parts.append("--no-default-features")
    if profile.cargo.features:
        parts.extend(["--features", ",".join(profile.cargo.features)])
    command = " ".join(shlex.quote(part) for part in parts)
    if profile.rustflags:
        rustflags = " ".join(profile.rustflags)
        return f"RUSTFLAGS={shlex.quote(rustflags)} {command}"
    return command


def render_wasm_opt_command(profile: OptimizationProfile) -> str | None:
    if not profile.wasm_opt.enabled:
        return None
    parts = ["wasm-opt", *profile.wasm_opt.passes, "-o", profile.artifact.optimized, profile.artifact.source]
    return " ".join(shlex.quote(part) for part in parts)


def build_summary(
    policy_path: pathlib.Path,
    target: str,
    profiles: list[OptimizationProfile],
) -> dict[str, Any]:
    profile_rows: list[dict[str, Any]] = []
    for profile in sorted(profiles, key=lambda item: item.variant):
        profile_rows.append(
            {
                "id": profile.profile_id,
                "variant": profile.variant,
                "budget_profile": profile.budget_profile,
                "cargo_command": render_cargo_command(target, profile),
                "wasm_opt_command": render_wasm_opt_command(profile),
                "source_artifact": profile.artifact.source,
                "optimized_artifact": profile.artifact.optimized,
                "tradeoff": profile.tradeoff,
            }
        )

    return {
        "schema_version": "wasm-optimization-pipeline-summary-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "policy_path": str(policy_path),
        "target": target,
        "profiles": profile_rows,
        "profile_count": len(profile_rows),
        "budget_summary_contract": "artifacts/wasm_budget_summary.json",
        "downstream_blockers": ["asupersync-umelq.13.5", "asupersync-umelq.18.5"],
    }


def write_summary(path: pathlib.Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> None:
    base_policy: dict[str, Any] = {
        "schema_version": "wasm-optimization-policy-v1",
        "budget_contract": {
            "source_document": "WASM_SIZE_PERF_BUDGETS.md",
            "allowed_budget_profiles": ["core-min", "full-dev"],
        },
        "invariants": {
            "target": "wasm32-unknown-unknown",
            "required_features": ["wasm-browser-preview", "getrandom/wasm_js"],
            "forbidden_features": ["cli"],
        },
        "profiles": [
            {
                "id": "wasm-browser-dev",
                "variant": "dev",
                "budget_profile": "full-dev",
                "cargo": {
                    "release": False,
                    "no_default_features": True,
                    "features": ["wasm-browser-preview", "getrandom/wasm_js"],
                },
                "rustflags": ["-Copt-level=1"],
                "wasm_opt": {"enabled": False, "passes": []},
                "artifact": {
                    "source": "target/wasm32-unknown-unknown/debug/asupersync.wasm",
                    "optimized": "artifacts/wasm/dev/asupersync.dev.wasm",
                },
                "tradeoff": "debug-first",
            }
        ],
        "output": {"summary_path": "artifacts/test_summary.json"},
    }

    target, required, forbidden, allowed_budgets, _summary_path = parse_contract(base_policy)
    profiles = parse_profiles(base_policy, required, forbidden, allowed_budgets, set())
    summary = build_summary(pathlib.Path("policy.json"), target, profiles)
    assert summary["profile_count"] == 1
    assert "cargo build" in summary["profiles"][0]["cargo_command"]

    bad_missing_feature = copy.deepcopy(base_policy)
    bad_missing_feature["profiles"][0]["cargo"]["features"] = ["wasm-browser-preview"]
    try:
        parse_profiles(bad_missing_feature, required, forbidden, allowed_budgets, set())
    except PolicyError:
        pass
    else:
        raise AssertionError("expected missing required feature rejection")

    bad_duplicate_variant = copy.deepcopy(base_policy)
    bad_duplicate_variant["profiles"].append(copy.deepcopy(base_policy["profiles"][0]))
    bad_duplicate_variant["profiles"][1]["id"] = "wasm-browser-dev-2"
    try:
        parse_profiles(bad_duplicate_variant, required, forbidden, allowed_budgets, set())
    except PolicyError:
        pass
    else:
        raise AssertionError("expected duplicate variant rejection")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        print("wasm optimization policy self-test passed")
        return 0

    policy_path = pathlib.Path(args.policy)
    policy = load_json(policy_path)
    target, required, forbidden, allowed_budgets, default_summary_path = parse_contract(policy)
    only_profiles = set(args.only_profile)
    profiles = parse_profiles(policy, required, forbidden, allowed_budgets, only_profiles)

    summary = build_summary(policy_path, target, profiles)
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
