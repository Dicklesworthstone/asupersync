#!/usr/bin/env python3
"""Emit deterministic proof-pack cache-key receipts.

The helper is intentionally non-mutating. It defines the key material a later
cache-warming planner may use to find warm rch workers, while refusing to make
cache reuse authoritative proof evidence.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-pack-cache-key-receipt-v1"
INPUT_SCHEMA_VERSION = "proof-pack-cache-key-input-v1"
MAIN_BRANCH = "main"
HEAD_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
KEYED_ENV_FLAGS = {
    "CARGO_BUILD_JOBS",
    "CARGO_INCREMENTAL",
    "CARGO_PROFILE_TEST_DEBUG",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and item})


def object_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(item)
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        if item is not None
    }


def normalized_env(raw_env: Any) -> tuple[dict[str, str], list[str]]:
    env = string_map(raw_env)
    keyed = {key: env[key] for key in sorted(env) if key in KEYED_ENV_FLAGS}
    ignored = [key for key in sorted(env) if key not in KEYED_ENV_FLAGS]
    return keyed, ignored


def nested_string(raw: dict[str, Any], dotted_path: str) -> str:
    cursor: Any = raw
    for part in dotted_path.split("."):
        if not isinstance(cursor, dict):
            return ""
        cursor = cursor.get(part)
    return string_value(cursor)


def normalize_key_material(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    repo = object_value(raw.get("repo"))
    rust_toolchain = object_value(raw.get("rust_toolchain"))
    cargo_lock_sha256 = string_value(raw.get("cargo_lock_sha256")) or nested_string(
        raw, "cargo_lock.sha256"
    )
    keyed_env, ignored_env_keys = normalized_env(raw.get("env"))

    return (
        {
            "schema_version": INPUT_SCHEMA_VERSION,
            "cargo_lock_sha256": cargo_lock_sha256,
            "env": keyed_env,
            "features": string_list(raw.get("features")),
            "git": {
                "branch": string_value(repo.get("branch")) or string_value(raw.get("git_branch")),
                "head_sha": string_value(repo.get("head_sha")) or string_value(raw.get("head_sha")),
                "ref_kind": string_value(repo.get("ref_kind")) or "branch",
            },
            "proof_lane_family": string_value(raw.get("proof_lane_family")),
            "rust_toolchain": {
                "channel": string_value(rust_toolchain.get("channel")),
                "components": string_list(rust_toolchain.get("components")),
                "profile": string_value(rust_toolchain.get("profile")),
                "targets": string_list(rust_toolchain.get("targets")),
            },
            "target_triple": string_value(raw.get("target_triple")),
            "workspace_package": string_value(raw.get("workspace_package")),
        },
        ignored_env_keys,
    )


def missing_required_reasons(material: dict[str, Any]) -> list[str]:
    required_paths = [
        ("cargo_lock_sha256",),
        ("proof_lane_family",),
        ("target_triple",),
        ("workspace_package",),
        ("git", "branch"),
        ("git", "head_sha"),
        ("rust_toolchain", "channel"),
    ]
    reasons = []
    for path in required_paths:
        cursor: Any = material
        for key in path:
            cursor = cursor.get(key) if isinstance(cursor, dict) else ""
        if not isinstance(cursor, str) or not cursor:
            reasons.append("missing-required-input:" + ".".join(path))
    return reasons


def refusal_reasons(material: dict[str, Any]) -> list[str]:
    reasons = missing_required_reasons(material)
    branch = material["git"]["branch"]
    head_sha = material["git"]["head_sha"]
    if branch and branch != MAIN_BRANCH:
        reasons.append("non-main-ref")
    if head_sha and HEAD_SHA_RE.fullmatch(head_sha) is None:
        reasons.append("unknown-head-sha")
    return sorted(set(reasons))


def safety_contract() -> dict[str, Any]:
    return {
        "warmed_caches_are_advisory_only": True,
        "proof_must_still_execute": True,
        "branch_required": MAIN_BRANCH,
        "cross_ref_reuse_forbidden": True,
        "unknown_ref_reuse_forbidden": True,
        "stale_cache_behavior": "discard cache hint, recompute key, and run proof in an isolated CARGO_TARGET_DIR",
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    raw = load_json(args.input)
    if not isinstance(raw, dict):
        raise ValueError("input must be a JSON object")
    generated_at = args.generated_at or utc_now()
    material, ignored_env_keys = normalize_key_material(raw)
    reasons = refusal_reasons(material)
    material_digest = canonical_digest(material)
    valid = not reasons
    cache_key = f"proof-pack-cache-v1:{material_digest[:24]}" if valid else ""

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "input_schema_version": INPUT_SCHEMA_VERSION,
        "decision": "emit-advisory-cache-key" if valid else "refuse-cache-key",
        "cache_key_valid": valid,
        "cache_key": cache_key,
        "cache_key_sha256": material_digest if valid else "",
        "key_material_digest_sha256": material_digest,
        "normalized_key_material": material,
        "ignored_env_keys": ignored_env_keys,
        "refusal_reasons": reasons,
        "invalidation_inputs": [
            "Cargo.lock sha256",
            "rust-toolchain identity",
            "target triple",
            "workspace package",
            "normalized feature set",
            "proof lane family",
            "keyed env flags",
            "main branch head sha",
        ],
        "safety_contract": safety_contract(),
        "non_mutating": True,
        "forbidden_actions": {
            "reads_remote_cache": False,
            "writes_remote_cache": False,
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a proof-pack cache-key receipt")
    parser.add_argument("--input", required=True, help="Proof-pack cache-key input JSON")
    parser.add_argument("--generated-at", default="", help="Stable UTC timestamp")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
