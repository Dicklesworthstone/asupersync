#!/usr/bin/env python3
"""Validate fuzz target registration and render bin-scoped proof lanes.

The helper reads a Cargo fuzz manifest and a fuzz target directory. It does not
edit the manifest, create targets, run cargo, mutate git, or mutate beads.
"""

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "fuzz-target-registry-contract-v1"
DEFAULT_PROOF_MANIFEST_PATH = "fuzz/Cargo.toml"
DEFAULT_TARGET_ROOT = "fuzz/fuzz_targets"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime | None:
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


def normalize_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return normalize_path(resolved.relative_to(Path.cwd().resolve()).as_posix())
    except ValueError:
        return normalize_path(resolved.as_posix())


def relative_to_manifest(manifest_path: Path, target_path: str) -> str:
    path = Path(target_path)
    if not path.is_absolute():
        path = manifest_path.parent / path
    return display_path(path)


def proof_target_dir(target_name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_]+", "_", target_name).strip("_")
    return f"${{TMPDIR:-/tmp}}/rch_target_<agent>_{safe_name}"


def proof_lane_commands(target_name: str, manifest_path: str) -> dict[str, str]:
    target_dir = proof_target_dir(target_name)
    prefix = f"rch exec -- env CARGO_TARGET_DIR={target_dir} cargo"
    return {
        "target_dir": target_dir,
        "check": f"{prefix} check --manifest-path {manifest_path} --bin {target_name}",
        "clippy": (
            f"{prefix} clippy --manifest-path {manifest_path} --bin {target_name} "
            "--no-deps -- -D warnings"
        ),
        "smoke_run": f"{prefix} run --manifest-path {manifest_path} --bin {target_name} -- -runs=1",
    }


def allowed_names_for_path(path: str) -> list[str]:
    stem = Path(path).stem
    return [stem, f"fuzz_{stem}"]


def bin_rows(manifest_path: Path, proof_manifest_path: str) -> list[dict[str, Any]]:
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for item in data.get("bin", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        path = normalize_path(str(item.get("path") or ""))
        if not name or not path:
            continue
        full_path = relative_to_manifest(manifest_path, path)
        rows.append(
            {
                "name": name,
                "manifest_path": path,
                "target_path": full_path,
                "test": bool(item.get("test", True)),
                "doc": bool(item.get("doc", True)),
                "bench": bool(item.get("bench", True)),
                "allowed_names": allowed_names_for_path(path),
                "proof_lane": proof_lane_commands(name, proof_manifest_path),
            }
        )
    return sorted(rows, key=lambda row: (row["target_path"], row["name"]))


def target_files(target_root: Path) -> list[str]:
    if not target_root.exists():
        return []
    return sorted(display_path(path) for path in target_root.glob("*.rs") if path.is_file())


def issue(code: str, severity: str, **fields: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"code": code, "severity": severity}
    row.update(fields)
    return row


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.manifest)
    proof_manifest_path = args.proof_manifest_path or DEFAULT_PROOF_MANIFEST_PATH
    generated_at = args.generated_at or utc_now()
    rows = bin_rows(manifest_path, proof_manifest_path)
    files = target_files(Path(args.target_root))

    names = Counter(row["name"] for row in rows)
    paths = Counter(row["target_path"] for row in rows)
    registered_paths = {row["target_path"] for row in rows}
    file_set = set(files)
    issues: list[dict[str, Any]] = []

    for name, count in sorted(names.items()):
        if count > 1:
            issues.append(issue("duplicate-bin-name", "blocker", name=name, count=count))
    for path, count in sorted(paths.items()):
        if count > 1:
            issues.append(issue("duplicate-target-path", "blocker", path=path, count=count))
    for path in files:
        if path not in registered_paths:
            issues.append(issue("missing-registration", "blocker", path=path))
    for row in rows:
        if row["target_path"] not in file_set:
            issues.append(
                issue(
                    "missing-target-file",
                    "blocker",
                    name=row["name"],
                    path=row["target_path"],
                )
            )
        if row["name"] not in row["allowed_names"]:
            issues.append(
                issue(
                    "bin-name-path-mismatch",
                    "blocker",
                    name=row["name"],
                    path=row["target_path"],
                    allowed_names=row["allowed_names"],
                )
            )
        for flag in ("test", "doc", "bench"):
            if row[flag]:
                issues.append(
                    issue(
                        "missing-fuzz-bin-flag",
                        "blocker",
                        name=row["name"],
                        path=row["target_path"],
                        flag=flag,
                    )
                )

    blocker_count = sum(1 for row in issues if row["severity"] == "blocker")
    warning_count = sum(1 for row in issues if row["severity"] == "warning")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "manifest_path": display_path(manifest_path),
        "target_root": display_path(Path(args.target_root)),
        "proof_manifest_path": proof_manifest_path,
        "summary": {
            "passes": blocker_count == 0,
            "registered_targets": len(rows),
            "target_files": len(files),
            "blockers": blocker_count,
            "warnings": warning_count,
        },
        "registered_targets": rows,
        "orphan_target_files": sorted(path for path in files if path not in registered_paths),
        "issues": sorted(issues, key=lambda row: (row["code"], row.get("path", ""), row.get("name", ""))),
        "requirements": {
            "every_target_file_has_one_bin": not any(
                row["code"] in {"missing-registration", "duplicate-target-path"} for row in issues
            ),
            "bin_names_are_unique": not any(row["code"] == "duplicate-bin-name" for row in issues),
            "bin_name_matches_target_file": not any(
                row["code"] == "bin-name-path-mismatch" for row in issues
            ),
            "bin_scoped_proof_lane_documented": not any(
                row["code"] == "missing-fuzz-bin-flag" for row in issues
            ),
        },
        "non_mutating": True,
        "forbidden_actions": {
            "edits_fuzz_manifest": False,
            "creates_fuzz_targets": False,
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate fuzz target registry proof lanes")
    parser.add_argument("--manifest", required=True, help="Path to fuzz/Cargo.toml or a fixture")
    parser.add_argument(
        "--target-root",
        required=True,
        help="Directory containing fuzz target .rs files",
    )
    parser.add_argument(
        "--proof-manifest-path",
        default=DEFAULT_PROOF_MANIFEST_PATH,
        help="Manifest path to embed in generated proof commands",
    )
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except OSError as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2
    except tomllib.TOMLDecodeError as error:
        print(json.dumps({"error": f"invalid TOML: {error}"}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
