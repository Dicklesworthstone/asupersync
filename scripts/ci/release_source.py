#!/usr/bin/env python3
"""Resolve an existing release tag once; never infer its source from dispatch HEAD.

Reads Git objects, not the calling checkout's manifests. No Cargo execution,
network access, tag creation, or publishing. Python 3.11+ (stdlib only).
"""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")
SHA = re.compile(r"[0-9a-f]{40}")
NIGHTLY = re.compile(r"nightly-(\d{4}-\d{2}-\d{2})")


class ReleaseSourceError(ValueError):
    """A release identity could not be established without guessing."""


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        check=False, capture_output=True, text=True,
    )
    if result.returncode:
        raise ReleaseSourceError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def resolve(repo: Path, tag: str, *, allow_missing_changelog: bool = False,
            expected_sha: str | None = None) -> dict[str, str]:
    match = TAG.fullmatch(tag)
    if not match or any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in (match.group(4) or "").split(".")
    ):
        raise ReleaseSourceError("expected an exact vMAJOR.MINOR.PATCH[-PRERELEASE] tag")
    # Qualifying refs/tags explicitly avoids branch/tag ambiguity. ^{commit}
    # peels annotated tags and refuses tags pointing at blobs or trees.
    source_sha = git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").strip()
    if not SHA.fullmatch(source_sha):
        raise ReleaseSourceError("tag did not resolve to a full GitHub commit SHA")
    if expected_sha is not None:
        if not SHA.fullmatch(expected_sha) or source_sha != expected_sha:
            raise ReleaseSourceError("release tag moved or differs from the planned source SHA")
        if git(repo, "rev-parse", "HEAD").strip() != expected_sha:
            raise ReleaseSourceError("checkout HEAD differs from the qualified release source")
        if git(repo, "status", "--porcelain=v1", "--untracked-files=no").strip():
            raise ReleaseSourceError("release checkout has tracked modifications")

    def document(path: str) -> dict:
        try:
            return tomllib.loads(git(repo, "show", f"{source_sha}:{path}"))
        except tomllib.TOMLDecodeError as error:
            raise ReleaseSourceError(f"invalid tagged {path}: {error}") from error

    package = document("Cargo.toml").get("package", {})
    version = tag[1:]
    if package.get("name") != "asupersync" or package.get("version") != version:
        raise ReleaseSourceError("tag version does not match the tagged asupersync package")
    toolchain = document("rust-toolchain.toml").get("toolchain", {}).get("channel")
    pin = NIGHTLY.fullmatch(toolchain) if isinstance(toolchain, str) else None
    if pin is None:
        raise ReleaseSourceError("tagged release toolchain must pin nightly-YYYY-MM-DD")
    try:
        date.fromisoformat(pin.group(1))
    except ValueError as error:
        raise ReleaseSourceError("tagged nightly pin is not a calendar date") from error
    if not allow_missing_changelog:
        changelog = git(repo, "show", f"{source_sha}:CHANGELOG.md")
        heading = re.compile(r"^##\s+\[?v?" + re.escape(version) + r"\]?(?:\s|$)", re.MULTILINE)
        if not heading.search(changelog):
            raise ReleaseSourceError("release entry missing from the tagged CHANGELOG.md")
    return {
        "tag": tag,
        "version": version,
        "prerelease": str(match.group(4) is not None).lower(),
        "source_sha": source_sha,
        "rust_toolchain": toolchain,
    }


def validate_publish_order(metadata: dict, contract: dict, workflow: str) -> list[str]:
    """Check the declared release surface against Cargo's complete workspace graph.

    Cargo metadata preserves optional, target-specific, renamed and inherited
    dependencies here, without resolving a feature-filtered build graph.
    Development edges do not constrain publication order (they can be cyclic).
    """
    rows = contract.get("published_crate_surface", [])
    names = [row.get("package") for row in rows]
    if not names or len(set(names)) != len(names):
        raise ReleaseSourceError("publish surface is empty or contains duplicate packages")
    if [row.get("publish_order") for row in rows] != list(range(1, len(rows) + 1)):
        raise ReleaseSourceError("publish surface orders must be contiguous starting at one")

    arrays = re.findall(r"^[ \t]*crates=\(\s*\n(.*?)^[ \t]*\)", workflow,
                        re.MULTILINE | re.DOTALL)
    if len(arrays) != 1:
        raise ReleaseSourceError("expected one explicit crates array in publish workflow")
    workflow_names = shlex.split(arrays[0], comments=True)
    if names != workflow_names:
        raise ReleaseSourceError("publish workflow order differs from the crate surface")

    workspace_ids = set(metadata.get("workspace_members", []))
    packages = {package["name"]: package for package in metadata.get("packages", [])
                if package["id"] in workspace_ids}
    if len(packages) != len(workspace_ids):
        raise ReleaseSourceError("Cargo metadata does not describe every workspace package")
    publishable = {name for name, package in packages.items()
                   if package.get("publish") is None or "crates-io" in package["publish"]}
    if set(names) != publishable:
        raise ReleaseSourceError(
            f"publish surface differs from publishable workspace packages: "
            f"missing={sorted(publishable - set(names))}, "
            f"extra={sorted(set(names) - publishable)}")

    workspace_root = Path(metadata["workspace_root"]).resolve()
    order = {name: index for index, name in enumerate(names)}
    for row in rows:
        name = row["package"]
        manifest = Path(row["manifest_path"])
        if manifest.is_absolute() or not (workspace_root / manifest).resolve().is_relative_to(workspace_root):
            raise ReleaseSourceError(f"{name}: manifest must stay inside the workspace")
        expected_manifest = Path(packages[name]["manifest_path"]).resolve()
        if (workspace_root / manifest).resolve() != expected_manifest:
            raise ReleaseSourceError(f"{name}: manifest path differs from Cargo metadata")
        for dependency in packages[name].get("dependencies", []):
            if dependency.get("kind") == "dev" or dependency.get("path") is None:
                continue
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                continue  # A local dependency outside this workspace is not our release surface.
            if dependency_name not in order:
                raise ReleaseSourceError(f"{name}: workspace dependency {dependency_name} is not publishable")
            dependency_manifest = Path(dependency["path"]) / "Cargo.toml"
            if dependency_manifest.resolve() != Path(packages[dependency_name]["manifest_path"]).resolve():
                raise ReleaseSourceError(f"{name}: workspace dependency {dependency_name} has a different path")
            if order[dependency_name] >= order[name]:
                raise ReleaseSourceError(f"{name}: publish dependency {dependency_name} first")
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    parser.add_argument("--verify-head", metavar="PLANNED_SHA")
    parser.add_argument("--allow-missing-changelog", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--check-publish-order", type=Path, metavar="CARGO_METADATA_JSON")
    args = parser.parse_args()
    if not args.tag and args.check_publish_order is None:
        parser.error("--tag or RELEASE_TAG is required")
    try:
        if args.check_publish_order is not None:
            metadata = json.loads(args.check_publish_order.read_text(encoding="utf-8"))
            contract = json.loads((args.repo / "artifacts/rust_crate_release_provenance_contract_v1.json")
                                  .read_text(encoding="utf-8"))
            workflow = (args.repo / ".github/workflows/publish.yml").read_text(encoding="utf-8")
            print(json.dumps({"publish_order": validate_publish_order(metadata, contract, workflow)}))
            return 0
        identity = resolve(args.repo, args.tag,
                           allow_missing_changelog=args.allow_missing_changelog,
                           expected_sha=args.verify_head)
        # Emit outputs only after every check passes. All values have been
        # constrained above; no caller-controlled newline enters GITHUB_OUTPUT.
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in identity.items():
                    output.write(f"{key}={value}\n")
        print(json.dumps(identity, sort_keys=True))
    except (ReleaseSourceError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"release source refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
