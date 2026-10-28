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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    parser.add_argument("--verify-head", metavar="PLANNED_SHA")
    parser.add_argument("--allow-missing-changelog", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if not args.tag:
        parser.error("--tag or RELEASE_TAG is required")
    try:
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
    except (ReleaseSourceError, OSError) as error:
        print(f"release source refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
