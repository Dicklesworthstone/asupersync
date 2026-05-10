#!/usr/bin/env python3
"""Scan fuzz targets for conservative oracle-debt patterns.

The scanner is intentionally read-only and line-oriented. It focuses on
patterns that commonly hide fuzzer-visible failures: fallback defaults on
serialization, ignored encoder/parser results, swallowed thread panics, and
catch_unwind paths that turn panics into ordinary early returns.
"""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "fuzz-oracle-debt-scan-v1"
FUZZ_ROOT = Path("fuzz/fuzz_targets")
SERDE_DEFAULT_RE = re.compile(
    r"(serde_json::to_(?:string|vec)(?:_pretty)?|rmp_serde::to_vec).*\.unwrap_or_default\("
)
JOIN_FALLBACK_RE = re.compile(r"\.join\(\)\.unwrap_or(?:_default)?\(")
IGNORED_RESULT_RE = re.compile(
    r"^\s*let\s+_\s*=\s*.*(?:\.encode\(|\.decode\(|serde_json::to_|serde_json::from_)"
)
CATCH_UNWIND_RE = re.compile(r"(?:std::panic::)?catch_unwind\(")
ERR_RETURN_RE = re.compile(r"^\s*Err\s*\([^)]*\)\s*=>\s*return\b")


SUGGESTIONS = {
    "swallowed-serialization-default": (
        "replace the fallback with expect(...) carrying scenario context, or assert the "
        "round-trip result explicitly"
    ),
    "thread-join-fallback": (
        "use join().expect(...) so worker thread panics stay visible to libFuzzer"
    ),
    "ignored-result": (
        "assert success or match the error explicitly with scenario context instead of discarding it"
    ),
    "catch-unwind-return": (
        "assert the panic result or attach scenario context before returning from the fuzz case"
    ),
}


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


def relpath(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def add_finding(
    findings: list[dict[str, Any]],
    *,
    repo_root: Path,
    path: Path,
    line_number: int,
    pattern: str,
    line: str,
) -> None:
    findings.append(
        {
            "file": relpath(path, repo_root),
            "line": line_number,
            "pattern": pattern,
            "confidence": "high",
            "snippet": line.strip(),
            "suggested_assertion": SUGGESTIONS[pattern],
        }
    )


def has_recent_catch_unwind(lines: list[str], index: int) -> bool:
    start = max(0, index - 8)
    return any(CATCH_UNWIND_RE.search(line) for line in lines[start : index + 1])


def scan_file(path: Path, repo_root: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    findings: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        line_number = index + 1
        if SERDE_DEFAULT_RE.search(line):
            add_finding(
                findings,
                repo_root=repo_root,
                path=path,
                line_number=line_number,
                pattern="swallowed-serialization-default",
                line=line,
            )
        if JOIN_FALLBACK_RE.search(line):
            add_finding(
                findings,
                repo_root=repo_root,
                path=path,
                line_number=line_number,
                pattern="thread-join-fallback",
                line=line,
            )
        if IGNORED_RESULT_RE.search(line):
            add_finding(
                findings,
                repo_root=repo_root,
                path=path,
                line_number=line_number,
                pattern="ignored-result",
                line=line,
            )
        if ERR_RETURN_RE.search(line) and has_recent_catch_unwind(lines, index):
            add_finding(
                findings,
                repo_root=repo_root,
                path=path,
                line_number=line_number,
                pattern="catch-unwind-return",
                line=line,
            )
    return findings


def scan_root(root: Path, repo_root: Path) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    findings: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.rs")):
        if path.is_file():
            findings.extend(scan_file(path, repo_root))
    return sorted(
        findings,
        key=lambda row: (row["file"], row["line"], row["pattern"], row["snippet"]),
    )


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_pattern: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for row in findings:
        by_pattern[row["pattern"]] = by_pattern.get(row["pattern"], 0) + 1
        by_file[row["file"]] = by_file.get(row["file"], 0) + 1
    return {
        "total_findings": len(findings),
        "by_pattern": dict(sorted(by_pattern.items())),
        "by_file": dict(sorted(by_file.items())),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    scan_root_path = (repo_root / args.root).resolve()
    generated_at = args.generated_at or utc_now()
    findings = scan_root(scan_root_path, repo_root)
    summary = summarize(findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "repo_root": str(repo_root),
        "scan_root": relpath(scan_root_path, repo_root),
        "scope": "fuzz-targets-only",
        "summary": summary,
        "findings": findings,
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan fuzz targets for oracle debt")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--root", default=FUZZ_ROOT.as_posix(), help="Scan root relative to repo")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        report = build_report(args)
    except OSError as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
