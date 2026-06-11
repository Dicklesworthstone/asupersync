#!/usr/bin/env python3
"""Deterministic semantic lint runner for high-risk asupersync rules."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

RULE_ID = "ambient-time-or-entropy-in-lab-sensitive-code"
SCHEMA_VERSION = "semantic-lint-results-v1"
ALLOW_PREFIX = "asupersync-lint:allow"
OWNER_RE = re.compile(r"^asupersync-[A-Za-z0-9_.-]+$")
TARGET_PREFIXES = (
    "src/lab/",
    "src/trace/",
    "src/runtime/scheduler/",
    "tests/",
)


@dataclass(frozen=True)
class PatternSpec:
    pattern_id: str
    ast_grep_pattern: str
    diagnostic: str


@dataclass(frozen=True)
class RawMatch:
    path: str
    line: int
    column: int
    matched_text: str
    pattern: PatternSpec


PATTERNS = (
    PatternSpec(
        "system-time-now-qualified",
        "std::time::SystemTime::now()",
        "ambient wall-clock call in lab-sensitive path risks deterministic replay",
    ),
    PatternSpec(
        "system-time-now-imported",
        "SystemTime::now()",
        "ambient wall-clock call in lab-sensitive path risks deterministic replay",
    ),
    PatternSpec(
        "instant-now-qualified",
        "std::time::Instant::now()",
        "ambient monotonic host-time call in lab-sensitive path risks deterministic replay",
    ),
    PatternSpec(
        "instant-now-imported",
        "Instant::now()",
        "ambient monotonic host-time call in lab-sensitive path risks deterministic replay",
    ),
    PatternSpec(
        "wall-now-crate",
        "crate::time::wall_now()",
        "crate wall-clock helper in lab-sensitive path must be virtualized or allowed",
    ),
    PatternSpec(
        "wall-now-imported",
        "wall_now()",
        "wall-clock helper in lab-sensitive path must be virtualized or allowed",
    ),
    PatternSpec(
        "thread-rng-qualified",
        "rand::thread_rng()",
        "ambient entropy call in lab-sensitive path risks nondeterministic replay",
    ),
    PatternSpec(
        "thread-rng-imported",
        "thread_rng()",
        "ambient entropy call in lab-sensitive path risks nondeterministic replay",
    ),
    PatternSpec(
        "rand-rng-qualified",
        "rand::rng()",
        "ambient entropy call in lab-sensitive path risks nondeterministic replay",
    ),
    PatternSpec(
        "rand-rng-imported",
        "rng()",
        "ambient entropy call in lab-sensitive path risks nondeterministic replay",
    ),
)


def repo_relative(path: Path, cwd: Path) -> str:
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def is_in_target_scope(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in TARGET_PREFIXES)


def collect_rust_files(paths: Iterable[str], cwd: Path, all_paths: bool) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.is_absolute():
            path = cwd / path
        if path.is_dir():
            files.extend(child for child in path.rglob("*.rs") if child.is_file())
        elif path.is_file() and path.suffix == ".rs":
            files.append(path)

    unique = sorted({path.resolve() for path in files}, key=lambda item: repo_relative(item, cwd))
    if all_paths:
        return unique
    return [path for path in unique if is_in_target_scope(repo_relative(path, cwd))]


def parse_marker(line: str) -> dict[str, object] | None:
    if ALLOW_PREFIX not in line:
        return None

    marker = line.split(ALLOW_PREFIX, 1)[1].strip()
    parts = marker.split()
    if not parts:
        return {
            "valid": False,
            "reason": "",
            "owner": "",
            "errors": ["missing rule id"],
        }

    marker_rule = parts[0]
    metadata: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        metadata[key] = value

    if marker_rule != RULE_ID:
        return None

    errors: list[str] = []
    reason = metadata.get("reason", "")
    owner = metadata.get("owner", "")
    if not reason:
        errors.append("missing reason")
    if not owner:
        errors.append("missing owner")
    elif not OWNER_RE.fullmatch(owner):
        errors.append("owner must be an asupersync bead id")

    return {
        "valid": not errors,
        "reason": reason,
        "owner": owner,
        "errors": errors,
    }


def allow_marker_for(lines: list[str], one_based_line: int) -> dict[str, object] | None:
    candidate_indexes = [one_based_line - 1, one_based_line - 2]
    for index in candidate_indexes:
        if 0 <= index < len(lines):
            marker = parse_marker(lines[index])
            if marker is not None:
                return marker
    return None


def strip_simple_comments_and_strings(line: str) -> str:
    masked: list[str] = []
    in_string = False
    in_char = False
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        next_char = line[index + 1] if index + 1 < len(line) else ""
        if not in_string and not in_char and char == "/" and next_char == "/":
            masked.extend(" " * (len(line) - index))
            break
        if in_string:
            masked.append(" ")
            if char == '"' and not escaped:
                in_string = False
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            index += 1
            continue
        if in_char:
            masked.append(" ")
            if char == "'" and not escaped:
                in_char = False
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            index += 1
            continue
        if char == '"':
            in_string = True
            escaped = False
            masked.append(" ")
        elif char == "'":
            in_char = True
            escaped = False
            masked.append(" ")
        else:
            masked.append(char)
        index += 1
    return "".join(masked)


def token_has_boundary(masked: str, start: int, token: str) -> bool:
    before = masked[start - 1] if start > 0 else ""
    end = start + len(token)
    after = masked[end] if end < len(masked) else ""
    if token.startswith(("std::", "crate::", "rand::")):
        return not (before.isalnum() or before == "_")
    if before.isalnum() or before in "_.:":
        return False
    return not (after.isalnum() or after == "_")


def fallback_positions(masked: str, token: str) -> list[int]:
    positions: list[int] = []
    cursor = 0
    while cursor < len(masked):
        start = masked.find(token, cursor)
        if start < 0:
            break
        if token_has_boundary(masked, start, token):
            positions.append(start)
        cursor = start + 1
    return positions


def run_portable_fallback(files: list[Path], cwd: Path) -> list[RawMatch]:
    matches: list[RawMatch] = []
    for path in files:
        rel = repo_relative(path, cwd)
        for line_index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            masked = strip_simple_comments_and_strings(line)
            for pattern in PATTERNS:
                token = pattern.ast_grep_pattern
                for start in fallback_positions(masked, token):
                    matches.append(
                        RawMatch(
                            path=rel,
                            line=line_index,
                            column=start + 1,
                            matched_text=token,
                            pattern=pattern,
                        )
                    )
    return matches


def run_ast_grep(files: list[Path], cwd: Path) -> list[RawMatch]:
    matches: list[RawMatch] = []
    for pattern in PATTERNS:
        command = [
            "ast-grep",
            "run",
            "--lang",
            "rust",
            "--pattern",
            pattern.ast_grep_pattern,
            "--json=compact",
            "--color",
            "never",
            *[str(path) for path in files],
        ]
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise RuntimeError(
                f"ast-grep failed for {pattern.pattern_id}: {completed.stderr.strip()}"
            )
        parsed = json.loads(completed.stdout or "[]")
        for item in parsed:
            raw_path = Path(item["file"])
            if not raw_path.is_absolute():
                raw_path = cwd / raw_path
            start = item["range"]["start"]
            matches.append(
                RawMatch(
                    path=repo_relative(raw_path, cwd),
                    line=int(start["line"]) + 1,
                    column=int(start["column"]) + 1,
                    matched_text=item["text"],
                    pattern=pattern,
                )
            )
    return matches


def dedupe_matches(matches: Iterable[RawMatch]) -> list[RawMatch]:
    by_key: dict[tuple[str, int, int, str], RawMatch] = {}
    for match in matches:
        key = (match.path, match.line, match.column, match.pattern.pattern_id)
        by_key[key] = match
    return [by_key[key] for key in sorted(by_key)]


def build_result(files: list[Path], matches: list[RawMatch], engine: str, cwd: Path) -> dict[str, object]:
    lines_by_path = {
        repo_relative(path, cwd): path.read_text(encoding="utf-8").splitlines()
        for path in files
    }
    findings: list[dict[str, object]] = []
    suppressed: list[dict[str, object]] = []

    for match in dedupe_matches(matches):
        marker = allow_marker_for(lines_by_path[match.path], match.line)
        base = {
            "rule_id": RULE_ID,
            "path": match.path,
            "line": match.line,
            "column": match.column,
            "matched_text": match.matched_text,
            "pattern_id": match.pattern.pattern_id,
        }

        if marker and marker["valid"]:
            suppressed.append(
                {
                    **base,
                    "owner": marker["owner"],
                    "reason": marker["reason"],
                }
            )
            continue

        if marker and not marker["valid"]:
            findings.append(
                {
                    **base,
                    "kind": "invalid_allow_marker",
                    "severity": "error",
                    "diagnostic": "invalid allow marker metadata for deterministic replay risk",
                    "allow_marker_errors": marker["errors"],
                }
            )

        findings.append(
            {
                **base,
                "kind": "ambient_time_or_entropy",
                "severity": "error",
                "diagnostic": match.pattern.diagnostic,
            }
        )

    findings.sort(key=lambda item: (item["path"], item["line"], item["column"], item["kind"], item["pattern_id"]))
    suppressed.sort(key=lambda item: (item["path"], item["line"], item["column"], item["pattern_id"]))
    scanned = [repo_relative(path, cwd) for path in files]
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_id": RULE_ID,
        "engine": engine,
        "engine_fallback": engine == "portable-fallback",
        "verdict": "pass" if not findings else "fail",
        "scanned_files": scanned,
        "findings": findings,
        "suppressed": suppressed,
        "summary": {
            "files_scanned": len(scanned),
            "findings": len(findings),
            "suppressed": len(suppressed),
            "invalid_allow_markers": sum(
                1 for finding in findings if finding["kind"] == "invalid_allow_marker"
            ),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Rust files or directories to scan")
    parser.add_argument(
        "--rule",
        default=RULE_ID,
        choices=[RULE_ID],
        help="semantic lint rule id to run",
    )
    parser.add_argument(
        "--engine",
        default="auto",
        choices=["auto", "ast-grep", "portable-fallback"],
        help="analysis engine; auto prefers ast-grep and falls back deterministically",
    )
    parser.add_argument(
        "--all-paths",
        action="store_true",
        help="scan provided Rust files even when they are outside the rule target paths",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit deterministic JSON results",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="return success even when findings are present, for contract tests",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    cwd = Path.cwd()
    files = collect_rust_files(args.paths, cwd, args.all_paths)

    engine = args.engine
    if engine == "auto":
        engine = "ast-grep" if shutil.which("ast-grep") else "portable-fallback"
    if engine == "ast-grep" and not shutil.which("ast-grep"):
        result = {
            "schema_version": SCHEMA_VERSION,
            "rule_id": RULE_ID,
            "engine": "ast-grep",
            "engine_fallback": False,
            "verdict": "fail",
            "scanned_files": [repo_relative(path, cwd) for path in files],
            "findings": [
                {
                    "rule_id": RULE_ID,
                    "kind": "missing_engine",
                    "severity": "error",
                    "diagnostic": "ast-grep is required for this semantic lint rule",
                }
            ],
            "suppressed": [],
            "summary": {
                "files_scanned": len(files),
                "findings": 1,
                "suppressed": 0,
                "invalid_allow_markers": 0,
            },
        }
    else:
        matches = run_ast_grep(files, cwd) if engine == "ast-grep" else run_portable_fallback(files, cwd)
        result = build_result(files, matches, engine, cwd)

    output = json.dumps(result, indent=2, sort_keys=True)
    if args.json:
        print(output)
    else:
        print(output)
    if args.exit_zero:
        return 0
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
