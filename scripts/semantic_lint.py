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

AMBIENT_RULE_ID = "ambient-time-or-entropy-in-lab-sensitive-code"
CLEANUP_BUDGET_RULE_ID = "unbounded-cleanup-budget"
CORE_TOKIO_RULE_ID = "core-tokio-feature-leakage"
SCHEMA_VERSION = "semantic-lint-results-v1"
ALLOW_PREFIX = "asupersync-lint:allow"
OWNER_RE = re.compile(r"^asupersync-[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class PatternSpec:
    pattern_id: str
    ast_grep_pattern: str
    fallback_tokens: tuple[str, ...]
    diagnostic: str


@dataclass(frozen=True)
class RuleConfig:
    rule_id: str
    finding_kind: str
    severity: str
    target_prefixes: tuple[str, ...]
    invalid_allow_marker_diagnostic: str
    patterns: tuple[PatternSpec, ...]


@dataclass(frozen=True)
class RawMatch:
    path: str
    line: int
    column: int
    matched_text: str
    pattern: PatternSpec


RULES: dict[str, RuleConfig] = {
    AMBIENT_RULE_ID: RuleConfig(
        rule_id=AMBIENT_RULE_ID,
        finding_kind="ambient_time_or_entropy",
        severity="error",
        target_prefixes=(
            "src/lab/",
            "src/trace/",
            "src/runtime/scheduler/",
            "tests/",
        ),
        invalid_allow_marker_diagnostic=(
            "invalid allow marker metadata for deterministic replay risk"
        ),
        patterns=(
            PatternSpec(
                "system-time-now-qualified",
                "std::time::SystemTime::now()",
                ("std::time::SystemTime::now()",),
                "ambient wall-clock call in lab-sensitive path risks deterministic replay",
            ),
            PatternSpec(
                "system-time-now-imported",
                "SystemTime::now()",
                ("SystemTime::now()",),
                "ambient wall-clock call in lab-sensitive path risks deterministic replay",
            ),
            PatternSpec(
                "instant-now-qualified",
                "std::time::Instant::now()",
                ("std::time::Instant::now()",),
                "ambient monotonic host-time call in lab-sensitive path risks deterministic replay",
            ),
            PatternSpec(
                "instant-now-imported",
                "Instant::now()",
                ("Instant::now()",),
                "ambient monotonic host-time call in lab-sensitive path risks deterministic replay",
            ),
            PatternSpec(
                "wall-now-crate",
                "crate::time::wall_now()",
                ("crate::time::wall_now()",),
                "crate wall-clock helper in lab-sensitive path must be virtualized or allowed",
            ),
            PatternSpec(
                "wall-now-imported",
                "wall_now()",
                ("wall_now()",),
                "wall-clock helper in lab-sensitive path must be virtualized or allowed",
            ),
            PatternSpec(
                "thread-rng-qualified",
                "rand::thread_rng()",
                ("rand::thread_rng()",),
                "ambient entropy call in lab-sensitive path risks nondeterministic replay",
            ),
            PatternSpec(
                "thread-rng-imported",
                "thread_rng()",
                ("thread_rng()",),
                "ambient entropy call in lab-sensitive path risks nondeterministic replay",
            ),
            PatternSpec(
                "rand-rng-qualified",
                "rand::rng()",
                ("rand::rng()",),
                "ambient entropy call in lab-sensitive path risks nondeterministic replay",
            ),
            PatternSpec(
                "rand-rng-imported",
                "rng()",
                ("rng()",),
                "ambient entropy call in lab-sensitive path risks nondeterministic replay",
            ),
        ),
    ),
    CLEANUP_BUDGET_RULE_ID: RuleConfig(
        rule_id=CLEANUP_BUDGET_RULE_ID,
        finding_kind="unbounded_cleanup_budget",
        severity="warning",
        target_prefixes=(
            "src/supervision.rs",
            "src/cancel/",
            "src/runtime/",
            "src/database/",
            "src/http/",
            "tests/",
        ),
        invalid_allow_marker_diagnostic=(
            "invalid allow marker metadata for cleanup budget risk"
        ),
        patterns=(
            PatternSpec(
                "budget-infinite",
                "Budget::INFINITE",
                ("Budget::INFINITE",),
                "cleanup or drain path uses Budget::INFINITE without a bounded owner",
            ),
            PatternSpec(
                "duration-from-secs-qualified",
                "std::time::Duration::from_secs($SECONDS)",
                ("std::time::Duration::from_secs(",),
                "ad hoc cleanup wall-duration should be derived from an explicit Budget",
            ),
            PatternSpec(
                "duration-from-secs-imported",
                "Duration::from_secs($SECONDS)",
                ("Duration::from_secs(",),
                "ad hoc cleanup wall-duration should be derived from an explicit Budget",
            ),
            PatternSpec(
                "cleanup-call-without-budget",
                "cleanup($$$ARGS)",
                ("cleanup(",),
                "cleanup call is missing an obvious Budget argument or owner allow marker",
            ),
            PatternSpec(
                "drain-call-without-budget",
                "drain($$$ARGS)",
                ("drain(",),
                "drain call is missing an obvious Budget argument or owner allow marker",
            ),
            PatternSpec(
                "finalize-call-without-budget",
                "finalize($$$ARGS)",
                ("finalize(",),
                "finalizer call is missing an obvious Budget argument or owner allow marker",
            ),
        ),
    ),
}


def repo_relative(path: Path, cwd: Path) -> str:
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def is_in_target_scope(path: str, rule: RuleConfig) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in rule.target_prefixes)


def collect_rust_files(
    paths: Iterable[str],
    cwd: Path,
    all_paths: bool,
    rule: RuleConfig,
) -> list[Path]:
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
    return [path for path in unique if is_in_target_scope(repo_relative(path, cwd), rule)]


def collect_json_files(paths: Iterable[str], cwd: Path) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.is_absolute():
            path = cwd / path
        if path.is_dir():
            files.extend(child for child in path.rglob("*.json") if child.is_file())
        elif path.is_file() and path.suffix == ".json":
            files.append(path)

    return sorted({path.resolve() for path in files}, key=lambda item: repo_relative(item, cwd))


def parse_marker(line: str, rule_id: str) -> dict[str, object] | None:
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

    if marker_rule != rule_id:
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


def allow_marker_for(
    lines: list[str],
    one_based_line: int,
    rule_id: str,
) -> dict[str, object] | None:
    candidate_indexes = [one_based_line - 1, one_based_line - 2]
    for index in candidate_indexes:
        if 0 <= index < len(lines):
            marker = parse_marker(lines[index], rule_id)
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
    if token.endswith("("):
        return True
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


def run_portable_fallback(
    files: list[Path],
    cwd: Path,
    rule: RuleConfig,
) -> list[RawMatch]:
    matches: list[RawMatch] = []
    for path in files:
        rel = repo_relative(path, cwd)
        for line_index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            masked = strip_simple_comments_and_strings(line)
            for pattern in rule.patterns:
                for token in pattern.fallback_tokens:
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


def run_ast_grep(
    files: list[Path],
    cwd: Path,
    rule: RuleConfig,
) -> list[RawMatch]:
    matches: list[RawMatch] = []
    for pattern in rule.patterns:
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


def raw_match_line_key(match: RawMatch) -> tuple[str, int, str]:
    return (match.path, match.line, match.pattern.pattern_id)


def line_has_budget_keyword(line: str) -> bool:
    return any(
        keyword in line
        for keyword in (
            "Budget",
            "budget",
            "deadline",
            "shutdown_budget",
            "cleanup_budget",
            "meet(",
        )
    )


def line_declares_function(line: str, name: str) -> bool:
    stripped = line.lstrip()
    visibility = r"(?:pub(?:\([^)]*\))?\s+)?"
    async_marker = r"(?:async\s+)?"
    pattern = rf"^{visibility}{async_marker}fn\s+{re.escape(name)}\s*\("
    return re.match(pattern, stripped) is not None


def cleanup_budget_filter(
    files: list[Path],
    matches: list[RawMatch],
    cwd: Path,
) -> list[RawMatch]:
    lines_by_path = {
        repo_relative(path, cwd): path.read_text(encoding="utf-8").splitlines()
        for path in files
    }
    filtered: list[RawMatch] = []
    for match in matches:
        if match.pattern.pattern_id in {
            "cleanup-call-without-budget",
            "drain-call-without-budget",
            "finalize-call-without-budget",
        }:
            line = lines_by_path[match.path][match.line - 1]
            function_name = match.pattern.pattern_id.split("-", 1)[0]
            if line_declares_function(line, function_name):
                continue
            if line_has_budget_keyword(line):
                continue
        filtered.append(match)
    return filtered


def postprocess_matches(
    files: list[Path],
    matches: list[RawMatch],
    cwd: Path,
    rule: RuleConfig,
) -> list[RawMatch]:
    if rule.rule_id == CLEANUP_BUDGET_RULE_ID:
        return cleanup_budget_filter(files, matches, cwd)
    return matches


def dedupe_matches(matches: Iterable[RawMatch]) -> list[RawMatch]:
    by_key: dict[tuple[str, int, int, str], RawMatch] = {}
    for match in matches:
        key = (match.path, match.line, match.column, match.pattern.pattern_id)
        by_key[key] = match
    return [by_key[key] for key in sorted(by_key)]


def suppress_overlapping_cleanup_call_findings(
    matches: list[RawMatch],
) -> list[RawMatch]:
    infinite_lines = {
        raw_match_line_key(match)
        for match in matches
        if match.pattern.pattern_id == "budget-infinite"
    }
    duration_lines = {
        (match.path, match.line)
        for match in matches
        if match.pattern.pattern_id
        in {"duration-from-secs-qualified", "duration-from-secs-imported"}
    }
    kept: list[RawMatch] = []
    for match in matches:
        if match.pattern.pattern_id in {
            "cleanup-call-without-budget",
            "drain-call-without-budget",
            "finalize-call-without-budget",
        }:
            if (
                (match.path, match.line, "budget-infinite") in infinite_lines
                or (match.path, match.line) in duration_lines
            ):
                continue
        kept.append(match)
    return kept


def normalize_matches(rule: RuleConfig, matches: Iterable[RawMatch]) -> list[RawMatch]:
    deduped = dedupe_matches(matches)
    if rule.rule_id == CLEANUP_BUDGET_RULE_ID:
        return suppress_overlapping_cleanup_call_findings(deduped)
    return deduped


def build_result(
    files: list[Path],
    matches: list[RawMatch],
    engine: str,
    cwd: Path,
    rule: RuleConfig,
) -> dict[str, object]:
    lines_by_path = {
        repo_relative(path, cwd): path.read_text(encoding="utf-8").splitlines()
        for path in files
    }
    findings: list[dict[str, object]] = []
    suppressed: list[dict[str, object]] = []

    for match in normalize_matches(rule, matches):
        marker = allow_marker_for(lines_by_path[match.path], match.line, rule.rule_id)
        base = {
            "rule_id": rule.rule_id,
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
                    "diagnostic": rule.invalid_allow_marker_diagnostic,
                    "allow_marker_errors": marker["errors"],
                }
            )

        findings.append(
            {
                **base,
                "kind": rule.finding_kind,
                "severity": rule.severity,
                "diagnostic": match.pattern.diagnostic,
            }
        )

    findings.sort(
        key=lambda item: (
            item["path"],
            item["line"],
            item["column"],
            item["kind"],
            item["pattern_id"],
        )
    )
    suppressed.sort(
        key=lambda item: (
            item["path"],
            item["line"],
            item["column"],
            item["pattern_id"],
        )
    )
    scanned = [repo_relative(path, cwd) for path in files]
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_id": rule.rule_id,
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


def missing_engine_result(files: list[Path], cwd: Path, rule: RuleConfig) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_id": rule.rule_id,
        "engine": "ast-grep",
        "engine_fallback": False,
        "verdict": "fail",
        "scanned_files": [repo_relative(path, cwd) for path in files],
        "findings": [
            {
                "rule_id": rule.rule_id,
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


def json_list_of_strings(value: dict[str, object], key: str) -> list[str]:
    raw = value.get(key, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, str)]


def cargo_tree_proof_command_errors(
    command: object,
    *,
    production: bool,
    scoped_audit: bool,
) -> list[str]:
    if not isinstance(command, str) or not command:
        return ["missing proof_command"]

    errors: list[str] = []
    padded = f" {command} "
    if not command.startswith("rch exec -- env "):
        errors.append("proof_command must start with `rch exec -- env`")
    if "CARGO_TARGET_DIR=" not in command:
        errors.append("proof_command must pin CARGO_TARGET_DIR")
    if " cargo tree " not in padded:
        errors.append("proof_command must invoke `cargo tree`")
    if "tokio" not in command:
        errors.append("proof_command must inspect tokio")
    if production and "--workspace" in command:
        errors.append("production proof_command must be package-scoped, not --workspace")
    if scoped_audit and "--workspace" not in command:
        errors.append("scoped audit proof_command must include --workspace")
    return errors


def add_core_tokio_finding(
    findings: list[dict[str, object]],
    *,
    path: str,
    section: str,
    profile: str,
    kind: str,
    diagnostic: str,
    details: object | None = None,
) -> None:
    finding: dict[str, object] = {
        "rule_id": CORE_TOKIO_RULE_ID,
        "kind": kind,
        "severity": "error",
        "path": path,
        "section": section,
        "profile": profile,
        "diagnostic": diagnostic,
    }
    if details is not None:
        finding["details"] = details
    findings.append(finding)


def classify_core_tokio_contract(
    path: Path,
    cwd: Path,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    rel = repo_relative(path, cwd)
    counts = {
        "production_profiles": 0,
        "quarantined_profiles": 0,
        "scoped_audit_profiles": 0,
    }
    findings: list[dict[str, object]] = []
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        add_core_tokio_finding(
            findings,
            path=rel,
            section="contract",
            profile="",
            kind="invalid_policy_contract",
            diagnostic=f"JSON contract could not be parsed: {err.msg}",
        )
        return findings, counts

    if not isinstance(parsed, dict):
        add_core_tokio_finding(
            findings,
            path=rel,
            section="contract",
            profile="",
            kind="invalid_policy_contract",
            diagnostic="contract root must be a JSON object",
        )
        return findings, counts

    production = parsed.get("production_guarantees", [])
    if not isinstance(production, list):
        add_core_tokio_finding(
            findings,
            path=rel,
            section="production_guarantees",
            profile="",
            kind="invalid_policy_contract",
            diagnostic="production_guarantees must be an array",
        )
        production = []

    for guarantee in production:
        if not isinstance(guarantee, dict):
            continue
        counts["production_profiles"] += 1
        profile = str(guarantee.get("profile", ""))
        status = guarantee.get("status")
        fragments = json_list_of_strings(guarantee, "expected_path_fragments")
        if status != "tokio_free_normal_graph":
            add_core_tokio_finding(
                findings,
                path=rel,
                section="production_guarantees",
                profile=profile,
                kind="core_tokio_feature_leakage",
                diagnostic="production asupersync normal dependency graph is not classified tokio-free",
                details={"status": status},
            )
        if any(fragment == "tokio" or fragment.startswith("tokio ") for fragment in fragments):
            add_core_tokio_finding(
                findings,
                path=rel,
                section="production_guarantees",
                profile=profile,
                kind="core_tokio_feature_leakage",
                diagnostic="production profile declares a tokio dependency path",
                details={"expected_path_fragments": fragments},
            )
        command_errors = cargo_tree_proof_command_errors(
            guarantee.get("proof_command"),
            production=True,
            scoped_audit=False,
        )
        if command_errors:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="production_guarantees",
                profile=profile,
                kind="malformed_proof_command",
                diagnostic="production profile proof command is not an RCH cargo-tree inversion",
                details=command_errors,
            )

    quarantined = parsed.get("quarantined_tokio_carrying_profiles", [])
    if not isinstance(quarantined, list):
        add_core_tokio_finding(
            findings,
            path=rel,
            section="quarantined_tokio_carrying_profiles",
            profile="",
            kind="invalid_policy_contract",
            diagnostic="quarantined_tokio_carrying_profiles must be an array",
        )
        quarantined = []

    for profile_row in quarantined:
        if not isinstance(profile_row, dict):
            continue
        counts["quarantined_profiles"] += 1
        profile = str(profile_row.get("profile", ""))
        status = profile_row.get("status")
        fragments = json_list_of_strings(profile_row, "expected_path_fragments")
        rationale = str(profile_row.get("rationale", "")).lower()
        if status != "tokio_carrying_quarantined":
            add_core_tokio_finding(
                findings,
                path=rel,
                section="quarantined_tokio_carrying_profiles",
                profile=profile,
                kind="misclassified_tokio_carveout",
                diagnostic="tokio-carrying fuzz or test profile must be explicitly quarantined",
                details={"status": status},
            )
        if "tokio" not in fragments:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="quarantined_tokio_carrying_profiles",
                profile=profile,
                kind="malformed_tokio_carveout",
                diagnostic="quarantined profile must declare the tokio path fragments it carries",
                details={"expected_path_fragments": fragments},
            )
        if "not" not in rationale or "production" not in rationale:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="quarantined_tokio_carrying_profiles",
                profile=profile,
                kind="malformed_tokio_carveout",
                diagnostic="quarantine rationale must state why the profile is not production proof",
            )
        command_errors = cargo_tree_proof_command_errors(
            profile_row.get("proof_command"),
            production=False,
            scoped_audit=False,
        )
        if command_errors:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="quarantined_tokio_carrying_profiles",
                profile=profile,
                kind="malformed_proof_command",
                diagnostic="quarantined profile proof command is not an RCH cargo-tree inversion",
                details=command_errors,
            )

    scoped_audits = parsed.get("scoped_audit_profiles", [])
    if not isinstance(scoped_audits, list):
        add_core_tokio_finding(
            findings,
            path=rel,
            section="scoped_audit_profiles",
            profile="",
            kind="invalid_policy_contract",
            diagnostic="scoped_audit_profiles must be an array",
        )
        scoped_audits = []

    for profile_row in scoped_audits:
        if not isinstance(profile_row, dict):
            continue
        counts["scoped_audit_profiles"] += 1
        profile = str(profile_row.get("profile", ""))
        status = profile_row.get("status")
        fragments = json_list_of_strings(profile_row, "expected_path_fragments")
        rationale = str(profile_row.get("rationale", "")).lower()
        if status != "tokio_carrying_scoped_audit":
            add_core_tokio_finding(
                findings,
                path=rel,
                section="scoped_audit_profiles",
                profile=profile,
                kind="misclassified_tokio_carveout",
                diagnostic="workspace, dev, or test tokio paths must stay scoped to audit profiles",
                details={"status": status},
            )
        if "tokio" not in fragments:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="scoped_audit_profiles",
                profile=profile,
                kind="malformed_tokio_carveout",
                diagnostic="scoped audit profile must declare the tokio path fragments it carries",
                details={"expected_path_fragments": fragments},
            )
        if "not" not in rationale or "production" not in rationale:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="scoped_audit_profiles",
                profile=profile,
                kind="malformed_tokio_carveout",
                diagnostic="scoped audit rationale must state why the profile is not production proof",
            )
        command_errors = cargo_tree_proof_command_errors(
            profile_row.get("proof_command"),
            production=False,
            scoped_audit=True,
        )
        if command_errors:
            add_core_tokio_finding(
                findings,
                path=rel,
                section="scoped_audit_profiles",
                profile=profile,
                kind="malformed_proof_command",
                diagnostic="scoped audit proof command is not an RCH cargo-tree inversion",
                details=command_errors,
            )

    findings.sort(
        key=lambda item: (
            item["path"],
            item["section"],
            item["profile"],
            item["kind"],
            item["diagnostic"],
        )
    )
    return findings, counts


def build_core_tokio_result(files: list[Path], engine: str, cwd: Path) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    summary = {
        "files_scanned": len(files),
        "findings": 0,
        "suppressed": 0,
        "invalid_allow_markers": 0,
        "production_profiles": 0,
        "quarantined_profiles": 0,
        "scoped_audit_profiles": 0,
    }
    for path in files:
        file_findings, counts = classify_core_tokio_contract(path, cwd)
        findings.extend(file_findings)
        for key, value in counts.items():
            summary[key] += value

    findings.sort(
        key=lambda item: (
            item["path"],
            item["section"],
            item["profile"],
            item["kind"],
            item["diagnostic"],
        )
    )
    summary["findings"] = len(findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_id": CORE_TOKIO_RULE_ID,
        "engine": engine,
        "engine_fallback": False,
        "verdict": "pass" if not findings else "fail",
        "scanned_files": [repo_relative(path, cwd) for path in files],
        "findings": findings,
        "suppressed": [],
        "summary": summary,
    }


def unsupported_engine_result(
    files: list[Path],
    cwd: Path,
    *,
    rule_id: str,
    engine: str,
    diagnostic: str,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_id": rule_id,
        "engine": engine,
        "engine_fallback": False,
        "verdict": "fail",
        "scanned_files": [repo_relative(path, cwd) for path in files],
        "findings": [
            {
                "rule_id": rule_id,
                "kind": "unsupported_engine",
                "severity": "error",
                "diagnostic": diagnostic,
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Rust or JSON files/directories to scan")
    parser.add_argument(
        "--rule",
        default=AMBIENT_RULE_ID,
        choices=sorted([*RULES, CORE_TOKIO_RULE_ID]),
        help="semantic lint rule id to run",
    )
    parser.add_argument(
        "--engine",
        default="auto",
        choices=["auto", "ast-grep", "portable-fallback", "cargo-metadata"],
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

    if args.rule == CORE_TOKIO_RULE_ID:
        files = collect_json_files(args.paths, cwd)
        engine = "cargo-metadata" if args.engine == "auto" else args.engine
        if engine != "cargo-metadata":
            result = unsupported_engine_result(
                files,
                cwd,
                rule_id=CORE_TOKIO_RULE_ID,
                engine=engine,
                diagnostic="core-tokio-feature-leakage requires the cargo-metadata engine",
            )
        else:
            result = build_core_tokio_result(files, engine, cwd)

        output = json.dumps(result, indent=2, sort_keys=True)
        if args.json:
            print(output)
        else:
            print(output)
        if args.exit_zero:
            return 0
        return 0 if result["verdict"] == "pass" else 1

    rule = RULES[args.rule]
    files = collect_rust_files(args.paths, cwd, args.all_paths, rule)

    engine = args.engine
    if engine == "cargo-metadata":
        result = unsupported_engine_result(
            files,
            cwd,
            rule_id=rule.rule_id,
            engine=engine,
            diagnostic=f"{rule.rule_id} requires ast-grep or portable-fallback",
        )
        output = json.dumps(result, indent=2, sort_keys=True)
        if args.json:
            print(output)
        else:
            print(output)
        if args.exit_zero:
            return 0
        return 1

    if engine == "auto":
        engine = "ast-grep" if shutil.which("ast-grep") else "portable-fallback"
    if engine == "ast-grep" and not shutil.which("ast-grep"):
        result = missing_engine_result(files, cwd, rule)
    else:
        matches = (
            run_ast_grep(files, cwd, rule)
            if engine == "ast-grep"
            else run_portable_fallback(files, cwd, rule)
        )
        matches = postprocess_matches(files, matches, cwd, rule)
        result = build_result(files, matches, engine, cwd, rule)

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
