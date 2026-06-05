#!/usr/bin/env python3
"""Emit a non-mutating proof artifact freshness receipt.

The receipt answers one narrow operator question: can this green-looking proof
artifact still be cited for the current shared-main tree? It refuses stale HEADs,
wrong branches, missing provenance, and artifacts whose touched surface overlaps
current dirty work.
"""

import argparse
import datetime as dt
import hashlib
import fnmatch
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-artifact-freshness-receipt-v1"
PROOF_REUSE_SCHEMA_VERSION = "proof-reuse-classifier-v1"
PROOF_REUSE_INDEX_SCHEMA_VERSION = "proof-reuse-index-v1"
PROOF_REUSE_QUERY_SCHEMA_VERSION = "proof-reuse-query-result-v1"
DEFAULT_PROOF_REUSE_QUERY_ROW_LIMIT = 100
MAX_PROOF_REUSE_QUERY_ROW_LIMIT = 1000
MAIN_BRANCH = "main"
APPROVED_PROOF_REUSE_INDEX_ROOTS = (
    "artifacts",
    "tests/fixtures/proof_artifact_freshness_receipt",
)
GIT_READ_COMMANDS = [
    "git rev-parse HEAD",
    "git branch --show-current",
    "git status --porcelain=v1",
]
CARGO_PROOF_COMMAND = re.compile(
    r"\bcargo(?:\s+fuzz)?\s+"
    r"(?:build|check|clippy|doc|fmt|fuzz|run|test|tree)\b",
    re.IGNORECASE,
)
LIBTEST_RUNNING_COUNT_RE = re.compile(
    r"(?m)^\s*running\s+(\d+)\s+tests?\b",
    re.IGNORECASE,
)
LIBTEST_RESULT_RE = re.compile(
    r"test result:\s+\w+\.\s+"
    r"(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored\b",
    re.IGNORECASE,
)
CARGO_TEST_VALUE_OPTIONS = {
    "-j",
    "-p",
    "-Z",
    "--bench",
    "--bin",
    "--color",
    "--config",
    "--example",
    "--exclude",
    "--features",
    "--jobs",
    "--manifest-path",
    "--message-format",
    "--package",
    "--profile",
    "--target",
    "--target-dir",
    "--test",
}
LIBTEST_VALUE_OPTIONS = {
    "--color",
    "--ensure-time",
    "--exclude-should-panic",
    "--format",
    "--logfile",
    "--report-time",
    "--shuffle-seed",
    "--skip",
    "--test-threads",
}
RCH_LOCAL_FALLBACK_RE = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
RCH_REMOTE_ROUTE_RE = re.compile(
    r"(?m)(?:^\s*\[RCH\]\s+remote\s+\S+|\bSelected worker:\s+\S+|\bRCH_WORKER=\S+)",
    re.IGNORECASE,
)
FUZZ_ALL_BINS_CHECK_RE = re.compile(
    r"\bcargo\s+check\b"
    r"(?=[^\n]*?(?:^|\s)--bins(?:\s|$))"
    r"(?=[^\n]*?(?:^|\s)--manifest-path(?:=|\s+)[\"']?(?:\./)?fuzz/cargo\.toml[\"']?(?:\s|$))",
    re.IGNORECASE,
)
SUCCESS_ONLY_PROOF_RE = re.compile(
    r"\bFinished\b|exit\s+(?:status|code):?\s*0|Process exited with code 0",
    re.IGNORECASE,
)
SOURCE_FRESH_TARGET_DIR_VALUES = {
    "cold",
    "dedicated",
    "empty-before-run",
    "fresh",
    "isolated",
    "source-fresh",
    "unique",
}
FAILED_ARTIFACT_STATUSES = {
    "error",
    "fail",
    "failed",
    "failure",
    "nonzero",
    "non-zero",
    "non-zero-exit",
    "red",
    "timeout",
    "timed-out",
}
BROAD_CACHE_CLAIMS = {
    "fresh-rch-pass",
    "release-readiness",
    "workspace-health",
}
REUSE_REFUSAL_BY_CLASSIFICATION = {
    "dirty-surface-overlap": "dirty-frontier-overlap",
    "failed-proof-artifact": "failed-proof-status",
    "exact-filter-no-executed-tests": "exact-filter-no-executed-tests",
    "exact-filter-zero-tests": "exact-filter-zero-tests",
    "repo-not-main": "branch-mismatch",
    "rch-local-fallback-proof": "local-fallback-marker",
    "superseded-head": "stale-head",
    "unverifiable-exact-filter-proof": "missing-exact-filter-test-count",
    "unverifiable-command": "missing-command-fingerprint",
    "unverifiable-fuzz-extent-proof": "missing-command-fingerprint",
    "unverifiable-head": "stale-head",
    "unverifiable-rch-remote-proof": "missing-command-fingerprint",
    "unverifiable-surface": "missing-touched-files",
    "unsafe-proof-command": "command-mismatch",
    "wrong-branch": "branch-mismatch",
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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run_text(repo_path: Path, command: list[str], timeout: float) -> tuple[str, str]:
    try:
        output = subprocess.run(
            command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except FileNotFoundError:
        return "unavailable", ""
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except subprocess.CalledProcessError as error:
        return f"error:{error.returncode}", ""
    return "ok", output.stdout.rstrip("\n")


def parse_status_lines(raw: str) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        if len(line) < 4:
            continue
        status = line[:2]
        for path in status_paths(status, line[3:]):
            entries.append(
                {
                    "status": status,
                    "path": path,
                    "classification": "unattributed-dirty",
                    "owner": "",
                }
            )
    return entries


def live_probe(repo_path: Path, artifact_paths: list[str], timeout: float) -> dict[str, Any]:
    head_status, head_sha = run_text(repo_path, ["git", "rev-parse", "HEAD"], timeout)
    branch_status, branch = run_text(repo_path, ["git", "branch", "--show-current"], timeout)
    dirty_status, dirty_raw = run_text(repo_path, ["git", "status", "--porcelain=v1"], timeout)

    artifacts = []
    artifact_errors = []
    for path_text in artifact_paths:
        path = Path(path_text)
        if not path.is_absolute():
            path = repo_path / path
        try:
            artifacts.append(normalize_artifact(load_json(path), str(path_text)))
        except Exception as error:
            artifact_errors.append({"artifact_path": str(path_text), "error": str(error)})

    return {
        "repo": {
            "head_sha": head_sha if head_status == "ok" else "",
            "branch": branch if branch_status == "ok" else "",
            "probe_status": {
                "head": head_status,
                "branch": branch_status,
                "dirty": dirty_status,
            },
        },
        "artifacts": artifacts,
        "artifact_errors": artifact_errors,
        "dirty_tree": {
            "entries": parse_status_lines(dirty_raw if dirty_status == "ok" else ""),
        },
    }


def first_string(value: Any, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        cursor = value
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if isinstance(cursor, str) and cursor:
            return cursor
    return ""


def first_string_list(value: Any, paths: list[tuple[str, ...]]) -> list[str]:
    for path in paths:
        cursor = value
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if isinstance(cursor, list):
            return [str(item) for item in cursor if isinstance(item, str) and item]
    return []


def first_bool(value: Any, paths: list[tuple[str, ...]]) -> bool | None:
    for path in paths:
        cursor = value
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if isinstance(cursor, bool):
            return cursor
    return None


def string_values(value: Any, paths: list[tuple[str, ...]]) -> list[str]:
    values = []
    for path in paths:
        cursor = value
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if isinstance(cursor, str) and cursor:
            values.append(cursor)
        elif isinstance(cursor, list):
            values.extend(item for item in cursor if isinstance(item, str) and item)
    return values


def normalize_fuzz_extent(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "registered_targets": first_string_list(
            raw,
            [
                ("registered_targets",),
                ("expected_targets",),
                ("fuzz_registered_targets",),
                ("fuzz_extent", "registered_targets"),
                ("fuzz_extent", "expected_targets"),
                ("metadata", "fuzz_extent", "registered_targets"),
            ],
        ),
        "compiled_targets": first_string_list(
            raw,
            [
                ("compiled_targets",),
                ("observed_compiled_targets",),
                ("fuzz_compiled_targets",),
                ("fuzz_extent", "compiled_targets"),
                ("fuzz_extent", "observed_compiled_targets"),
                ("metadata", "fuzz_extent", "compiled_targets"),
            ],
        ),
        "source_fresh_targets": first_string_list(
            raw,
            [
                ("source_fresh_targets",),
                ("fresh_targets",),
                ("fuzz_extent", "source_fresh_targets"),
                ("metadata", "fuzz_extent", "source_fresh_targets"),
            ],
        ),
        "command_fingerprint": first_string(
            raw,
            [
                ("command_fingerprint",),
                ("fuzz_extent", "command_fingerprint"),
                ("metadata", "fuzz_extent", "command_fingerprint"),
            ],
        ),
        "toolchain_fingerprint": first_string(
            raw,
            [
                ("toolchain_fingerprint",),
                ("fuzz_extent", "toolchain_fingerprint"),
                ("metadata", "fuzz_extent", "toolchain_fingerprint"),
            ],
        ),
        "target_dir_identity": first_string(
            raw,
            [
                ("target_dir_identity",),
                ("target_dir_fingerprint",),
                ("fuzz_extent", "target_dir_identity"),
                ("fuzz_extent", "target_dir_fingerprint"),
                ("metadata", "fuzz_extent", "target_dir_identity"),
            ],
        ),
        "target_dir_freshness": first_string(
            raw,
            [
                ("target_dir_freshness",),
                ("target_dir_provenance",),
                ("fuzz_extent", "target_dir_freshness"),
                ("fuzz_extent", "target_dir_provenance"),
                ("metadata", "fuzz_extent", "target_dir_freshness"),
            ],
        ),
        "cache_warmth_used_as_correctness_evidence": first_bool(
            raw,
            [
                ("cache_warmth_is_correctness_evidence",),
                ("cache_warmth_used_as_correctness_evidence",),
                ("fuzz_extent", "cache_warmth_is_correctness_evidence"),
                ("fuzz_extent", "cache_warmth_used_as_correctness_evidence"),
                ("metadata", "fuzz_extent", "cache_warmth_used_as_correctness_evidence"),
            ],
        ),
    }


def normalize_proof_output_text(texts: list[str]) -> str:
    normalized = [
        text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
        for text in texts
    ]
    return "\n".join(normalized)


def sha256_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def proof_output_digest(texts: list[str]) -> dict[str, Any]:
    normalized = normalize_proof_output_text(texts)
    payload = normalized.encode("utf-8")
    return {
        "proof_output_digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "proof_output_byte_count": len(payload),
        "proof_output_segment_count": len(texts),
    }


def normalized_command_argv(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def command_fingerprint(command: str) -> str:
    argv = normalized_command_argv(command)
    return sha256_text(json.dumps(argv, separators=(",", ":"), ensure_ascii=True))


def split_option_separator(args: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in args:
        return args, []
    index = args.index("--")
    return args[:index], args[index + 1 :]


def positional_arguments(args: list[str], value_options: set[str]) -> list[str]:
    positionals = []
    skip_next = False
    for token in args:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("--"):
            if "=" not in token and token in value_options:
                skip_next = True
            continue
        if token.startswith("-") and token != "-":
            if token in value_options:
                skip_next = True
            continue
        positionals.append(token)
    return positionals


def cargo_test_exact_filter(command: str) -> str:
    argv = normalized_command_argv(command)
    for index, token in enumerate(argv):
        if token != "cargo":
            continue
        command_index = index + 1
        if command_index < len(argv) and argv[command_index].startswith("+"):
            command_index += 1
        if command_index >= len(argv) or argv[command_index] != "test":
            continue
        cargo_args, harness_args = split_option_separator(argv[command_index + 1 :])
        if "--exact" not in harness_args:
            continue
        filter_candidates = [
            *positional_arguments(cargo_args, CARGO_TEST_VALUE_OPTIONS),
            *positional_arguments(
                [arg for arg in harness_args if arg != "--exact"],
                LIBTEST_VALUE_OPTIONS,
            ),
        ]
        if filter_candidates:
            return filter_candidates[0]
    return ""


def exact_cargo_test_findings(command: str, texts: list[str]) -> dict[str, Any]:
    exact_filter = cargo_test_exact_filter(command)
    if not exact_filter:
        return {"is_exact_filter": False, "defects": []}

    output = normalize_proof_output_text(texts)
    running_counts = [int(match.group(1)) for match in LIBTEST_RUNNING_COUNT_RE.finditer(output)]
    result_counts = [
        {
            "passed": int(match.group(1)),
            "failed": int(match.group(2)),
            "ignored": int(match.group(3)),
        }
        for match in LIBTEST_RESULT_RE.finditer(output)
    ]
    total_tests = sum(running_counts)
    passed_tests = sum(row["passed"] for row in result_counts)
    failed_tests = sum(row["failed"] for row in result_counts)
    ignored_tests = sum(row["ignored"] for row in result_counts)
    executed_tests = passed_tests + failed_tests

    defects = []
    if not running_counts:
        defects.append("missing-test-count")
    elif total_tests == 0:
        defects.append("zero-tests")
    elif not result_counts:
        defects.append("missing-test-result")
    elif executed_tests == 0:
        defects.append("no-executed-tests")

    return {
        "is_exact_filter": True,
        "exact_filter": exact_filter,
        "running_count_segments": running_counts,
        "result_count_segments": result_counts,
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "ignored_tests": ignored_tests,
        "executed_tests": executed_tests,
        "defects": defects,
    }


def command_has_required_rch_prefix(command: str) -> bool:
    argv = normalized_command_argv(command)
    if len(argv) < 4:
        return False
    return argv[:4] == ["RCH_REQUIRE_REMOTE=1", "rch", "exec", "--"]


def normalize_artifact(raw: Any, fallback_path: str = "") -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "proof_id": "",
            "artifact_path": fallback_path,
            "git_sha": "",
            "git_branch": "",
            "command": "",
            "touched_files": [],
            "status": "",
            "generated_at": "",
        }

    return {
        "proof_id": first_string(
            raw,
            [
                ("proof_id",),
                ("id",),
                ("proof", "proof_id"),
                ("metadata", "proof_id"),
                ("reuse", "proof_id"),
            ],
        ),
        "artifact_path": first_string(
            raw,
            [
                ("artifact_path",),
                ("path",),
                ("manifest_path",),
                ("metadata", "artifact_path"),
            ],
        )
        or fallback_path,
        "git_sha": first_string(
            raw,
            [
                ("git_sha",),
                ("head_sha",),
                ("commit",),
                ("git", "sha"),
                ("git", "head_sha"),
                ("metadata", "git_sha"),
            ],
        ),
        "git_branch": first_string(
            raw,
            [
                ("git_branch",),
                ("branch",),
                ("git", "branch"),
                ("metadata", "git_branch"),
            ],
        ),
        "command": first_string(
            raw,
            [
                ("command",),
                ("proof_command",),
                ("repro_command",),
                ("metadata", "command"),
            ],
        ),
        "command_fingerprint": first_string(
            raw,
            [
                ("command_fingerprint",),
                ("proof", "command_fingerprint"),
                ("metadata", "command_fingerprint"),
                ("reuse", "command_fingerprint"),
            ],
        ),
        "manifest_lane_id": first_string(
            raw,
            [
                ("manifest_lane_id",),
                ("lane_id",),
                ("proof", "manifest_lane_id"),
                ("metadata", "manifest_lane_id"),
                ("reuse", "manifest_lane_id"),
            ],
        ),
        "manifest_guarantee_ids": first_string_list(
            raw,
            [
                ("manifest_guarantee_ids",),
                ("guarantee_ids",),
                ("proof", "manifest_guarantee_ids"),
                ("metadata", "manifest_guarantee_ids"),
                ("reuse", "manifest_guarantee_ids"),
            ],
        ),
        "claim_scope": first_string(
            raw,
            [
                ("claim_scope",),
                ("proof", "claim_scope"),
                ("metadata", "claim_scope"),
                ("reuse", "claim_scope"),
            ],
        ),
        "allowed_cache_hit_claims": first_string_list(
            raw,
            [
                ("allowed_cache_hit_claims",),
                ("reuse", "allowed_cache_hit_claims"),
                ("metadata", "allowed_cache_hit_claims"),
            ],
        ),
        "feature_flags": first_string_list(
            raw,
            [
                ("feature_flags",),
                ("features",),
                ("proof", "feature_flags"),
                ("metadata", "feature_flags"),
                ("reuse", "feature_flags"),
            ],
        ),
        "touched_files": first_string_list(
            raw,
            [
                ("touched_files",),
                ("files",),
                ("changed_files",),
                ("metadata", "touched_files"),
            ],
        ),
        "status": first_string(
            raw,
            [
                ("status",),
                ("decision",),
                ("verdict",),
                ("metadata", "status"),
            ],
        ),
        "generated_at": first_string(
            raw,
            [
                ("generated_at",),
                ("finished_at",),
                ("timestamp",),
                ("metadata", "generated_at"),
            ],
        ),
        "proof_text": string_values(
            raw,
            [
                ("stdout",),
                ("stderr",),
                ("output",),
                ("log",),
                ("run_log",),
                ("proof_text",),
                ("command_output",),
                ("proof_output",),
                ("validation",),
                ("validation_output",),
                ("metadata", "stdout"),
                ("metadata", "stderr"),
                ("metadata", "output"),
                ("metadata", "log"),
                ("metadata", "validation_output"),
                ("proof", "stdout"),
                ("proof", "stderr"),
                ("result", "stdout"),
                ("result", "stderr"),
            ],
        ),
        "local_fallback_markers": first_string_list(
            raw,
            [
                ("local_fallback_markers",),
                ("rch_local_fallback_segments",),
                ("evidence", "local_fallback_markers"),
                ("evidence", "rch_local_fallback_segments"),
                ("metadata", "local_fallback_markers"),
                ("outcome", "local_fallback_markers"),
                ("proof", "local_fallback_markers"),
                ("reuse", "local_fallback_markers"),
            ],
        ),
        "rch_remote_route_segments": first_string_list(
            raw,
            [
                ("rch_remote_route_segments",),
                ("remote_route_segments",),
                ("evidence", "rch_remote_route_segments"),
                ("metadata", "rch_remote_route_segments"),
                ("outcome", "rch_remote_route_segments"),
                ("proof", "rch_remote_route_segments"),
                ("reuse", "rch_remote_route_segments"),
            ],
        ),
        "source_fingerprint": first_string(
            raw,
            [
                ("source_fingerprint",),
                ("source_digest",),
                ("source_sha256",),
                ("source", "fingerprint"),
                ("source", "sha256"),
                ("metadata", "source_fingerprint"),
                ("metadata", "source_digest"),
                ("metadata", "source_sha256"),
            ],
        ),
        "tree_fingerprint": first_string(
            raw,
            [
                ("tree_fingerprint",),
                ("source_tree_fingerprint",),
                ("git_tree_sha",),
                ("tree", "fingerprint"),
                ("source_tree", "fingerprint"),
                ("metadata", "tree_fingerprint"),
                ("metadata", "source_tree_fingerprint"),
                ("metadata", "git_tree_sha"),
            ],
        ),
        "toolchain_fingerprint": first_string(
            raw,
            [
                ("toolchain_fingerprint",),
                ("toolchain", "fingerprint"),
                ("metadata", "toolchain_fingerprint"),
                ("reuse", "toolchain_fingerprint"),
            ],
        ),
        "env_fingerprint": first_string(
            raw,
            [
                ("env_fingerprint",),
                ("environment_fingerprint",),
                ("env", "fingerprint"),
                ("environment", "fingerprint"),
                ("metadata", "env_fingerprint"),
                ("metadata", "environment_fingerprint"),
                ("reuse", "env_fingerprint"),
            ],
        ),
        "fuzz_extent": normalize_fuzz_extent(raw),
    }


def artifact_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = source.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    rows = []
    for index, artifact in enumerate(artifacts):
        normalized = normalize_artifact(artifact)
        if not normalized["artifact_path"]:
            normalized["artifact_path"] = f"artifact[{index}]"
        rows.append(normalized)
    return rows


def dirty_entries(source: dict[str, Any]) -> list[dict[str, str]]:
    dirty_tree = source.get("dirty_tree", {})
    raw_entries = dirty_tree.get("entries") if isinstance(dirty_tree, dict) else []
    entries = []
    for item in raw_entries if isinstance(raw_entries, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", ""))
        for path in status_paths(status, str(item.get("path", ""))):
            entries.append(
                {
                    "status": status,
                    "path": path,
                    "classification": str(item.get("classification", "")),
                    "owner": str(item.get("owner", "")),
                }
            )
    return entries


def normalize_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def status_paths(status: str, path: str) -> list[str]:
    if not path.strip():
        return []
    if ("R" in status or "C" in status) and " -> " in path:
        return [normalize_path(part) for part in path.split(" -> ", 1) if part.strip()]
    return [path]


def has_glob_magic(path: str) -> bool:
    return any(char in path for char in "*?[")


def path_matches(pattern: str, path: str) -> bool:
    pattern = normalize_path(pattern)
    path = normalize_path(path)
    if not pattern or not path:
        return False
    if pattern == path or fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path):
        return True
    pattern_is_glob = has_glob_magic(pattern)
    path_is_glob = has_glob_magic(path)
    return (not pattern_is_glob and path.startswith(f"{pattern}/")) or (
        not path_is_glob and pattern.startswith(f"{path}/")
    )


def cargo_proof_command_defects(command: str) -> list[str]:
    lowered = command.lower()
    defects: list[str] = []
    for match in CARGO_PROOF_COMMAND.finditer(command):
        prefix = lowered[: match.start()]
        if "rch exec" not in prefix:
            defects.append("bare-cargo")
            continue
        if "rch_require_remote=1" not in prefix:
            defects.append("missing-rch-require-remote")
        if "cargo_target_dir=" not in prefix:
            defects.append("missing-cargo-target-dir")
        if "rch exec -- env" not in prefix:
            defects.append("missing-rch-env-wrapper")
    return sorted(set(defects))


def artifact_status_is_failed(status: str) -> bool:
    normalized = status.strip().lower().replace("_", "-")
    if not normalized:
        return False
    if normalized in FAILED_ARTIFACT_STATUSES:
        return True
    tokens = [token for token in normalized.split("-") if token]
    if "exit" not in tokens:
        return False
    exit_codes = [int(token) for token in tokens if token.isdigit()]
    return bool(exit_codes) and exit_codes[-1] != 0


def is_fuzz_all_bins_check(command: str) -> bool:
    return bool(FUZZ_ALL_BINS_CHECK_RE.search(command.replace("\\", "/").lower()))


def normalize_target_names(targets: list[str]) -> set[str]:
    names = set()
    for target in targets:
        normalized = normalize_path(target)
        if normalized.endswith(".rs"):
            normalized = Path(normalized).stem
        elif "/" in normalized:
            normalized = normalized.rsplit("/", 1)[-1]
        if normalized:
            names.add(normalized)
    return names


def fuzz_extent_proof_findings(artifact: dict[str, Any]) -> dict[str, Any]:
    if not is_fuzz_all_bins_check(artifact["command"]):
        return {"defects": [], "missing_targets": []}

    extent = artifact.get("fuzz_extent", {})
    registered_targets = normalize_target_names(extent.get("registered_targets", []))
    compiled_targets = normalize_target_names(extent.get("compiled_targets", []))
    source_fresh_targets = normalize_target_names(extent.get("source_fresh_targets", []))
    coverage_targets = source_fresh_targets or compiled_targets
    target_dir_freshness = str(extent.get("target_dir_freshness", "")).lower()

    defects = []
    missing_targets: list[str] = []
    if not registered_targets:
        defects.append("missing-registered-targets")
    if not coverage_targets:
        defects.append("missing-source-fresh-target-coverage")
    elif registered_targets:
        missing_targets = sorted(registered_targets - coverage_targets)
        if missing_targets:
            defects.append("source-fresh-target-coverage-incomplete")

    if not extent.get("command_fingerprint"):
        defects.append("missing-command-fingerprint")
    if not extent.get("toolchain_fingerprint"):
        defects.append("missing-toolchain-fingerprint")
    if not extent.get("target_dir_identity"):
        defects.append("missing-target-dir-identity")
    if not target_dir_freshness:
        defects.append("missing-target-dir-freshness")
    elif target_dir_freshness not in SOURCE_FRESH_TARGET_DIR_VALUES:
        defects.append("target-dir-not-source-fresh")

    if extent.get("cache_warmth_used_as_correctness_evidence") is True:
        defects.append("cache-warmth-used-as-correctness-evidence")
    if (
        not registered_targets
        and not coverage_targets
        and any(SUCCESS_ONLY_PROOF_RE.search(text) for text in artifact.get("proof_text", []))
    ):
        defects.append("success-output-without-target-coverage")

    return {"defects": sorted(set(defects)), "missing_targets": missing_targets}


def proof_command_uses_bare_cargo(command: str) -> bool:
    return "bare-cargo" in cargo_proof_command_defects(command)


def remote_required_rerun_command(command: str) -> str:
    match = CARGO_PROOF_COMMAND.search(command)
    cargo_command = command[match.start() :].strip() if match else command.strip()
    return f"RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR {cargo_command}"


def rch_local_fallback_segments(texts: list[str]) -> list[str]:
    segments = []
    for text in texts:
        for segment in text.splitlines() or [text]:
            compact = segment.strip()
            if compact and RCH_LOCAL_FALLBACK_RE.search(compact):
                segments.append(compact[:260])
    return segments


def rch_remote_route_segments(texts: list[str]) -> list[str]:
    segments = []
    for text in texts:
        for segment in text.splitlines() or [text]:
            compact = segment.strip()
            if compact and RCH_REMOTE_ROUTE_RE.search(compact):
                segments.append(compact[:260])
    return segments


def dirty_overlaps(touched_files: list[str], entries: list[dict[str, str]]) -> list[dict[str, str]]:
    overlaps = []
    for touched in touched_files:
        for entry in entries:
            dirty_path = entry["path"]
            if path_matches(touched, dirty_path):
                overlaps.append(entry)
    return overlaps


def classify_artifact(
    artifact: dict[str, Any],
    current_head: str,
    current_branch: str,
    dirty: list[dict[str, str]],
) -> dict[str, Any]:
    artifact_path = artifact["artifact_path"]
    git_sha = artifact["git_sha"]
    git_branch = artifact["git_branch"]
    command = artifact["command"]
    touched_files = artifact["touched_files"]
    status = artifact["status"]
    overlaps = dirty_overlaps(touched_files, dirty)
    unsafe_cargo_reasons = cargo_proof_command_defects(command)
    bare_cargo_command = "bare-cargo" in unsafe_cargo_reasons
    rch_remote_route_required = bool(CARGO_PROOF_COMMAND.search(command)) and not unsafe_cargo_reasons
    local_fallback_segments = sorted(
        set(
            [
                *artifact.get("local_fallback_markers", []),
                *rch_local_fallback_segments([command, *artifact.get("proof_text", [])]),
            ]
        )
    )
    remote_route_segments = sorted(
        set(
            [
                *artifact.get("rch_remote_route_segments", []),
                *rch_remote_route_segments(artifact.get("proof_text", [])),
            ]
        )
    )
    fuzz_extent_findings = fuzz_extent_proof_findings(artifact)
    exact_test_findings = exact_cargo_test_findings(command, artifact.get("proof_text", []))

    evidence = {
        "artifact_git_sha": git_sha,
        "current_head_sha": current_head,
        "artifact_git_branch": git_branch,
        "current_branch": current_branch,
        "dirty_overlap_count": len(overlaps),
        "dirty_overlaps": overlaps,
        **proof_output_digest(artifact.get("proof_text", [])),
    }
    if artifact.get("source_fingerprint"):
        evidence["artifact_source_fingerprint"] = artifact["source_fingerprint"]
    if artifact.get("tree_fingerprint"):
        evidence["artifact_tree_fingerprint"] = artifact["tree_fingerprint"]
    if bare_cargo_command:
        evidence["bare_cargo_command"] = True
    if unsafe_cargo_reasons:
        evidence["unsafe_cargo_command_reasons"] = unsafe_cargo_reasons
    if local_fallback_segments:
        evidence["rch_local_fallback"] = True
        evidence["rch_local_fallback_segments"] = local_fallback_segments
    if is_fuzz_all_bins_check(command):
        evidence["fuzz_extent_proof_reasons"] = fuzz_extent_findings["defects"]
        evidence["fuzz_extent_missing_targets"] = fuzz_extent_findings["missing_targets"]
        evidence["fuzz_extent"] = artifact.get("fuzz_extent", {})
    if exact_test_findings.get("is_exact_filter"):
        evidence["exact_filter"] = exact_test_findings["exact_filter"]
        evidence["exact_filter_running_count_segments"] = exact_test_findings[
            "running_count_segments"
        ]
        evidence["exact_filter_result_count_segments"] = exact_test_findings[
            "result_count_segments"
        ]
        evidence["exact_filter_total_tests"] = exact_test_findings["total_tests"]
        evidence["exact_filter_passed_tests"] = exact_test_findings["passed_tests"]
        evidence["exact_filter_failed_tests"] = exact_test_findings["failed_tests"]
        evidence["exact_filter_ignored_tests"] = exact_test_findings["ignored_tests"]
        evidence["exact_filter_executed_tests"] = exact_test_findings["executed_tests"]
        if exact_test_findings["defects"]:
            evidence["exact_filter_proof_reasons"] = exact_test_findings["defects"]

    if not git_sha or not current_head:
        classification = "unverifiable-head"
        decision = "suppress-as-unverifiable"
        reason = "artifact or repository is missing git HEAD provenance"
    elif git_branch and git_branch != MAIN_BRANCH:
        classification = "wrong-branch"
        decision = "suppress-as-stale"
        reason = "artifact was produced on a non-main branch"
    elif current_branch and current_branch != MAIN_BRANCH:
        classification = "repo-not-main"
        decision = "suppress-as-stale"
        reason = "current repository branch is not main"
    elif git_sha != current_head:
        classification = "superseded-head"
        decision = "suppress-as-stale"
        reason = "artifact git SHA does not match current HEAD"
    elif not command:
        classification = "unverifiable-command"
        decision = "suppress-as-unverifiable"
        reason = "artifact does not declare a reproducible proof command"
    elif not touched_files:
        classification = "unverifiable-surface"
        decision = "suppress-as-unverifiable"
        reason = "artifact does not declare touched files"
    elif artifact_status_is_failed(status):
        classification = "failed-proof-artifact"
        decision = "rerun-required"
        reason = "artifact status reports a failed proof"
    elif unsafe_cargo_reasons:
        classification = "unsafe-proof-command"
        decision = "rerun-required"
        reason = "artifact proof command lacks remote-required rch Cargo routing"
    elif local_fallback_segments:
        classification = "rch-local-fallback-proof"
        decision = "rerun-required"
        reason = "artifact proof evidence reports rch local fallback"
    elif rch_remote_route_required and not remote_route_segments:
        classification = "unverifiable-rch-remote-proof"
        decision = "rerun-required"
        reason = "artifact proof evidence lacks positive rch remote worker route marker"
    elif exact_test_findings.get("is_exact_filter") and "zero-tests" in exact_test_findings["defects"]:
        classification = "exact-filter-zero-tests"
        decision = "rerun-required"
        reason = "artifact exact cargo test proof ran zero tests"
    elif exact_test_findings.get("is_exact_filter") and "no-executed-tests" in exact_test_findings["defects"]:
        classification = "exact-filter-no-executed-tests"
        decision = "rerun-required"
        reason = "artifact exact cargo test proof did not execute a matched test"
    elif exact_test_findings.get("is_exact_filter") and exact_test_findings["defects"]:
        classification = "unverifiable-exact-filter-proof"
        decision = "rerun-required"
        reason = "artifact exact cargo test proof lacks parseable executed-test evidence"
    elif fuzz_extent_findings["defects"]:
        classification = "unverifiable-fuzz-extent-proof"
        decision = "rerun-required"
        reason = "artifact does not prove source-fresh coverage for fuzz all-bins"
    elif overlaps:
        classification = "dirty-surface-overlap"
        decision = "rerun-required"
        reason = "artifact touched files overlap current dirty tree entries"
    else:
        classification = "current-clean"
        decision = "cite-as-current"
        reason = "artifact HEAD and touched files match a clean cited surface"

    if rch_remote_route_required and classification in {
        "unverifiable-rch-remote-proof",
        "unverifiable-fuzz-extent-proof",
        "exact-filter-no-executed-tests",
        "exact-filter-zero-tests",
        "unverifiable-exact-filter-proof",
        "dirty-surface-overlap",
        "current-clean",
    }:
        evidence["rch_remote_route_required"] = True
        evidence["rch_remote_route_segments"] = remote_route_segments

    safe_to_cite = classification == "current-clean"
    return {
        "artifact_path": artifact_path,
        "classification": classification,
        "decision": decision,
        "safe_to_cite": safe_to_cite,
        "reason": reason,
        "status": status,
        "command": command,
        "touched_files": touched_files,
        "generated_at": artifact["generated_at"],
        "evidence": evidence,
        "remediation": remediation_for(classification, command),
    }


def normalize_reuse_request(raw: Any) -> dict[str, Any]:
    request = raw if isinstance(raw, dict) else {}
    command = first_string(request, [("command",), ("proof_command",)])
    explicit_fingerprint = first_string(
        request,
        [
            ("command_fingerprint",),
            ("proof", "command_fingerprint"),
            ("reuse", "command_fingerprint"),
        ],
    )
    return {
        "request_id": first_string(request, [("request_id",), ("id",)]) or "proof-reuse-request",
        "manifest_lane_id": first_string(request, [("manifest_lane_id",), ("lane_id",)]),
        "claim_scope": first_string(request, [("claim_scope",), ("claim",)]),
        "command": command,
        "command_fingerprint": explicit_fingerprint or (command_fingerprint(command) if command else ""),
        "source_fingerprint": first_string(
            request,
            [
                ("source_fingerprint",),
                ("source", "fingerprint"),
                ("metadata", "source_fingerprint"),
            ],
        ),
        "tree_fingerprint": first_string(
            request,
            [
                ("tree_fingerprint",),
                ("source_tree_fingerprint",),
                ("source_tree", "fingerprint"),
                ("metadata", "tree_fingerprint"),
            ],
        ),
        "toolchain_fingerprint": first_string(
            request,
            [
                ("toolchain_fingerprint",),
                ("toolchain", "fingerprint"),
                ("metadata", "toolchain_fingerprint"),
            ],
        ),
        "env_fingerprint": first_string(
            request,
            [
                ("env_fingerprint",),
                ("environment_fingerprint",),
                ("env", "fingerprint"),
                ("environment", "fingerprint"),
                ("metadata", "env_fingerprint"),
                ("metadata", "environment_fingerprint"),
            ],
        ),
        "feature_flags": first_string_list(
            request,
            [
                ("feature_flags",),
                ("features",),
                ("metadata", "feature_flags"),
            ],
        ),
        "touched_files": first_string_list(
            request,
            [
                ("touched_files",),
                ("files",),
                ("changed_files",),
                ("metadata", "touched_files"),
            ],
        ),
        "dirty_frontier_status": first_string(
            request,
            [
                ("dirty_frontier_status",),
                ("dirty_frontier", "status"),
                ("metadata", "dirty_frontier_status"),
            ],
        ),
        "require_full_pass": first_bool(
            request,
            [
                ("require_full_pass",),
                ("reuse", "require_full_pass"),
                ("metadata", "require_full_pass"),
            ],
        )
        is not False,
    }


def candidate_command_fingerprint(artifact: dict[str, Any]) -> str:
    return artifact.get("command_fingerprint") or command_fingerprint(artifact.get("command", ""))


def reusable_candidate_evidence(
    request: dict[str, Any],
    artifact: dict[str, Any],
    freshness_row: dict[str, Any],
) -> dict[str, Any]:
    evidence = {
        "request_command_fingerprint": request.get("command_fingerprint", ""),
        "candidate_command_fingerprint": candidate_command_fingerprint(artifact),
        "request_manifest_lane_id": request.get("manifest_lane_id", ""),
        "candidate_manifest_lane_id": artifact.get("manifest_lane_id", ""),
        "request_claim_scope": request.get("claim_scope", ""),
        "candidate_allowed_cache_hit_claims": artifact.get("allowed_cache_hit_claims", []),
        "request_source_fingerprint": request.get("source_fingerprint", ""),
        "candidate_source_fingerprint": artifact.get("source_fingerprint", ""),
        "request_tree_fingerprint": request.get("tree_fingerprint", ""),
        "candidate_tree_fingerprint": artifact.get("tree_fingerprint", ""),
        "request_toolchain_fingerprint": request.get("toolchain_fingerprint", ""),
        "candidate_toolchain_fingerprint": artifact.get("toolchain_fingerprint", ""),
        "request_env_fingerprint": request.get("env_fingerprint", ""),
        "candidate_env_fingerprint": artifact.get("env_fingerprint", ""),
        "request_feature_flags": request.get("feature_flags", []),
        "candidate_feature_flags": artifact.get("feature_flags", []),
        "candidate_local_fallback_markers": artifact.get("local_fallback_markers", []),
        "required_rch_command_prefix_present": command_has_required_rch_prefix(
            artifact.get("command", "")
        ),
        "freshness_classification": freshness_row.get("classification", ""),
        "freshness_safe_to_cite": bool(freshness_row.get("safe_to_cite")),
    }
    if "rch_remote_route_segments" in freshness_row.get("evidence", {}):
        evidence["rch_remote_route_segments"] = freshness_row["evidence"][
            "rch_remote_route_segments"
        ]
    return evidence


def proof_reuse_reason_codes(
    request: dict[str, Any],
    artifact: dict[str, Any],
    freshness_row: dict[str, Any],
) -> tuple[str, list[str]]:
    reasons: list[str] = []

    request_lane = request.get("manifest_lane_id", "")
    candidate_lane = artifact.get("manifest_lane_id", "")
    if request_lane and candidate_lane and request_lane != candidate_lane:
        return "miss", ["lane-mismatch"]
    if not request_lane or not candidate_lane:
        reasons.append("unknown-cache-policy")

    if not request.get("dirty_frontier_status"):
        reasons.append("missing-dirty-frontier-status")
    elif request["dirty_frontier_status"] != "clean":
        reasons.append("dirty-frontier-overlap")

    if not request.get("touched_files") or not artifact.get("touched_files"):
        reasons.append("missing-touched-files")
    elif set(request.get("touched_files", [])) != set(artifact.get("touched_files", [])):
        reasons.append("source-hash-mismatch")

    request_claim = request.get("claim_scope", "")
    allowed_claims = set(artifact.get("allowed_cache_hit_claims", []))
    if not request_claim or not allowed_claims:
        reasons.append("unknown-cache-policy")
    elif request_claim in BROAD_CACHE_CLAIMS or request_claim not in allowed_claims:
        reasons.append("broad-claim-unsupported")

    if (
        not request.get("command")
        or not artifact.get("command")
        or not request.get("command_fingerprint")
        or not artifact.get("command_fingerprint")
        or not command_has_required_rch_prefix(artifact.get("command", ""))
    ):
        reasons.append("missing-command-fingerprint")
    elif request.get("command_fingerprint") != candidate_command_fingerprint(artifact):
        reasons.append("command-mismatch")

    evidence = freshness_row.get("evidence", {})
    if freshness_row.get("safe_to_cite") and (
        not isinstance(evidence, dict) or not evidence.get("rch_remote_route_segments")
    ):
        reasons.append("missing-command-fingerprint")
    if artifact.get("local_fallback_markers"):
        reasons.append("local-fallback-marker")

    for key, reason in [
        ("source_fingerprint", "source-hash-mismatch"),
        ("tree_fingerprint", "source-hash-mismatch"),
        ("toolchain_fingerprint", "toolchain-mismatch"),
    ]:
        request_value = request.get(key, "")
        candidate_value = artifact.get(key, "")
        if not request_value or not candidate_value or request_value != candidate_value:
            reasons.append(reason)

    if set(request.get("feature_flags", [])) != set(artifact.get("feature_flags", [])):
        reasons.append("toolchain-mismatch")

    request_env = request.get("env_fingerprint", "")
    candidate_env = artifact.get("env_fingerprint", "")
    if request_env or candidate_env:
        if not request_env or not candidate_env or request_env != candidate_env:
            reasons.append("toolchain-mismatch")

    if not freshness_row.get("safe_to_cite"):
        reasons.append(
            REUSE_REFUSAL_BY_CLASSIFICATION.get(
                str(freshness_row.get("classification", "")),
                "unknown-cache-policy",
            )
        )

    reasons = sorted(set(reasons))
    return ("refused", reasons) if reasons else ("reusable", [])


def classify_proof_reuse_candidate(
    request: dict[str, Any],
    artifact: dict[str, Any],
    freshness_row: dict[str, Any],
) -> dict[str, Any]:
    decision, reason_codes = proof_reuse_reason_codes(request, artifact, freshness_row)
    safe_to_reuse = decision == "reusable"
    return {
        "candidate_id": artifact.get("proof_id") or artifact.get("artifact_path") or "candidate",
        "manifest_lane_id": artifact.get("manifest_lane_id", ""),
        "decision": decision,
        "safe_to_reuse": safe_to_reuse,
        "cache_hit_is_fresh_rch_pass": False,
        "reason_codes": reason_codes,
        "freshness_classification": freshness_row.get("classification", ""),
        "freshness_decision": freshness_row.get("decision", ""),
        "evidence": reusable_candidate_evidence(request, artifact, freshness_row),
        "remediation": proof_reuse_remediation(decision, reason_codes, request, artifact),
    }


def proof_reuse_remediation(
    decision: str,
    reason_codes: list[str],
    request: dict[str, Any],
    artifact: dict[str, Any],
) -> dict[str, Any]:
    if decision == "reusable":
        return {
            "operator_note": "Candidate may be cited only as an approved cache hit for the requested scope.",
            "next_steps": [
                "include the candidate id, request fingerprint, and cache-hit wording in closeout"
            ],
        }
    if decision == "miss":
        return {
            "operator_note": "Candidate does not cover the requested proof lane.",
            "next_steps": ["continue scanning candidates or rerun the requested proof lane"],
            "rerun_command": request.get("command", ""),
        }
    notes = {
        "broad-claim-unsupported": "Cache hit cannot support the requested broad claim.",
        "command-mismatch": "Rerun because the command fingerprint differs.",
        "dirty-frontier-overlap": "Rerun after the dirty frontier is clean or non-overlapping.",
        "failed-proof-status": "Rerun because the candidate proof failed.",
        "local-fallback-marker": "Rerun remotely because candidate evidence records local fallback.",
        "missing-command-fingerprint": "Rerun because the candidate lacks required remote RCH command provenance.",
        "missing-dirty-frontier-status": "Add a dirty-frontier verdict before reusing proof evidence.",
        "missing-touched-files": "Candidate and request must both declare touched files.",
        "source-hash-mismatch": "Rerun because source fingerprints differ.",
        "stale-head": "Rerun because candidate HEAD is stale.",
        "toolchain-mismatch": "Rerun because toolchain, feature, or environment fingerprints differ.",
        "unknown-cache-policy": "Candidate reuse policy is missing or not explicit enough.",
    }
    top_reason = reason_codes[0] if reason_codes else "unknown-cache-policy"
    return {
        "operator_note": notes.get(top_reason, "Candidate is not safe to reuse."),
        "next_steps": ["rerun the requested proof lane with RCH_REQUIRE_REMOTE=1"],
        "rerun_command": request.get("command") or artifact.get("command", ""),
    }


def summarize_proof_reuse(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": len(rows),
        "reusable": 0,
        "miss": 0,
        "refused": 0,
        "by_reason_code": {},
    }
    for row in rows:
        summary[row["decision"]] += 1
        for reason in row.get("reason_codes", []):
            summary["by_reason_code"][reason] = summary["by_reason_code"].get(reason, 0) + 1
    return summary


def build_proof_reuse_receipt(
    source: dict[str, Any],
    artifacts: list[dict[str, Any]],
    freshness_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    raw_request = source.get("reuse_request")
    if not isinstance(raw_request, dict):
        return None
    request = normalize_reuse_request(raw_request)
    rows = [
        classify_proof_reuse_candidate(request, artifact, freshness_row)
        for artifact, freshness_row in zip(artifacts, freshness_rows, strict=True)
    ]
    return {
        "schema_version": PROOF_REUSE_SCHEMA_VERSION,
        "request": request,
        "rows": rows,
        "summary": summarize_proof_reuse(rows),
        "safety": {
            "non_mutating": True,
            "cache_hit_is_never_fresh_rch_pass": True,
            "tracker_mutation_allowed": False,
        },
    }


def stable_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_text(payload)


def sorted_strings(values: list[str]) -> list[str]:
    return sorted(set(value for value in values if value))


def resolve_repo_local_path(path_text: str, repo_path: Path) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path.resolve()
    repo_candidate = repo_path / path
    if repo_candidate.exists():
        return repo_candidate.resolve()
    return path.resolve()


def repo_relative_path(path_text: str, repo_path: Path) -> tuple[Path, str]:
    resolved = resolve_repo_local_path(path_text, repo_path)
    bases = [repo_path.resolve(), Path.cwd().resolve()]
    for base in bases:
        try:
            relative = resolved.relative_to(base)
            return resolved, normalize_path(str(relative))
        except ValueError:
            continue
    raise ValueError(f"proof reuse index root must be inside repo: {path_text}")


def require_approved_reuse_root(path_text: str, repo_path: Path) -> tuple[Path, str]:
    path, relative = repo_relative_path(path_text, repo_path)
    if not any(
        relative == approved or relative.startswith(f"{approved}/")
        for approved in APPROVED_PROOF_REUSE_INDEX_ROOTS
    ):
        approved = ", ".join(APPROVED_PROOF_REUSE_INDEX_ROOTS)
        raise ValueError(
            f"proof reuse index root {relative!r} is not approved; use one of: {approved}"
        )
    return path, relative


def iter_reuse_index_json_files(root_texts: list[str], repo_path: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for root_text in root_texts:
        root, _relative = require_approved_reuse_root(root_text, repo_path)
        if root.is_file():
            if root.suffix == ".json":
                files.append(repo_relative_path(str(root), repo_path))
            continue
        if not root.is_dir():
            continue
        for candidate in sorted(root.rglob("*.json")):
            if candidate.is_file():
                files.append(repo_relative_path(str(candidate), repo_path))
    return sorted(set(files), key=lambda item: item[1])


def normalized_approved_reuse_roots(root_texts: list[str], repo_path: Path) -> list[str]:
    return sorted(
        {
            relative
            for _path, relative in (
                require_approved_reuse_root(root_text, repo_path) for root_text in root_texts
            )
        }
    )


def raw_looks_like_artifact(raw: dict[str, Any]) -> bool:
    return any(
        key in raw
        for key in [
            "artifact_path",
            "command",
            "proof_command",
            "git_sha",
            "head_sha",
            "status",
            "touched_files",
        ]
    )


def artifact_from_freshness_row(row: dict[str, Any], source_path: str, index: int) -> dict[str, Any]:
    evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
    raw = {
        "proof_id": row.get("proof_id", ""),
        "artifact_path": row.get("artifact_path") or f"{source_path}#row[{index}]",
        "git_sha": evidence.get("artifact_git_sha", ""),
        "git_branch": evidence.get("artifact_git_branch", ""),
        "command": row.get("command", ""),
        "command_fingerprint": row.get("command_fingerprint", ""),
        "manifest_lane_id": row.get("manifest_lane_id", ""),
        "manifest_guarantee_ids": row.get("manifest_guarantee_ids", []),
        "claim_scope": row.get("claim_scope", ""),
        "allowed_cache_hit_claims": row.get("allowed_cache_hit_claims", []),
        "source_fingerprint": evidence.get("artifact_source_fingerprint", ""),
        "tree_fingerprint": evidence.get("artifact_tree_fingerprint", ""),
        "toolchain_fingerprint": row.get("toolchain_fingerprint", ""),
        "env_fingerprint": row.get("env_fingerprint", ""),
        "feature_flags": row.get("feature_flags", []),
        "touched_files": row.get("touched_files", []),
        "status": row.get("status", ""),
        "generated_at": row.get("generated_at", ""),
        "rch_remote_route_segments": evidence.get("rch_remote_route_segments", []),
        "local_fallback_markers": evidence.get("rch_local_fallback_segments", []),
    }
    return normalize_artifact(raw)


def candidate_sources_from_json(
    raw: Any,
    source_path: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    if not isinstance(raw, dict):
        return []
    if isinstance(raw.get("artifacts"), list):
        repo = raw.get("repo", {}) if isinstance(raw.get("repo"), dict) else {}
        current_head = str(repo.get("head_sha") or repo.get("current_head") or "")
        current_branch = str(repo.get("branch") or "")
        dirty = dirty_entries(raw)
        artifacts = artifact_rows(raw)
        return [
            (artifact, classify_artifact(artifact, current_head, current_branch, dirty))
            for artifact in artifacts
        ]
    if isinstance(raw.get("rows"), list):
        pairs = []
        for index, row in enumerate(raw["rows"]):
            if not isinstance(row, dict):
                continue
            artifact = artifact_from_freshness_row(row, source_path, index)
            pairs.append((artifact, row))
        return pairs
    if raw_looks_like_artifact(raw):
        artifact = normalize_artifact(raw, source_path)
        current_head = first_string(raw, [("current_head_sha",), ("repo", "head_sha")])
        current_branch = first_string(raw, [("current_branch",), ("repo", "branch")])
        if not current_head:
            current_head = artifact.get("git_sha", "")
        if not current_branch:
            current_branch = MAIN_BRANCH
        dirty = dirty_entries(raw)
        return [(artifact, classify_artifact(artifact, current_head, current_branch, dirty))]
    return []


def proof_id_for(artifact: dict[str, Any], source_path: str, index: int) -> str:
    if artifact.get("proof_id"):
        return artifact["proof_id"]
    if artifact.get("artifact_path"):
        return artifact["artifact_path"]
    digest = stable_digest({"source_path": source_path, "index": index, "artifact": artifact})
    return f"proof:{digest.removeprefix('sha256:')[:16]}"


def freshness_refusal_reason(row: dict[str, Any]) -> str:
    if row.get("safe_to_cite"):
        return ""
    return REUSE_REFUSAL_BY_CLASSIFICATION.get(
        str(row.get("classification", "")),
        "unknown-cache-policy",
    )


def proof_reuse_index_entry(
    artifact: dict[str, Any],
    freshness_row: dict[str, Any],
    source_path: str,
    index: int,
) -> dict[str, Any]:
    evidence = freshness_row.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "proof_id": proof_id_for(artifact, source_path, index),
        "source_path": source_path,
        "artifact_path": artifact.get("artifact_path", ""),
        "manifest_lane_id": artifact.get("manifest_lane_id", ""),
        "manifest_guarantee_ids": sorted_strings(artifact.get("manifest_guarantee_ids", [])),
        "command": artifact.get("command", ""),
        "command_fingerprint": candidate_command_fingerprint(artifact),
        "source_fingerprint": artifact.get("source_fingerprint", ""),
        "tree_fingerprint": artifact.get("tree_fingerprint", ""),
        "toolchain_fingerprint": artifact.get("toolchain_fingerprint", ""),
        "env_fingerprint": artifact.get("env_fingerprint", ""),
        "feature_flags": sorted_strings(artifact.get("feature_flags", [])),
        "touched_surfaces": sorted_strings(artifact.get("touched_files", [])),
        "status": artifact.get("status", ""),
        "generated_at": artifact.get("generated_at", ""),
        "citeable_claims": sorted_strings(artifact.get("allowed_cache_hit_claims", [])),
        "refusal_metadata": {
            "freshness_classification": freshness_row.get("classification", ""),
            "freshness_decision": freshness_row.get("decision", ""),
            "freshness_reason": freshness_row.get("reason", ""),
            "freshness_refusal_reason_code": freshness_refusal_reason(freshness_row),
            "safe_to_cite": bool(freshness_row.get("safe_to_cite")),
            "dirty_overlap_count": evidence.get("dirty_overlap_count", 0),
            "remote_route_count": len(evidence.get("rch_remote_route_segments", [])),
            "local_fallback_marker_count": len(evidence.get("rch_local_fallback_segments", [])),
        },
    }


def build_proof_reuse_corpus(
    root_texts: list[str],
    repo_path: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    corpus = []
    approved_sources = []
    for path, relative in iter_reuse_index_json_files(root_texts, repo_path):
        approved_sources.append(relative)
        raw = load_json(path)
        for artifact, freshness_row in candidate_sources_from_json(raw, relative):
            corpus.append(
                {
                    "source_path": relative,
                    "artifact": artifact,
                    "freshness_row": freshness_row,
                }
            )
    corpus.sort(
        key=lambda item: (
            str(item["artifact"].get("manifest_lane_id", "")),
            str(item["artifact"].get("generated_at", "")),
            str(item["artifact"].get("artifact_path", "")),
            str(item["source_path"]),
        )
    )
    for index, item in enumerate(corpus):
        item["index_entry"] = proof_reuse_index_entry(
            item["artifact"],
            item["freshness_row"],
            item["source_path"],
            index,
        )
    return corpus, sorted(set(approved_sources))


def summarize_proof_reuse_index(entries: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "candidate_count": len(entries),
        "safe_to_cite": 0,
        "freshness_refused": 0,
        "by_lane": {},
        "by_freshness_classification": {},
    }
    for entry in entries:
        metadata = entry["refusal_metadata"]
        lane = entry.get("manifest_lane_id") or "<missing>"
        classification = metadata.get("freshness_classification") or "<missing>"
        summary["by_lane"][lane] = summary["by_lane"].get(lane, 0) + 1
        summary["by_freshness_classification"][classification] = (
            summary["by_freshness_classification"].get(classification, 0) + 1
        )
        if metadata.get("safe_to_cite"):
            summary["safe_to_cite"] += 1
        else:
            summary["freshness_refused"] += 1
    summary["by_lane"] = dict(sorted(summary["by_lane"].items()))
    summary["by_freshness_classification"] = dict(
        sorted(summary["by_freshness_classification"].items())
    )
    return summary


def build_proof_reuse_index(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    repo_path = Path(args.repo_path).resolve()
    generated_at = args.generated_at or utc_now()
    corpus, approved_sources = build_proof_reuse_corpus(args.reuse_index_root, repo_path)
    entries = [item["index_entry"] for item in corpus]
    summary = summarize_proof_reuse_index(entries)
    index = {
        "schema_version": PROOF_REUSE_INDEX_SCHEMA_VERSION,
        "generated_at": generated_at,
        "repo_path": str(repo_path),
        "approved_roots": normalized_approved_reuse_roots(args.reuse_index_root, repo_path),
        "approved_sources": approved_sources,
        "entries": entries,
        "summary": summary,
        "logs": [
            {
                "stage": "scan",
                "approved_root_count": len(args.reuse_index_root),
                "approved_source_count": len(approved_sources),
                "candidate_count": summary["candidate_count"],
            }
        ],
        "safety": {
            "non_mutating": True,
            "network_access_required": False,
            "tracker_mutation_allowed": False,
            "beads_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "destructive_commands_executed": False,
            "raw_proof_logs_embedded": False,
        },
    }
    return index, corpus


REUSE_REASON_RANK_WEIGHTS = {
    "lane-mismatch": 1000,
    "unknown-cache-policy": 600,
    "missing-command-fingerprint": 500,
    "command-mismatch": 450,
    "source-hash-mismatch": 400,
    "toolchain-mismatch": 350,
    "dirty-frontier-overlap": 300,
    "local-fallback-marker": 250,
    "failed-proof-status": 220,
    "stale-head": 200,
    "branch-mismatch": 180,
    "missing-touched-files": 160,
    "missing-dirty-frontier-status": 140,
    "broad-claim-unsupported": 120,
}


def proof_reuse_rank_score(row: dict[str, Any]) -> int:
    if row["decision"] == "reusable":
        return 0
    reason_codes = row.get("reason_codes", [])
    score = sum(REUSE_REASON_RANK_WEIGHTS.get(reason, 700) for reason in reason_codes)
    return score + len(reason_codes)


def compact_proof_reuse_query_row(
    item: dict[str, Any],
    classifier_row: dict[str, Any],
) -> dict[str, Any]:
    entry = item["index_entry"]
    row = {
        "rank": 0,
        "rank_score": proof_reuse_rank_score(classifier_row),
        "proof_id": entry["proof_id"],
        "candidate_id": classifier_row["candidate_id"],
        "source_path": entry["source_path"],
        "manifest_lane_id": entry["manifest_lane_id"],
        "decision": classifier_row["decision"],
        "safe_to_reuse": classifier_row["safe_to_reuse"],
        "classifier_decision": classifier_row["decision"],
        "cache_hit_is_fresh_rch_pass": classifier_row["cache_hit_is_fresh_rch_pass"],
        "reason_codes": classifier_row["reason_codes"],
        "freshness_classification": classifier_row["freshness_classification"],
        "freshness_decision": classifier_row["freshness_decision"],
        "command_fingerprint": entry["command_fingerprint"],
        "source_fingerprint": entry["source_fingerprint"],
        "tree_fingerprint": entry["tree_fingerprint"],
        "toolchain_fingerprint": entry["toolchain_fingerprint"],
        "env_fingerprint": entry["env_fingerprint"],
        "feature_flags": entry["feature_flags"],
        "touched_surfaces": entry["touched_surfaces"],
        "status": entry["status"],
        "citeable_claims": entry["citeable_claims"],
        "remediation": classifier_row["remediation"],
    }
    return row


def sort_proof_reuse_query_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decision_rank = {"reusable": 0, "refused": 1, "miss": 2}
    rows = sorted(
        rows,
        key=lambda row: (
            decision_rank.get(str(row["decision"]), 9),
            row["rank_score"],
            str(row.get("proof_id", "")),
            str(row.get("source_path", "")),
        ),
    )
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
    return rows


def bounded_proof_reuse_query_row_limit(raw_limit: Any) -> int:
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        limit = DEFAULT_PROOF_REUSE_QUERY_ROW_LIMIT
    return max(0, min(limit, MAX_PROOF_REUSE_QUERY_ROW_LIMIT))


def summarize_proof_reuse_query(
    rows: list[dict[str, Any]],
    request: dict[str, Any],
    emitted_count: int,
    row_limit: int,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "candidate_count": len(rows),
        "accepted_count": 0,
        "refused_count": 0,
        "miss_count": 0,
        "candidate_pruned_count": 0,
        "row_limit": row_limit,
        "rows_emitted_count": emitted_count,
        "rows_omitted_count": max(0, len(rows) - emitted_count),
        "rows_omission_reason": "bounded-query-output" if len(rows) > emitted_count else "",
        "chosen_proof_id": "",
        "top_rerun_command": request.get("command", ""),
        "by_reason_code": {},
        "elapsed_time": {
            "measured": False,
            "reason": "deterministic CLI output omits wall-clock timing; contract tests log elapsed_ms",
        },
    }
    for row in rows:
        if row["decision"] == "reusable":
            summary["accepted_count"] += 1
            if not summary["chosen_proof_id"]:
                summary["chosen_proof_id"] = row["proof_id"]
        elif row["decision"] == "refused":
            summary["refused_count"] += 1
        elif row["decision"] == "miss":
            summary["miss_count"] += 1
        for reason in row.get("reason_codes", []):
            summary["by_reason_code"][reason] = summary["by_reason_code"].get(reason, 0) + 1
    summary["by_reason_code"] = dict(sorted(summary["by_reason_code"].items()))
    summary["candidate_pruned_count"] = summary["refused_count"] + summary["miss_count"]
    if not summary["top_rerun_command"]:
        for row in rows:
            rerun = row.get("remediation", {}).get("rerun_command", "")
            if rerun:
                summary["top_rerun_command"] = rerun
                break
    return summary


def build_proof_reuse_query(args: argparse.Namespace) -> dict[str, Any]:
    index, corpus = build_proof_reuse_index(args)
    request_path, _request_relative = repo_relative_path(
        args.reuse_request_path,
        Path(args.repo_path).resolve(),
    )
    request = normalize_reuse_request(load_json(request_path))
    all_rows = sort_proof_reuse_query_rows(
        [
            compact_proof_reuse_query_row(
                item,
                classify_proof_reuse_candidate(
                    request,
                    item["artifact"],
                    item["freshness_row"],
                ),
            )
            for item in corpus
        ]
    )
    row_limit = bounded_proof_reuse_query_row_limit(
        getattr(args, "max_query_rows", DEFAULT_PROOF_REUSE_QUERY_ROW_LIMIT)
    )
    rows = all_rows[:row_limit]
    summary = summarize_proof_reuse_query(all_rows, request, len(rows), row_limit)
    best_candidate = next((row for row in all_rows if row["decision"] == "reusable"), None)
    result = {
        "schema_version": PROOF_REUSE_QUERY_SCHEMA_VERSION,
        "generated_at": index["generated_at"],
        "request": request,
        "best_candidate": best_candidate,
        "rows": rows,
        "summary": summary,
        "index_summary": index["summary"],
        "logs": [
            index["logs"][0],
            {
                "stage": "classify",
                "candidate_count": summary["candidate_count"],
                "accepted_count": summary["accepted_count"],
                "refused_count": summary["refused_count"],
                "miss_count": summary["miss_count"],
                "candidate_pruned_count": summary["candidate_pruned_count"],
                "pruning_reason_counts": summary["by_reason_code"],
            },
            {
                "stage": "project",
                "row_limit": summary["row_limit"],
                "rows_emitted_count": summary["rows_emitted_count"],
                "rows_omitted_count": summary["rows_omitted_count"],
                "rows_omission_reason": summary["rows_omission_reason"],
            },
            {
                "stage": "choose",
                "chosen_proof_id": summary["chosen_proof_id"],
                "top_rerun_command": summary["top_rerun_command"],
            },
        ],
        "safety": {
            "non_mutating": True,
            "network_access_required": False,
            "tracker_mutation_allowed": False,
            "beads_mutated": False,
            "cache_hit_is_never_fresh_rch_pass": True,
            "query_never_overrides_classifier": True,
            "raw_proof_logs_embedded": False,
        },
    }
    return result


def render_proof_reuse_query_markdown(result: dict[str, Any]) -> str:
    request = result["request"]
    summary = result["summary"]
    chosen = summary["chosen_proof_id"] or "<none>"
    lines = [
        f"# Proof reuse query: {request.get('request_id') or '<missing>'}",
        "",
        f"- lane: {request.get('manifest_lane_id') or '<missing>'}",
        f"- claim_scope: {request.get('claim_scope') or '<missing>'}",
        f"- candidates_scanned: {summary['candidate_count']}",
        f"- accepted: {summary['accepted_count']}",
        f"- refused: {summary['refused_count']}",
        f"- misses: {summary['miss_count']}",
        f"- candidate_pruned: {summary['candidate_pruned_count']}",
        f"- detailed_rows_emitted: {summary['rows_emitted_count']}",
        f"- detailed_rows_omitted: {summary['rows_omitted_count']}",
        f"- chosen_proof_id: {chosen}",
        f"- top_rerun_command: {summary['top_rerun_command'] or '<missing>'}",
        "",
        "## Ranked candidates",
    ]
    for row in result["rows"]:
        reasons = ",".join(row.get("reason_codes", [])) or "<none>"
        lines.append(
            f"{row['rank']}. {row['proof_id']} | decision={row['decision']} | "
            f"safe_to_reuse={str(row['safe_to_reuse']).lower()} | reasons={reasons}"
        )
    return "\n".join(lines)


def render_proof_reuse_index_markdown(index: dict[str, Any]) -> str:
    summary = index["summary"]
    lines = [
        "# Proof reuse index",
        "",
        f"- candidates_scanned: {summary['candidate_count']}",
        f"- safe_to_cite: {summary['safe_to_cite']}",
        f"- freshness_refused: {summary['freshness_refused']}",
        "",
        "## Lanes",
    ]
    for lane, count in summary["by_lane"].items():
        lines.append(f"- {lane}: {count}")
    return "\n".join(lines)


def remediation_for(classification: str, command: str) -> dict[str, Any]:
    if classification == "current-clean":
        return {
            "operator_note": "Artifact may be cited for the current clean surface.",
            "next_steps": ["include the artifact path and git SHA in the closeout"],
        }
    if classification == "dirty-surface-overlap":
        return {
            "operator_note": "Do not cite stale green output across dirty shared-main work.",
            "next_steps": [
                "identify the dirty owner before staging or citing proof",
                "rerun the focused proof after the touched surface is committed or cleaned",
            ],
            "rerun_command": command,
        }
    if classification == "unsafe-proof-command":
        return {
            "operator_note": "Do not cite green output from a Cargo proof that can fall back locally.",
            "next_steps": [
                "rerun the proof as RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo ...",
                "replace the artifact command before citing it",
            ],
            "rerun_command": remote_required_rerun_command(command),
        }
    if classification == "rch-local-fallback-proof":
        return {
            "operator_note": "Do not cite green output from an rch local fallback proof.",
            "next_steps": [
                "rerun the proof remotely and require an [RCH] remote summary",
                "replace the artifact output before citing it",
            ],
            "rerun_command": command,
        }
    if classification == "unverifiable-rch-remote-proof":
        return {
            "operator_note": "Do not cite an RCH Cargo proof without positive remote-worker route evidence.",
            "next_steps": [
                "rerun the proof remotely and capture a transcript line starting with [RCH] remote",
                "replace the artifact output before citing it",
            ],
            "rerun_command": command,
        }
    if classification == "exact-filter-zero-tests":
        return {
            "operator_note": "Do not cite an exact-filter Cargo proof that ran zero tests.",
            "next_steps": [
                "verify that the exact test name still exists on current main",
                "rerun the intended proof lane or update the stale filter before citing it",
            ],
            "rerun_command": command,
        }
    if classification == "exact-filter-no-executed-tests":
        return {
            "operator_note": "Do not cite an exact-filter Cargo proof whose matched tests were all ignored.",
            "next_steps": [
                "run a proof lane that executes at least one matched test",
                "keep the stale or ignored exact-filter output as diagnostic evidence only",
            ],
            "rerun_command": command,
        }
    if classification == "unverifiable-exact-filter-proof":
        return {
            "operator_note": "Do not cite an exact-filter Cargo proof without parseable test-count evidence.",
            "next_steps": [
                "rerun with --nocapture or otherwise capture libtest running/test-result summary lines",
                "replace the artifact output before citing it",
            ],
            "rerun_command": command,
        }
    if classification == "failed-proof-artifact":
        return {
            "operator_note": "Do not cite a proof artifact whose own status is failed.",
            "next_steps": [
                "inspect the failed proof output",
                "fix the underlying failure or rerun the proof after the relevant source changes",
            ],
            "rerun_command": command,
        }
    if classification == "unverifiable-fuzz-extent-proof":
        return {
            "operator_note": "Do not cite fuzz all-bins output without source-fresh target coverage.",
            "next_steps": [
                "rerun the fuzz all-bins proof with a unique target directory",
                "emit registered targets, source-fresh compiled targets, toolchain identity, and target-dir identity",
            ],
            "rerun_command": command,
        }
    if classification in {"superseded-head", "wrong-branch", "repo-not-main"}:
        return {
            "operator_note": "Suppress this artifact as stale before reporting a green lane.",
            "next_steps": ["rerun the proof command on current main HEAD"],
            "rerun_command": command,
        }
    return {
        "operator_note": "Artifact lacks enough provenance to support a green claim.",
        "next_steps": ["produce a new artifact with git_sha, git_branch, command, and touched_files"],
        "rerun_command": command,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": len(rows),
        "safe_to_cite": 0,
        "suppressed": 0,
        "rerun_required": 0,
        "unverifiable": 0,
        "by_classification": {},
    }
    for row in rows:
        classification = row["classification"]
        summary["by_classification"][classification] = (
            summary["by_classification"].get(classification, 0) + 1
        )
        if row["safe_to_cite"]:
            summary["safe_to_cite"] += 1
        if row["decision"].startswith("suppress"):
            summary["suppressed"] += 1
        if row["decision"] == "rerun-required":
            summary["rerun_required"] += 1
        if "unverifiable" in classification:
            summary["unverifiable"] += 1
    return summary


def top_remediation(row: dict[str, Any]) -> str:
    remediation = row.get("remediation", {})
    if not isinstance(remediation, dict):
        return ""
    operator_note = remediation.get("operator_note")
    if isinstance(operator_note, str) and operator_note:
        return operator_note
    next_steps = remediation.get("next_steps")
    if isinstance(next_steps, list):
        for step in next_steps:
            if isinstance(step, str) and step:
                return step
    return ""


def summary_scalar(value: Any, fallback: str = "<missing>") -> str:
    if not isinstance(value, str) or not value:
        return fallback
    compact = " ".join(value.split())
    return compact or fallback


def agent_mail_summary(rows: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    lines = [
        "Proof receipt closeout summary: "
        f"{summary['total']} total; "
        f"{summary['safe_to_cite']} citeable; "
        f"{summary['rerun_required']} rerun-required; "
        f"{summary['suppressed']} suppressed."
    ]
    if not rows:
        lines.append("- no proof artifacts found")
        return "\n".join(lines)

    for row in rows:
        lines.append(
            f"- {summary_scalar(row['artifact_path'])} | "
            f"classification={summary_scalar(row['classification'])} | "
            f"decision={summary_scalar(row['decision'])} | "
            f"safe_to_cite={str(row['safe_to_cite']).lower()}"
        )
        lines.append(f"  command: {summary_scalar(row['command'])}")
        lines.append(f"  top_remediation: {summary_scalar(top_remediation(row), '<none>')}")
    return "\n".join(lines)


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    repo_path = Path(args.repo_path).resolve()
    source = load_json(Path(args.fixture)) if args.fixture else live_probe(repo_path, args.artifact, args.timeout)
    generated_at = args.generated_at or utc_now()
    repo = source.get("repo", {}) if isinstance(source.get("repo"), dict) else {}
    current_head = str(repo.get("head_sha") or repo.get("current_head") or "")
    current_branch = str(repo.get("branch") or "")
    dirty = dirty_entries(source)
    artifacts = artifact_rows(source)
    rows = [
        classify_artifact(artifact, current_head, current_branch, dirty)
        for artifact in artifacts
    ]
    summary = summarize(rows)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": args.agent,
        "agent_mail_summary": agent_mail_summary(rows, summary),
        "repo_path": str(repo_path),
        "current_head_sha": current_head,
        "current_branch": current_branch,
        "artifact_errors": source.get("artifact_errors", []),
        "rows": rows,
        "summary": summary,
        "safety": {
            "non_mutating": True,
            "executed_commands": GIT_READ_COMMANDS if not args.fixture else [],
            "mutating_commands_executed": False,
            "beads_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "destructive_commands_executed": False,
        },
    }
    proof_reuse = build_proof_reuse_receipt(source, artifacts, rows)
    if proof_reuse is not None:
        receipt["proof_reuse"] = proof_reuse
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a non-mutating proof artifact freshness receipt")
    parser.add_argument("--fixture", default="", help="Read deterministic input from a JSON fixture")
    parser.add_argument("--artifact", action="append", default=[], help="Proof artifact JSON path for live mode")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="", help="Agent generating the receipt")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic receipts")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument(
        "--reuse-index-root",
        action="append",
        default=[],
        help="Approved repo-local artifact or receipt-fixture root to scan for proof reuse",
    )
    parser.add_argument(
        "--request",
        "--query",
        dest="reuse_request_path",
        default="",
        help="Desired proof lane JSON envelope for proof reuse query mode",
    )
    parser.add_argument(
        "--max-query-rows",
        type=int,
        default=DEFAULT_PROOF_REUSE_QUERY_ROW_LIMIT,
        help=(
            "Maximum detailed rows to emit for proof reuse query results "
            f"(0-{MAX_PROOF_REUSE_QUERY_ROW_LIMIT}; full summary counts are preserved)"
        ),
    )
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    try:
        if args.reuse_index_root:
            receipt = (
                build_proof_reuse_query(args)
                if args.reuse_request_path
                else build_proof_reuse_index(args)[0]
            )
        elif args.reuse_request_path:
            raise ValueError("--request/--query requires at least one --reuse-index-root")
        else:
            receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    if args.output == "markdown":
        if receipt.get("schema_version") == PROOF_REUSE_QUERY_SCHEMA_VERSION:
            print(render_proof_reuse_query_markdown(receipt))
        elif receipt.get("schema_version") == PROOF_REUSE_INDEX_SCHEMA_VERSION:
            print(render_proof_reuse_index_markdown(receipt))
        else:
            print(receipt.get("agent_mail_summary", ""))
    else:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
