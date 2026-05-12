#!/usr/bin/env python3
"""Emit a non-mutating proof artifact freshness receipt.

The receipt answers one narrow operator question: can this green-looking proof
artifact still be cited for the current shared-main tree? It refuses stale HEADs,
wrong branches, missing provenance, and artifacts whose touched surface overlaps
current dirty work.
"""

import argparse
import datetime as dt
import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-artifact-freshness-receipt-v1"
MAIN_BRANCH = "main"
GIT_READ_COMMANDS = [
    "git rev-parse HEAD",
    "git branch --show-current",
    "git status --porcelain=v1",
]


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
        entries.append(
            {
                "status": line[:2],
                "path": line[3:],
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


def normalize_artifact(raw: Any, fallback_path: str = "") -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "artifact_path": fallback_path,
            "git_sha": "",
            "git_branch": "",
            "command": "",
            "touched_files": [],
            "status": "",
            "generated_at": "",
        }

    return {
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
        path = str(item.get("path", ""))
        if not path:
            continue
        entries.append(
            {
                "status": str(item.get("status", "")),
                "path": path,
                "classification": str(item.get("classification", "")),
                "owner": str(item.get("owner", "")),
            }
        )
    return entries


def path_matches(pattern: str, path: str) -> bool:
    return pattern == path or fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(pattern, path)


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
    touched_files = artifact["touched_files"]
    overlaps = dirty_overlaps(touched_files, dirty)

    evidence = {
        "artifact_git_sha": git_sha,
        "current_head_sha": current_head,
        "artifact_git_branch": git_branch,
        "current_branch": current_branch,
        "dirty_overlap_count": len(overlaps),
        "dirty_overlaps": overlaps,
    }

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
    elif not touched_files:
        classification = "unverifiable-surface"
        decision = "suppress-as-unverifiable"
        reason = "artifact does not declare touched files"
    elif overlaps:
        classification = "dirty-surface-overlap"
        decision = "rerun-required"
        reason = "artifact touched files overlap current dirty tree entries"
    else:
        classification = "current-clean"
        decision = "cite-as-current"
        reason = "artifact HEAD and touched files match a clean cited surface"

    safe_to_cite = classification == "current-clean"
    return {
        "artifact_path": artifact_path,
        "classification": classification,
        "decision": decision,
        "safe_to_cite": safe_to_cite,
        "reason": reason,
        "status": artifact["status"],
        "command": artifact["command"],
        "touched_files": touched_files,
        "generated_at": artifact["generated_at"],
        "evidence": evidence,
        "remediation": remediation_for(classification, artifact["command"]),
    }


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


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    repo_path = Path(args.repo_path).resolve()
    source = load_json(Path(args.fixture)) if args.fixture else live_probe(repo_path, args.artifact, args.timeout)
    generated_at = args.generated_at or utc_now()
    repo = source.get("repo", {}) if isinstance(source.get("repo"), dict) else {}
    current_head = str(repo.get("head_sha") or repo.get("current_head") or "")
    current_branch = str(repo.get("branch") or "")
    dirty = dirty_entries(source)
    rows = [
        classify_artifact(artifact, current_head, current_branch, dirty)
        for artifact in artifact_rows(source)
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": args.agent,
        "repo_path": str(repo_path),
        "current_head_sha": current_head,
        "current_branch": current_branch,
        "artifact_errors": source.get("artifact_errors", []),
        "rows": rows,
        "summary": summarize(rows),
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a non-mutating proof artifact freshness receipt")
    parser.add_argument("--fixture", default="", help="Read deterministic input from a JSON fixture")
    parser.add_argument("--artifact", action="append", default=[], help="Proof artifact JSON path for live mode")
    parser.add_argument("--repo-path", default=".", help="Repository path to report/probe")
    parser.add_argument("--agent", default="", help="Agent generating the receipt")
    parser.add_argument("--generated-at", default="", help="Stable timestamp for deterministic receipts")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
