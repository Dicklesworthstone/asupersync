#!/usr/bin/env python3
"""Classify proof artifacts against the current repo frontier.

The receipt is intentionally non-mutating. It checks whether a validation
artifact was produced for the current HEAD and whether dirty working-tree paths
overlap the files that artifact claims to prove.
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "validation-artifact-freshness-v1"
GIT_COMMAND_TIMEOUT_SECONDS = 5.0


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


def repo_head(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_COMMAND_TIMEOUT_SECONDS,
    )
    return result.stdout.strip()


def git_dirty_paths(repo_root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "status", "--short"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_COMMAND_TIMEOUT_SECONDS,
    )
    return parse_status_lines(result.stdout.splitlines())


def parse_status_lines(lines: list[str]) -> list[str]:
    paths: list[str] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if len(line) < 4:
            continue
        status = line[:2]
        path = line[3:]
        if ("R" in status or "C" in status) and " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path)
    return paths


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def artifact_head(artifact: dict[str, Any]) -> str:
    for key in ("repo_head", "git_head", "head", "commit", "commit_sha"):
        value = artifact.get(key)
        if isinstance(value, str) and value:
            return value

    git = artifact.get("git")
    if isinstance(git, dict):
        value = git.get("head") or git.get("commit")
        if isinstance(value, str) and value:
            return value

    return ""


def artifact_touched_files(artifact: dict[str, Any]) -> list[str]:
    direct = string_list(artifact.get("touched_files"))
    if direct:
        return direct

    record = artifact.get("validation_frontier_record")
    if isinstance(record, dict):
        nested = string_list(record.get("touched_files"))
        if nested:
            return nested

    receipt = artifact.get("receipt")
    if isinstance(receipt, dict):
        nested = string_list(receipt.get("touched_files"))
        if nested:
            return nested

    return []


def artifact_decision(artifact: dict[str, Any]) -> str:
    decision = artifact.get("decision")
    if isinstance(decision, str):
        return decision
    record = artifact.get("validation_frontier_record")
    if isinstance(record, dict) and isinstance(record.get("decision"), str):
        return record["decision"]
    return ""


def normalize_path(path: str) -> str:
    return path.strip().replace("\\", "/").lstrip("./").rstrip("/")


def normalize_paths(paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for path in paths:
        clean = normalize_path(path)
        if clean:
            normalized.append(clean)
    return normalized


def paths_overlap(touched_path: str, dirty_path: str) -> bool:
    if touched_path == dirty_path:
        return True
    return dirty_path.startswith(f"{touched_path}/") or touched_path.startswith(f"{dirty_path}/")


def classify(
    artifact: dict[str, Any],
    current_head: str,
    dirty_paths: list[str],
) -> dict[str, Any]:
    proof_head = artifact_head(artifact)
    touched_files = artifact_touched_files(artifact)
    touched = normalize_paths(touched_files)
    dirty = normalize_paths(dirty_paths)
    dirty_overlap = sorted(
        path for path in dirty if any(paths_overlap(surface, path) for surface in touched)
    )
    dirty_external = sorted(path for path in dirty if path not in dirty_overlap)
    decision = artifact_decision(artifact)

    if not proof_head:
        classification = "unbound-artifact"
        verdict = "invalid"
    elif proof_head != current_head:
        classification = "stale-head"
        verdict = "stale"
    elif dirty_overlap:
        classification = "stale-dirty-overlap"
        verdict = "stale"
    elif dirty_external:
        classification = "current-with-external-dirt"
        verdict = "blocked-external"
    else:
        classification = "current"
        verdict = "current"

    return {
        "classification": classification,
        "verdict": verdict,
        "artifact": {
            "head": proof_head,
            "decision": decision,
            "touched_files": touched_files,
        },
        "current": {
            "head": current_head,
            "dirty_paths": dirty_paths,
        },
        "markers": {
            "head_matches": bool(proof_head) and proof_head == current_head,
            "has_artifact_head": bool(proof_head),
            "dirty_touched_overlap": dirty_overlap,
            "dirty_external_paths": dirty_external,
        },
    }


def remediation_for(classification: str) -> dict[str, Any]:
    if classification == "stale-head":
        return {
            "summary": "artifact was produced for a superseded HEAD",
            "operator_note": "Do not cite this artifact as current proof.",
            "next_steps": [
                "rerun the focused proof lane at the current HEAD",
                "keep the old artifact only as historical evidence",
            ],
        }
    if classification == "stale-dirty-overlap":
        return {
            "summary": "dirty files overlap the artifact's touched surface",
            "operator_note": "Treat the artifact as stale until the overlapping files are committed or revalidated.",
            "next_steps": [
                "finish or coordinate the overlapping dirty paths",
                "rerun the focused proof lane after the overlap is clean",
            ],
        }
    if classification == "current-with-external-dirt":
        return {
            "summary": "artifact matches HEAD, but unrelated dirty paths remain",
            "operator_note": "The artifact may support its touched files; unrelated dirty paths still block broad proof lanes.",
            "next_steps": [
                "cite the artifact only for its touched surface",
                "surface the unrelated dirty paths separately",
            ],
        }
    if classification == "current":
        return {
            "summary": "artifact matches the current frontier",
            "operator_note": "The artifact can be cited for its touched surface.",
            "next_steps": ["include this receipt alongside the proof artifact"],
        }
    return {
        "summary": "artifact lacks a usable repo HEAD marker",
        "operator_note": "Do not infer freshness from an unbound artifact.",
        "next_steps": [
            "regenerate the artifact with repo_head or git.head",
            "record touched_files before citing the proof",
        ],
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    artifact = load_json(args.artifact)
    if not isinstance(artifact, dict):
        raise ValueError("artifact JSON must be an object")

    repo_root = Path(args.repo_root).resolve()
    current_head = args.current_head or repo_head(repo_root)
    if args.dirty_paths_json:
        dirty_paths = string_list(load_json(args.dirty_paths_json))
    else:
        dirty_paths = git_dirty_paths(repo_root)

    generated_at = args.generated_at or utc_now()
    analysis = classify(artifact, current_head, dirty_paths)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "artifact_path": args.artifact,
        **analysis,
        "remediation": remediation_for(analysis["classification"]),
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify validation artifact freshness against HEAD and dirty paths"
    )
    parser.add_argument("--artifact", required=True, help="Validation artifact JSON to classify")
    parser.add_argument("--repo-root", default=".", help="Repository root for live git probes")
    parser.add_argument("--current-head", default="", help="Override current HEAD for deterministic tests")
    parser.add_argument("--dirty-paths-json", default="", help="JSON array of dirty paths for deterministic tests")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
