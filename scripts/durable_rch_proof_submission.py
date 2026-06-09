#!/usr/bin/env python3
"""Plan durable RCH proof submissions without invoking RCH.

This helper creates a deterministic submission record for a manifest proof lane.
It is deliberately non-executing: later beads can consume the record to launch,
observe, and capture terminal output, but this bead only freezes the command,
source, duplicate lease, and resume expectations that must exist before an
agent detaches.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any


SUBMISSION_SCHEMA_VERSION = "durable-rch-proof-submission-v1"
CLI_SCHEMA_VERSION = "durable-rch-proof-cli-v1"
CANCELLATION_SCHEMA_VERSION = "durable-rch-proof-cancellation-v1"
DEFAULT_MANIFEST = "artifacts/proof_lane_manifest_v1.json"
DEFAULT_RECEIPT_CONTRACT = "artifacts/durable_rch_proof_receipt_contract_v1.json"
MAIN_BRANCH = "main"
SHA_PREFIX = "sha256:"
BROAD_UNSUPPORTED_CLAIMS = {
    "release-readiness",
    "workspace-health",
    "live-rch-fleet-availability",
}
NONTERMINAL_STATES = {"queued", "running", "client_disconnected", "partial"}
TERMINAL_STATES = {
    "terminal_pass",
    "terminal_fail",
    "terminal_canceled",
    "terminal_stale",
    "terminal_infra_error",
}
TRACKER_ROOTS = {".beads", "agents", "messages", "file_reservations"}
TEMP_OUTPUT_ROOTS = (Path("/tmp"), Path("/data/tmp"))
SUBCOMMANDS = {"submit", "status", "query", "cancel"}

EXAMPLE_TEXT = """examples:
  durable_rch_proof_submission.py submit --lane-id proof-lane-manifest-contract \\
    --branch main --head-commit HEAD --source-tree-fingerprint git-tree:HEAD
  durable_rch_proof_submission.py status --job-store artifacts/durable_rch_jobs.json \\
    --submission-id drps-example
  durable_rch_proof_submission.py query --job-store artifacts/durable_rch_jobs.json \\
    --submission-id drps-example --claim proof-lane-manifest-contract
  durable_rch_proof_submission.py cancel --job-store artifacts/durable_rch_jobs.json \\
    --submission-id drps-example --agent MistyMill --reason-code operator-requested

RCH proof commands referenced by submissions must use the AGENTS.md pattern:
  RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/..." cargo test ...
"""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_text(value: str) -> str:
    return SHA_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_short_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def env_assignments(tokens: list[str]) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        name, value = token.split("=", 1)
        if name and name.replace("_", "A").isalnum() and not name[0].isdigit():
            assignments[name] = value
    return assignments


def target_dir_from_env(assignments: dict[str, str]) -> str:
    return assignments.get("CARGO_TARGET_DIR", "")


def manifest_lane(manifest: dict[str, Any], lane_id: str) -> dict[str, Any] | None:
    for lane in manifest.get("lanes", []):
        if isinstance(lane, dict) and lane.get("lane_id") == lane_id:
            return lane
    return None


def sorted_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(item for item in value if isinstance(item, str) and item)


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def string_value(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def bool_value(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def overlaps_dirty_source(dirty_paths: list[str], source_paths: list[str]) -> bool:
    for dirty in dirty_paths:
        for source in source_paths:
            if dirty == source:
                return True
            if dirty.startswith(source.rstrip("/") + "/"):
                return True
            if source.startswith(dirty.rstrip("/") + "/"):
                return True
            if fnmatch.fnmatchcase(dirty, source) or fnmatch.fnmatchcase(source, dirty):
                return True
    return False


def existing_submissions(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    raw = load_json(path)
    return submission_rows(raw)


def submission_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [
            row.get("submission") if isinstance(row.get("submission"), dict) else row
            for row in raw
            if isinstance(row, dict)
        ]
    if isinstance(raw, dict):
        if isinstance(raw.get("submission"), dict):
            return [raw["submission"]]
        rows = raw.get("submissions", [])
        if isinstance(rows, list):
            return [
                row.get("submission") if isinstance(row.get("submission"), dict) else row
                for row in rows
                if isinstance(row, dict)
            ]
    return []


def receipt_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [row for row in raw if isinstance(row, dict) and "receipt_id" in row]
    if isinstance(raw, dict):
        if string_value(raw.get("schema_version")) == "durable-rch-proof-receipt-v1":
            return [raw]
        rows = raw.get("receipts", [])
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def cancellation_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        rows = raw.get("cancellations", [])
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
        if isinstance(raw.get("cancellation"), dict):
            return [raw["cancellation"]]
    return []


def load_job_store(path: Path) -> dict[str, list[dict[str, Any]]]:
    raw = load_json(path)
    return {
        "submissions": submission_rows(raw),
        "receipts": receipt_rows(raw),
        "cancellations": cancellation_rows(raw),
    }


def find_submission(rows: list[dict[str, Any]], submission_id: str) -> dict[str, Any] | None:
    for row in rows:
        if string_value(row.get("submission_id")) == submission_id:
            return row
    return None


def find_receipt(rows: list[dict[str, Any]], submission_id: str) -> dict[str, Any] | None:
    matches = [row for row in rows if string_value(row.get("submission_id")) == submission_id]
    if not matches:
        return None
    return sorted(matches, key=lambda row: string_value(row.get("generated_at")))[-1]


def find_cancellation(rows: list[dict[str, Any]], submission_id: str) -> dict[str, Any] | None:
    matches = [row for row in rows if string_value(row.get("submission_id")) == submission_id]
    if not matches:
        return None
    return sorted(matches, key=lambda row: string_value(row.get("requested_at")))[-1]


def nested_string(row: dict[str, Any], *path: str) -> str:
    cursor: Any = row
    for key in path:
        if not isinstance(cursor, dict):
            return ""
        cursor = cursor.get(key)
    return cursor if isinstance(cursor, str) else ""


def duplicate_result(
    rows: list[dict[str, Any]],
    lane_id: str,
    expected_head: str,
    command_fingerprint: str,
    match_key: str,
) -> dict[str, Any] | None:
    for row in rows:
        existing_lane = str(row.get("manifest_lane_id") or row.get("lane_id") or "")
        existing_head = (
            nested_string(row, "source", "expected_head")
            or nested_string(row, "source", "head_commit")
            or str(row.get("expected_head") or "")
        )
        if existing_lane != lane_id or existing_head != expected_head:
            continue

        existing_command = nested_string(row, "command", "command_fingerprint") or str(
            row.get("command_fingerprint") or ""
        )
        existing_match_key = str(row.get("match_key") or nested_string(row, "lease", "match_key"))
        existing_state = str(row.get("lifecycle_state") or "")

        if existing_match_key == match_key or existing_command == command_fingerprint:
            return {
                "decision": "coalesced",
                "reason_codes": [],
                "duplicate_action": "coalesced-existing-submission",
                "existing_submission_id": str(row.get("submission_id") or ""),
                "existing_lifecycle_state": existing_state,
                "existing_terminal": existing_state in TERMINAL_STATES,
            }

        return {
            "decision": "refused",
            "reason_codes": ["duplicate-submission-conflict"],
            "duplicate_action": "rejected-conflicting-lane-head-command",
            "existing_submission_id": str(row.get("submission_id") or ""),
            "existing_lifecycle_state": existing_state,
            "existing_terminal": existing_state in TERMINAL_STATES,
        }
    return None


def output_path_allowed(repo_root: Path, output_path: Path) -> bool:
    resolved = output_path if output_path.is_absolute() else repo_root / output_path
    resolved = resolved.resolve()
    try:
        relative = resolved.relative_to(repo_root.resolve())
    except ValueError:
        temp_roots = set(TEMP_OUTPUT_ROOTS)
        temp_roots.add(Path(tempfile.gettempdir()))
        return any(path_is_under(resolved, root) for root in temp_roots)
    if not relative.parts:
        return False
    if relative.parts[0] in TRACKER_ROOTS:
        return False
    return relative.parts[0] == "artifacts"


def path_is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return True


def terminal_classification_for(reason_codes: list[str]) -> str | None:
    if not reason_codes:
        return None
    if "local-fallback-marker" in reason_codes or "command-mismatch" in reason_codes:
        return "local_fallback_refused"
    return "cargo_failure"


def record_command(record: dict[str, Any]) -> dict[str, Any]:
    command = record.get("command") if isinstance(record.get("command"), dict) else {}
    return {
        "command_fingerprint": string_value(command.get("command_fingerprint")),
        "remote_required": bool_value(command.get("remote_required")),
        "local_fallback_allowed": bool_value(command.get("local_fallback_allowed")),
        "target_dir": string_value(command.get("target_dir")),
    }


def record_source(record: dict[str, Any]) -> dict[str, Any]:
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    return {
        "branch": string_value(source.get("branch")),
        "head_commit": string_value(source.get("head_commit")),
        "expected_head": string_value(source.get("expected_head")),
        "source_tree_fingerprint": string_value(source.get("source_tree_fingerprint")),
        "dirty_frontier_status": string_value(source.get("dirty_frontier_status")),
        "dirty_frontier_paths": sorted_string_list(source.get("dirty_frontier_paths")),
        "touched_files": sorted_string_list(source.get("touched_files")),
    }


def record_provenance(record: dict[str, Any]) -> dict[str, Any]:
    provenance = record.get("rch_provenance") if isinstance(record.get("rch_provenance"), dict) else {}
    return {
        "worker_id": string_value(provenance.get("worker_id")),
        "remote_route_segments": string_list(provenance.get("remote_route_segments")),
        "submitted_at": string_value(provenance.get("submitted_at")),
        "started_at": string_value(provenance.get("started_at")),
        "finished_at": string_value(provenance.get("finished_at")),
        "detector_progress_stale": bool_value(provenance.get("detector_progress_stale")),
        "detector_heartbeat_stale": bool_value(provenance.get("detector_heartbeat_stale")),
    }


def record_claim_boundaries(record: dict[str, Any]) -> dict[str, Any]:
    boundaries = (
        record.get("claim_boundaries") if isinstance(record.get("claim_boundaries"), dict) else {}
    )
    return {
        "citable": bool_value(boundaries.get("citable")),
        "refusal_reason_codes": sorted_string_list(boundaries.get("refusal_reason_codes")),
        "explicit_not_covered": sorted_string_list(boundaries.get("explicit_not_covered")),
    }


def status_record(
    generated_at: str,
    command_name: str,
    decision: str,
    reason_codes: list[str],
    submission: dict[str, Any] | None,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    primary = receipt if receipt is not None else submission or {}
    submission_id = string_value(primary.get("submission_id")) or (
        string_value(submission.get("submission_id")) if submission else ""
    )
    lifecycle_state = string_value(primary.get("lifecycle_state"))
    terminal = lifecycle_state in TERMINAL_STATES
    return {
        "schema_version": CLI_SCHEMA_VERSION,
        "generated_at": generated_at,
        "operation": command_name,
        "decision": decision,
        "reason_codes": sorted(set(reason_codes)),
        "submission_id": submission_id,
        "receipt_id": string_value(primary.get("receipt_id")),
        "manifest_lane_id": string_value(primary.get("manifest_lane_id")),
        "claim_scope": string_value(primary.get("claim_scope")),
        "proof_evidence_status": string_value(primary.get("proof_evidence_status")),
        "lifecycle_state": lifecycle_state,
        "terminal_classification": string_value(primary.get("terminal_classification")),
        "terminal": terminal,
        "receipt_available": receipt is not None,
        "command": record_command(primary),
        "source": record_source(primary),
        "rch_provenance": record_provenance(primary),
        "claim_boundaries": record_claim_boundaries(primary),
    }


def unknown_record(generated_at: str, command_name: str, submission_id: str) -> dict[str, Any]:
    return {
        "schema_version": CLI_SCHEMA_VERSION,
        "generated_at": generated_at,
        "operation": command_name,
        "decision": "refused",
        "reason_codes": ["unknown-submission-id"],
        "submission_id": submission_id,
        "receipt_id": "",
        "manifest_lane_id": "",
        "claim_scope": "",
        "proof_evidence_status": "refused",
        "lifecycle_state": "unknown",
        "terminal_classification": "",
        "terminal": False,
        "receipt_available": False,
        "command": record_command({}),
        "source": record_source({}),
        "rch_provenance": record_provenance({}),
        "claim_boundaries": record_claim_boundaries({}),
    }


def build_status(args: argparse.Namespace) -> dict[str, Any]:
    generated_at = args.generated_at or utc_now()
    store = load_job_store(Path(args.job_store))
    submission = find_submission(store["submissions"], args.submission_id)
    if submission is None:
        return unknown_record(generated_at, "status", args.submission_id)
    receipt = find_receipt(store["receipts"], args.submission_id)
    cancellation = find_cancellation(store["cancellations"], args.submission_id)
    record = status_record(generated_at, "status", "accepted", [], submission, receipt)
    if receipt is None and cancellation is not None:
        record["lifecycle_state"] = "terminal_canceled"
        record["terminal_classification"] = "operator_canceled"
        record["proof_evidence_status"] = "blocked"
        record["terminal"] = True
        record["cancellation"] = cancellation
    return record


def build_query(args: argparse.Namespace) -> dict[str, Any]:
    generated_at = args.generated_at or utc_now()
    store = load_job_store(Path(args.job_store))
    submission = find_submission(store["submissions"], args.submission_id)
    if submission is None:
        return unknown_record(generated_at, "query", args.submission_id)
    receipt = find_receipt(store["receipts"], args.submission_id)

    reason_codes: list[str] = []
    if args.claim in BROAD_UNSUPPORTED_CLAIMS:
        reason_codes.append("broad-claim-unsupported")
    if receipt is None:
        reason_codes.append("receipt-not-available")
    else:
        if string_value(receipt.get("lifecycle_state")) not in TERMINAL_STATES:
            reason_codes.append("receipt-not-terminal")
        boundaries = record_claim_boundaries(receipt)
        if not boundaries["citable"]:
            receipt_reasons = boundaries["refusal_reason_codes"] or ["failed-proof-status"]
            reason_codes.extend(receipt_reasons)

    decision = "accepted" if not reason_codes else "refused"
    record = status_record(generated_at, "query", decision, reason_codes, submission, receipt)
    if reason_codes:
        record["claim_boundaries"]["citable"] = False
    record["requested_claim"] = args.claim
    if receipt is not None:
        record["receipt"] = receipt
    else:
        cancellation = find_cancellation(store["cancellations"], args.submission_id)
        if cancellation is not None:
            record["lifecycle_state"] = "terminal_canceled"
            record["terminal_classification"] = "operator_canceled"
            record["proof_evidence_status"] = "blocked"
            record["terminal"] = True
            record["cancellation"] = cancellation
    return record


def build_cancel(args: argparse.Namespace) -> dict[str, Any]:
    generated_at = args.generated_at or utc_now()
    store = load_job_store(Path(args.job_store))
    submission = find_submission(store["submissions"], args.submission_id)
    if submission is None:
        return unknown_record(generated_at, "cancel", args.submission_id)

    existing_receipt = find_receipt(store["receipts"], args.submission_id)
    if existing_receipt is not None and string_value(existing_receipt.get("lifecycle_state")) in TERMINAL_STATES:
        record = status_record(
            generated_at,
            "cancel",
            "refused",
            ["already-terminal"],
            submission,
            existing_receipt,
        )
        return record

    cancellation_id = stable_short_id(
        "drpc",
        "|".join([args.submission_id, args.agent, args.reason_code, generated_at]),
    )
    cancellation = {
        "schema_version": CANCELLATION_SCHEMA_VERSION,
        "cancellation_id": cancellation_id,
        "submission_id": args.submission_id,
        "requested_at": generated_at,
        "requested_by_agent": args.agent,
        "reason_code": args.reason_code,
        "lifecycle_state": "terminal_canceled",
        "terminal_classification": "operator_canceled",
        "proof_evidence_status": "blocked",
        "not_cargo_failure": True,
        "rch_cancel_invoked": False,
        "tracker_mutation_allowed": False,
    }
    record = status_record(generated_at, "cancel", "accepted", [], submission, None)
    record["lifecycle_state"] = "terminal_canceled"
    record["terminal_classification"] = "operator_canceled"
    record["proof_evidence_status"] = "blocked"
    record["terminal"] = True
    record["cancellation"] = cancellation
    if args.record_output:
        record = write_record(Path(args.repo_root).resolve(), args.record_output, record)
    return record


def build_submission(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    manifest = load_json(repo_root / args.manifest)
    receipt_contract = load_json(repo_root / args.receipt_contract)
    policy = receipt_contract.get("decision_policy", {})
    required_prefix = str(
        policy.get("required_command_prefix")
        or manifest.get("command_policy", {}).get("all_commands_must_start_with")
        or "RCH_REQUIRE_REMOTE=1 rch exec -- "
    )
    required_branch = str(policy.get("required_branch") or MAIN_BRANCH)
    lane = manifest_lane(manifest, args.lane_id)

    reason_codes: list[str] = []
    if lane is None:
        reason_codes.append("missing-manifest-lane")
        lane = {
            "lane_id": args.lane_id,
            "command": "",
            "guarantee_ids": [],
            "source_paths": [],
            "covers": "",
            "explicit_not_covered": "",
        }

    command = str(lane.get("command") or "")
    tokens = command_tokens(command)
    assignments = env_assignments(tokens)
    command_fingerprint = sha256_text(command)
    env_fingerprint = sha256_text(json.dumps(assignments, sort_keys=True, separators=(",", ":")))
    source_paths = sorted_string_list(lane.get("source_paths"))
    dirty_paths = sorted(set(args.dirty_path or []))

    if not command.startswith(required_prefix):
        reason_codes.append("command-mismatch")
    if "local fallback" in command.lower() or "[rch] local" in command.lower():
        reason_codes.append("local-fallback-marker")
    if args.branch != required_branch:
        reason_codes.append("branch-mismatch")
    if args.expected_head and args.head_commit and args.expected_head != args.head_commit:
        reason_codes.append("stale-head")
    if args.dirty_frontier_status == "dirty-overlap" or overlaps_dirty_source(
        dirty_paths, source_paths
    ):
        reason_codes.append("dirty-frontier-overlap")

    match_key_material = "|".join(
        [
            args.lane_id,
            args.expected_head or args.head_commit,
            args.source_tree_fingerprint,
            command_fingerprint,
        ]
    )
    match_key = sha256_text(match_key_material)
    duplicate = duplicate_result(
        existing_submissions(Path(args.existing_submissions) if args.existing_submissions else None),
        args.lane_id,
        args.expected_head or args.head_commit,
        command_fingerprint,
        match_key,
    )
    if duplicate and duplicate["decision"] == "refused":
        reason_codes.extend(duplicate["reason_codes"])

    reason_codes = sorted(set(reason_codes))
    if reason_codes:
        decision = "refused"
        lifecycle_state = "terminal_fail"
        proof_evidence_status = "refused"
        duplicate_action = duplicate["duplicate_action"] if duplicate else "not-applicable"
    elif duplicate and duplicate["decision"] == "coalesced":
        decision = "coalesced"
        lifecycle_state = duplicate["existing_lifecycle_state"] or "queued"
        proof_evidence_status = "rerun-required"
        duplicate_action = duplicate["duplicate_action"]
    else:
        decision = "accepted"
        lifecycle_state = "queued"
        proof_evidence_status = "rerun-required"
        duplicate_action = "new-submission"

    submission_id = stable_short_id("drps", match_key)
    resume_token = stable_short_id("drps-resume", f"{match_key}|{args.agent}")
    terminal_classification = terminal_classification_for(reason_codes)
    generated_at = args.generated_at or utc_now()

    submission = {
        "schema_version": SUBMISSION_SCHEMA_VERSION,
        "submission_id": submission_id,
        "generated_at": generated_at,
        "agent": args.agent,
        "manifest_lane_id": args.lane_id,
        "manifest_guarantee_ids": sorted_string_list(lane.get("guarantee_ids")),
        "claim_scope": ",".join(sorted_string_list(lane.get("guarantee_ids"))),
        "proof_evidence_status": proof_evidence_status,
        "lifecycle_state": lifecycle_state,
        "terminal_classification": terminal_classification,
        "command": {
            "command": command,
            "argv": tokens,
            "command_fingerprint": command_fingerprint,
            "env_fingerprint": env_fingerprint,
            "env_allowlist": sorted(assignments),
            "remote_required": command.startswith(required_prefix),
            "local_fallback_allowed": False,
            "target_dir": target_dir_from_env(assignments),
        },
        "source": {
            "branch": args.branch,
            "head_commit": args.head_commit,
            "expected_head": args.expected_head or args.head_commit,
            "source_tree_fingerprint": args.source_tree_fingerprint,
            "dirty_frontier_status": args.dirty_frontier_status,
            "dirty_frontier_paths": dirty_paths,
            "touched_files": source_paths,
        },
        "lease": {
            "match_key": match_key,
            "duplicate_policy": "coalesce-identical-lane-head-command",
            "duplicate_action": duplicate_action,
            "existing_submission_id": duplicate.get("existing_submission_id", "") if duplicate else "",
            "owner_agent": args.agent,
        },
        "resume": {
            "resume_token": resume_token,
            "status_query_key": match_key,
            "observable_without_submitter": True,
        },
        "receipt_expectations": {
            "receipt_schema_version": receipt_contract.get("receipt_schema_version"),
            "required_sections": receipt_contract.get("required_receipt_sections", []),
            "allowed_lifecycle_states": receipt_contract.get("allowed_lifecycle_states", []),
            "terminal_lifecycle_states": receipt_contract.get("terminal_lifecycle_states", []),
            "terminal_classifications": receipt_contract.get("terminal_classifications", []),
        },
        "execution": {
            "live_rch_invoked": False,
            "network_access_required": False,
            "tracker_mutation_allowed": False,
        },
    }

    return {
        "schema_version": SUBMISSION_SCHEMA_VERSION,
        "generated_at": generated_at,
        "decision": decision,
        "reason_codes": reason_codes,
        "submission": submission,
    }


def write_record(repo_root: Path, output_path: str, record: dict[str, Any]) -> dict[str, Any]:
    path = Path(output_path)
    if not output_path_allowed(repo_root, path):
        record = deep_copy(record)
        record["decision"] = "refused"
        record["reason_codes"] = sorted(
            set(string_list(record.get("reason_codes")) + ["output-path-not-allowed"])
        )
        if isinstance(record.get("submission"), dict):
            record["submission"]["lifecycle_state"] = "terminal_fail"
            record["submission"]["proof_evidence_status"] = "refused"
            record["submission"]["terminal_classification"] = terminal_classification_for(
                record["reason_codes"]
            )
        else:
            record["lifecycle_state"] = "terminal_fail"
            record["proof_evidence_status"] = "refused"
            record["terminal_classification"] = terminal_classification_for(record["reason_codes"])
            if isinstance(record.get("cancellation"), dict):
                record["cancellation"]["recorded"] = False
        return record

    resolved = path if path.is_absolute() else repo_root / path
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    record = json.loads(json.dumps(record))
    record["record_output_path"] = str(path)
    return record


def submit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=EXAMPLE_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--receipt-contract", default=DEFAULT_RECEIPT_CONTRACT)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--agent", default="unknown-agent")
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--expected-head", default="")
    parser.add_argument("--source-tree-fingerprint", required=True)
    parser.add_argument(
        "--dirty-frontier-status",
        choices=["clean", "dirty", "dirty-overlap", "unknown"],
        default="clean",
    )
    parser.add_argument("--dirty-path", action="append", default=[])
    parser.add_argument("--existing-submissions", default="")
    parser.add_argument("--record-output", default="")
    parser.add_argument("--output", choices=["json", "human"], default="json")
    return parser


def status_parser(command_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Read durable RCH {command_name} state without invoking RCH.",
        epilog=EXAMPLE_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--job-store", required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--output", choices=["json", "human"], default="json")
    if command_name == "query":
        parser.add_argument("--claim", default="")
    if command_name == "cancel":
        parser.add_argument("--repo-root", default=".")
        parser.add_argument("--agent", required=True)
        parser.add_argument("--reason-code", required=True)
        parser.add_argument("--record-output", default="")
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    if argv and argv[0] in SUBCOMMANDS:
        command_name = argv[0]
        rest = argv[1:]
    else:
        command_name = "submit"
        rest = argv

    if command_name == "submit":
        parser = submit_parser()
    else:
        parser = status_parser(command_name)
    args = parser.parse_args(rest)
    args.cli_command = command_name
    return args


def human_summary(record: dict[str, Any]) -> str:
    parts = [
        string_value(record.get("operation"), "submit"),
        string_value(record.get("decision"), "unknown"),
    ]
    submission_id = string_value(record.get("submission_id"))
    if not submission_id and isinstance(record.get("submission"), dict):
        submission_id = string_value(record["submission"].get("submission_id"))
    if submission_id:
        parts.append(f"submission={submission_id}")
    receipt_id = string_value(record.get("receipt_id"))
    if receipt_id:
        parts.append(f"receipt={receipt_id}")
    lifecycle = string_value(record.get("lifecycle_state"))
    if not lifecycle and isinstance(record.get("submission"), dict):
        lifecycle = string_value(record["submission"].get("lifecycle_state"))
    if lifecycle:
        parts.append(f"state={lifecycle}")
    lane_id = string_value(record.get("manifest_lane_id"))
    if not lane_id and isinstance(record.get("submission"), dict):
        lane_id = string_value(record["submission"].get("manifest_lane_id"))
    if lane_id:
        parts.append(f"lane={lane_id}")
    reasons = string_list(record.get("reason_codes"))
    if reasons:
        parts.append("reasons=" + ",".join(reasons))
    return " ".join(parts)


def emit_record(record: dict[str, Any], output: str) -> None:
    if output == "human":
        sys.stdout.write(human_summary(record))
        sys.stdout.write("\n")
        return
    json.dump(record, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.cli_command == "submit":
        repo_root = Path(args.repo_root).resolve()
        record = build_submission(args)
        if args.record_output:
            record = write_record(repo_root, args.record_output, record)
    elif args.cli_command == "status":
        record = build_status(args)
    elif args.cli_command == "query":
        record = build_query(args)
    elif args.cli_command == "cancel":
        record = build_cancel(args)
    else:
        raise AssertionError(f"unhandled command {args.cli_command}")
    emit_record(record, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
