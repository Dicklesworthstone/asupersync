#!/usr/bin/env python3
"""Build deterministic durable RCH terminal receipts from captured outcomes.

This helper is intentionally non-mutating. It does not invoke RCH, Agent Mail,
or tracker tooling; it only normalizes a captured proof outcome into the
durable-rch-proof-receipt-v1 schema.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


RECEIPT_SCHEMA_VERSION = "durable-rch-proof-receipt-v1"
DEFAULT_MANIFEST = "artifacts/proof_lane_manifest_v1.json"
DEFAULT_RECEIPT_CONTRACT = "artifacts/durable_rch_proof_receipt_contract_v1.json"
SHA_PREFIX = "sha256:"
DEFAULT_EXPLICIT_NOT_COVERED = [
    "release-readiness",
    "workspace-health",
    "live-rch-fleet-availability",
]
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(token|secret|password|api_key|registration_token)=\S+"),
    re.compile(r"(?i)\b(authorization:\s*bearer)\s+\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
]
BLOCKER_PATTERNS = [
    re.compile(r"(^|\s)error(\[|:|\s)", re.IGNORECASE),
    re.compile(r"panicked at", re.IGNORECASE),
    re.compile(r"\bFAILED\b"),
    re.compile(r"test result: FAILED", re.IGNORECASE),
    re.compile(r"timed out|timeout|stale|heartbeat|disconnect|cancel", re.IGNORECASE),
    re.compile(r"local fallback|\[RCH\] local", re.IGNORECASE),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_text(path: Path | None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8")


def sha256_text(value: str) -> str:
    return SHA_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return SHA_PREFIX + hashlib.sha256(path.read_bytes()).hexdigest()


def stable_short_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def sorted_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(item for item in value if isinstance(item, str) and item)


def string_array(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


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


def manifest_lane(manifest: dict[str, Any], lane_id: str) -> dict[str, Any]:
    for lane in manifest.get("lanes", []):
        if isinstance(lane, dict) and lane.get("lane_id") == lane_id:
            return lane
    raise SystemExit(f"manifest lane not found: {lane_id}")


def string_value(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def bool_value(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def int_value(value: Any, default: int = -1) -> int:
    return value if isinstance(value, int) else default


def deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(base))
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def build_default_submission(
    fixture: dict[str, Any],
    manifest: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    lane_id = string_value(fixture.get("lane_id"), "proof-lane-manifest-contract")
    lane = manifest_lane(manifest, lane_id)
    command = string_value(lane.get("command"))
    tokens = command_tokens(command)
    assignments = env_assignments(tokens)
    source = fixture.get("source") if isinstance(fixture.get("source"), dict) else {}
    head = string_value(source.get("head_commit"), "f7f924efe965be84e3ed95a08de0f4b8ffaed352")
    expected_head = string_value(source.get("expected_head"), head)
    source_paths = sorted_string_list(lane.get("source_paths"))
    guarantee_ids = sorted_string_list(lane.get("guarantee_ids"))
    return {
        "schema_version": "durable-rch-proof-submission-v1",
        "submission_id": string_value(
            fixture.get("submission_id"),
            stable_short_id("drps", f"{lane_id}|{head}|{command}"),
        ),
        "generated_at": string_value(fixture.get("submitted_at"), utc_now()),
        "manifest_lane_id": lane_id,
        "manifest_guarantee_ids": guarantee_ids,
        "claim_scope": ",".join(guarantee_ids),
        "proof_evidence_status": "rerun-required",
        "lifecycle_state": "queued",
        "terminal_classification": None,
        "command": {
            "command": command,
            "argv": tokens,
            "command_fingerprint": sha256_text(command),
            "env_fingerprint": sha256_text(json.dumps(assignments, sort_keys=True, separators=(",", ":"))),
            "env_allowlist": sorted(assignments),
            "remote_required": command.startswith(
                string_value(
                    contract.get("decision_policy", {}).get("required_command_prefix"),
                    "RCH_REQUIRE_REMOTE=1 rch exec -- ",
                )
            ),
            "local_fallback_allowed": False,
        },
        "source": {
            "branch": string_value(source.get("branch"), "main"),
            "head_commit": head,
            "expected_head": expected_head,
            "source_tree_fingerprint": string_value(source.get("source_tree_fingerprint"), f"git-tree:{head}"),
            "dirty_frontier_status": string_value(source.get("dirty_frontier_status"), "clean"),
            "dirty_frontier_paths": sorted_string_list(source.get("dirty_frontier_paths")),
            "touched_files": sorted_string_list(source.get("touched_files")) or source_paths,
        },
        "lane_contract": {
            "covers": string_value(lane.get("covers")),
            "explicit_not_covered": string_value(lane.get("explicit_not_covered")),
        },
    }


def fixture_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.fixture:
        fixture = load_json(Path(args.fixture))
        if not isinstance(fixture, dict):
            raise SystemExit("fixture must be a JSON object")
        return fixture
    payload: dict[str, Any] = {
        "fixture_id": "explicit-input",
        "rch_outcome": load_json(Path(args.rch_outcome)) if args.rch_outcome else {},
        "stdout": read_text(Path(args.stdout_file)) if args.stdout_file else "",
        "stderr": read_text(Path(args.stderr_file)) if args.stderr_file else "",
    }
    if args.submission:
        raw = load_json(Path(args.submission))
        payload["submission"] = raw.get("submission") if isinstance(raw, dict) and "submission" in raw else raw
    return payload


def redact_line(line: str) -> str:
    redacted = line
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: redact_match(match.group(0)), redacted)
    return redacted


def redact_match(value: str) -> str:
    if "=" in value:
        key = value.split("=", 1)[0]
        return f"{key}=[REDACTED]"
    if ":" in value:
        key = value.split(":", 1)[0]
        return f"{key}: Bearer [REDACTED]"
    return "Bearer [REDACTED]"


def bounded_line(line: str, max_chars: int) -> str:
    if len(line) <= max_chars:
        return line
    return line[: max(0, max_chars - 23)] + "... [line truncated]"


def output_digest(stdout: str, stderr: str) -> str:
    return sha256_text(stdout + "\n--- STDERR ---\n" + stderr)


def first_blocker_lines(stdout: str, stderr: str, max_lines: int, max_chars: int) -> list[str]:
    lines = (stdout + "\n" + stderr).splitlines()
    if not lines:
        return []
    start = next(
        (index for index, line in enumerate(lines) if any(pattern.search(line) for pattern in BLOCKER_PATTERNS)),
        None,
    )
    if start is None:
        return []
    selected = lines[start : start + max_lines]
    return [bounded_line(redact_line(line), max_chars) for line in selected]


def has_local_fallback(output: str, outcome: dict[str, Any]) -> bool:
    if string_value(outcome.get("location")).lower() == "local":
        return True
    lowered = output.lower()
    return "local fallback" in lowered or "[rch] local" in lowered


def classify(outcome: dict[str, Any], stdout: str, stderr: str) -> str:
    combined = stdout + "\n" + stderr
    if has_local_fallback(combined, outcome):
        return "local_fallback_refused"
    if bool_value(outcome.get("client_disconnected")) or string_value(outcome.get("status")) == "client_disconnected":
        return "client_disconnected_partial"
    if bool_value(outcome.get("detector_heartbeat_stale")) or string_value(outcome.get("status")) == "infra_error":
        return "heartbeat_stale_infra"
    cancellation = outcome.get("cancellation") if isinstance(outcome.get("cancellation"), dict) else {}
    if bool_value(outcome.get("detector_progress_stale")) and (
        cancellation or string_value(outcome.get("status")) in {"canceled", "timeout"}
    ):
        return "stale_progress_canceled"
    if cancellation or string_value(outcome.get("status")) == "canceled":
        return "operator_canceled"
    if int_value(outcome.get("exit_code")) == 0 and string_value(outcome.get("status"), "completed") != "failed":
        return "pass"
    return "cargo_failure"


def lifecycle_state(classification: str) -> str:
    return {
        "pass": "terminal_pass",
        "cargo_failure": "terminal_fail",
        "operator_canceled": "terminal_canceled",
        "stale_progress_canceled": "terminal_stale",
        "heartbeat_stale_infra": "terminal_infra_error",
        "client_disconnected_partial": "partial",
        "local_fallback_refused": "terminal_fail",
    }[classification]


def outcome_status(classification: str) -> str:
    return {
        "pass": "pass",
        "cargo_failure": "fail",
        "operator_canceled": "canceled",
        "stale_progress_canceled": "stale",
        "heartbeat_stale_infra": "infra_error",
        "client_disconnected_partial": "partial",
        "local_fallback_refused": "local_fallback_refused",
    }[classification]


def proof_status(classification: str) -> str:
    if classification == "pass":
        return "fresh-rch-pass"
    if classification == "stale_progress_canceled":
        return "stale-evidence"
    return "blocked"


def refusal_reasons(classification: str, submission: dict[str, Any], outcome: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    source = submission.get("source") if isinstance(submission.get("source"), dict) else {}
    if string_value(source.get("branch"), "main") != "main":
        reasons.append("branch-mismatch")
    if string_value(source.get("head_commit")) != string_value(source.get("expected_head")):
        reasons.append("stale-head")
    if string_value(source.get("dirty_frontier_status"), "clean") != "clean" or sorted_string_list(
        source.get("dirty_frontier_paths")
    ):
        reasons.append("dirty-frontier-overlap")
    if classification == "local_fallback_refused":
        reasons.append("local-fallback-marker")
    elif classification != "pass":
        reasons.append("failed-proof-status")
    return sorted(set(reasons))


def touched_hashes(repo_root: Path, touched_files: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in touched_files:
        path = repo_root / relative
        hashes[relative] = sha256_file(path) if path.exists() else "sha256:missing"
    return hashes


def route_segments(worker_id: str, outcome: dict[str, Any]) -> list[str]:
    segments = sorted_string_list(outcome.get("remote_route_segments"))
    if segments:
        return segments
    if worker_id and worker_id != "local":
        return ["rch-daemon", worker_id]
    return []


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    manifest = load_json(repo_root / args.manifest)
    contract = load_json(repo_root / args.receipt_contract)
    payload = fixture_payload(args)
    fixture_submission = payload.get("submission") if isinstance(payload.get("submission"), dict) else {}
    submission = deep_merge(
        build_default_submission(payload, manifest, contract),
        fixture_submission,
    )
    outcome = payload.get("rch_outcome") if isinstance(payload.get("rch_outcome"), dict) else {}
    stdout = string_value(payload.get("stdout"))
    stderr = string_value(payload.get("stderr"))
    classification = classify(outcome, stdout, stderr)
    lifecycle = lifecycle_state(classification)
    reasons = refusal_reasons(classification, submission, outcome)
    generated_at = args.generated_at or string_value(payload.get("generated_at")) or utc_now()

    command = submission.get("command") if isinstance(submission.get("command"), dict) else {}
    source = submission.get("source") if isinstance(submission.get("source"), dict) else {}
    touched_files = sorted_string_list(source.get("touched_files"))
    worker_id = string_value(outcome.get("worker_id"), "unknown")
    local_markers = []
    if classification == "local_fallback_refused":
        local_markers.append("[RCH] local fallback")

    digest = output_digest(stdout, stderr)
    receipt_id = stable_short_id(
        "drpr",
        "|".join(
            [
                string_value(submission.get("submission_id")),
                classification,
                string_value(outcome.get("build_id")),
                digest,
            ]
        ),
    )
    citable = classification == "pass" and not reasons
    lane_contract = submission.get("lane_contract") if isinstance(submission.get("lane_contract"), dict) else {}
    covers = (
        "The captured remote-required RCH proof passed for the exact manifest lane and source fingerprint."
        if citable
        else f"The captured RCH proof is not citable as green proof because it classified as {classification}."
    )
    if string_value(lane_contract.get("covers")) and citable:
        covers = string_value(lane_contract.get("covers"))

    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "submission_id": string_value(submission.get("submission_id")),
        "generated_at": generated_at,
        "manifest_lane_id": string_value(submission.get("manifest_lane_id")),
        "manifest_guarantee_ids": sorted_string_list(submission.get("manifest_guarantee_ids")),
        "claim_scope": string_value(submission.get("claim_scope")),
        "proof_evidence_status": proof_status(classification),
        "lifecycle_state": lifecycle,
        "terminal_classification": classification,
        "command": {
            "command": string_value(command.get("command")),
            "argv": string_array(command.get("argv")) or command_tokens(string_value(command.get("command"))),
            "command_fingerprint": string_value(command.get("command_fingerprint")),
            "env_fingerprint": string_value(command.get("env_fingerprint")),
            "env_allowlist": sorted_string_list(command.get("env_allowlist")),
            "remote_required": bool_value(command.get("remote_required"), True),
            "local_fallback_allowed": bool_value(command.get("local_fallback_allowed"), False),
            "local_fallback_markers": local_markers,
        },
        "source": {
            "branch": string_value(source.get("branch"), "main"),
            "head_commit": string_value(source.get("head_commit")),
            "expected_head": string_value(source.get("expected_head")),
            "source_tree_fingerprint": string_value(source.get("source_tree_fingerprint")),
            "dirty_frontier_status": string_value(source.get("dirty_frontier_status"), "clean"),
            "dirty_frontier_paths": sorted_string_list(source.get("dirty_frontier_paths")),
            "touched_files": touched_files,
            "touched_file_hashes": touched_hashes(repo_root, touched_files),
        },
        "rch_provenance": {
            "worker_id": worker_id,
            "remote_route_segments": route_segments(worker_id, outcome),
            "submitted_at": string_value(outcome.get("submitted_at")),
            "started_at": string_value(outcome.get("started_at")),
            "finished_at": string_value(outcome.get("finished_at")),
            "detector_progress_stale": bool_value(outcome.get("detector_progress_stale")),
            "detector_heartbeat_stale": bool_value(outcome.get("detector_heartbeat_stale")),
        },
        "outcome": {
            "status": outcome_status(classification),
            "exit_code": int_value(outcome.get("exit_code")),
            "output_digest": digest,
            "first_blocker_lines": first_blocker_lines(
                stdout,
                stderr,
                args.max_blocker_lines,
                args.max_line_chars,
            ),
            "cancellation_reason": cancellation_reason(outcome, classification),
            "staleness_reason": staleness_reason(outcome, classification),
        },
        "claim_boundaries": {
            "citable": citable,
            "covers": covers,
            "explicit_not_covered": DEFAULT_EXPLICIT_NOT_COVERED,
            "refusal_reason_codes": reasons,
        },
    }


def cancellation_reason(outcome: dict[str, Any], classification: str) -> str | None:
    cancellation = outcome.get("cancellation") if isinstance(outcome.get("cancellation"), dict) else {}
    reason = string_value(cancellation.get("reason_code")) or string_value(outcome.get("cancellation_reason"))
    if reason:
        return reason
    if classification == "operator_canceled":
        return "operator-canceled"
    if classification == "client_disconnected_partial":
        return "client-disconnected"
    return None


def staleness_reason(outcome: dict[str, Any], classification: str) -> str | None:
    reason = string_value(outcome.get("staleness_reason"))
    if reason:
        return reason
    if classification == "stale_progress_canceled":
        return "progress-stale"
    if classification == "heartbeat_stale_infra":
        return "heartbeat-stale"
    return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default="")
    parser.add_argument("--submission", default="")
    parser.add_argument("--rch-outcome", default="")
    parser.add_argument("--stdout-file", default="")
    parser.add_argument("--stderr-file", default="")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--receipt-contract", default=DEFAULT_RECEIPT_CONTRACT)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--max-blocker-lines", type=int, default=8)
    parser.add_argument("--max-line-chars", type=int, default=240)
    parser.add_argument("--output", choices=["json"], default="json")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    receipt = build_receipt(args)
    json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
