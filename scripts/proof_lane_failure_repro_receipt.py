#!/usr/bin/env python3
"""Emit deterministic minimal-repro receipts for failed proof lanes.

The helper is intentionally read-only. It consumes an explicit fixture or
contract artifact and writes JSON or Markdown to stdout. It does not run Cargo,
inspect Git, mutate beads, query Agent Mail, or rewrite artifacts.
"""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-lane-failure-repro-receipt-v1"
FIXTURE_SCHEMA_VERSION = "proof-lane-failure-repro-fixture-v1"
CONTRACT_SCHEMA_VERSION = "proof-lane-failure-repro-contract-v1"
REQUIRED_RCH_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- "

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "rustc-compile-error": {
        "severity": 90,
        "outcome_class": "failed-local",
        "operator_action": "Rerun the smallest compiling Cargo target and fix the named source location.",
    },
    "test-assertion-failure": {
        "severity": 85,
        "outcome_class": "failed-local",
        "operator_action": "Rerun the failing test filter with nocapture and preserve the first assertion site.",
    },
    "zero-test-proof": {
        "severity": 80,
        "outcome_class": "failed-local",
        "operator_action": "Reject the zero-test evidence and correct the filter before citing the lane.",
    },
    "local-fallback-refused": {
        "severity": 75,
        "outcome_class": "blocked-external",
        "operator_action": "Keep remote-required RCH; wait for worker admission instead of accepting local fallback.",
    },
    "timeout-after-first-failure": {
        "severity": 70,
        "outcome_class": "blocked-external",
        "operator_action": "Use the first hard failure already present in the timeout log as the repro surface.",
    },
    "worker-disk-pressure": {
        "severity": 65,
        "outcome_class": "blocked-external",
        "operator_action": "Treat the worker as blocked by disk pressure; retry on a healthy worker or after cleanup.",
    },
    "ssh-transport-failure": {
        "severity": 60,
        "outcome_class": "blocked-external",
        "operator_action": "Treat this as RCH transport infrastructure; do not rewrite the proof command locally.",
    },
    "retrieval-timeout-after-pass": {
        "severity": 55,
        "outcome_class": "blocked-external",
        "operator_action": "Classify artifact retrieval separately before using the remote pass as evidence.",
    },
    "unknown-proof-lane-failure": {
        "severity": 50,
        "outcome_class": "blocked-external",
        "operator_action": "Preserve the log and rerun the narrowest listed remote-required command.",
    },
}

RUST_ERROR_RE = re.compile(r"error(?:\[(?P<code>[^\]]+)\])?:\s*(?P<message>.+)")
CARGO_LOCATION_RE = re.compile(r"^\s*-->\s+(?P<file>[^:\s]+):(?P<line>\d+):(?P<column>\d+)")
PANIC_RE = re.compile(
    r"thread\s+'(?P<test>[^']+)'\s+panicked at\s+(?P<file>[^:\s]+):(?P<line>\d+):(?P<column>\d+)"
)
TEST_FAILURE_RE = re.compile(r"(?m)^failures:\s*\n\s+(?P<test>[A-Za-z0-9_:.-]+)")
ZERO_TEST_RE = re.compile(r"(?m)\brunning\s+0\s+tests\b")
LOCAL_FALLBACK_RE = re.compile(
    r"remote required; refusing local fallback|local fallback refused|falling back to local|executing locally",
    re.IGNORECASE,
)
TIMEOUT_RE = re.compile(r"timed out|timeout|exit(?:=| status )124", re.IGNORECASE)
ENOSPC_RE = re.compile(r"No space left on device|ENOSPC|disk full", re.IGNORECASE)
SSH_RE = re.compile(r"\bssh:|connection refused|connection timed out|host key", re.IGNORECASE)
RETRIEVAL_TIMEOUT_RE = re.compile(
    r"retrieval timed out|timed out while retrieving|artifact retrieval timed out|retrieval stalled",
    re.IGNORECASE,
)
REMOTE_PASS_RE = re.compile(r"Remote command finished:\s*exit=0|test result:\s+ok", re.IGNORECASE)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    return default


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def load_fixture(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: fixture must be a JSON object")
    fixture = value.get("fixture") if isinstance(value.get("fixture"), dict) else value
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: fixture schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    return fixture


def first_rust_error(log_text: str) -> dict[str, Any] | None:
    lines = log_text.splitlines()
    for index, line in enumerate(lines):
        error_match = RUST_ERROR_RE.search(line)
        if not error_match:
            continue
        location = None
        for candidate in lines[index + 1 : index + 8]:
            location_match = CARGO_LOCATION_RE.match(candidate)
            if location_match:
                location = location_match.groupdict()
                break
        if location is None:
            location = {"file": "rustc", "line": "0", "column": "0"}
        return {
            "file": location["file"],
            "line": int_value(location["line"]),
            "column": int_value(location["column"]),
            "code": string(error_match.group("code")),
            "message": string(error_match.group("message")).strip(),
        }
    return None


def first_test_failure(log_text: str) -> dict[str, Any] | None:
    panic_match = PANIC_RE.search(log_text)
    if panic_match:
        return {
            "file": panic_match.group("file"),
            "line": int_value(panic_match.group("line")),
            "column": int_value(panic_match.group("column")),
            "code": "test-panicked",
            "message": f"test {panic_match.group('test')} panicked",
        }
    failure_match = TEST_FAILURE_RE.search(log_text)
    if failure_match:
        return {
            "file": "test-harness",
            "line": 0,
            "column": 0,
            "code": "test-failed",
            "message": f"test {failure_match.group('test')} failed",
        }
    return None


def synthetic_blocker(
    file: str,
    code: str,
    message: str,
    line: int = 0,
    column: int = 0,
) -> dict[str, Any]:
    return {
        "file": file,
        "line": line,
        "column": column,
        "code": code,
        "message": message,
    }


def classify_failure(failure: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    log_text = string(failure.get("log_excerpt"))
    rust_error = first_rust_error(log_text)
    test_failure = first_test_failure(log_text)

    if LOCAL_FALLBACK_RE.search(log_text):
        return (
            "local-fallback-refused",
            synthetic_blocker(
                "rch-local-fallback",
                "local-fallback-refused",
                "remote-required proof refused local fallback",
            ),
        )
    if ENOSPC_RE.search(log_text):
        return (
            "worker-disk-pressure",
            synthetic_blocker(
                "rch-worker",
                "enospc",
                "remote worker reported no space left on device",
            ),
        )
    if SSH_RE.search(log_text):
        return (
            "ssh-transport-failure",
            synthetic_blocker(
                "rch-ssh",
                "ssh-transport-failure",
                "RCH worker SSH transport failed before proof completion",
            ),
        )
    if RETRIEVAL_TIMEOUT_RE.search(log_text) and REMOTE_PASS_RE.search(log_text):
        return (
            "retrieval-timeout-after-pass",
            synthetic_blocker(
                "rch-retrieval",
                "retrieval-timeout-after-pass",
                "remote proof passed but artifact retrieval timed out",
            ),
        )
    if ZERO_TEST_RE.search(log_text) or int_value(failure.get("executed_tests"), 1) == 0:
        return (
            "zero-test-proof",
            synthetic_blocker(
                "cargo-test-filter",
                "zero-tests",
                "proof command executed zero tests",
            ),
        )
    if TIMEOUT_RE.search(log_text) and (rust_error or test_failure):
        return ("timeout-after-first-failure", rust_error or test_failure)
    if rust_error:
        return ("rustc-compile-error", rust_error)
    if test_failure:
        return ("test-assertion-failure", test_failure)
    if TIMEOUT_RE.search(log_text):
        return (
            "timeout-after-first-failure",
            synthetic_blocker("rch", "timeout", "proof lane timed out"),
        )
    return (
        "unknown-proof-lane-failure",
        synthetic_blocker("proof-log", "unknown", "no supported blocker pattern found"),
    )


def command_preserves_remote_required(command: str) -> bool:
    return command.startswith(REQUIRED_RCH_PREFIX)


def command_has_target_dir(command: str) -> bool:
    return "CARGO_TARGET_DIR=" in command


def command_is_cargo(command: str) -> bool:
    return " cargo " in f" {command} "


def command_row(command: str, failure: dict[str, Any], classification: str) -> dict[str, Any]:
    is_cargo = command_is_cargo(command)
    preserves_rch = command_preserves_remote_required(command)
    has_target_dir = command_has_target_dir(command)
    envelope_ok = (not is_cargo) or (preserves_rch and has_target_dir)
    return {
        "command": command,
        "command_kind": string(failure.get("command_kind")) or "cargo-proof-rerun",
        "is_cargo": is_cargo,
        "preserves_remote_required": preserves_rch,
        "has_cargo_target_dir": has_target_dir,
        "local_fallback_allowed": False,
        "envelope_ok": envelope_ok,
        "why_minimal": string(failure.get("why_minimal"))
        or f"minimal command for {classification}",
    }


def reservation_overlaps(failure: dict[str, Any], reservations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    touched = set(string_list(failure.get("touched_files")))
    overlaps: list[dict[str, Any]] = []
    for reservation in reservations:
        if string(reservation.get("status")).lower() not in {"active", "held"}:
            continue
        pattern = string(reservation.get("path_pattern"))
        if not pattern:
            continue
        matched = sorted(path for path in touched if path == pattern)
        if matched:
            overlaps.append(
                {
                    "holder": string(reservation.get("holder")),
                    "path_pattern": pattern,
                    "overlap_paths": matched,
                }
            )
    return overlaps


def build_row(
    failure: dict[str, Any],
    reservations: list[dict[str, Any]],
) -> dict[str, Any]:
    classification, first_blocker = classify_failure(failure)
    catalog = CLASSIFICATION_CATALOG[classification]
    command = string(failure.get("minimal_repro_command"))
    command_info = command_row(command, failure, classification)
    peer_overlaps = reservation_overlaps(failure, reservations)
    evidence_proves = string_list(failure.get("evidence_proves"))
    evidence_does_not_prove = string_list(failure.get("evidence_does_not_prove"))
    if not evidence_does_not_prove:
        evidence_does_not_prove = [
            "workspace health",
            "release readiness",
            "fresh correctness proof",
        ]

    return {
        "failure_id": string(failure.get("failure_id")),
        "lane_id": string(failure.get("lane_id")),
        "classification": classification,
        "outcome_class": catalog["outcome_class"],
        "severity": catalog["severity"],
        "source_log_path": string(failure.get("source_log_path")),
        "source_log_sha256": string(failure.get("source_log_sha256")),
        "first_blocker": first_blocker,
        "touched_files": sorted(set(string_list(failure.get("touched_files")))),
        "suspected_owner": string(failure.get("suspected_owner")) or "unknown",
        "peer_reservation_overlaps": peer_overlaps,
        "minimal_repro": command_info,
        "operator_action": catalog["operator_action"],
        "blocked": catalog["outcome_class"] == "blocked-external",
        "proof_admissible": False,
        "evidence_proves": evidence_proves,
        "evidence_does_not_prove": evidence_does_not_prove,
        "environment": {
            "required": string_list(failure.get("required_env")),
            "forbidden": ["local Cargo fallback", "branch/worktree rerun", "unscoped broad retry"],
        },
    }


def build_receipt(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    reservations = dict_list(fixture.get("reservations"))
    rows = [build_row(failure, reservations) for failure in dict_list(fixture.get("failures"))]
    rows.sort(key=lambda row: (-row["severity"], row["failure_id"]))

    classification_counts = {key: 0 for key in CLASSIFICATION_CATALOG}
    for row in rows:
        classification_counts[row["classification"]] = (
            classification_counts.get(row["classification"], 0) + 1
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "fixture_id": string(fixture.get("fixture_id")),
        "policy": {
            "required_rch_prefix": REQUIRED_RCH_PREFIX,
            "non_claims": [
                "This receipt chooses minimal repro commands; it is not workspace health.",
                "A repro command is not a fresh proof until it is rerun through RCH.",
                "Local fallback evidence remains rejected for remote-required proof lanes.",
            ],
        },
        "classification_catalog": CLASSIFICATION_CATALOG,
        "summary": {
            "total_failures": len(rows),
            "cargo_repro_commands": sum(1 for row in rows if row["minimal_repro"]["is_cargo"]),
            "envelope_ok": sum(1 for row in rows if row["minimal_repro"]["envelope_ok"]),
            "blocked_external": sum(1 for row in rows if row["outcome_class"] == "blocked-external"),
            "failed_local": sum(1 for row in rows if row["outcome_class"] == "failed-local"),
            "proof_admissible": sum(1 for row in rows if row["proof_admissible"]),
            "classification_counts": classification_counts,
        },
        "rows": rows,
    }


def markdown_report(receipt: dict[str, Any]) -> str:
    summary = receipt["summary"]
    lines = [
        "# Proof Lane Failure Repro Receipts",
        "",
        f"- fixture: `{receipt['fixture_id']}`",
        f"- generated_at: `{receipt['generated_at']}`",
        f"- total_failures: `{summary['total_failures']}`",
        f"- cargo_repro_commands: `{summary['cargo_repro_commands']}`",
        f"- blocked_external: `{summary['blocked_external']}`",
        f"- failed_local: `{summary['failed_local']}`",
        "",
        "Non-claims:",
    ]
    for non_claim in receipt["policy"]["non_claims"]:
        lines.append(f"- {non_claim}")
    lines.extend(
        [
            "",
            "| rank | failure | classification | blocker | minimal repro |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for index, row in enumerate(receipt["rows"], start=1):
        blocker = row["first_blocker"]
        blocker_ref = (
            f"{blocker['file']}:{blocker['line']}"
            if blocker.get("line")
            else blocker["file"]
        )
        command = row["minimal_repro"]["command"] or "<missing>"
        lines.append(
            f"| {index} | `{row['failure_id']}` | `{row['classification']}` | "
            f"`{blocker_ref}` | `{command}` |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, help="Fixture or contract JSON path")
    parser.add_argument(
        "--generated-at",
        default="",
        help="Stable generated_at timestamp; defaults to current UTC time",
    )
    parser.add_argument(
        "--output",
        choices=("json", "markdown"),
        default="json",
        help="Output format",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    fixture = load_fixture(Path(args.fixture))
    receipt = build_receipt(fixture, args.generated_at or utc_now())
    if args.output == "json":
        print(json.dumps(receipt, sort_keys=True, indent=2))
    else:
        print(markdown_report(receipt))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
