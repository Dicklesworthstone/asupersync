#!/usr/bin/env python3
"""Emit a deterministic proof-evidence debt graph.

The helper is intentionally read-only. It consumes an explicit fixture or
contract artifact and writes either JSON or Markdown to stdout. It does not run
Cargo, inspect Agent Mail, mutate Git, or rewrite artifacts.
"""

import argparse
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-evidence-debt-graph-v1"
FIXTURE_SCHEMA_VERSION = "proof-evidence-debt-fixture-v1"
CONTRACT_SCHEMA_VERSION = "proof-evidence-debt-graph-contract-v1"
REQUIRED_RCH_PREFIX = "RCH_REQUIRE_REMOTE=1 rch exec -- "

REASON_CATALOG: dict[str, dict[str, Any]] = {
    "blocked-by-peer-reservation": {
        "severity": 10,
        "operator_action": "Coordinate with the reservation holder or wait for release before rerunning this lane.",
    },
    "dirty-overlap": {
        "severity": 20,
        "operator_action": "Rerun the lane after the overlapping dirty paths are landed or removed from the claim surface.",
    },
    "local-fallback": {
        "severity": 30,
        "operator_action": "Reject this evidence and rerun with remote-required RCH proof.",
    },
    "missing-envelope": {
        "severity": 40,
        "operator_action": "Add a manifest envelope with remote-required, target-dir, timeout, and memory metadata before citing.",
    },
    "zero-tests": {
        "severity": 50,
        "operator_action": "Do not cite a zero-test proof; verify the filter and rerun a command that executes tests.",
    },
    "stale-head": {
        "severity": 60,
        "operator_action": "Rerun because the artifact HEAD does not match the requested source HEAD.",
    },
    "superseded-by-newer-artifact": {
        "severity": 70,
        "operator_action": "Use the superseding artifact or rerun the current lane instead of citing this one.",
    },
    "advisory-only": {
        "severity": 80,
        "operator_action": "Treat this as operator guidance only; pair it with a correctness proof before citing.",
    },
    "failed-proof-status": {
        "severity": 90,
        "operator_action": "Treat the lane as blocked and preserve the first hard failure for crashpack/repro work.",
    },
}

PASS_STATUSES = {"ok", "pass", "passed", "success", "succeeded", "green"}


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
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return default


def int_value(value: Any, default: int | None = None) -> int | None:
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
    if isinstance(value.get("fixture"), dict):
        fixture = value["fixture"]
    else:
        fixture = value
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: fixture schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    return fixture


def path_matches(pattern: str, path: str) -> bool:
    return (
        pattern == path
        or fnmatch.fnmatchcase(path, pattern)
        or fnmatch.fnmatchcase(pattern, path)
    )


def overlaps(patterns: list[str], paths: list[str]) -> list[str]:
    matches: list[str] = []
    for path in paths:
        if any(path_matches(pattern, path) for pattern in patterns):
            matches.append(path)
    return sorted(dict.fromkeys(matches))


def lane_by_id(fixture: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lanes: dict[str, dict[str, Any]] = {}
    for lane in dict_list(fixture.get("lanes")):
        lane_id = string(lane.get("lane_id"))
        if lane_id:
            lanes[lane_id] = lane
    return lanes


def reservation_holders(
    reservations: list[dict[str, Any]], touched_files: list[str]
) -> list[dict[str, Any]]:
    holders: list[dict[str, Any]] = []
    for reservation in reservations:
        if string(reservation.get("status")).lower() not in {"active", "held"}:
            continue
        holder = string(reservation.get("holder"))
        if not holder or holder == "PinkStream":
            continue
        pattern = string(reservation.get("path_pattern") or reservation.get("path"))
        if not pattern:
            continue
        matched = overlaps([pattern], touched_files)
        if matched:
            holders.append(
                {
                    "holder": holder,
                    "path_pattern": pattern,
                    "overlap_paths": matched,
                }
            )
    return holders


def command_has_required_envelope(lane: dict[str, Any], artifact: dict[str, Any]) -> bool:
    command = string(
        artifact.get("rerun_command")
        or lane.get("rerun_command")
        or artifact.get("proof_command")
        or lane.get("proof_command")
    )
    envelope = lane.get("envelope") if isinstance(lane.get("envelope"), dict) else {}
    remote_required = bool_value(envelope.get("remote_required"), False)
    target_dir = string(envelope.get("target_dir") or "")
    timeout = int_value(envelope.get("timeout_seconds"))
    memory = int_value(envelope.get("memory_mb"))
    return (
        command.startswith(REQUIRED_RCH_PREFIX)
        and "CARGO_TARGET_DIR=" in command
        and remote_required
        and bool(target_dir)
        and timeout is not None
        and memory is not None
    )


def classify_artifact(
    fixture: dict[str, Any],
    artifact: dict[str, Any],
    lanes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    repo = fixture.get("repo") if isinstance(fixture.get("repo"), dict) else {}
    repo_head = string(repo.get("head_sha"))
    dirty_paths = string_list(repo.get("dirty_paths"))
    lane_id = string(artifact.get("lane_id"))
    lane = lanes.get(lane_id, {})
    artifact_id = string(artifact.get("artifact_id")) or string(artifact.get("proof_id"))
    touched_files = string_list(artifact.get("touched_files"))
    reason_codes: list[str] = []

    active_peer_holders = reservation_holders(dict_list(fixture.get("reservations")), touched_files)
    if active_peer_holders:
        reason_codes.append("blocked-by-peer-reservation")

    dirty_overlap = overlaps(touched_files, dirty_paths)
    if dirty_overlap:
        reason_codes.append("dirty-overlap")

    if bool_value(artifact.get("local_fallback"), False):
        reason_codes.append("local-fallback")

    if not command_has_required_envelope(lane, artifact):
        reason_codes.append("missing-envelope")

    executed_tests = int_value(artifact.get("executed_tests"))
    if executed_tests == 0:
        reason_codes.append("zero-tests")

    artifact_head = string(artifact.get("head_sha"))
    if artifact_head and repo_head and artifact_head != repo_head:
        reason_codes.append("stale-head")

    superseded_by = string(artifact.get("superseded_by"))
    if superseded_by:
        reason_codes.append("superseded-by-newer-artifact")

    if bool_value(artifact.get("advisory_only"), False) or bool_value(
        lane.get("advisory_only"), False
    ):
        reason_codes.append("advisory-only")

    status = string(artifact.get("status")).lower()
    if status and status not in PASS_STATUSES:
        reason_codes.append("failed-proof-status")

    reason_codes = sorted(dict.fromkeys(reason_codes), key=reason_sort_key)
    severity = max((REASON_CATALOG[reason]["severity"] for reason in reason_codes), default=0)
    rerun_command = string(artifact.get("rerun_command") or lane.get("rerun_command"))
    operator_actions = [
        REASON_CATALOG[reason]["operator_action"] for reason in reason_codes
    ]
    if not operator_actions and rerun_command:
        operator_actions = [
            "Evidence is current for its narrow claim; rerun command is listed for fresh proof."
        ]

    return {
        "artifact_id": artifact_id,
        "artifact_path": string(artifact.get("artifact_path")),
        "lane_id": lane_id,
        "claim_scope": string(artifact.get("claim_scope") or lane.get("claim_scope")),
        "status": status,
        "classification": "current-clean" if not reason_codes else "proof-debt",
        "reason_codes": reason_codes,
        "severity": severity,
        "safe_to_cite": not reason_codes,
        "safe_for_correctness_claim": not reason_codes,
        "repo_head": repo_head,
        "artifact_head": artifact_head,
        "touched_files": touched_files,
        "dirty_overlap_paths": dirty_overlap,
        "peer_reservation_overlaps": active_peer_holders,
        "superseded_by": superseded_by,
        "rerun_command": rerun_command,
        "operator_actions": operator_actions,
    }


def reason_sort_key(reason: str) -> tuple[int, str]:
    return (REASON_CATALOG.get(reason, {"severity": 999})["severity"], reason)


def build_graph(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    lanes = lane_by_id(fixture)
    rows = [
        classify_artifact(fixture, artifact, lanes)
        for artifact in dict_list(fixture.get("artifacts"))
    ]
    rows.sort(key=lambda row: (-row["severity"], row["artifact_id"]))

    nodes = []
    for lane_id in sorted(lanes):
        nodes.append(
            {
                "node_id": f"lane:{lane_id}",
                "kind": "lane",
                "lane_id": lane_id,
                "claim_scope": string(lanes[lane_id].get("claim_scope")),
            }
        )
    for row in sorted(rows, key=lambda item: item["artifact_id"]):
        nodes.append(
            {
                "node_id": f"artifact:{row['artifact_id']}",
                "kind": "artifact",
                "artifact_id": row["artifact_id"],
                "classification": row["classification"],
                "safe_to_cite": row["safe_to_cite"],
            }
        )

    edges = []
    for row in rows:
        edges.append(
            {
                "from": f"artifact:{row['artifact_id']}",
                "to": f"lane:{row['lane_id']}",
                "kind": "covers-lane",
            }
        )
        if row["superseded_by"]:
            edges.append(
                {
                    "from": f"artifact:{row['artifact_id']}",
                    "to": f"artifact:{row['superseded_by']}",
                    "kind": "superseded-by",
                }
            )

    reason_counts: dict[str, int] = {reason: 0 for reason in REASON_CATALOG}
    for row in rows:
        for reason in row["reason_codes"]:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "fixture_id": string(fixture.get("fixture_id")),
        "repo": fixture.get("repo", {}),
        "policy": {
            "required_rch_prefix": REQUIRED_RCH_PREFIX,
            "non_claims": [
                "This graph ranks proof debt and rerun needs; it is not workspace health.",
                "Advisory-only evidence is never upgraded to correctness evidence.",
                "A cache hit is not a fresh RCH pass.",
            ],
        },
        "reason_catalog": REASON_CATALOG,
        "summary": {
            "total_artifacts": len(rows),
            "safe_to_cite": sum(1 for row in rows if row["safe_to_cite"]),
            "proof_debt": sum(1 for row in rows if not row["safe_to_cite"]),
            "reason_counts": reason_counts,
        },
        "nodes": nodes,
        "edges": edges,
        "rows": rows,
    }


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Proof Evidence Debt Graph",
        "",
        f"- fixture: `{report['fixture_id']}`",
        f"- generated_at: `{report['generated_at']}`",
        f"- artifacts: `{summary['total_artifacts']}`",
        f"- safe_to_cite: `{summary['safe_to_cite']}`",
        f"- proof_debt: `{summary['proof_debt']}`",
        "",
        "Non-claims:",
    ]
    for non_claim in report["policy"]["non_claims"]:
        lines.append(f"- {non_claim}")
    lines.extend(
        [
            "",
            "| rank | artifact | lane | safe | reasons | rerun command |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for index, row in enumerate(report["rows"], start=1):
        reasons = ", ".join(row["reason_codes"]) if row["reason_codes"] else "<none>"
        command = row["rerun_command"] or "<missing>"
        lines.append(
            f"| {index} | `{row['artifact_id']}` | `{row['lane_id']}` | "
            f"{str(row['safe_to_cite']).lower()} | {reasons} | `{command}` |"
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
    generated_at = args.generated_at or utc_now()
    report = build_graph(fixture, generated_at)
    if args.output == "json":
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(markdown_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
