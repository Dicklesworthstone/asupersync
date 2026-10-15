#!/usr/bin/env python3
"""Evaluate shared-main coordination replay fixtures.

The replay pack turns Agent-Mail/Beads/rch-style event rows into deterministic
invariant checks. It never contacts services or mutates state; callers provide
the event transcript as JSON.
"""

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-coordination-replay-pack-v1"
INPUT_SCHEMA_VERSION = "swarm-coordination-replay-input-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.max.replace(tzinfo=dt.timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def current_date(generated_at: str) -> str:
    try:
        return parse_timestamp(generated_at).date().isoformat()
    except OverflowError:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def normalize_event(raw: dict[str, Any], index: int) -> dict[str, Any]:
    event_type = str(raw.get("type", "note"))
    bead_id = str(raw.get("bead_id", ""))
    agent = str(raw.get("agent", ""))
    path = str(raw.get("path", ""))
    status = str(raw.get("status", ""))
    return {
        "id": str(raw.get("id") or f"event-{index:04d}"),
        "timestamp": str(raw.get("timestamp", "")),
        "sort_key": parse_timestamp(str(raw.get("timestamp", ""))).isoformat(),
        "agent": agent,
        "type": event_type,
        "bead_id": bead_id,
        "path": path,
        "exclusive": bool(raw.get("exclusive", False)),
        "status": status,
        "proof_id": str(raw.get("proof_id", "")),
        "remote_exit": raw.get("remote_exit"),
        "artifact_retrieved": raw.get("artifact_retrieved"),
        "commit": str(raw.get("commit", "")),
        "summary": str(raw.get("summary", "")),
        "evidence": string_list(raw.get("evidence")),
    }


def normalize_events(raw_events: list[Any]) -> list[dict[str, Any]]:
    events = [
        normalize_event(raw, index)
        for index, raw in enumerate(raw_events)
        if isinstance(raw, dict)
    ]
    return sorted(events, key=lambda event: (event["sort_key"], event["id"]))


def violation(code: str, severity: str, message: str, event_ids: list[str], remediation: str) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "event_ids": sorted(event_ids),
        "remediation": remediation,
    }


def active_duplicate_claims(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active_by_bead: dict[str, dict[str, str]] = defaultdict(dict)
    claim_events: dict[tuple[str, str], str] = {}
    findings: list[dict[str, Any]] = []

    for event in events:
        bead = event["bead_id"]
        agent = event["agent"]
        if not bead or not agent:
            continue
        key = (bead, agent)
        if event["type"] == "claim":
            active_by_bead[bead][agent] = event["id"]
            claim_events[key] = event["id"]
        elif event["type"] in {"ship", "close", "stand_down"}:
            active_by_bead[bead].pop(agent, None)
            claim_events.pop(key, None)

    for bead, claims in sorted(active_by_bead.items()):
        if len(claims) > 1:
            agents = ", ".join(sorted(claims))
            findings.append(
                violation(
                    "duplicate-active-claim",
                    "error",
                    f"{bead} has simultaneous active claims from {agents}",
                    list(claims.values()),
                    "one agent should stand down or split the write surface before edits continue",
                )
            )
    return findings


def reservation_contention(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active_by_path: dict[str, dict[str, str]] = defaultdict(dict)
    findings: list[dict[str, Any]] = []

    for event in events:
        if event["type"] != "reservation":
            continue
        path = event["path"]
        agent = event["agent"]
        if not path or not agent:
            continue
        if event["status"] in {"released", "expired"}:
            active_by_path[path].pop(agent, None)
        elif event["exclusive"]:
            active_by_path[path][agent] = event["id"]

    for path, holders in sorted(active_by_path.items()):
        if len(holders) > 1:
            agents = ", ".join(sorted(holders))
            findings.append(
                violation(
                    "exclusive-reservation-contention",
                    "error",
                    f"{path} has overlapping exclusive reservations from {agents}",
                    list(holders.values()),
                    "coordinate holders or wait for one lease to release before editing that path",
                )
            )
    return findings


def partial_proof_launches(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    proof_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings: list[dict[str, Any]] = []
    for event in events:
        if event["proof_id"]:
            proof_events[event["proof_id"]].append(event)

    for proof_id, proof in sorted(proof_events.items()):
        launched = [event for event in proof if event["type"] == "proof_start"]
        if not launched:
            continue
        remote_done = [event for event in proof if event["type"] == "proof_remote_exit"]
        if not remote_done:
            findings.append(
                violation(
                    "partial-proof-launch",
                    "error",
                    f"{proof_id} started but has no remote exit event",
                    [event["id"] for event in proof],
                    "capture a remote exit event or rerun the focused rch proof lane",
                )
            )
            continue
        if any(event["remote_exit"] != 0 for event in remote_done):
            findings.append(
                violation(
                    "failed-proof-launch",
                    "error",
                    f"{proof_id} has a non-zero remote proof exit",
                    [event["id"] for event in remote_done],
                    "do not close the bead on this proof; fix or surface the first remote failure",
                )
            )
        elif not any(event["type"] == "proof_artifact" and event["artifact_retrieved"] is True for event in proof):
            findings.append(
                violation(
                    "proof-artifact-missing",
                    "warning",
                    f"{proof_id} reached remote success without artifact retrieval evidence",
                    [event["id"] for event in proof],
                    "record remote success and artifact retrieval as separate evidence rows",
                )
            )
    return findings


def closeout_evidence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events_by_bead: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings: list[dict[str, Any]] = []
    for event in events:
        if event["bead_id"]:
            events_by_bead[event["bead_id"]].append(event)

    for bead, bead_events in sorted(events_by_bead.items()):
        closes = [event for event in bead_events if event["type"] == "close"]
        if not closes:
            continue
        has_ship = any(event["type"] == "ship" and event["commit"] for event in bead_events)
        has_proof = any(event["type"] == "proof_remote_exit" and event["remote_exit"] == 0 for event in bead_events)
        if not has_ship or not has_proof:
            missing = []
            if not has_ship:
                missing.append("ship commit")
            if not has_proof:
                missing.append("remote proof exit 0")
            findings.append(
                violation(
                    "closeout-evidence-gap",
                    "warning",
                    f"{bead} closeout is missing {', '.join(missing)} evidence",
                    [event["id"] for event in closes],
                    "attach commit and rch proof evidence before relying on the closeout",
                )
            )
    return findings


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    generated_at = args.generated_at or utc_now()
    events = normalize_events(as_list(data.get("events")))
    violations = (
        active_duplicate_claims(events)
        + reservation_contention(events)
        + partial_proof_launches(events)
        + closeout_evidence(events)
    )
    error_count = sum(1 for finding in violations if finding["severity"] == "error")
    warning_count = sum(1 for finding in violations if finding["severity"] == "warning")

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": data.get("schema_version", ""),
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "source": str(input_path),
        "source_counts": {
            "events": len(events),
            "agents": len({event["agent"] for event in events if event["agent"]}),
            "beads": len({event["bead_id"] for event in events if event["bead_id"]}),
            "proofs": len({event["proof_id"] for event in events if event["proof_id"]}),
        },
        "invariants": {
            "no_duplicate_active_claims": not any(
                finding["code"] == "duplicate-active-claim" for finding in violations
            ),
            "no_exclusive_reservation_contention": not any(
                finding["code"] == "exclusive-reservation-contention" for finding in violations
            ),
            "proofs_have_remote_exit_events": not any(
                finding["code"] == "partial-proof-launch" for finding in violations
            ),
            "successful_proofs_have_artifact_evidence": not any(
                finding["code"] == "proof-artifact-missing" for finding in violations
            ),
            "closeouts_have_commit_and_remote_proof": not any(
                finding["code"] == "closeout-evidence-gap" for finding in violations
            ),
        },
        "summary": {
            "passes": error_count == 0 and warning_count == 0,
            "error_count": error_count,
            "warning_count": warning_count,
            "violation_count": len(violations),
        },
        "violations": violations,
        "action_items": [finding["remediation"] for finding in violations],
        "timeline": [
            {
                "id": event["id"],
                "timestamp": event["timestamp"],
                "agent": event["agent"],
                "type": event["type"],
                "bead_id": event["bead_id"],
                "proof_id": event["proof_id"],
                "path": event["path"],
                "summary": event["summary"],
            }
            for event in events
        ],
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_agent_mail_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a swarm coordination replay pack")
    parser.add_argument("--input", required=True, help="JSON coordination event transcript")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
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
