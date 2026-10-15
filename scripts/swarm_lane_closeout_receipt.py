#!/usr/bin/env python3
"""Emit deterministic swarm lane closeout receipts.

The helper consumes explicit fixture snapshots for bead state, Agent Mail,
file reservations, proof commands, Git evidence, and dirty-tree ownership. It
does not run commands, mutate beads, inspect live Git state, query Agent Mail,
or rewrite artifacts.
"""

import argparse
import copy
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-lane-closeout-receipt-v1"
FIXTURE_SCHEMA_VERSION = "swarm-lane-closeout-fixture-v1"
CONTRACT_SCHEMA_VERSION = "swarm-lane-closeout-contract-v1"

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-dirty-files",
    "do-not-cite-local-fallback-as-rch-proof",
    "do-not-cite-failed-proof-as-green",
    "do-not-cite-zero-test-filter-as-passing",
    "do-not-overwrite-or-rewrite-beads-jsonl",
    "do-not-claim-unverified-pushed-refs",
    "do-not-leave-owned-dirty-files-unclassified",
]

GLOBAL_NON_CLAIMS = [
    "This receipt classifies closeout evidence; it does not prove source correctness beyond the listed commands.",
    "Fixture snapshots do not override live br, Agent Mail, Git, reservation, or RCH state.",
    "An admissible receipt still requires the normal claim, reservation, validation, commit, push, and legacy mirror workflow.",
    "Peer dirty files are admissible only when classified and outside the owned path set.",
]

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "malformed-closeout-evidence": {
        "severity": 110,
        "admissible": False,
        "recommended_action": "repair-closeout-fixture",
        "operator_action": "Do not use this receipt until required closeout fields are present.",
    },
    "failed-proof-cited-green": {
        "severity": 100,
        "admissible": False,
        "recommended_action": "rerun-or-fix-failed-proof",
        "operator_action": "Do not close the lane; a failed proof command was cited as green.",
    },
    "missing-remote-worker-evidence": {
        "severity": 95,
        "admissible": False,
        "recommended_action": "rerun-with-remote-rch-proof",
        "operator_action": "Do not cite the proof; remote-required RCH evidence lacks a worker identity.",
    },
    "zero-test-exact-filter": {
        "severity": 90,
        "admissible": False,
        "recommended_action": "rerun-exact-filter-with-nonzero-tests",
        "operator_action": "Do not cite the test as green; the exact filter ran zero tests.",
    },
    "expired-reservation-gap": {
        "severity": 85,
        "admissible": False,
        "recommended_action": "renew-reservations-and-revalidate",
        "operator_action": "Do not close the lane; at least one reserved path was uncovered during validation.",
    },
    "unverified-pushed-refs": {
        "severity": 80,
        "admissible": False,
        "recommended_action": "verify-pushed-main-and-legacy-mirror",
        "operator_action": "Do not claim closeout until pushed refs and their mirror check are verified.",
    },
    "agent-mail-closeout-gap": {
        "severity": 75,
        "admissible": False,
        "recommended_action": "handle-agent-mail-acks",
        "operator_action": "Do not close the lane until required coordination messages are acknowledged.",
    },
    "dirty-tree-unclassified": {
        "severity": 70,
        "admissible": False,
        "recommended_action": "classify-or-clean-owned-dirty-files",
        "operator_action": "Do not close the lane with owned or unclassified dirty-tree entries.",
    },
    "peer-dirt-shared-main": {
        "severity": 30,
        "admissible": True,
        "recommended_action": "close-with-peer-dirt-note",
        "operator_action": "The lane is admissible if remaining dirt is classified as peer-owned or intentionally unstaged.",
    },
    "admissible-closeout": {
        "severity": 10,
        "admissible": True,
        "recommended_action": "close-commit-push-and-release-reservations",
        "operator_action": "The fixture contains enough evidence for a deterministic closeout receipt.",
    },
}


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


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
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


def merge_defaults(defaults: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(defaults)
    for key, value in scenario.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_defaults(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def expanded_scenarios(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    defaults = fixture.get("scenario_defaults")
    if not isinstance(defaults, dict):
        defaults = {}
    return [
        merge_defaults(defaults, scenario)
        for scenario in dict_list(fixture.get("scenarios"))
    ]


def parse_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def timestamp_le(left: str, right: str) -> bool:
    parsed_left = parse_timestamp(left)
    parsed_right = parse_timestamp(right)
    return parsed_left is not None and parsed_right is not None and parsed_left <= parsed_right


def timestamp_ge(left: str, right: str) -> bool:
    parsed_left = parse_timestamp(left)
    parsed_right = parse_timestamp(right)
    return parsed_left is not None and parsed_right is not None and parsed_left >= parsed_right


def list_contains(values: list[str], wanted: str) -> bool:
    return any(value == wanted for value in values)


def sorted_strings(values: list[str]) -> list[str]:
    return sorted(set(value for value in values if value))


def bead_blockers(bead: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for field in ["id", "title", "pre_status", "post_status", "assignee"]:
        if not string(bead.get(field)):
            blockers.append(f"bead:{field}:missing")
    if string(bead.get("post_status")) == "closed" and not string(bead.get("close_reason")):
        blockers.append("bead:close_reason:missing")
    return blockers


def agent_mail_blockers(agent_mail: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not string(agent_mail.get("agent_name")):
        blockers.append("agent_mail:agent_name:missing")
    if not string(agent_mail.get("thread_id")):
        blockers.append("agent_mail:thread_id:missing")
    for message in dict_list(agent_mail.get("ack_required_messages")):
        if not bool_value(message.get("acknowledged"), False):
            message_id = string(message.get("id")) or "<unknown>"
            blockers.append(f"agent_mail:ack-required-unhandled:{message_id}")
    return sorted_strings(blockers)


def reservation_covers_path(
    reservation: dict[str, Any],
    path: str,
    validation_started_at: str,
    validation_finished_at: str,
) -> bool:
    if string(reservation.get("path")) != path:
        return False
    if not bool_value(reservation.get("exclusive"), False):
        return False
    granted_at = string(reservation.get("granted_at"))
    expires_at = string(reservation.get("expires_at"))
    released_at = string(reservation.get("released_at"))
    if not timestamp_le(granted_at, validation_started_at):
        return False
    if not timestamp_ge(expires_at, validation_finished_at):
        return False
    if released_at and not timestamp_ge(released_at, validation_finished_at):
        return False
    return True


def reservation_gaps(scenario: dict[str, Any]) -> list[str]:
    reservations = scenario.get("reservations")
    if not isinstance(reservations, dict):
        return ["reservations:missing"]
    validation_started_at = string(reservations.get("validation_started_at"))
    validation_finished_at = string(reservations.get("validation_finished_at"))
    if not validation_started_at or not validation_finished_at:
        return ["reservations:validation-window-missing"]

    held = dict_list(reservations.get("held"))
    gaps: list[str] = []
    for path in string_list(scenario.get("owned_paths")):
        if not any(
            reservation_covers_path(
                reservation,
                path,
                validation_started_at,
                validation_finished_at,
            )
            for reservation in held
        ):
            gaps.append(f"reservation-gap:{path}")
    return sorted_strings(gaps)


def proof_rows(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    proofs = scenario.get("proof_commands")
    if not isinstance(proofs, list):
        return []
    return sorted(
        dict_list(proofs),
        key=lambda proof: (
            string(proof.get("command_id")),
            " ".join(string_list(proof.get("argv"))),
        ),
    )


def failed_proof_cited_green_blockers(scenario: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for proof in proof_rows(scenario):
        if bool_value(proof.get("cited_as_green"), False) and int_value(proof.get("exit_code"), 1) != 0:
            command_id = string(proof.get("command_id")) or "<unknown>"
            blockers.append(f"{command_id}:exit={int_value(proof.get('exit_code'), 1)}")
    return sorted_strings(blockers)


def missing_remote_worker_blockers(scenario: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for proof in proof_rows(scenario):
        if bool_value(proof.get("rch_remote_required"), False) and not string(proof.get("worker_identity")):
            command_id = string(proof.get("command_id")) or "<unknown>"
            blockers.append(f"{command_id}:missing-worker-identity")
    return sorted_strings(blockers)


def zero_test_exact_filter_blockers(scenario: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for proof in proof_rows(scenario):
        if bool_value(proof.get("exact_filter"), False) and int_value(proof.get("tests_run"), 0) <= 0:
            command_id = string(proof.get("command_id")) or "<unknown>"
            blockers.append(f"{command_id}:tests_run=0")
    return sorted_strings(blockers)


def malformed_proof_blockers(scenario: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    proofs = proof_rows(scenario)
    if not proofs:
        return ["proof_commands:missing"]
    for proof in proofs:
        command_id = string(proof.get("command_id")) or "<unknown>"
        if not string(proof.get("command_id")):
            blockers.append("proof_command:command_id:missing")
        if not string_list(proof.get("argv")):
            blockers.append(f"{command_id}:argv:missing")
        if not isinstance(proof.get("env"), dict):
            blockers.append(f"{command_id}:env:missing")
        if not string(proof.get("target_dir_class")):
            blockers.append(f"{command_id}:target_dir_class:missing")
        if not string(proof.get("source_fingerprint")):
            blockers.append(f"{command_id}:source_fingerprint:missing")
    return sorted_strings(blockers)


def git_blockers(scenario: dict[str, Any]) -> list[str]:
    git = scenario.get("git")
    if not isinstance(git, dict):
        return ["git:missing"]
    blockers: list[str] = []
    for field in ["starting_head", "committed_head"]:
        if not string(git.get(field)):
            blockers.append(f"git:{field}:missing")
    origin = git.get("origin_main") if isinstance(git.get("origin_main"), dict) else {}
    if not bool_value(origin.get("push_success"), False):
        blockers.append("git:origin-main-push:not-successful")
    if not bool_value(origin.get("verified"), False):
        blockers.append("git:origin-main:unverified")
    ahead_behind = origin.get("post_push_ahead_behind")
    if not isinstance(ahead_behind, dict):
        blockers.append("git:origin-main:ahead-behind-missing")
    else:
        if int_value(ahead_behind.get("ahead"), -1) != 0:
            blockers.append("git:origin-main:ahead-not-zero")
        if int_value(ahead_behind.get("behind"), -1) != 0:
            blockers.append("git:origin-main:behind-not-zero")
        if not bool_value(ahead_behind.get("verified"), False):
            blockers.append("git:origin-main:ahead-behind-unverified")
    legacy = git.get("legacy_mirror") if isinstance(git.get("legacy_mirror"), dict) else {}
    if not bool_value(legacy.get("push_success"), False):
        blockers.append("git:legacy-mirror-push:not-successful")
    if not bool_value(legacy.get("verified"), False):
        blockers.append("git:legacy-mirror:unverified")
    return sorted_strings(blockers)


def dirty_tree_rows(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        dict_list(scenario.get("dirty_tree")),
        key=lambda row: (string(row.get("path")), string(row.get("classification"))),
    )


def dirty_tree_blockers(scenario: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    owned_paths = set(string_list(scenario.get("owned_paths")))
    allowed = {"peer-owned", "intentionally-unstaged"}
    for row in dirty_tree_rows(scenario):
        path = string(row.get("path"))
        classification = string(row.get("classification"))
        if not path:
            blockers.append("dirty-tree:path:missing")
            continue
        if classification not in allowed:
            blockers.append(f"dirty-tree:{path}:classification={classification or '<missing>'}")
        if path in owned_paths:
            blockers.append(f"dirty-tree:{path}:owned-path-left-dirty")
    return sorted_strings(blockers)


def dirty_tree_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    rows = dirty_tree_rows(scenario)
    counts = {"peer-owned": 0, "intentionally-unstaged": 0, "other": 0}
    for row in rows:
        classification = string(row.get("classification"))
        if classification in counts:
            counts[classification] += 1
        else:
            counts["other"] += 1
    return {
        "remaining_count": len(rows),
        "classification_counts": counts,
        "rows": rows,
    }


def proof_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    proofs = proof_rows(scenario)
    return {
        "command_count": len(proofs),
        "remote_required_count": sum(
            1 for proof in proofs if bool_value(proof.get("rch_remote_required"), False)
        ),
        "green_count": sum(
            1
            for proof in proofs
            if bool_value(proof.get("cited_as_green"), False)
            and int_value(proof.get("exit_code"), 1) == 0
        ),
        "tests_run_total": sum(int_value(proof.get("tests_run"), 0) for proof in proofs),
        "commands": proofs,
    }


def reservation_summary(scenario: dict[str, Any], gaps: list[str]) -> dict[str, Any]:
    reservations = scenario.get("reservations")
    if not isinstance(reservations, dict):
        reservations = {}
    return {
        "validation_started_at": string(reservations.get("validation_started_at")),
        "validation_finished_at": string(reservations.get("validation_finished_at")),
        "required_path_count": len(string_list(scenario.get("owned_paths"))),
        "held_count": len(dict_list(reservations.get("held"))),
        "renewed_count": len(dict_list(reservations.get("renewed"))),
        "released_count": len(dict_list(reservations.get("released"))),
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def git_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    git = scenario.get("git")
    if not isinstance(git, dict):
        return {}
    return {
        "starting_head": string(git.get("starting_head")),
        "committed_head": string(git.get("committed_head")),
        "origin_main": git.get("origin_main") if isinstance(git.get("origin_main"), dict) else {},
        "legacy_mirror": git.get("legacy_mirror") if isinstance(git.get("legacy_mirror"), dict) else {},
    }


def row_for(
    scenario: dict[str, Any],
    classification: str,
    blockers: list[str],
    *,
    reservation_gaps_for_row: list[str],
) -> dict[str, Any]:
    catalog = CLASSIFICATION_CATALOG[classification]
    bead = scenario.get("bead") if isinstance(scenario.get("bead"), dict) else {}
    agent_mail = (
        scenario.get("agent_mail") if isinstance(scenario.get("agent_mail"), dict) else {}
    )
    return {
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": catalog["severity"],
        "admissible": bool_value(catalog.get("admissible"), False),
        "recommended_action": catalog["recommended_action"],
        "operator_action": catalog["operator_action"],
        "bead": {
            "id": string(bead.get("id")),
            "title": string(bead.get("title")),
            "pre_status": string(bead.get("pre_status")),
            "post_status": string(bead.get("post_status")),
            "assignee": string(bead.get("assignee")),
            "close_reason": string(bead.get("close_reason")),
        },
        "agent_mail": {
            "agent_name": string(agent_mail.get("agent_name")),
            "thread_id": string(agent_mail.get("thread_id")),
            "messages_sent": dict_list(agent_mail.get("messages_sent")),
            "ack_required_messages": dict_list(agent_mail.get("ack_required_messages")),
            "active_agents": dict_list(agent_mail.get("active_agents")),
        },
        "owned_paths": sorted_strings(string_list(scenario.get("owned_paths"))),
        "reservation_summary": reservation_summary(scenario, reservation_gaps_for_row),
        "proof_summary": proof_summary(scenario),
        "git_summary": git_summary(scenario),
        "dirty_tree_summary": dirty_tree_summary(scenario),
        "blockers": sorted_strings(blockers),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def classify_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    bead = scenario.get("bead") if isinstance(scenario.get("bead"), dict) else {}
    malformed = (
        bead_blockers(bead)
        + malformed_proof_blockers(scenario)
        + ([] if string(scenario.get("scenario_id")) else ["scenario_id:missing"])
    )
    reservation_gap_list = reservation_gaps(scenario)
    if malformed:
        return row_for(
            scenario,
            "malformed-closeout-evidence",
            malformed,
            reservation_gaps_for_row=reservation_gap_list,
        )

    failed = failed_proof_cited_green_blockers(scenario)
    if failed:
        return row_for(
            scenario,
            "failed-proof-cited-green",
            failed,
            reservation_gaps_for_row=reservation_gap_list,
        )

    missing_remote = missing_remote_worker_blockers(scenario)
    if missing_remote:
        return row_for(
            scenario,
            "missing-remote-worker-evidence",
            missing_remote,
            reservation_gaps_for_row=reservation_gap_list,
        )

    zero_tests = zero_test_exact_filter_blockers(scenario)
    if zero_tests:
        return row_for(
            scenario,
            "zero-test-exact-filter",
            zero_tests,
            reservation_gaps_for_row=reservation_gap_list,
        )

    if reservation_gap_list:
        return row_for(
            scenario,
            "expired-reservation-gap",
            reservation_gap_list,
            reservation_gaps_for_row=reservation_gap_list,
        )

    git_gaps = git_blockers(scenario)
    if git_gaps:
        return row_for(
            scenario,
            "unverified-pushed-refs",
            git_gaps,
            reservation_gaps_for_row=reservation_gap_list,
        )

    mail_gaps = agent_mail_blockers(
        scenario.get("agent_mail") if isinstance(scenario.get("agent_mail"), dict) else {}
    )
    if mail_gaps:
        return row_for(
            scenario,
            "agent-mail-closeout-gap",
            mail_gaps,
            reservation_gaps_for_row=reservation_gap_list,
        )

    dirty_gaps = dirty_tree_blockers(scenario)
    if dirty_gaps:
        return row_for(
            scenario,
            "dirty-tree-unclassified",
            dirty_gaps,
            reservation_gaps_for_row=reservation_gap_list,
        )

    if dirty_tree_rows(scenario):
        return row_for(
            scenario,
            "peer-dirt-shared-main",
            [],
            reservation_gaps_for_row=reservation_gap_list,
        )

    return row_for(
        scenario,
        "admissible-closeout",
        [],
        reservation_gaps_for_row=reservation_gap_list,
    )


def build_report(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    rows = [classify_scenario(scenario) for scenario in expanded_scenarios(fixture)]
    rows.sort(key=lambda row: (-int_value(row.get("severity")), string(row.get("scenario_id"))))
    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1
    admissible = [row for row in rows if bool_value(row.get("admissible"), False)]
    summary = {
        "scenario_count": len(rows),
        "admissible_count": len(admissible),
        "non_admissible_count": len(rows) - len(admissible),
        "fail_closed_count": len(rows) - len(admissible),
        "peer_dirt_admissible_count": sum(
            1
            for row in rows
            if string(row.get("classification")) == "peer-dirt-shared-main"
        ),
        "proof_command_count": sum(
            int_value(row.get("proof_summary", {}).get("command_count")) for row in rows
        ),
        "highest_severity_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "classification_catalog": CLASSIFICATION_CATALOG,
        "policy": {
            "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
            "non_claims": list(GLOBAL_NON_CLAIMS),
        },
        "summary": summary,
        "rows": rows,
    }


def comma_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Swarm Lane Closeout Receipt",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Scenarios: {summary['scenario_count']}",
        f"- Admissible: {summary['admissible_count']}",
        f"- Non-admissible: {summary['non_admissible_count']}",
        f"- Peer-dirt admissible: {summary['peer_dirt_admissible_count']}",
        f"- Highest severity scenario: `{summary['highest_severity_scenario']}`",
        "",
        "| Scenario | Classification | Admissible | Bead | Proofs | Dirty | Action | Blockers |",
        "|---|---|---:|---|---:|---:|---|---|",
    ]
    for row in report["rows"]:
        proof_count = row["proof_summary"]["command_count"]
        dirty_count = row["dirty_tree_summary"]["remaining_count"]
        lines.append(
            "| {scenario} | `{classification}` | {admissible} | `{bead}` | {proofs} | {dirty} | `{action}` | {blockers} |".format(
                scenario=row["scenario_id"],
                classification=row["classification"],
                admissible="yes" if row["admissible"] else "no",
                bead=row["bead"]["id"],
                proofs=proof_count,
                dirty=dirty_count,
                action=row["recommended_action"],
                blockers=comma_or_dash(row["blockers"]),
            )
        )
    lines.extend(["", "## Forbidden Actions", ""])
    for action in report["policy"]["forbidden_actions"]:
        lines.append(f"- `{action}`")
    lines.extend(["", "## Non-Claims", ""])
    for non_claim in report["policy"]["non_claims"]:
        lines.append(f"- {non_claim}")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit a deterministic swarm lane closeout receipt."
    )
    parser.add_argument(
        "--fixture",
        required=True,
        type=Path,
        help="fixture JSON or contract artifact containing a fixture object",
    )
    parser.add_argument(
        "--generated-at",
        default=utc_now(),
        help="deterministic timestamp for contract tests",
    )
    parser.add_argument(
        "--output",
        choices=["json", "markdown"],
        default="json",
        help="output format",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    fixture = load_fixture(args.fixture)
    report = build_report(fixture, args.generated_at)
    if args.output == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(markdown_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
