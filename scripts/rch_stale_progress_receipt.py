#!/usr/bin/env python3
"""Emit deterministic RCH stale-progress receipts from explicit fixtures."""

import argparse
import copy
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-stale-progress-receipt-v1"
FIXTURE_SCHEMA_VERSION = "rch-stale-progress-fixture-v1"

GLOBAL_NON_CLAIMS = [
    "Stale progress is infrastructure evidence; it does not prove source correctness.",
    "Heartbeat-stale or progress-stale receipts do not prove release readiness.",
    "Local fallback is never acceptable proof for remote-required Cargo validation.",
    "Peer-owned stale builds must be coordinated, not canceled by another agent.",
]

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-cite-stale-progress-as-success",
    "do-not-cancel-peer-owned-builds",
    "do-not-retry-without-receipt-or-diagnostic",
    "do-not-use-local-fallback-as-proof",
    "do-not-close-release-readiness-from-stale-receipt",
]

CLASSIFICATION_CATALOG: dict[str, dict[str, Any]] = {
    "local-fallback-refused": {
        "severity": 100,
        "cancel_allowed": False,
        "retry_allowed": False,
        "operator_action": "Wait for remote RCH admission; do not use local fallback.",
    },
    "heartbeat-stale-infra": {
        "severity": 95,
        "cancel_allowed": False,
        "retry_allowed": True,
        "operator_action": "Record infrastructure staleness, avoid source claims, and retry only after the receipt is preserved.",
    },
    "peer-owned-do-not-cancel": {
        "severity": 90,
        "cancel_allowed": False,
        "retry_allowed": False,
        "operator_action": "Do not cancel the build; notify the owning agent or wait for terminal state.",
    },
    "owned-stale-cancel-recommended": {
        "severity": 80,
        "cancel_allowed": True,
        "retry_allowed": False,
        "operator_action": "Cancel only the current agent's stale build, preserve the receipt, then retry after cleanup.",
    },
    "stale-progress-canceled": {
        "severity": 70,
        "cancel_allowed": True,
        "retry_allowed": True,
        "operator_action": "Retry is allowed because cancellation completed and this receipt captures the stale-progress state.",
    },
    "heartbeat-live-progress-stale-wait": {
        "severity": 60,
        "cancel_allowed": False,
        "retry_allowed": False,
        "operator_action": "Keep polling while heartbeat is fresh; do not treat quiet progress as failure or success.",
    },
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
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


def dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def int_list(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    return [int_value(item) for item in value if not isinstance(item, bool)]


def sorted_strings(values: list[str]) -> list[str]:
    return sorted(set(value for value in values if value))


def merge_defaults(defaults: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(defaults)
    for key, value in scenario.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_defaults(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


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


def expanded_scenarios(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    defaults = dict_value(fixture.get("scenario_defaults"))
    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list):
        return []
    return [
        merge_defaults(defaults, scenario)
        for scenario in scenarios
        if isinstance(scenario, dict)
    ]


def classify_scenario(
    scenario: dict[str, Any], policy: dict[str, Any], current_agent: str
) -> str:
    lane = dict_value(scenario.get("lane"))
    status = dict_value(scenario.get("rch_status"))
    cancellation = dict_value(scenario.get("cancellation_outcome"))
    progress_age = int_value(status.get("progress_age_secs"))
    heartbeat_age = int_value(status.get("heartbeat_age_secs"))
    progress_stale = bool_value(status.get("detector_progress_stale")) or progress_age >= int_value(
        policy.get("progress_stale_after_secs"), 600
    )
    heartbeat_stale = bool_value(status.get("detector_heartbeat_stale")) or heartbeat_age >= int_value(
        policy.get("heartbeat_stale_after_secs"), 300
    )
    quiet_warning = progress_age >= int_value(policy.get("quiet_warning_seconds"), 300)
    local_fallback = bool(string_list(status.get("local_fallback_markers")))
    remote_required = bool_value(lane.get("remote_required"), False)
    local_fallback_allowed = bool_value(lane.get("local_fallback_allowed"), True)
    owned = bool_value(scenario.get("owned_by_current_agent"), False) or (
        string(status.get("build_owner")) == current_agent and current_agent != ""
    )

    if local_fallback or not remote_required or local_fallback_allowed:
        return "local-fallback-refused"
    if heartbeat_stale:
        return "heartbeat-stale-infra"
    if progress_stale and not owned:
        return "peer-owned-do-not-cancel"
    if progress_stale and string(cancellation.get("final_state")) == "completed":
        return "stale-progress-canceled"
    if progress_stale and bool_value(status.get("detector_cancel_recommended")):
        return "owned-stale-cancel-recommended"
    if quiet_warning:
        return "heartbeat-live-progress-stale-wait"
    return "heartbeat-live-progress-stale-wait"


def scenario_blockers(
    classification: str, scenario: dict[str, Any], policy: dict[str, Any]
) -> list[str]:
    status = dict_value(scenario.get("rch_status"))
    blockers: list[str] = []
    if classification == "local-fallback-refused":
        markers = string_list(status.get("local_fallback_markers"))
        blockers.extend(f"local-fallback-marker:{index}" for index, _ in enumerate(markers, start=1))
        if not markers:
            blockers.append("remote-required-or-no-local-fallback-missing")
    if classification == "heartbeat-stale-infra":
        blockers.append(f"heartbeat-age-secs={int_value(status.get('heartbeat_age_secs'))}")
    if classification == "peer-owned-do-not-cancel":
        blockers.append(f"peer-owner={string(status.get('build_owner'))}")
    if classification in {
        "owned-stale-cancel-recommended",
        "stale-progress-canceled",
        "peer-owned-do-not-cancel",
    }:
        blockers.append(f"progress-age-secs={int_value(status.get('progress_age_secs'))}")
    if classification == "heartbeat-live-progress-stale-wait":
        blockers.append(
            f"quiet-warning-secs={int_value(policy.get('quiet_warning_seconds'), 300)}"
        )
    return sorted_strings(blockers)


def scenario_warnings(scenario: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    status = dict_value(scenario.get("rch_status"))
    warnings: list[str] = []
    progress_age = int_value(status.get("progress_age_secs"))
    heartbeat_age = int_value(status.get("heartbeat_age_secs"))
    if progress_age >= int_value(policy.get("quiet_warning_seconds"), 300):
        warnings.append(f"progress-quiet-warning={progress_age}")
    if heartbeat_age >= int_value(policy.get("heartbeat_stale_after_secs"), 300):
        warnings.append(f"heartbeat-stale-warning={heartbeat_age}")
    return sorted_strings(warnings)


def build_receipt(
    scenario: dict[str, Any],
    fixture: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    policy = dict_value(fixture.get("policy"))
    current_agent = string(fixture.get("current_agent"))
    lane = dict_value(scenario.get("lane"))
    status = dict_value(scenario.get("rch_status"))
    cancellation = scenario.get("cancellation_outcome")
    cancellation_obj = dict_value(cancellation)
    classification = classify_scenario(scenario, policy, current_agent)
    catalog = CLASSIFICATION_CATALOG[classification]
    owned = bool_value(scenario.get("owned_by_current_agent"), False) or (
        string(status.get("build_owner")) == current_agent and current_agent != ""
    )
    peer_builds = int_list(status.get("peer_owned_active_builds"))
    cancel_allowed = bool_value(catalog.get("cancel_allowed")) and owned
    if peer_builds and not owned:
        cancel_allowed = False
    retry_allowed = bool_value(catalog.get("retry_allowed"))

    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": f"stale-progress-{string(scenario.get('scenario_id'))}",
        "generated_at": generated_at,
        "scenario_id": string(scenario.get("scenario_id")),
        "description": string(scenario.get("description")),
        "classification": classification,
        "severity": int_value(catalog.get("severity")),
        "proof_success_citable": False,
        "code_evidence_claimable": False,
        "lane": {
            "bead_id": string(lane.get("bead_id")),
            "manifest_lane_id": string(lane.get("manifest_lane_id")),
            "command_id": string(lane.get("command_id")),
            "command": string(lane.get("command")),
            "remote_required": bool_value(lane.get("remote_required")),
            "local_fallback_allowed": bool_value(lane.get("local_fallback_allowed")),
            "source_fingerprint": string(lane.get("source_fingerprint")),
        },
        "rch_status": {
            "build_id": int_value(status.get("build_id")),
            "project_id": string(status.get("project_id")),
            "worker_id": string(status.get("worker_id")),
            "build_owner": string(status.get("build_owner")),
            "selected_target_dir": string(status.get("selected_target_dir")),
            "heartbeat_phase": string(status.get("heartbeat_phase")),
            "heartbeat_detail": string(status.get("heartbeat_detail")),
            "heartbeat_age_secs": int_value(status.get("heartbeat_age_secs")),
            "progress_age_secs": int_value(status.get("progress_age_secs")),
            "detector_confidence": status.get("detector_confidence", 0),
            "detector_progress_stale": bool_value(status.get("detector_progress_stale")),
            "detector_heartbeat_stale": bool_value(status.get("detector_heartbeat_stale")),
            "detector_cancel_recommended": bool_value(
                status.get("detector_cancel_recommended")
            ),
            "last_compiler_line": string(status.get("last_compiler_line")),
            "peer_owned_active_builds": peer_builds,
            "local_fallback_markers": string_list(status.get("local_fallback_markers")),
        },
        "ownership": {
            "current_agent": current_agent,
            "owned_by_current_agent": owned,
            "peer_owned_active_builds": peer_builds,
        },
        "cancellation_policy": {
            "wait_for_fresh_heartbeat": bool_value(policy.get("wait_for_fresh_heartbeat")),
            "never_cancel_peer_owned_builds": bool_value(
                policy.get("never_cancel_peer_owned_builds")
            ),
            "receipt_required_before_retry": bool_value(
                policy.get("receipt_required_before_retry")
            ),
            "cancel_allowed": cancel_allowed,
            "operator_action": string(catalog.get("operator_action")),
        },
        "cancellation_outcome": cancellation_obj if isinstance(cancellation, dict) else None,
        "retry_policy": {
            "retry_allowed": retry_allowed,
            "retry_policy": string(policy.get("retry_policy")),
            "retry_requires_receipt": bool_value(policy.get("receipt_required_before_retry")),
        },
        "warnings": scenario_warnings(scenario, policy),
        "blockers": scenario_blockers(classification, scenario, policy),
        "forbidden_actions": list(GLOBAL_FORBIDDEN_ACTIONS),
        "evidence_does_not_prove": list(GLOBAL_NON_CLAIMS),
    }


def build_report(fixture: dict[str, Any], generated_at: str) -> dict[str, Any]:
    rows = [
        build_receipt(scenario, fixture, generated_at)
        for scenario in expanded_scenarios(fixture)
    ]
    rows.sort(key=lambda row: (-int_value(row.get("severity")), string(row.get("scenario_id"))))
    classification_counts = {
        classification: 0 for classification in CLASSIFICATION_CATALOG
    }
    for row in rows:
        classification_counts[string(row.get("classification"))] += 1
    summary = {
        "scenario_count": len(rows),
        "code_evidence_claimable_count": sum(
            1 for row in rows if bool_value(row.get("code_evidence_claimable"))
        ),
        "proof_success_citable_count": sum(
            1 for row in rows if bool_value(row.get("proof_success_citable"))
        ),
        "cancel_allowed_count": sum(
            1 for row in rows if bool_value(row["cancellation_policy"].get("cancel_allowed"))
        ),
        "retry_allowed_count": sum(
            1 for row in rows if bool_value(row["retry_policy"].get("retry_allowed"))
        ),
        "peer_cancel_forbidden_count": sum(
            1 for row in rows if row["classification"] == "peer-owned-do-not-cancel"
        ),
        "local_fallback_count": classification_counts["local-fallback-refused"],
        "heartbeat_stale_count": classification_counts["heartbeat-stale-infra"],
        "highest_severity_scenario": string(rows[0].get("scenario_id")) if rows else "",
        "classification_counts": classification_counts,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "generated_at": generated_at,
        "policy": dict_value(fixture.get("policy")),
        "classification_catalog": CLASSIFICATION_CATALOG,
        "summary": summary,
        "rows": rows,
    }


def comma_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# RCH Stale-Progress Receipt",
        "",
        f"- Fixture: `{report['fixture_id']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Scenarios: `{summary['scenario_count']}`",
        f"- Highest severity: `{summary['highest_severity_scenario']}`",
        f"- Code-evidence-claimable rows: `{summary['code_evidence_claimable_count']}`",
        "",
        "| Scenario | Classification | Build | Worker | Cancel | Retry | Blockers |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for row in report["rows"]:
        cancel = "yes" if row["cancellation_policy"]["cancel_allowed"] else "no"
        retry = "yes" if row["retry_policy"]["retry_allowed"] else "no"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{row['scenario_id']}`",
                    f"`{row['classification']}`",
                    str(row["rch_status"]["build_id"]),
                    f"`{row['rch_status']['worker_id'] or '-'}`",
                    cancel,
                    retry,
                    comma_or_dash(row["blockers"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Forbidden Actions",
            "",
        ]
    )
    lines.extend(f"- `{action}`" for action in GLOBAL_FORBIDDEN_ACTIONS)
    lines.extend(["", "## Non-Claims", ""])
    lines.extend(f"- {claim}" for claim in GLOBAL_NON_CLAIMS)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    fixture = load_fixture(args.fixture)
    report = build_report(fixture, args.generated_at)
    if args.output == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(markdown_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
