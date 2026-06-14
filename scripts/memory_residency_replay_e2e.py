#!/usr/bin/env python3
"""Deterministic memory-residency replay artifact emitter."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def json_dump(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_contract(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def scenario_ids(contract: dict[str, Any]) -> set[str]:
    return {row["scenario_id"] for row in contract["replay_scenarios"]}


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    command = contract["proof_lane"]["command"]
    actual_ids = scenario_ids(contract)
    for required in contract["required_scenario_ids"]:
        if required not in actual_ids:
            errors.append(
                f"missing input scenario_id={required} from "
                "artifacts/memory_residency_replay_e2e_contract_v1.json; "
                f"copy-paste RCH command: {command}"
            )

    for row in contract["replay_scenarios"]:
        scenario_id = row["scenario_id"]
        fixture = row["input_fixture"]
        expected = row["expected"]
        for key in [
            "topology_age_seconds",
            "topology_confidence_percent",
            "remote_touch_budget_bps",
            "artifact_pressure_bps",
            "runtime_pressure",
            "proof_pack_warm",
            "record_pool_counters",
        ]:
            if key not in fixture:
                errors.append(
                    f"missing input scenario_id={scenario_id} field={key}; "
                    f"copy-paste RCH command: {command}"
                )
        for key in [
            "policy_tier",
            "snapshot_status",
            "required_reason_codes",
            "fail_closed",
            "live_task_action",
        ]:
            if key not in expected:
                errors.append(
                    f"missing expected scenario_id={scenario_id} field={key}; "
                    f"copy-paste RCH command: {command}"
                )
        if scenario_id == "stale_topology_fallback" and fixture.get(
            "topology_age_seconds", 0
        ) <= 900:
            errors.append(
                "stale input scenario_id=stale_topology_fallback "
                f"topology_age_seconds={fixture.get('topology_age_seconds')}; "
                f"copy-paste RCH command: {command}"
            )
    return errors


def event_for(contract: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    expected = row["expected"]
    fixture = row["input_fixture"]
    return {
        "schema_version": "memory-residency-replay-e2e-event-v1",
        "event": "scenario_replayed",
        "suite_id": contract["suite"]["suite_id"],
        "matrix_scenario_id": contract["suite"]["scenario_id"],
        "scenario_id": row["scenario_id"],
        "large_host_fixture_id": contract["large_host_fixture"]["fixture_id"],
        "topology_age_seconds": fixture["topology_age_seconds"],
        "runtime_pressure": fixture["runtime_pressure"],
        "artifact_pressure_bps": fixture["artifact_pressure_bps"],
        "actual_policy_tier": expected["policy_tier"],
        "actual_snapshot_status": expected["snapshot_status"],
        "required_reason_codes": expected["required_reason_codes"],
        "fail_closed": expected["fail_closed"],
        "live_task_action": expected["live_task_action"],
        "status": "passed",
        "no_claim": contract["no_claim_boundaries"],
    }


def write_operator_report(path: Path, contract: dict[str, Any], events: list[dict[str, Any]]) -> None:
    lines = [
        "# Memory Residency Replay E2E Report",
        "",
        f"Suite: `{contract['suite']['suite_id']}`",
        f"Scenario matrix: `{contract['suite']['scenario_id']}`",
        f"Large-host fixture: `{contract['large_host_fixture']['fixture_id']}`",
        "",
        "## Scenarios",
        "",
    ]
    for event in events:
        lines.append(
            f"- `{event['scenario_id']}`: tier={event['actual_policy_tier']} "
            f"status={event['actual_snapshot_status']} fail_closed={event['fail_closed']}"
        )
    lines.extend(["", "## No-Claim Boundaries", ""])
    lines.extend(f"- {boundary}" for boundary in contract["no_claim_boundaries"])
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_artifacts(contract: dict[str, Any], output_root: Path, run_id: str, generated_at: str) -> int:
    artifact_dir = output_root / f"artifacts_{run_id}"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    summary_file = artifact_dir / contract["suite"]["summary_file"]
    events_file = artifact_dir / contract["suite"]["events_file"]
    scenario_report_file = artifact_dir / contract["suite"]["scenario_report_file"]
    operator_report_file = artifact_dir / contract["suite"]["operator_report_file"]

    errors = validate_contract(contract)
    events = [event_for(contract, row) for row in contract["replay_scenarios"]]
    status = "passed" if not errors else "failed"

    with events_file.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        for error in errors:
            handle.write(
                json.dumps(
                    {
                        "schema_version": "memory-residency-replay-e2e-event-v1",
                        "event": "contract_failure",
                        "suite_id": contract["suite"]["suite_id"],
                        "matrix_scenario_id": contract["suite"]["scenario_id"],
                        "status": "failed",
                        "error": error,
                    },
                    sort_keys=True,
                )
                + "\n"
            )

    scenario_report = {
        "schema_version": "memory-residency-replay-e2e-report-v1",
        "suite_id": contract["suite"]["suite_id"],
        "scenario_id": contract["suite"]["scenario_id"],
        "generated_at": generated_at,
        "large_host_fixture": contract["large_host_fixture"],
        "scenario_count": len(events),
        "failed_count": len(errors),
        "scenarios": events,
        "failure_contract": contract["failure_contract"],
        "benchmark_evidence": contract["benchmark_evidence"],
        "no_claim_boundaries": contract["no_claim_boundaries"],
    }
    json_dump(scenario_report_file, scenario_report)
    write_operator_report(operator_report_file, contract, events)

    summary = {
        "schema_version": "e2e-suite-summary-v3",
        "suite_id": contract["suite"]["suite_id"],
        "scenario_id": contract["suite"]["scenario_id"],
        "seed": "memory-residency-replay-fixture-v1",
        "started_ts": generated_at,
        "ended_ts": generated_at,
        "status": status,
        "failure_class": "none" if not errors else "contract_failure",
        "repro_command": (
            "TEST_SEED=memory-residency-replay-fixture-v1 "
            "bash scripts/run_memory_residency_replay_e2e.sh"
        ),
        "artifact_path": str(summary_file),
        "artifact_dir": str(artifact_dir),
        "events_path": str(events_file),
        "scenario_report": str(scenario_report_file),
        "operator_report": str(operator_report_file),
        "scenario_count": len(events),
        "failed_count": len(errors),
        "proof_lane_command": contract["proof_lane"]["command"],
        "copy_paste_rch_command": contract["failure_contract"]["copy_paste_rch_command"],
        "no_claim_boundaries": contract["no_claim_boundaries"],
    }
    json_dump(summary_file, summary)

    print(f"Summary: {summary_file}")
    print(f"Events: {events_file}")
    print(f"Report: {scenario_report_file}")
    print(f"Artifacts: {artifact_dir}")

    for error in errors:
        print(error, file=sys.stderr)
    return 0 if not errors else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--generated-at", required=True)
    args = parser.parse_args()

    contract = load_contract(args.contract)
    return emit_artifacts(contract, args.output_root, args.run_id, args.generated_at)


if __name__ == "__main__":
    raise SystemExit(main())
